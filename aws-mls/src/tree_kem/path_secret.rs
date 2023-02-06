use crate::group::key_schedule::{kdf_derive_secret, KeyScheduleError};
use crate::provider::crypto::{CipherSuiteProvider, HpkePublicKey, HpkeSecretKey};
use crate::serde_utils::vec_u8_as_base64::VecAsBase64;
use serde_with::serde_as;
use std::ops::Deref;
use thiserror::Error;
use tls_codec_derive::{TlsDeserialize, TlsSerialize, TlsSize};
use zeroize::{Zeroize, Zeroizing};

use super::hpke_encryption::HpkeEncryptable;

#[derive(Error, Debug)]
pub enum PathSecretError {
    #[error(transparent)]
    CipherSuiteProviderError(Box<dyn std::error::Error + Send + Sync + 'static>),
    #[error(transparent)]
    KeyScheduleError(#[from] KeyScheduleError),
}

#[serde_as]
#[derive(
    Debug,
    Clone,
    Zeroize,
    Eq,
    PartialEq,
    TlsSerialize,
    TlsDeserialize,
    TlsSize,
    serde::Serialize,
    serde::Deserialize,
)]
#[zeroize(drop)]
pub struct PathSecret(
    #[tls_codec(with = "crate::tls::ByteVec")]
    #[serde_as(as = "VecAsBase64")]
    Vec<u8>,
);

impl Deref for PathSecret {
    type Target = Vec<u8>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl From<Vec<u8>> for PathSecret {
    fn from(data: Vec<u8>) -> Self {
        PathSecret(data)
    }
}

impl PathSecret {
    pub fn random<P: CipherSuiteProvider>(
        cipher_suite_provider: &P,
    ) -> Result<PathSecret, PathSecretError> {
        cipher_suite_provider
            .random_bytes_vec(cipher_suite_provider.kdf_extract_size())
            .map(Into::into)
            .map_err(|e| PathSecretError::CipherSuiteProviderError(e.into()))
    }

    pub fn empty<P: CipherSuiteProvider>(cipher_suite_provider: &P) -> Self {
        // Define commit_secret as the all-zero vector of the same length as a path_secret
        PathSecret::from(vec![0u8; cipher_suite_provider.kdf_extract_size()])
    }
}

impl HpkeEncryptable for PathSecret {
    const ENCRYPT_LABEL: &'static str = "UpdatePathNode";
}

#[derive(Clone, Debug)]
pub struct PathSecretGeneration<'a, P> {
    pub path_secret: PathSecret,
    cipher_suite_provider: &'a P,
}

impl<'a, P: CipherSuiteProvider> PathSecretGeneration<'a, P> {
    pub fn random(cipher_suite_provider: &'a P) -> Result<Self, PathSecretError> {
        Ok(Self {
            path_secret: PathSecret::random(cipher_suite_provider)?,
            cipher_suite_provider,
        })
    }

    pub fn to_hpke_key_pair(&self) -> Result<(HpkeSecretKey, HpkePublicKey), PathSecretError> {
        let node_secret = Zeroizing::new(kdf_derive_secret(
            self.cipher_suite_provider,
            &self.path_secret,
            "node",
        )?);

        self.cipher_suite_provider
            .kem_derive(&node_secret)
            .map_err(|e| PathSecretError::CipherSuiteProviderError(e.into()))
    }
}

#[derive(Clone, Debug)]
pub struct PathSecretGenerator<'a, P> {
    cipher_suite_provider: &'a P,
    last: Option<PathSecret>,
    starting_with: Option<PathSecret>,
}

impl<'a, P: CipherSuiteProvider> PathSecretGenerator<'a, P> {
    pub fn new(cipher_suite_provider: &'a P) -> Self {
        Self {
            cipher_suite_provider,
            last: None,
            starting_with: None,
        }
    }

    pub fn starting_from(cipher_suite_provider: &'a P, secret: PathSecret) -> Self {
        Self {
            last: Some(secret),
            ..Self::new(cipher_suite_provider)
        }
    }

    pub fn starting_with(cipher_suite_provider: &'a P, secret: PathSecret) -> Self {
        Self {
            starting_with: Some(secret),
            ..Self::new(cipher_suite_provider)
        }
    }

    pub fn next_secret(&mut self) -> Result<PathSecretGeneration<'a, P>, PathSecretError> {
        let secret = if let Some(starting_with) = self.starting_with.take() {
            Ok(starting_with)
        } else if let Some(last) = self.last.take() {
            kdf_derive_secret(self.cipher_suite_provider, &last, "path")
                .map(PathSecret::from)
                .map_err(|e| PathSecretError::CipherSuiteProviderError(e.into()))
        } else {
            PathSecret::random(self.cipher_suite_provider)
        }?;

        self.last = Some(secret.clone());

        Ok(PathSecretGeneration {
            path_secret: secret,
            cipher_suite_provider: self.cipher_suite_provider,
        })
    }
}

impl<'a, P: CipherSuiteProvider> Iterator for PathSecretGenerator<'a, P> {
    type Item = Result<PathSecretGeneration<'a, P>, PathSecretError>;

    fn next(&mut self) -> Option<Self::Item> {
        Some(self.next_secret())
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        cipher_suite::CipherSuite,
        client::test_utils::TEST_CIPHER_SUITE,
        provider::crypto::test_utils::{
            test_cipher_suite_provider, try_test_cipher_suite_provider, TestCryptoProvider,
        },
    };

    use super::*;

    #[cfg(target_arch = "wasm32")]
    use wasm_bindgen_test::wasm_bindgen_test as test;

    #[derive(serde::Deserialize, serde::Serialize)]
    struct TestCase {
        cipher_suite: u16,
        generations: Vec<String>,
    }

    impl TestCase {
        fn generate() -> Vec<TestCase> {
            CipherSuite::all()
                .map(|cipher_suite| {
                    let cs_provider = test_cipher_suite_provider(cipher_suite);
                    let generator = PathSecretGenerator::new(&cs_provider);
                    let generations = generator
                        .into_iter()
                        .take(10)
                        .map(|res| hex::encode(&*res.unwrap().path_secret))
                        .collect();

                    TestCase {
                        cipher_suite: cipher_suite.into(),
                        generations,
                    }
                })
                .collect()
        }
    }

    fn load_test_cases() -> Vec<TestCase> {
        load_test_cases!(path_secret, TestCase::generate())
    }

    #[test]
    fn test_path_secret_generation() {
        let cases = load_test_cases();

        for one_case in cases {
            let Some(cs_provider) = try_test_cipher_suite_provider(one_case.cipher_suite) else {
                continue;
            };

            let first_secret = PathSecret::from(hex::decode(&one_case.generations[0]).unwrap());
            let generator = PathSecretGenerator::starting_with(&cs_provider, first_secret);

            let generated_results = generator
                .take(one_case.generations.len())
                .map(|r| hex::encode(&*r.unwrap().path_secret))
                .collect::<Vec<String>>();

            assert_eq!(generated_results, one_case.generations);
        }
    }

    #[test]
    fn test_first_path_is_random() {
        let cs_provider = test_cipher_suite_provider(TEST_CIPHER_SUITE);

        let mut generator = PathSecretGenerator::new(&cs_provider);
        let first_secret = generator.next_secret().unwrap();

        for _ in 0..100 {
            let mut next_generator = PathSecretGenerator::new(&cs_provider);
            let next_secret = next_generator.next_secret().unwrap();
            assert_ne!(first_secret.path_secret, next_secret.path_secret);
        }
    }

    #[test]
    fn test_iterator() {
        let cs_provider = test_cipher_suite_provider(TEST_CIPHER_SUITE);
        let secret = PathSecret::random(&cs_provider).unwrap();

        let mut generator = PathSecretGenerator::starting_with(&cs_provider, secret);

        let mut cloned_generator = generator.clone();
        let expected = generator.next_secret().unwrap().path_secret;
        let actual = cloned_generator.next().unwrap().unwrap().path_secret;

        assert_eq!(actual, expected);
    }

    #[test]
    fn test_starting_with() {
        let cs_provider = test_cipher_suite_provider(TEST_CIPHER_SUITE);
        let secret = PathSecret::random(&cs_provider).unwrap();

        let mut generator = PathSecretGenerator::starting_with(&cs_provider, secret.clone());

        let first_secret = generator.next_secret().unwrap();
        let second_secret = generator.next_secret().unwrap();

        assert_eq!(
            first_secret.cipher_suite_provider.cipher_suite(),
            TEST_CIPHER_SUITE
        );
        assert_eq!(secret, first_secret.path_secret);
        assert_ne!(first_secret.path_secret, second_secret.path_secret);
    }

    #[test]
    fn test_starting_from() {
        let cs_provider = test_cipher_suite_provider(TEST_CIPHER_SUITE);

        let mut generator = PathSecretGenerator::new(&cs_provider);

        let first_secret = generator.next_secret().unwrap();
        let second_secret = generator.next_secret().unwrap();

        let mut from_first_generator =
            PathSecretGenerator::starting_from(&cs_provider, first_secret.path_secret);

        assert_eq!(
            second_secret.path_secret,
            from_first_generator.next_secret().unwrap().path_secret
        );
    }

    #[test]
    fn test_empty_path_secret() {
        for cipher_suite in TestCryptoProvider::all_supported_cipher_suites() {
            let cs_provider = test_cipher_suite_provider(cipher_suite);
            let empty = PathSecret::empty(&cs_provider);
            assert_eq!(
                empty,
                PathSecret::from(vec![0u8; cs_provider.kdf_extract_size()])
            )
        }
    }

    #[test]
    fn test_random_path_secret() {
        let cs_provider = test_cipher_suite_provider(CipherSuite::P256_AES128);
        let initial = PathSecret::random(&cs_provider).unwrap();

        for _ in 0..100 {
            let next = PathSecret::random(&cs_provider).unwrap();
            assert_ne!(next, initial);
        }
    }

    #[test]
    fn test_random_path_secret_generation() {
        let cs_provider = test_cipher_suite_provider(TEST_CIPHER_SUITE);

        let initial = PathSecretGeneration::random(&cs_provider).unwrap();

        for _ in 0..100 {
            let next = PathSecretGeneration::random(&cs_provider).unwrap();
            assert_ne!(next.path_secret, initial.path_secret);
        }
    }
}
