use crate::client::MlsError;
use crate::crypto::{CipherSuiteProvider, HpkePublicKey, HpkeSecretKey};
use crate::group::key_schedule::kdf_derive_secret;
use alloc::vec;
use alloc::vec::Vec;
use aws_mls_codec::{MlsDecode, MlsEncode, MlsSize};
use aws_mls_core::error::IntoAnyError;
use core::ops::Deref;
use zeroize::{Zeroize, Zeroizing};

use super::hpke_encryption::HpkeEncryptable;

#[derive(Debug, Clone, Zeroize, Eq, PartialEq, MlsSize, MlsEncode, MlsDecode)]
#[zeroize(drop)]
pub struct PathSecret(#[mls_codec(with = "aws_mls_codec::byte_vec")] Zeroizing<Vec<u8>>);

impl Deref for PathSecret {
    type Target = Vec<u8>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl From<Vec<u8>> for PathSecret {
    fn from(data: Vec<u8>) -> Self {
        PathSecret(Zeroizing::new(data))
    }
}

impl From<Zeroizing<Vec<u8>>> for PathSecret {
    fn from(data: Zeroizing<Vec<u8>>) -> Self {
        PathSecret(data)
    }
}

impl PathSecret {
    pub fn random<P: CipherSuiteProvider>(
        cipher_suite_provider: &P,
    ) -> Result<PathSecret, MlsError> {
        cipher_suite_provider
            .random_bytes_vec(cipher_suite_provider.kdf_extract_size())
            .map(Into::into)
            .map_err(|e| MlsError::CryptoProviderError(e.into_any_error()))
    }

    pub fn empty<P: CipherSuiteProvider>(cipher_suite_provider: &P) -> Self {
        // Define commit_secret as the all-zero vector of the same length as a path_secret
        PathSecret::from(vec![0u8; cipher_suite_provider.kdf_extract_size()])
    }
}

impl HpkeEncryptable for PathSecret {
    const ENCRYPT_LABEL: &'static str = "UpdatePathNode";

    fn from_bytes(bytes: Vec<u8>) -> Result<Self, MlsError> {
        Ok(Self(Zeroizing::new(bytes)))
    }

    fn get_bytes(&self) -> Result<Vec<u8>, MlsError> {
        Ok(self.to_vec())
    }
}

impl PathSecret {
    pub fn to_hpke_key_pair<P: CipherSuiteProvider>(
        &self,
        cs: &P,
    ) -> Result<(HpkeSecretKey, HpkePublicKey), MlsError> {
        let node_secret = Zeroizing::new(kdf_derive_secret(cs, self, b"node")?);

        cs.kem_derive(&node_secret)
            .map_err(|e| MlsError::CryptoProviderError(e.into_any_error()))
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

    pub fn starting_with(cipher_suite_provider: &'a P, secret: PathSecret) -> Self {
        Self {
            starting_with: Some(secret),
            ..Self::new(cipher_suite_provider)
        }
    }

    pub fn next_secret(&mut self) -> Result<PathSecret, MlsError> {
        let secret = if let Some(starting_with) = self.starting_with.take() {
            Ok(starting_with)
        } else if let Some(last) = self.last.take() {
            kdf_derive_secret(self.cipher_suite_provider, &last, b"path").map(PathSecret::from)
        } else {
            PathSecret::random(self.cipher_suite_provider)
        }?;

        self.last = Some(secret.clone());

        Ok(secret)
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        cipher_suite::CipherSuite,
        client::test_utils::TEST_CIPHER_SUITE,
        crypto::test_utils::{
            test_cipher_suite_provider, try_test_cipher_suite_provider, TestCryptoProvider,
        },
    };

    use super::*;

    use alloc::string::String;
    use itertools::Itertools;
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
                    let mut generator = PathSecretGenerator::new(&cs_provider);

                    let generations = (0..10)
                        .map(|_| hex::encode(&*generator.next_secret().unwrap()))
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
        load_test_case_json!(path_secret, TestCase::generate())
    }

    #[test]
    fn test_path_secret_generation() {
        let cases = load_test_cases();

        for one_case in cases {
            let Some(cs_provider) = try_test_cipher_suite_provider(one_case.cipher_suite) else {
                continue;
            };

            let first_secret = PathSecret::from(hex::decode(&one_case.generations[0]).unwrap());
            let mut generator = PathSecretGenerator::starting_with(&cs_provider, first_secret);

            let generated_results = (0..one_case.generations.len())
                .map(|_| hex::encode(&*generator.next_secret().unwrap()))
                .collect_vec();

            assert_eq!(one_case.generations, generated_results);
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
            assert_ne!(first_secret, next_secret);
        }
    }

    #[test]
    fn test_starting_with() {
        let cs_provider = test_cipher_suite_provider(TEST_CIPHER_SUITE);
        let secret = PathSecret::random(&cs_provider).unwrap();

        let mut generator = PathSecretGenerator::starting_with(&cs_provider, secret.clone());

        let first_secret = generator.next_secret().unwrap();
        let second_secret = generator.next_secret().unwrap();

        assert_eq!(secret, first_secret);
        assert_ne!(first_secret, second_secret);
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
}
