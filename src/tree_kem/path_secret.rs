use crate::cipher_suite::CipherSuite;
use crate::group::key_schedule::{KeyScheduleKdf, KeyScheduleKdfError};
use crate::serde_utils::vec_u8_as_base64::VecAsBase64;
use ferriscrypt::hpke::kem::{HpkePublicKey, HpkeSecretKey, KemType};
use ferriscrypt::hpke::HpkeError;
use ferriscrypt::rand::{SecureRng, SecureRngError};
use serde_with::serde_as;
use std::ops::Deref;
use thiserror::Error;
use tls_codec_derive::{TlsDeserialize, TlsSerialize, TlsSize};
use zeroize::Zeroize;

#[derive(Error, Debug)]
pub enum PathSecretError {
    #[error(transparent)]
    RngError(#[from] SecureRngError),
    #[error(transparent)]
    KeyDerivationError(#[from] KeyScheduleKdfError),
    #[error(transparent)]
    KemError(#[from] HpkeError),
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
    pub fn random(cipher_suite: CipherSuite) -> Result<PathSecret, PathSecretError> {
        let data = SecureRng::gen(cipher_suite.kem_type().sk_len())?;
        Ok(PathSecret::from(data))
    }

    pub fn empty(cipher_suite: CipherSuite) -> Self {
        let kdf = KeyScheduleKdf::new(cipher_suite.kdf_type());
        // Define commit_secret as the all-zero vector of the same length as a path_secret
        // value would be

        PathSecret::from(vec![0u8; kdf.extract_size()])
    }
}

#[derive(Clone, Debug)]
pub struct PathSecretGeneration {
    pub path_secret: PathSecret,
    cipher_suite: CipherSuite,
    kdf: KeyScheduleKdf,
}

impl PathSecretGeneration {
    pub fn random(cipher_suite: CipherSuite) -> Result<PathSecretGeneration, PathSecretError> {
        let kdf = KeyScheduleKdf::new(cipher_suite.kdf_type());

        Ok(PathSecretGeneration {
            path_secret: PathSecret::random(cipher_suite)?,
            cipher_suite,
            kdf,
        })
    }

    pub fn to_hpke_key_pair(&self) -> Result<(HpkeSecretKey, HpkePublicKey), PathSecretError> {
        let leaf_node_secret = self.kdf.derive_secret(&self.path_secret, "node")?;

        self.cipher_suite
            .kem()
            .derive(&leaf_node_secret)
            .map_err(Into::into)
    }
}

#[derive(Clone, Debug)]
pub struct PathSecretGenerator {
    cipher_suite: CipherSuite,
    kdf: KeyScheduleKdf,
    last: Option<PathSecret>,
    starting_with: Option<PathSecret>,
}

impl PathSecretGenerator {
    pub fn new(cipher_suite: CipherSuite) -> Self {
        let kdf = KeyScheduleKdf::new(cipher_suite.kdf_type());

        PathSecretGenerator {
            cipher_suite,
            kdf,
            last: None,
            starting_with: None,
        }
    }

    pub fn starting_from(cipher_suite: CipherSuite, secret: PathSecret) -> Self {
        Self {
            last: Some(secret),
            ..Self::new(cipher_suite)
        }
    }

    pub fn starting_with(cipher_suite: CipherSuite, secret: PathSecret) -> Self {
        Self {
            starting_with: Some(secret),
            ..Self::new(cipher_suite)
        }
    }

    pub fn next_secret(&mut self) -> Result<PathSecretGeneration, PathSecretError> {
        let secret = if let Some(starting_with) = self.starting_with.take() {
            Ok(starting_with)
        } else if let Some(last) = self.last.take() {
            self.kdf
                .derive_secret(&last, "path")
                .map(PathSecret::from)
                .map_err(PathSecretError::from)
        } else {
            PathSecret::random(self.cipher_suite)
        }?;

        self.last = Some(secret.clone());

        Ok(PathSecretGeneration {
            path_secret: secret,
            cipher_suite: self.cipher_suite,
            kdf: self.kdf.clone(),
        })
    }
}

impl Iterator for PathSecretGenerator {
    type Item = Result<PathSecretGeneration, PathSecretError>;

    fn next(&mut self) -> Option<Self::Item> {
        Some(self.next_secret())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use num_enum::TryFromPrimitive;
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
                    let generator = PathSecretGenerator::new(cipher_suite);
                    let generations = generator
                        .into_iter()
                        .take(10)
                        .map(|res| hex::encode(&*res.unwrap().path_secret))
                        .collect();

                    TestCase {
                        cipher_suite: cipher_suite as u16,
                        generations,
                    }
                })
                .collect()
        }
    }

    fn load_test_cases() -> Vec<TestCase> {
        load_test_cases!(path_secret, TestCase::generate)
    }

    #[test]
    fn test_path_secret_generation() {
        let cases = load_test_cases();

        for one_case in cases {
            let cipher_suite = CipherSuite::try_from_primitive(one_case.cipher_suite);

            if cipher_suite.is_err() {
                println!("Skipping test for unsupported cipher suite");
                continue;
            }

            let first_secret = PathSecret::from(hex::decode(&one_case.generations[0]).unwrap());
            let generator = PathSecretGenerator::starting_with(cipher_suite.unwrap(), first_secret);

            let generated_results = generator
                .take(one_case.generations.len())
                .map(|r| hex::encode(&*r.unwrap().path_secret))
                .collect::<Vec<String>>();

            assert_eq!(generated_results, one_case.generations);
        }
    }

    #[test]
    fn test_first_path_is_random() {
        let mut generator = PathSecretGenerator::new(CipherSuite::P256Aes128);
        let first_secret = generator.next_secret().unwrap();

        for _ in 0..100 {
            let mut next_generator = PathSecretGenerator::new(CipherSuite::P256Aes128);
            let next_secret = next_generator.next_secret().unwrap();
            assert_ne!(first_secret.path_secret, next_secret.path_secret);
        }
    }

    #[test]
    fn test_iterator() {
        let secret = PathSecret::random(CipherSuite::Curve25519Aes128).unwrap();

        let mut generator =
            PathSecretGenerator::starting_with(CipherSuite::Curve25519Aes128, secret);

        let mut cloned_generator = generator.clone();
        let expected = generator.next_secret().unwrap().path_secret;
        let actual = cloned_generator.next().unwrap().unwrap().path_secret;

        assert_eq!(actual, expected);
    }

    #[test]
    fn test_starting_with() {
        let secret = PathSecret::random(CipherSuite::Curve25519Aes128).unwrap();

        let mut generator =
            PathSecretGenerator::starting_with(CipherSuite::Curve25519Aes128, secret.clone());

        let first_secret = generator.next_secret().unwrap();
        let second_secret = generator.next_secret().unwrap();

        assert_eq!(first_secret.cipher_suite, CipherSuite::Curve25519Aes128);
        assert_eq!(secret, first_secret.path_secret);
        assert_ne!(first_secret.path_secret, second_secret.path_secret);
    }

    #[test]
    fn test_starting_from() {
        let mut generator = PathSecretGenerator::new(CipherSuite::Curve25519Aes128);

        let first_secret = generator.next_secret().unwrap();
        let second_secret = generator.next_secret().unwrap();

        let mut from_first_generator = PathSecretGenerator::starting_from(
            CipherSuite::Curve25519Aes128,
            first_secret.path_secret,
        );

        assert_eq!(
            second_secret.path_secret,
            from_first_generator.next_secret().unwrap().path_secret
        );
    }

    #[test]
    fn test_empty_path_secret() {
        for cipher_suite in CipherSuite::all() {
            let empty = PathSecret::empty(cipher_suite);
            let kdf = KeyScheduleKdf::new(cipher_suite.kdf_type());
            assert_eq!(empty, PathSecret::from(vec![0u8; kdf.extract_size()]))
        }
    }

    #[test]
    fn test_random_path_secret() {
        let initial = PathSecret::random(CipherSuite::P256Aes128).unwrap();

        for _ in 0..100 {
            let next = PathSecret::random(CipherSuite::P256Aes128).unwrap();
            assert_ne!(next, initial);
        }
    }

    #[test]
    fn test_random_path_secret_generation() {
        let initial = PathSecretGeneration::random(CipherSuite::P256Aes128).unwrap();

        for _ in 0..100 {
            let next = PathSecretGeneration::random(CipherSuite::P256Aes128).unwrap();
            assert_ne!(next.path_secret, initial.path_secret);
        }
    }
}
