use core::fmt::Debug;

use aws_mls_core::{crypto::CipherSuite, error::IntoAnyError};
use aws_mls_crypto_traits::KdfType;
use hkdf::SimpleHkdf;
use sha2::{Sha256, Sha384, Sha512};

use alloc::vec;
use alloc::vec::Vec;

#[derive(Debug)]
#[cfg_attr(feature = "std", derive(thiserror::Error))]
pub enum KdfError {
    #[cfg_attr(feature = "std", error("invalid prk length"))]
    InvalidPrkLength,
    #[cfg_attr(feature = "std", error("invalid length"))]
    InvalidLength,
    #[cfg_attr(
        feature = "std",
        error("the provided length of the key {0} is shorter than the minimum length {1}")
    )]
    TooShortKey(usize, usize),
    #[cfg_attr(feature = "std", error("unsupported cipher suite"))]
    UnsupportedCipherSuite,
}

impl From<hkdf::InvalidPrkLength> for KdfError {
    fn from(_value: hkdf::InvalidPrkLength) -> Self {
        KdfError::InvalidPrkLength
    }
}

impl From<hkdf::InvalidLength> for KdfError {
    fn from(_value: hkdf::InvalidLength) -> Self {
        KdfError::InvalidLength
    }
}

impl IntoAnyError for KdfError {
    #[cfg(feature = "std")]
    fn into_dyn_error(self) -> Result<Box<dyn std::error::Error + Send + Sync>, Self> {
        Ok(self.into())
    }
}

/// Aead KDF as specified in RFC 9180, Table 3.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u16)]
pub enum Kdf {
    HkdfSha256 = 0x0001,
    HkdfSha384 = 0x0002,
    HkdfSha512 = 0x0003,
}

impl Kdf {
    pub fn new(cipher_suite: CipherSuite) -> Result<Self, KdfError> {
        match cipher_suite {
            CipherSuite::CURVE25519_AES128
            | CipherSuite::P256_AES128
            | CipherSuite::CURVE25519_CHACHA => Ok(Kdf::HkdfSha256),
            CipherSuite::P384_AES256 => Ok(Kdf::HkdfSha384),
            CipherSuite::CURVE448_CHACHA
            | CipherSuite::CURVE448_AES256
            | CipherSuite::P521_AES256 => Ok(Kdf::HkdfSha512),
            _ => Err(KdfError::UnsupportedCipherSuite),
        }
    }
}

impl KdfType for Kdf {
    type Error = KdfError;

    fn expand(&self, prk: &[u8], info: &[u8], len: usize) -> Result<Vec<u8>, KdfError> {
        if prk.len() < self.extract_size() {
            return Err(KdfError::TooShortKey(prk.len(), self.extract_size()));
        }

        let mut buf = vec![0u8; len];

        match self {
            Kdf::HkdfSha256 => SimpleHkdf::<Sha256>::from_prk(prk)?.expand(info, &mut buf),
            Kdf::HkdfSha384 => SimpleHkdf::<Sha384>::from_prk(prk)?.expand(info, &mut buf),
            Kdf::HkdfSha512 => SimpleHkdf::<Sha512>::from_prk(prk)?.expand(info, &mut buf),
        }?;

        Ok(buf)
    }

    fn extract(&self, salt: &[u8], ikm: &[u8]) -> Result<Vec<u8>, KdfError> {
        if ikm.is_empty() {
            return Err(KdfError::TooShortKey(0, 1));
        }

        let salt = if salt.is_empty() { None } else { Some(salt) };

        Ok(match self {
            Kdf::HkdfSha256 => SimpleHkdf::<Sha256>::extract(salt, ikm).0.to_vec(),
            Kdf::HkdfSha384 => SimpleHkdf::<Sha384>::extract(salt, ikm).0.to_vec(),
            Kdf::HkdfSha512 => SimpleHkdf::<Sha512>::extract(salt, ikm).0.to_vec(),
        })
    }

    fn extract_size(&self) -> usize {
        match self {
            Kdf::HkdfSha256 => 32,
            Kdf::HkdfSha384 => 48,
            Kdf::HkdfSha512 => 64,
        }
    }

    fn kdf_id(&self) -> u16 {
        *self as u16
    }
}

#[cfg(test)]
mod test {
    use assert_matches::assert_matches;
    use aws_mls_core::crypto::CipherSuite;
    use aws_mls_crypto_traits::KdfType;
    use serde::Deserialize;

    use crate::kdf::{Kdf, KdfError};

    use alloc::vec;
    use alloc::vec::Vec;

    #[derive(Deserialize)]
    struct TestCase {
        pub ciphersuite: CipherSuite,
        #[serde(with = "hex::serde")]
        pub ikm: Vec<u8>,
        #[serde(with = "hex::serde")]
        pub salt: Vec<u8>,
        #[serde(with = "hex::serde")]
        pub info: Vec<u8>,
        pub len: usize,
        #[serde(with = "hex::serde")]
        pub prk: Vec<u8>,
        #[serde(with = "hex::serde")]
        pub okm: Vec<u8>,
    }

    fn run_test_case(case: &TestCase) {
        let kdf = Kdf::new(case.ciphersuite).unwrap();

        let extracted = kdf.extract(&case.salt, &case.ikm).unwrap();
        assert_eq!(extracted, case.prk);

        let expanded = kdf.expand(&case.prk, &case.info, case.len).unwrap();
        assert_eq!(expanded, case.okm);
    }

    #[test]
    fn test_vectors() {
        let test_case_file = include_str!("../test_data/test_kdf.json");

        let test_cases: Vec<TestCase> = serde_json::from_str(test_case_file).unwrap();

        for case in test_cases {
            run_test_case(&case);
        }
    }

    #[test]
    fn no_key() {
        let kdf = Kdf::new(CipherSuite::CURVE25519_AES128).unwrap();
        assert!(kdf.extract(b"key", &[]).is_err());
    }

    #[test]
    fn no_salt() {
        let kdf = Kdf::new(CipherSuite::CURVE25519_AES128).unwrap();
        assert!(kdf.extract(&[], b"key").is_ok());
    }

    #[test]
    fn no_info() {
        let kdf = Kdf::new(CipherSuite::CURVE25519_AES128).unwrap();
        let key = vec![0u8; kdf.extract_size()];
        assert!(kdf.expand(&key, &[], 42).is_ok());
    }

    #[test]
    fn test_short_key() {
        let kdf = Kdf::new(CipherSuite::CURVE25519_AES128).unwrap();
        let key = vec![0u8; kdf.extract_size() - 1];

        assert_matches!(kdf.expand(&key, &[], 42), Err(KdfError::TooShortKey(_, _)));
    }
}
