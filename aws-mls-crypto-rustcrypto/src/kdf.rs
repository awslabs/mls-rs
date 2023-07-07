use core::fmt::Debug;

use aws_mls_core::{crypto::CipherSuite, error::IntoAnyError};
use aws_mls_crypto_traits::{KdfId, KdfType};
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Kdf(KdfId);

impl Kdf {
    pub fn new(cipher_suite: CipherSuite) -> Option<Self> {
        KdfId::new(cipher_suite).map(Self)
    }
}

impl KdfType for Kdf {
    type Error = KdfError;

    fn expand(&self, prk: &[u8], info: &[u8], len: usize) -> Result<Vec<u8>, KdfError> {
        if prk.len() < self.extract_size() {
            return Err(KdfError::TooShortKey(prk.len(), self.extract_size()));
        }

        let mut buf = vec![0u8; len];

        match self.0 {
            KdfId::HkdfSha256 => Ok(SimpleHkdf::<Sha256>::from_prk(prk)?.expand(info, &mut buf)?),
            KdfId::HkdfSha384 => Ok(SimpleHkdf::<Sha384>::from_prk(prk)?.expand(info, &mut buf)?),
            KdfId::HkdfSha512 => Ok(SimpleHkdf::<Sha512>::from_prk(prk)?.expand(info, &mut buf)?),
            _ => Err(KdfError::UnsupportedCipherSuite),
        }?;

        Ok(buf)
    }

    fn extract(&self, salt: &[u8], ikm: &[u8]) -> Result<Vec<u8>, KdfError> {
        if ikm.is_empty() {
            return Err(KdfError::TooShortKey(0, 1));
        }

        let salt = if salt.is_empty() { None } else { Some(salt) };

        match self.0 {
            KdfId::HkdfSha256 => Ok(SimpleHkdf::<Sha256>::extract(salt, ikm).0.to_vec()),
            KdfId::HkdfSha384 => Ok(SimpleHkdf::<Sha384>::extract(salt, ikm).0.to_vec()),
            KdfId::HkdfSha512 => Ok(SimpleHkdf::<Sha512>::extract(salt, ikm).0.to_vec()),
            _ => Err(KdfError::UnsupportedCipherSuite),
        }
    }

    fn extract_size(&self) -> usize {
        self.0.extract_size()
    }

    fn kdf_id(&self) -> u16 {
        self.0 as u16
    }
}

#[cfg(test)]
mod test {
    use assert_matches::assert_matches;
    use aws_mls_core::crypto::CipherSuite;
    use aws_mls_crypto_traits::KdfType;

    use crate::kdf::{Kdf, KdfError};

    use alloc::vec;

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
