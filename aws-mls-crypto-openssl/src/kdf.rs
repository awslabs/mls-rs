use std::ops::Deref;

use aws_mls_core::crypto::CipherSuite;
use openssl::{
    md::{Md, MdRef},
    pkey::Id,
    pkey_ctx::{HkdfMode, PkeyCtx},
};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum KdfError {
    #[error(transparent)]
    OpensslError(#[from] openssl::error::ErrorStack),
    #[error("the provided length of the key {0} is shorter than the minimum length {1}")]
    TooShortKey(usize, usize),
}

#[derive(Clone)]
pub struct Kdf(&'static MdRef);

impl Deref for Kdf {
    type Target = MdRef;

    fn deref(&self) -> &Self::Target {
        self.0
    }
}

impl Kdf {
    pub fn new(cipher_suite: CipherSuite) -> Self {
        let md_ref = match cipher_suite {
            CipherSuite::Curve25519Aes128
            | CipherSuite::P256Aes128
            | CipherSuite::Curve25519ChaCha20 => Md::sha256(),
            CipherSuite::P384Aes256 => Md::sha384(),
            _ => Md::sha512(),
        };

        Self(md_ref)
    }

    /// # Warning
    /// The length of info can *not* exceed 1024 bytes when using the OpenSSL Engine due to underlying
    /// restrictions in OpenSSL. This function will throw an [EngineError](KdfError::EngineError)
    /// in the event info is > 1024 bytes.
    pub fn kdf_expand(&self, prk: &[u8], info: &[u8], len: usize) -> Result<Vec<u8>, KdfError> {
        if prk.len() < self.kdf_extract_size() {
            return Err(KdfError::TooShortKey(prk.len(), self.kdf_extract_size()));
        }

        let mut ctx = self.create_hkdf_ctx(HkdfMode::EXPAND_ONLY, prk)?;
        ctx.add_hkdf_info(info)?;

        let mut buf = vec![0u8; len];
        ctx.derive(Some(&mut buf))?;
        Ok(buf)
    }

    pub fn kdf_extract(&self, salt: &[u8], ikm: &[u8]) -> Result<Vec<u8>, KdfError> {
        if ikm.is_empty() {
            return Err(KdfError::TooShortKey(0, 1));
        }

        let mut ctx = self.create_hkdf_ctx(HkdfMode::EXTRACT_ONLY, ikm)?;
        ctx.set_hkdf_salt(salt)?;

        let mut buf = vec![0u8; self.size()];
        ctx.derive(Some(&mut buf))?;
        Ok(buf)
    }

    pub fn kdf_extract_size(&self) -> usize {
        self.size()
    }

    fn create_hkdf_ctx(&self, mode: HkdfMode, key: &[u8]) -> Result<PkeyCtx<()>, KdfError> {
        let mut ctx = PkeyCtx::new_id(Id::HKDF)?;
        ctx.derive_init()?;
        ctx.set_hkdf_mode(mode)?;
        ctx.set_hkdf_md(self)?;
        ctx.set_hkdf_key(key)?;

        Ok(ctx)
    }
}

#[cfg(test)]
mod test {
    use assert_matches::assert_matches;
    use aws_mls_core::crypto::CipherSuite;
    use serde::Deserialize;

    use crate::kdf::{Kdf, KdfError};

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
        println!(
            "Running HKDF test case for cipher suite: {:?}",
            case.ciphersuite
        );

        let kdf = Kdf::new(case.ciphersuite);

        let extracted = kdf.kdf_extract(&case.salt, &case.ikm).unwrap();
        assert_eq!(extracted, case.prk);

        let expanded = kdf.kdf_expand(&case.prk, &case.info, case.len).unwrap();
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
        let kdf = Kdf::new(CipherSuite::Curve25519Aes128);
        assert!(kdf.kdf_extract(b"key", &[]).is_err());
    }

    #[test]
    fn no_salt() {
        let kdf = Kdf::new(CipherSuite::Curve25519Aes128);
        assert!(kdf.kdf_extract(&[], b"key").is_ok());
    }

    #[test]
    fn no_info() {
        let kdf = Kdf::new(CipherSuite::Curve25519Aes128);
        let key = vec![0u8; kdf.kdf_extract_size()];
        assert!(kdf.kdf_expand(&key, &[], 42).is_ok());
    }

    #[test]
    fn test_short_key() {
        let kdf = Kdf::new(CipherSuite::Curve25519Aes128);
        let key = vec![0u8; kdf.kdf_extract_size() - 1];

        assert_matches!(
            kdf.kdf_expand(&key, &[], 42),
            Err(KdfError::TooShortKey(_, _))
        );
    }
}
