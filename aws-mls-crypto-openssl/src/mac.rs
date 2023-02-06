use std::ops::Deref;

use aws_mls_core::crypto::CipherSuite;
use openssl::{
    hash::{hash, MessageDigest},
    pkey::PKey,
    sign::Signer,
};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum HashError {
    #[error(transparent)]
    OpensslError(#[from] openssl::error::ErrorStack),
    #[error("unsupported cipher suite")]
    UnsupportedCipherSuite,
}

#[derive(Clone)]
pub struct Hash(MessageDigest);

impl Deref for Hash {
    type Target = MessageDigest;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Hash {
    pub fn new(cipher_suite: CipherSuite) -> Result<Self, HashError> {
        let md = match cipher_suite {
            CipherSuite::CURVE25519_AES128
            | CipherSuite::P256_AES128
            | CipherSuite::CURVE25519_CHACHA => Ok(MessageDigest::sha256()),
            CipherSuite::P384_AES256 => Ok(MessageDigest::sha384()),
            CipherSuite::CURVE448_CHACHA
            | CipherSuite::CURVE448_AES256
            | CipherSuite::P521_AES256 => Ok(MessageDigest::sha512()),
            _ => Err(HashError::UnsupportedCipherSuite),
        }?;

        Ok(Self(md))
    }

    pub fn hash(&self, data: &[u8]) -> Result<Vec<u8>, HashError> {
        Ok(hash(self.0, data)?.to_vec())
    }

    pub fn mac(&self, key: &[u8], data: &[u8]) -> Result<Vec<u8>, HashError> {
        let key = PKey::hmac(key)?;
        let mut signer = Signer::new(self.0, &key)?;
        Ok(signer.sign_oneshot_to_vec(data)?)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use serde::Deserialize;

    #[derive(Deserialize)]
    struct TestCase {
        pub ciphersuite: CipherSuite,
        #[serde(with = "hex::serde")]
        key: Vec<u8>,
        #[serde(with = "hex::serde")]
        message: Vec<u8>,
        #[serde(with = "hex::serde")]
        tag: Vec<u8>,
    }

    fn run_test_case(case: &TestCase) {
        println!(
            "Running HMAC test case for cipher suite: {:?}",
            case.ciphersuite
        );

        // Test Sign
        let hash = Hash::new(case.ciphersuite).unwrap();
        let tag = hash.mac(&case.key, &case.message).unwrap();
        assert_eq!(&tag, &case.tag);

        // Test different message
        let different_tag = hash.mac(&case.key, b"different message").unwrap();
        assert_ne!(&different_tag, &tag)
    }

    #[test]
    fn test_hmac_test_vectors() {
        let test_case_file = include_str!("../test_data/test_hmac.json");
        let test_cases: Vec<TestCase> = serde_json::from_str(test_case_file).unwrap();

        for case in test_cases {
            run_test_case(&case);
        }
    }
}
