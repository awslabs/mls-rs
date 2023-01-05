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
    pub fn new(cipher_suite: CipherSuite) -> Self {
        let md = match cipher_suite {
            CipherSuite::Curve25519Aes128
            | CipherSuite::P256Aes128
            | CipherSuite::Curve25519ChaCha20 => MessageDigest::sha256(),
            CipherSuite::P384Aes256 => MessageDigest::sha384(),
            _ => MessageDigest::sha512(),
        };

        Self(md)
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

// TODO add tests
