use crate::ciphersuite::CipherSuite;
use ferriscrypt::rand::{SecureRng, SecureRngError};
use std::ops::Deref;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum LeafSecretError {
    #[error(transparent)]
    RngError(#[from] SecureRngError),
}

pub struct LeafSecret(Vec<u8>);

impl Deref for LeafSecret {
    type Target = Vec<u8>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl LeafSecret {
    pub fn new(cipher_suite: CipherSuite) -> Result<LeafSecret, LeafSecretError> {
        let data = SecureRng::gen(cipher_suite.kem_type().sk_len())?;
        Ok(LeafSecret(data))
    }
}

impl From<Vec<u8>> for LeafSecret {
    fn from(data: Vec<u8>) -> Self {
        Self(data)
    }
}
