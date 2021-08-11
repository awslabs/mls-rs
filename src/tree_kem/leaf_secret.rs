use crate::ciphersuite::CipherSuite;
use crate::group::key_schedule::{KeyScheduleKdf, KeyScheduleKdfError};
use ferriscrypt::hpke::kem::{KemPublicKey, KemSecretKey, KemType};
use ferriscrypt::hpke::HpkeError;
use ferriscrypt::rand::{SecureRng, SecureRngError};
use std::ops::Deref;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum LeafSecretError {
    #[error(transparent)]
    RngError(#[from] SecureRngError),
    #[error(transparent)]
    KeyDerivationError(#[from] KeyScheduleKdfError),
    #[error(transparent)]
    KemError(#[from] HpkeError),
}

pub struct LeafSecret {
    cipher_suite: CipherSuite,
    pub data: Vec<u8>,
}

impl Deref for LeafSecret {
    type Target = Vec<u8>;

    fn deref(&self) -> &Self::Target {
        &self.data
    }
}

impl LeafSecret {
    pub fn generate(cipher_suite: CipherSuite) -> Result<LeafSecret, LeafSecretError> {
        let data = SecureRng::gen(cipher_suite.kem_type().sk_len())?;
        Ok(LeafSecret { cipher_suite, data })
    }

    pub fn as_leaf_key_pair(&self) -> Result<(KemSecretKey, KemPublicKey), LeafSecretError> {
        let kdf = KeyScheduleKdf::new(self.cipher_suite.kdf_type());
        let leaf_node_secret = kdf.derive_secret(&self.data, "node")?;
        self.cipher_suite
            .kem()
            .derive(&leaf_node_secret)
            .map_err(Into::into)
    }
}
