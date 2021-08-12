use crate::cipher_suite::CipherSuite;
use crate::group::key_schedule::{KeyScheduleKdf, KeyScheduleKdfError};
use crate::tree_kem::leaf_secret::LeafSecret;
use ferriscrypt::asym::ec_key::{EcKeyError, SecretKey};
use ferriscrypt::hpke::kem::{Kem, KemType};
use ferriscrypt::hpke::HpkeError;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum NodeSecretGeneratorError {
    #[error(transparent)]
    KeyScheduleKdfError(#[from] KeyScheduleKdfError),
    #[error(transparent)]
    HpkeError(#[from] HpkeError),
    #[error(transparent)]
    EcKeyError(#[from] EcKeyError),
}

#[derive(Clone, Debug)]
pub struct NodeSecrets {
    pub path_secret: Vec<u8>,
    pub public_key: Vec<u8>,
    pub secret_key: SecretKey,
}

pub struct NodeSecretGenerator {
    pub next_path_secret: Vec<u8>,
    kdf: KeyScheduleKdf,
    kem: Kem,
    cipher_suite: CipherSuite,
}

impl NodeSecretGenerator {
    // The first secret generated will be based on the path_secret passed in,
    // and will ratchet forward after that
    pub fn new_from_path_secret(cipher_suite: CipherSuite, path_secret: Vec<u8>) -> Self {
        Self {
            kdf: KeyScheduleKdf::new(cipher_suite.kdf_type()),
            next_path_secret: path_secret,
            kem: cipher_suite.kem(),
            cipher_suite,
        }
    }

    pub fn new_from_leaf_secret(cipher_suite: CipherSuite, leaf_secret: LeafSecret) -> Self {
        Self::new_from_path_secret(cipher_suite, leaf_secret.clone())
    }

    pub fn next_secret(&mut self) -> Result<NodeSecrets, NodeSecretGeneratorError> {
        let path_secret = self.next_path_secret.clone();
        let node_secret = self.kdf.derive_secret(&path_secret, "node")?;
        //TODO: This should be somehow updated to avoid dealing with bytes for secret key here
        let (secret_key, public_key) = self.kem.derive(&node_secret)?;

        self.next_path_secret = self.kdf.derive_secret(&path_secret, "path")?;

        Ok(NodeSecrets {
            path_secret,
            public_key,
            secret_key: SecretKey::from_bytes(&secret_key, self.cipher_suite.kem_type().curve())?,
        })
    }
}

impl Iterator for NodeSecretGenerator {
    type Item = Result<NodeSecrets, NodeSecretGeneratorError>;

    fn next(&mut self) -> Option<Self::Item> {
        Some(self.next_secret())
    }
}
