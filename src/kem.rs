use crate::kdf::{KeyDerivationFunction, Hkdf};
use openssl::ec::EcKey;
use openssl::pkey::{Private, Public};
use thiserror::Error;
use openssl::error::ErrorStack;

#[derive(Error, Debug)]
pub enum AsymmetricKeyError {
    #[error("Openssl error: {0}")]
    OpenSSLError(#[from] ErrorStack),
}

pub struct SharedSecret {
    pub secret: Vec<u8>,
    pub context: Vec<u8>
}

pub trait AsymmetricKeyEngine {
    type PubKeyType: AsymmetricKey;
    type SecretKeyType: AsymmetricKey;
    fn generate_key_pair(&self) -> Result<(Self::PubKeyType, Self::SecretKeyType), AsymmetricKeyError>;
    fn shared_secret(&self, remote_key: Self::PubKeyType) -> Result<SharedSecret, AsymmetricKeyError>;
}

pub trait AsymmetricKey : Sized {
    fn from_bytes(bytes: Vec<u8>) -> Result<Self, AsymmetricKeyError>;
    fn serialize(&self) -> Result<Vec<u8>, AsymmetricKeyError>;
}

pub trait KeyEncapsulationMechanism<E: AsymmetricKeyEngine, KDF: KeyDerivationFunction> {
    fn generate_key_pair(&self) -> (E::PubKeyType, E::SecretKeyType);
    fn derive_key_pair(&self, ikm: &Vec<u8>) -> (E::PubKeyType, E::SecretKeyType);
    fn encapsulate(&self, remote_key: &E::PubKeyType, out_len: usize) -> (Vec<u8>, Vec<u8>);
    fn decapsulate(&self, kem_data: &Vec<u8>, secret_key: &E::SecretKeyType) -> Vec<u8>;
}