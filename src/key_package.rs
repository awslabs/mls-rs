use crate::ciphersuite::CipherSuite;
use crate::credential::{Credential, CredentialError};
use crate::extension::{Extension, ExtensionError, ExtensionList};
use crate::protocol_version::ProtocolVersion;
use bincode::Options;
use ferriscrypt::asym::ec_key::{generate_keypair, EcKeyError, SecretKey};
use ferriscrypt::{Signer, Verifier};
use serde::{Deserialize, Serialize};
use std::time::SystemTime;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum KeyPackageError {
    #[error(transparent)]
    EcKeyError(#[from] EcKeyError),
    #[error(transparent)]
    ExtensionError(#[from] ExtensionError),
    #[error(transparent)]
    SerializationError(#[from] bincode::Error),
    #[error(transparent)]
    CredentialError(#[from] CredentialError),
    #[error("invalid signature")]
    InvalidSignature,
    #[error("key lifetime not found")]
    MissingKeyLifetime,
    #[error("not within lifetime")]
    InvalidKeyLifetime,
}

#[derive(Serialize, Deserialize, PartialEq, Clone, Debug)]
pub struct KeyPackage {
    pub version: ProtocolVersion,
    pub cipher_suite: CipherSuite,
    pub hpke_init_key: Vec<u8>,
    pub credential: Credential,
    pub extensions: ExtensionList,
    pub signature: Vec<u8>,
}

pub(crate) struct KeyPackageGenerator<'a> {
    pub(crate) cipher_suite: CipherSuite,
    pub(crate) credential: &'a Credential,
    pub(crate) extensions: ExtensionList,
    pub(crate) signing_key: &'a SecretKey,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KeyPackageGeneration {
    pub key_package: KeyPackage,
    pub secret_key: SecretKey,
    pub key_package_hash: Vec<u8>,
}

impl<'a> KeyPackageGenerator<'a> {
    pub fn generate(&self) -> Result<KeyPackageGeneration, KeyPackageError> {
        let (public, secret) = generate_keypair(self.cipher_suite.kem_type().curve())?;

        let mut package = KeyPackage {
            version: self.cipher_suite.protocol_version(),
            cipher_suite: self.cipher_suite,
            hpke_init_key: public.to_uncompressed_bytes()?,
            credential: self.credential.clone(),
            extensions: self.extensions.clone(),
            signature: vec![],
        };

        package.signature = self.signing_key.sign(&package.to_signable_vec()?)?;

        let key_package_hash = self
            .cipher_suite
            .hash_function()
            .digest(&bincode::serialize(&package)?);

        Ok(KeyPackageGeneration {
            key_package: package,
            secret_key: secret,
            key_package_hash,
        })
    }
}

impl KeyPackage {
    pub(crate) fn to_signable_vec(&self) -> Result<Vec<u8>, KeyPackageError> {
        #[derive(Serialize)]
        pub struct KeyPackageData<'a> {
            pub version: &'a ProtocolVersion,
            pub cipher_suite: &'a CipherSuite,
            pub hpke_init_key: &'a Vec<u8>,
            pub credential: &'a Credential,
            pub extensions: &'a Vec<Extension>,
        }

        let key_package_data = KeyPackageData {
            version: &self.version,
            cipher_suite: &self.cipher_suite,
            hpke_init_key: &self.hpke_init_key,
            credential: &self.credential,
            extensions: &self.extensions,
        };

        bincode::DefaultOptions::new()
            .with_big_endian()
            .serialize(&key_package_data)
            .map_err(Into::into)
    }

    pub fn has_valid_signature(&self) -> Result<bool, KeyPackageError> {
        self.credential
            .verify(&self.signature, &self.to_signable_vec()?)
            .map_err(Into::into)
    }

    pub fn has_valid_lifetime(&self, time: SystemTime) -> Result<bool, KeyPackageError> {
        self.extensions
            .get_lifetime()?
            .ok_or(KeyPackageError::MissingKeyLifetime)
            .and_then(|l| l.within_lifetime(time).map_err(KeyPackageError::from))
    }

    pub fn validate(&self, time: SystemTime) -> Result<(), KeyPackageError> {
        if !self.has_valid_signature()? {
            return Err(KeyPackageError::InvalidSignature);
        }

        if !self.has_valid_lifetime(time)? {
            return Err(KeyPackageError::InvalidKeyLifetime);
        }

        Ok(())
    }
}

//TODO: Tests for validate + has valid signature
