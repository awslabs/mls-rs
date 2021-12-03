use crate::cipher_suite::CipherSuite;
use crate::cipher_suite::ProtocolVersion;
use crate::credential::{Credential, CredentialError};
use crate::extension::{Extension, ExtensionError, ExtensionList};
use ferriscrypt::asym::ec_key::{generate_keypair, EcKeyError, SecretKey};
use ferriscrypt::{Signer, Verifier};
use std::time::SystemTime;
use thiserror::Error;
use tls_codec::Serialize;
use tls_codec_derive::{TlsDeserialize, TlsSerialize, TlsSize};

#[derive(Error, Debug)]
pub enum KeyPackageError {
    #[error(transparent)]
    EcKeyError(#[from] EcKeyError),
    #[error(transparent)]
    ExtensionError(#[from] ExtensionError),
    #[error(transparent)]
    SerializationError(#[from] tls_codec::Error),
    #[error(transparent)]
    CredentialError(#[from] CredentialError),
    #[error("invalid signature")]
    InvalidSignature,
    #[error("key lifetime not found")]
    MissingKeyLifetime,
    #[error("not within lifetime")]
    InvalidKeyLifetime,
}

#[derive(PartialEq, Clone, Debug, TlsDeserialize, TlsSerialize, TlsSize)]
pub struct KeyPackage {
    pub version: ProtocolVersion,
    pub cipher_suite: CipherSuite,
    #[tls_codec(with = "crate::tls::ByteVec::<u32>")]
    pub hpke_init_key: Vec<u8>,
    pub credential: Credential,
    pub extensions: ExtensionList,
    #[tls_codec(with = "crate::tls::ByteVec::<u32>")]
    pub signature: Vec<u8>,
}

impl KeyPackage {
    pub fn to_vec(&self) -> Result<Vec<u8>, KeyPackageError> {
        Ok(self.tls_serialize_detached()?)
    }
}

pub(crate) struct KeyPackageGenerator<'a> {
    pub(crate) cipher_suite: CipherSuite,
    pub(crate) credential: &'a Credential,
    pub(crate) extensions: ExtensionList,
    pub(crate) signing_key: &'a SecretKey,
}

#[derive(Clone, Debug, TlsDeserialize, TlsSerialize, TlsSize)]
pub struct KeyPackageGeneration {
    pub key_package: KeyPackage,
    #[tls_codec(with = "crate::tls::SecretKeySer")]
    pub secret_key: SecretKey,
}

impl KeyPackageGeneration {
    pub fn key_package_id(&self) -> Result<Vec<u8>, KeyPackageError> {
        Ok(self
            .key_package
            .cipher_suite
            .hash_function()
            .digest(&self.key_package.tls_serialize_detached()?))
    }
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

        package.sign(self.signing_key)?;

        Ok(KeyPackageGeneration {
            key_package: package,
            secret_key: secret,
        })
    }
}

impl KeyPackage {
    pub fn hash(&self) -> Result<Vec<u8>, KeyPackageError> {
        Ok(self
            .cipher_suite
            .hash_function()
            .digest(&self.tls_serialize_detached()?))
    }

    fn to_signable_bytes(&self) -> Result<Vec<u8>, KeyPackageError> {
        #[derive(TlsSerialize, TlsSize)]
        pub struct KeyPackageData<'a> {
            pub version: &'a ProtocolVersion,
            pub cipher_suite: &'a CipherSuite,
            #[tls_codec(with = "crate::tls::ByteVec::<u32>")]
            pub hpke_init_key: &'a Vec<u8>,
            pub credential: &'a Credential,
            #[tls_codec(with = "crate::tls::DefVec::<u32>")]
            pub extensions: &'a Vec<Extension>,
        }

        let key_package_data = KeyPackageData {
            version: &self.version,
            cipher_suite: &self.cipher_suite,
            hpke_init_key: &self.hpke_init_key,
            credential: &self.credential,
            extensions: &self.extensions,
        };
        Ok(key_package_data.tls_serialize_detached()?)
    }

    pub(crate) fn sign(&mut self, key: &SecretKey) -> Result<(), KeyPackageError> {
        self.signature = key.sign(&self.to_signable_bytes()?)?;
        Ok(())
    }

    pub fn has_valid_signature(&self) -> Result<bool, KeyPackageError> {
        self.credential
            .verify(&self.signature, &self.to_signable_bytes()?)
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