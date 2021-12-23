use crate::cipher_suite::CipherSuite;
use crate::cipher_suite::ProtocolVersion;
use crate::credential::{Credential, CredentialError};
use crate::extension::{Extension, ExtensionError, ExtensionList};
use crate::hash_reference::HashReference;
use ferriscrypt::asym::ec_key::{generate_keypair, EcKeyError, SecretKey};
use ferriscrypt::hpke::kem::{HpkePublicKey, HpkeSecretKey};
use ferriscrypt::kdf::KdfError;
use ferriscrypt::{Signer, Verifier};
use std::ops::Deref;
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
    #[error(transparent)]
    KdfError(#[from] KdfError),
    #[error("invalid signature")]
    InvalidSignature,
    #[error("key lifetime not found")]
    MissingKeyLifetime,
    #[error("not within lifetime")]
    InvalidKeyLifetime,
}

#[derive(Clone, Debug, TlsDeserialize, TlsSerialize, TlsSize)]
pub struct KeyPackage {
    pub version: ProtocolVersion,
    pub cipher_suite: CipherSuite,
    #[tls_codec(with = "crate::tls::ByteVec::<u32>")]
    pub hpke_init_key: HpkePublicKey,
    pub credential: Credential,
    pub extensions: ExtensionList,
    #[tls_codec(with = "crate::tls::ByteVec::<u32>")]
    pub signature: Vec<u8>,
}

impl KeyPackage {
    pub fn to_vec(&self) -> Result<Vec<u8>, KeyPackageError> {
        Ok(self.tls_serialize_detached()?)
    }
    pub fn to_reference(&self) -> Result<KeyPackageRef, KeyPackageError> {
        Ok(KeyPackageRef(HashReference::from_value(
            &self.tls_serialize_detached()?,
            self.cipher_suite,
        )?))
    }
}

#[derive(
    Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, TlsSerialize, TlsDeserialize, TlsSize,
)]
pub struct KeyPackageRef(HashReference);

impl Deref for KeyPackageRef {
    type Target = [u8; 16];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl ToString for KeyPackageRef {
    fn to_string(&self) -> String {
        hex::encode(self.deref())
    }
}

impl From<[u8; 16]> for KeyPackageRef {
    fn from(v: [u8; 16]) -> Self {
        Self(HashReference::from(v))
    }
}

impl PartialEq for KeyPackage {
    fn eq(&self, other: &Self) -> bool {
        self.to_reference().ok() == other.to_reference().ok()
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
    #[tls_codec(with = "crate::tls::ByteVec::<u32>")]
    pub secret_key: HpkeSecretKey,
}

impl<'a> KeyPackageGenerator<'a> {
    pub fn generate(&self) -> Result<KeyPackageGeneration, KeyPackageError> {
        let (public, secret) = generate_keypair(self.cipher_suite.kem_type().curve())?;

        let mut package = KeyPackage {
            version: self.cipher_suite.protocol_version(),
            cipher_suite: self.cipher_suite,
            hpke_init_key: public.try_into()?,
            credential: self.credential.clone(),
            extensions: self.extensions.clone(),
            signature: vec![],
        };

        package.sign(self.signing_key)?;

        Ok(KeyPackageGeneration {
            key_package: package,
            secret_key: secret.try_into()?,
        })
    }
}

impl KeyPackage {
    fn to_signable_bytes(&self) -> Result<Vec<u8>, KeyPackageError> {
        #[derive(TlsSerialize, TlsSize)]
        pub struct KeyPackageData<'a> {
            pub version: &'a ProtocolVersion,
            pub cipher_suite: &'a CipherSuite,
            #[tls_codec(with = "crate::tls::ByteVec::<u32>")]
            pub hpke_init_key: &'a HpkePublicKey,
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

//TODO: Tests for validate + has valid signature + key generation + lifetimes
#[cfg(test)]
mod test {
    use super::*;
    use tls_codec::Deserialize;

    #[test]
    fn test_key_package_ref() {
        #[derive(serde::Deserialize)]
        struct TestCase {
            #[serde(deserialize_with = "hex::serde::deserialize")]
            input: Vec<u8>,
            #[serde(deserialize_with = "hex::serde::deserialize")]
            output: Vec<u8>,
        }

        let cases: Vec<TestCase> =
            serde_json::from_slice(include_bytes!("../test_data/key_package_ref.json")).unwrap();

        for one_case in cases {
            let key_package = KeyPackage::tls_deserialize(&mut one_case.input.as_slice()).unwrap();
            let key_package_ref = key_package.to_reference().unwrap();

            let expected_out = KeyPackageRef(HashReference::from(
                <[u8; 16]>::try_from(one_case.output).unwrap(),
            ));

            assert_eq!(expected_out, key_package_ref);
        }
    }
}
