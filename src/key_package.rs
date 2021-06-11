use crate::ciphersuite::CipherSuiteError;
use crate::credential::Credential;
use crate::crypto::asym::AsymmetricKeyError;
use crate::crypto::rand::SecureRng;
use crate::crypto::signature::{Signable, SignatureError, Signer, Verifier};
use crate::extension::{Extension, ExtensionError, ExtensionList};
use crate::protocol_version::ProtocolVersion;
use bincode::Options;
use cfg_if::cfg_if;
use serde::{Deserialize, Serialize};
use std::time::SystemTime;
use thiserror::Error;

cfg_if! {
    if #[cfg(test)] {
        use crate::ciphersuite::test_util::MockCipherSuite as CipherSuite;
    } else {
        use crate::ciphersuite::{CipherSuite};
    }
}

#[derive(Error, Debug)]
pub enum KeyPackageError {
    #[error(transparent)]
    SignatureError(#[from] SignatureError),
    #[error(transparent)]
    ExtensionError(#[from] ExtensionError),
    #[error(transparent)]
    AsymmetricKeyError(#[from] AsymmetricKeyError),
    #[error(transparent)]
    CipherSuiteError(#[from] CipherSuiteError),
    #[error(transparent)]
    SerializationError(#[from] bincode::Error),
    #[error("invalid signature")]
    InvalidSignature,
    #[error("key lifetime not found")]
    MissingKeyLifetime,
    #[error("not within lifetime")]
    InvalidKeyLifetime,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub struct KeyPackage {
    pub version: ProtocolVersion,
    pub cipher_suite: CipherSuite,
    pub hpke_init_key: Vec<u8>,
    pub credential: Credential,
    pub extensions: ExtensionList,
    pub signature: Vec<u8>,
}

impl Signable for KeyPackage {
    type E = bincode::Error;
    fn to_signable_vec(&self) -> Result<Vec<u8>, Self::E> {
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
    }
}

impl KeyPackage {
    pub fn has_valid_signature(&self) -> Result<bool, KeyPackageError> {
        self.credential
            .verify(&self.signature, self)
            .map_err(KeyPackageError::from)
    }

    pub fn has_valid_lifetime(&self, time: SystemTime) -> Result<bool, KeyPackageError> {
        self.extensions
            .get_lifetime()?
            .ok_or(KeyPackageError::MissingKeyLifetime)
            .and_then(|l| {
                l.within_lifetime(time)
                    .map_err(KeyPackageError::from)
            })
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

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct KeyPackageGeneration {
    pub key_package: KeyPackage,
    pub secret_key: Vec<u8>,
    pub key_package_hash: Vec<u8>,
}

pub trait KeyPackageGenerator: Signer {
    fn gen_key_package<RNG: SecureRng + 'static>(
        &self,
        rng: &mut RNG,
        cipher_suite: &CipherSuite,
    ) -> Result<KeyPackageGeneration, KeyPackageError> {
        let kem_key_pair = cipher_suite.generate_kem_key_pair(rng)?;

        let mut package = self.package_from_pub_key(cipher_suite, kem_key_pair.public_key)?;
        package.signature = self.sign(&package)?;

        let key_package_hash = cipher_suite.hash(&bincode::serialize(&package)?)?;

        Ok(KeyPackageGeneration {
            key_package: package,
            secret_key: kem_key_pair.secret_key,
            key_package_hash,
        })
    }

    fn package_from_pub_key(
        &self,
        cipher_suite: &CipherSuite,
        pub_key: Vec<u8>,
    ) -> Result<KeyPackage, KeyPackageError>;
}

#[cfg(test)]
pub mod test_util {
    use super::{
        CipherSuite, KeyPackage, KeyPackageError, KeyPackageGeneration, KeyPackageGenerator,
        SecureRng,
    };
    use crate::crypto::signature::{Signable, SignatureError, Signer};
    use mockall::mock;

    mock! {
        pub KeyPackageGenerator {}
        impl Signer for KeyPackageGenerator {
            fn sign<T: Signable + 'static>(&self, data: &T) -> Result<Vec<u8>, SignatureError>;
        }
        impl KeyPackageGenerator for KeyPackageGenerator {
            fn gen_key_package<RNG: SecureRng + 'static>(
                &self, rng: &mut RNG, cipher_suite: &CipherSuite
            ) -> Result<KeyPackageGeneration, KeyPackageError>;

            fn package_from_pub_key(
                &self, cipher_suite: &CipherSuite, pub_key: Vec<u8>
            ) -> Result<KeyPackage, KeyPackageError>;
        }
    }
}

//TODO: Tests for validate + has valid signature
