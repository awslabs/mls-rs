use crate::credential::Credential;
use crate::asym::{AsymmetricKeyError};
use crate::protocol_version::ProtocolVersion;
use crate::extension::{Extension, ExtensionError};
use cfg_if::cfg_if;

cfg_if! {
    if #[cfg(test)] {
        use crate::ciphersuite::test_util::MockCipherSuite as CipherSuite;
    } else {
        use crate::ciphersuite::{CipherSuite};
    }
}

use serde::{Serialize, Deserialize};
use crate::signature::{SignatureError, Signable, Signer};
use thiserror::Error;
use std::convert::TryFrom;
use bincode::Options;
use std::error::Error;
use rand_core::{RngCore, CryptoRng};
use crate::ciphersuite::CipherSuiteError;

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
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub struct KeyPackageData {
    pub version: ProtocolVersion,
    pub cipher_suite: CipherSuite,
    pub hpke_init_key: Vec<u8>,
    pub credential: Credential,
    pub extensions: Vec<Extension>,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub struct KeyPackage {
    #[serde(flatten)]
    pub data: KeyPackageData,
    pub signature: Vec<u8>,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub struct KeyPackageSecret {
    pub cipher_suite: CipherSuite,
    pub hpke_secret_key: Vec<u8>,
    pub extensions: Vec<Extension>
}

impl Signable for KeyPackageData {
    type E = bincode::Error;
    fn to_signable_vec(&self) -> Result<Vec<u8>, Self::E> {
        bincode::DefaultOptions::new().with_big_endian().serialize(self)
    }
}

impl TryFrom<Vec<u8>> for KeyPackageData {
    type Error = bincode::Error;

    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        bincode::DefaultOptions::new().with_big_endian().deserialize(&value)
    }
}

pub struct KeyPackageGeneration {
    pub key_package: KeyPackage,
    pub secret_key: Vec<u8>
}

pub trait KeyPackageGenerator: Signer {

    fn gen_key_package<RNG: RngCore + CryptoRng + 'static>(
        &self, rng: &mut RNG, cipher_suite: &CipherSuite
    ) -> Result<KeyPackageGeneration, KeyPackageError> {
        let kem_key_pair = cipher_suite.generate_kem_key_pair(rng)?;

        let package = self.package_from_pub_key(cipher_suite,
                                                kem_key_pair.public_key)?;

        Ok(KeyPackageGeneration {
            key_package: package,
            secret_key: kem_key_pair.secret_key
        })
    }

    fn package_from_pub_key(
        &self, cipher_suite: &CipherSuite, pub_key: Vec<u8>
    ) -> Result<KeyPackage, KeyPackageError>;
}

#[cfg(test)]
pub mod test_util {
    use mockall::mock;
    use crate::signature::{ Signer, Signable , SignatureError };
    use super::{ 
        CipherSuite,
        KeyPackage,
        KeyPackageError,
        KeyPackageGenerator,
        KeyPackageGeneration,
        RngCore,
        CryptoRng
    };
    
    mock! {
        pub KeyPackageGenerator {}
        impl Signer for KeyPackageGenerator {
            fn sign<T: Signable + 'static>(&self, data: &T) -> Result<Vec<u8>, SignatureError>;
        }
        impl KeyPackageGenerator for KeyPackageGenerator {
            fn gen_key_package<RNG: RngCore + CryptoRng + 'static>(
                &self, rng: &mut RNG, cipher_suite: &CipherSuite
            ) -> Result<KeyPackageGeneration, KeyPackageError>;
    
            fn package_from_pub_key(
                &self, cipher_suite: &CipherSuite, pub_key: Vec<u8>
            ) -> Result<KeyPackage, KeyPackageError>;
        }
    }
}

#[cfg(test)]
mod test {
    use crate::key_package::KeyPackageData;
    use crate::protocol_version::ProtocolVersion;
    use crate::ciphersuite::test_util::MockCipherSuite;
    use crate::extension::{Lifetime, ExtensionTrait};
    use crate::credential::{BasicCredential, CredentialConvertable};
    use crate::signature::{SignatureSchemeId, Signable};
    use std::convert::TryFrom;

    #[test]
    fn test_signable_key_package_data() {

        let mut cipher_suite_mock = MockCipherSuite::new();
        cipher_suite_mock.expect_get_id().return_const(42u16);

        let data = KeyPackageData {
            version: ProtocolVersion::Test,
            cipher_suite: cipher_suite_mock,
            hpke_init_key: vec![0u8; 4],
            credential: BasicCredential {
                identity: vec![0u8;4],
                signature_scheme: SignatureSchemeId::Test,
                signature_key: vec![0u8;4]
            }.to_credential(),
            extensions: vec![Lifetime { not_before: 42, not_after: 42 }.to_extension().unwrap()]
        };

        let serialized = data.to_signable_vec().expect("failed serialization");
        let restored = KeyPackageData::try_from(serialized)
            .expect("failed deserialization");
        assert_eq!(data, restored);
    }
}

