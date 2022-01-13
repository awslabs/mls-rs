use crate::cipher_suite::CipherSuite;
use crate::cipher_suite::ProtocolVersion;
use crate::credential::{Credential, CredentialError};
use crate::extension::CapabilitiesExt;
use crate::extension::LifetimeExt;
use crate::extension::RequiredCapabilitiesExt;
use crate::extension::{Extension, ExtensionError, ExtensionList, ExtensionType};
use crate::group::proposal::ProposalType;
use crate::hash_reference::HashReference;
use ferriscrypt::asym::ec_key::{EcKeyError, SecretKey};
use ferriscrypt::hpke::kem::{HpkePublicKey, HpkeSecretKey};
use ferriscrypt::kdf::KdfError;
use ferriscrypt::Verifier;
use std::ops::Deref;
use std::time::SystemTime;
use thiserror::Error;
use tls_codec::Serialize;
use tls_codec_derive::{TlsDeserialize, TlsSerialize, TlsSize};

mod validator;
pub use validator::*;

mod generator;
pub use generator::*;

#[derive(Error, Debug)]
pub enum KeyPackageError {
    #[error(transparent)]
    SerializationError(#[from] tls_codec::Error),
    #[error(transparent)]
    KdfError(#[from] KdfError),
}

#[non_exhaustive]
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

        key_package_data
            .tls_serialize_detached()
            .map_err(Into::into)
    }

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
            serde_json::from_slice(include_bytes!("../../test_data/key_package_ref.json")).unwrap();

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
