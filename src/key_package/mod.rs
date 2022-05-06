use crate::cipher_suite::CipherSuite;
use crate::credential::{Credential, CredentialError};
use crate::extension::CapabilitiesExt;
use crate::extension::LifetimeExt;
use crate::extension::RequiredCapabilitiesExt;
use crate::extension::{ExtensionError, ExtensionList, ExtensionType};
use crate::group::proposal::ProposalType;
use crate::hash_reference::HashReference;
use crate::signer::Signable;
use crate::time::MlsTime;
use crate::tree_kem::leaf_node::LeafNode;
use crate::ProtocolVersion;
use ferriscrypt::hpke::kem::{HpkePublicKey, HpkeSecretKey};
use ferriscrypt::kdf::KdfError;
use std::ops::Deref;
use thiserror::Error;
use tls_codec::Serialize;
use tls_codec_derive::{TlsDeserialize, TlsSerialize, TlsSize};

pub mod repository;
pub use repository::{InMemoryKeyPackageRepository, KeyPackageRepository};

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
#[derive(
    Clone, Debug, TlsDeserialize, TlsSerialize, TlsSize, serde::Deserialize, serde::Serialize,
)]
pub struct KeyPackage {
    pub version: ProtocolVersion,
    pub cipher_suite: CipherSuite,
    #[tls_codec(with = "crate::tls::ByteVec")]
    pub hpke_init_key: HpkePublicKey,
    pub leaf_node: LeafNode,
    pub extensions: ExtensionList,
    #[tls_codec(with = "crate::tls::ByteVec")]
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

#[derive(TlsSerialize, TlsSize)]
pub struct KeyPackageData<'a> {
    pub version: &'a ProtocolVersion,
    pub cipher_suite: &'a CipherSuite,
    #[tls_codec(with = "crate::tls::ByteVec")]
    pub hpke_init_key: &'a HpkePublicKey,
    pub leaf_node: &'a LeafNode,
    #[tls_codec(with = "crate::tls::DefRef")]
    pub extensions: &'a ExtensionList,
}

impl KeyPackage {
    pub fn to_vec(&self) -> Result<Vec<u8>, KeyPackageError> {
        Ok(self.tls_serialize_detached()?)
    }

    pub fn to_reference(&self) -> Result<KeyPackageRef, KeyPackageError> {
        Ok(KeyPackageRef(HashReference::from_value(
            &self.tls_serialize_detached()?,
            b"MLS 1.0 KeyPackage Reference",
            self.cipher_suite,
        )?))
    }
}

impl<'a> Signable<'a> for KeyPackage {
    const SIGN_LABEL: &'static str = "KeyPackageTBS";

    type SigningContext = ();

    fn signature(&self) -> &[u8] {
        &self.signature
    }

    fn signable_content(
        &self,
        _context: &Self::SigningContext,
    ) -> Result<Vec<u8>, tls_codec::Error> {
        KeyPackageData {
            version: &self.version,
            cipher_suite: &self.cipher_suite,
            hpke_init_key: &self.hpke_init_key,
            leaf_node: &self.leaf_node,
            extensions: &self.extensions,
        }
        .tls_serialize_detached()
    }

    fn write_signature(&mut self, signature: Vec<u8>) {
        self.signature = signature
    }
}

#[cfg(test)]
pub(crate) mod test_utils {
    use ferriscrypt::asym::ec_key::SecretKey;

    use super::*;
    use crate::credential::test_utils::get_test_basic_credential;

    pub(crate) fn test_key_package(
        protocol_version: ProtocolVersion,
        cipher_suite: CipherSuite,
    ) -> KeyPackage {
        test_key_package_with_id(protocol_version, cipher_suite, "foo")
    }

    pub(crate) fn test_key_package_custom<F>(
        protocol_version: ProtocolVersion,
        cipher_suite: CipherSuite,
        id: &str,
        custom: F,
    ) -> KeyPackage
    where
        F: Fn(&mut KeyPackageGenerator<SecretKey>) -> KeyPackageGeneration,
    {
        let test_credential =
            get_test_basic_credential(id.as_bytes().to_vec(), cipher_suite.signature_scheme());

        let mut generator = KeyPackageGenerator {
            protocol_version,
            cipher_suite,
            credential: &test_credential.credential,
            signing_key: &test_credential.secret,
        };

        custom(&mut generator).key_package
    }

    pub(crate) fn test_key_package_with_id(
        protocol_version: ProtocolVersion,
        cipher_suite: CipherSuite,
        id: &str,
    ) -> KeyPackage {
        test_key_package_custom(protocol_version, cipher_suite, id, |generator| {
            generator
                .generate(
                    LifetimeExt::years(1).unwrap(),
                    CapabilitiesExt::default(),
                    ExtensionList::default(),
                    ExtensionList::default(),
                )
                .unwrap()
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tls_codec::Deserialize;

    #[cfg(target_arch = "wasm32")]
    use wasm_bindgen_test::wasm_bindgen_test as test;

    #[derive(serde::Deserialize, serde::Serialize)]
    struct TestCase {
        cipher_suite: u16,
        #[serde(with = "hex::serde")]
        input: Vec<u8>,
        #[serde(with = "hex::serde")]
        output: Vec<u8>,
    }

    impl TestCase {
        fn generate() -> Vec<TestCase> {
            ProtocolVersion::all()
                .flat_map(|p| CipherSuite::all().map(move |cs| (p, cs)))
                .map(|(protocol_version, cipher_suite)| {
                    let pkg = test_utils::test_key_package(protocol_version, cipher_suite);
                    let pkg_ref = pkg.to_reference().unwrap();
                    TestCase {
                        cipher_suite: cipher_suite as u16,
                        input: pkg.tls_serialize_detached().unwrap(),
                        output: pkg_ref.to_vec(),
                    }
                })
                .collect()
        }
    }

    fn load_test_cases() -> Vec<TestCase> {
        load_test_cases!(key_package_ref, TestCase::generate)
    }

    #[test]
    fn test_key_package_ref() {
        let cases = load_test_cases();

        for one_case in cases {
            if CipherSuite::from_raw(one_case.cipher_suite).is_none() {
                println!("Skipping test for unsupported cipher suite");
                continue;
            }

            let key_package = KeyPackage::tls_deserialize(&mut one_case.input.as_slice()).unwrap();
            let key_package_ref = key_package.to_reference().unwrap();

            let expected_out = KeyPackageRef(HashReference::from(
                <[u8; 16]>::try_from(one_case.output).unwrap(),
            ));

            assert_eq!(expected_out, key_package_ref);
        }
    }
}
