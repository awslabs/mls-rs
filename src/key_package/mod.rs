use crate::cipher_suite::CipherSuite;
use crate::credential::{Credential, CredentialError};
use crate::extension::CapabilitiesExt;
use crate::extension::LifetimeExt;
use crate::extension::RequiredCapabilitiesExt;
use crate::extension::{Extension, ExtensionError, ExtensionList, ExtensionType};
use crate::group::proposal::ProposalType;
use crate::hash_reference::HashReference;
use crate::signer::Signable;
use crate::time::MlsTime;
use crate::ProtocolVersion;
use ferriscrypt::hpke::kem::{HpkePublicKey, HpkeSecretKey};
use ferriscrypt::kdf::KdfError;
use std::ops::Deref;
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

impl<'a> KeyPackage {
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
            credential: &self.credential,
            extensions: &self.extensions,
        }
        .tls_serialize_detached()
    }

    fn write_signature(&mut self, signature: Vec<u8>) {
        self.signature = signature
    }
}

#[cfg(test)]
pub(crate) mod test_util {
    use super::*;
    use crate::client::test_util::test_client_with_key_pkg;

    pub(crate) fn test_key_package(
        protocol_version: ProtocolVersion,
        cipher_suite: CipherSuite,
    ) -> KeyPackage {
        test_key_package_with_id(protocol_version, cipher_suite, "foo")
    }

    pub(crate) fn test_key_package_with_id(
        protocol_version: ProtocolVersion,
        cipher_suite: CipherSuite,
        id: &str,
    ) -> KeyPackage {
        let (_, key_package_gen) = test_client_with_key_pkg(protocol_version, cipher_suite, id);
        key_package_gen.key_package.into()
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use tls_codec::Deserialize;

    #[cfg(target_arch = "wasm32")]
    use wasm_bindgen_test::{wasm_bindgen_test as test, wasm_bindgen_test_configure};

    #[cfg(target_arch = "wasm32")]
    wasm_bindgen_test_configure!(run_in_browser);

    #[derive(serde::Deserialize, serde::Serialize)]
    struct TestCase {
        cipher_suite: u16,
        #[serde(with = "hex::serde")]
        input: Vec<u8>,
        #[serde(with = "hex::serde")]
        output: Vec<u8>,
    }

    impl TestCase {
        #[allow(unused)]
        fn generate() {
            use tls_codec::Serialize;

            let test_cases = ProtocolVersion::all()
                .flat_map(|p| CipherSuite::all().map(move |cs| (p, cs)))
                .map(|(protocol_version, cipher_suite)| {
                    let pkg = test_util::test_key_package(protocol_version, cipher_suite);
                    let pkg_ref = pkg.to_reference().unwrap();
                    TestCase {
                        cipher_suite: cipher_suite as u16,
                        input: pkg.tls_serialize_detached().unwrap(),
                        output: pkg_ref.to_vec(),
                    }
                })
                .collect::<Vec<_>>();
            std::fs::write(
                concat!(
                    env!("CARGO_MANIFEST_DIR"),
                    "/test_data/key_package_ref.json"
                ),
                serde_json::to_string_pretty(&test_cases).unwrap(),
            )
            .unwrap();
        }
    }

    #[test]
    fn test_key_package_ref() {
        let cases: Vec<TestCase> =
            serde_json::from_slice(include_bytes!("../../test_data/key_package_ref.json")).unwrap();

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
