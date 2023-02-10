use crate::cipher_suite::CipherSuite;
use crate::extension::ExtensionType;
use crate::extension::RequiredCapabilitiesExt;
use crate::group::proposal::ProposalType;
use crate::hash_reference::{HashReference, HashReferenceError};
use crate::identity::SigningIdentity;
use crate::protocol_version::ProtocolVersion;
use crate::provider::crypto::{CipherSuiteProvider, HpkePublicKey};
use crate::serde_utils::vec_u8_as_base64::VecAsBase64;
use crate::signer::Signable;
use crate::time::MlsTime;
use crate::tree_kem::leaf_node::LeafNode;
use aws_mls_core::extension::ExtensionList;
use serde_with::serde_as;
use std::ops::Deref;
use thiserror::Error;
use tls_codec::Serialize;
use tls_codec_derive::{TlsDeserialize, TlsSerialize, TlsSize};

mod validator;
pub(crate) use validator::*;

pub(crate) mod generator;
pub(crate) use generator::*;

#[derive(Error, Debug)]
pub enum KeyPackageError {
    #[error(transparent)]
    SerializationError(#[from] tls_codec::Error),
    #[error("unsupported cipher suite: {0:?}")]
    UnsupportedCipherSuite(CipherSuite),
}

#[serde_as]
#[non_exhaustive]
#[derive(
    Clone,
    Debug,
    TlsDeserialize,
    TlsSerialize,
    TlsSize,
    serde::Deserialize,
    serde::Serialize,
    PartialEq,
)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct KeyPackage {
    pub(crate) version: ProtocolVersion,
    pub(crate) cipher_suite: CipherSuite,
    #[tls_codec(with = "crate::tls::ByteVec")]
    #[serde_as(as = "VecAsBase64")]
    pub(crate) hpke_init_key: HpkePublicKey,
    pub(crate) leaf_node: LeafNode,
    pub(crate) extensions: ExtensionList,
    #[tls_codec(with = "crate::tls::ByteVec")]
    #[serde_as(as = "VecAsBase64")]
    pub(crate) signature: Vec<u8>,
}

#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    TlsSerialize,
    TlsDeserialize,
    TlsSize,
    serde::Serialize,
    serde::Deserialize,
)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct KeyPackageRef(HashReference);

impl Deref for KeyPackageRef {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl ToString for KeyPackageRef {
    fn to_string(&self) -> String {
        hex::encode(self.deref())
    }
}

impl From<Vec<u8>> for KeyPackageRef {
    fn from(v: Vec<u8>) -> Self {
        Self(HashReference::from(v))
    }
}

#[derive(TlsSerialize, TlsSize)]
struct KeyPackageData<'a> {
    pub version: ProtocolVersion,
    pub cipher_suite: CipherSuite,
    #[tls_codec(with = "crate::tls::ByteVec")]
    pub hpke_init_key: &'a HpkePublicKey,
    pub leaf_node: &'a LeafNode,
    #[tls_codec(with = "crate::tls::DefRef")]
    pub extensions: &'a ExtensionList,
}

impl KeyPackage {
    pub fn version(&self) -> ProtocolVersion {
        self.version
    }

    pub fn cipher_suite(&self) -> CipherSuite {
        self.cipher_suite
    }

    pub fn extensions(&self) -> &ExtensionList {
        &self.extensions
    }

    pub fn signing_identity(&self) -> &SigningIdentity {
        &self.leaf_node.signing_identity
    }

    pub(crate) fn to_reference<CP: CipherSuiteProvider>(
        &self,
        cipher_suite_provider: &CP,
    ) -> Result<KeyPackageRef, HashReferenceError> {
        if cipher_suite_provider.cipher_suite() != self.cipher_suite {
            return Err(HashReferenceError::InvalidCipherSuite(
                cipher_suite_provider.cipher_suite(),
            ));
        }

        Ok(KeyPackageRef(HashReference::compute(
            &self.tls_serialize_detached()?,
            b"MLS 1.0 KeyPackage Reference",
            cipher_suite_provider,
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
            version: self.version,
            cipher_suite: self.cipher_suite,
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
    use super::*;
    use crate::{
        group::{framing::MLSMessagePayload, MLSMessage},
        identity::test_utils::get_test_signing_identity,
        provider::{
            crypto::{test_utils::test_cipher_suite_provider, CipherSuiteProvider},
            identity::BasicIdentityProvider,
        },
        tree_kem::{leaf_node::test_utils::get_test_capabilities, Lifetime},
    };
    use futures::{future::BoxFuture, FutureExt};

    pub(crate) async fn test_key_package_custom<F, CSP>(
        cipher_suite_provider: &CSP,
        protocol_version: ProtocolVersion,
        id: &str,
        custom: F,
    ) -> KeyPackage
    where
        CSP: CipherSuiteProvider,
        F: FnOnce(
            KeyPackageGenerator<'_, BasicIdentityProvider, CSP>,
        ) -> BoxFuture<'_, KeyPackageGeneration>,
    {
        let (signing_identity, secret_key) =
            get_test_signing_identity(cipher_suite_provider.cipher_suite(), id.as_bytes().to_vec());

        let generator = KeyPackageGenerator {
            protocol_version,
            cipher_suite_provider,
            signing_identity: &signing_identity,
            signing_key: &secret_key,
            identity_provider: &BasicIdentityProvider::new(),
        };

        custom(generator).await.key_package
    }

    pub(crate) async fn test_key_package(
        protocol_version: ProtocolVersion,
        cipher_suite: CipherSuite,
        id: &str,
    ) -> KeyPackage {
        test_key_package_custom(
            &test_cipher_suite_provider(cipher_suite),
            protocol_version,
            id,
            |generator| {
                async move {
                    generator
                        .generate(
                            Lifetime::years(1).unwrap(),
                            get_test_capabilities(),
                            ExtensionList::default(),
                            ExtensionList::default(),
                        )
                        .await
                        .unwrap()
                }
                .boxed()
            },
        )
        .await
    }

    pub(crate) async fn test_key_package_message(
        protocol_version: ProtocolVersion,
        cipher_suite: CipherSuite,
        id: &str,
    ) -> MLSMessage {
        MLSMessage::new(
            protocol_version,
            MLSMessagePayload::KeyPackage(
                test_key_package(protocol_version, cipher_suite, id).await,
            ),
        )
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        client::test_utils::{TEST_CIPHER_SUITE, TEST_PROTOCOL_VERSION},
        provider::crypto::test_utils::{
            test_cipher_suite_provider, try_test_cipher_suite_provider,
        },
    };

    use super::{test_utils::test_key_package, *};
    use assert_matches::assert_matches;
    use futures::StreamExt;
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
        async fn generate() -> Vec<TestCase> {
            futures::stream::iter(
                ProtocolVersion::all()
                    .flat_map(|p| CipherSuite::all().map(move |cs| (p, cs)))
                    .enumerate(),
            )
            .then(|(i, (protocol_version, cipher_suite))| async move {
                let pkg =
                    test_key_package(protocol_version, cipher_suite, &format!("alice{i}")).await;
                let pkg_ref = pkg
                    .to_reference(&test_cipher_suite_provider(cipher_suite))
                    .unwrap();
                TestCase {
                    cipher_suite: cipher_suite.into(),
                    input: pkg.tls_serialize_detached().unwrap(),
                    output: pkg_ref.to_vec(),
                }
            })
            .collect()
            .await
        }
    }

    async fn load_test_cases() -> Vec<TestCase> {
        load_test_cases!(key_package_ref, TestCase::generate().await)
    }

    #[futures_test::test]
    async fn test_key_package_ref() {
        let cases = load_test_cases().await;

        for one_case in cases {
            let Some(provider) = try_test_cipher_suite_provider(one_case.cipher_suite) else {
                println!("Skipping test for unsupported cipher suite");
                continue;
            };

            let key_package = KeyPackage::tls_deserialize(&mut one_case.input.as_slice()).unwrap();

            let key_package_ref = key_package.to_reference(&provider).unwrap();

            let expected_out = KeyPackageRef::from(one_case.output);
            assert_eq!(expected_out, key_package_ref);
        }
    }

    #[futures_test::test]
    async fn key_package_ref_fails_invalid_cipher_suite() {
        let key_package = test_key_package(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE, "test").await;

        assert_matches!(
            key_package.to_reference(&test_cipher_suite_provider(CipherSuite::P256_AES128)),
            Err(HashReferenceError::InvalidCipherSuite(
                CipherSuite::P256_AES128
            ))
        )
    }
}
