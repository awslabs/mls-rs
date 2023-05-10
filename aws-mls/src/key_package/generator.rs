use alloc::vec;
use alloc::vec::Vec;
use aws_mls_codec::{MlsDecode, MlsEncode};
use aws_mls_core::{error::IntoAnyError, identity::IdentityProvider, key_package::KeyPackageData};

use crate::client::MlsError;
use crate::{
    crypto::{HpkeSecretKey, SignatureSecretKey},
    group::framing::MLSMessagePayload,
    identity::SigningIdentity,
    protocol_version::ProtocolVersion,
    signer::Signable,
    tree_kem::{
        leaf_node::{ConfigProperties, LeafNode},
        Capabilities, Lifetime,
    },
    CipherSuiteProvider, ExtensionList, MLSMessage,
};

use super::{KeyPackage, KeyPackageRef};

#[derive(Clone, Debug)]
pub struct KeyPackageGenerator<'a, IP, CP>
where
    IP: IdentityProvider,
    CP: CipherSuiteProvider,
{
    pub protocol_version: ProtocolVersion,
    pub cipher_suite_provider: &'a CP,
    pub signing_identity: &'a SigningIdentity,
    pub signing_key: &'a SignatureSecretKey,
    pub identity_provider: &'a IP,
}

#[derive(Clone, Debug)]
pub struct KeyPackageGeneration {
    pub(crate) reference: KeyPackageRef,
    pub(crate) key_package: KeyPackage,
    pub(crate) init_secret_key: HpkeSecretKey,
    pub(crate) leaf_node_secret_key: HpkeSecretKey,
}

impl KeyPackageGeneration {
    pub fn to_storage(&self) -> Result<(Vec<u8>, KeyPackageData), MlsError> {
        let id = self.reference.to_vec();

        let data = KeyPackageData::new(
            self.key_package.mls_encode_to_vec()?,
            self.init_secret_key.clone(),
            self.leaf_node_secret_key.clone(),
        );

        Ok((id, data))
    }

    pub fn from_storage(id: Vec<u8>, data: KeyPackageData) -> Result<Self, MlsError> {
        Ok(KeyPackageGeneration {
            reference: KeyPackageRef::from(id),
            key_package: KeyPackage::mls_decode(&mut &*data.key_package_bytes)?,
            init_secret_key: data.init_key,
            leaf_node_secret_key: data.leaf_node_key,
        })
    }

    pub fn key_package_message(&self) -> MLSMessage {
        MLSMessage::new(
            self.key_package.version(),
            MLSMessagePayload::KeyPackage(self.key_package.clone()),
        )
    }
}

impl<'a, IP, CP> KeyPackageGenerator<'a, IP, CP>
where
    IP: IdentityProvider,
    CP: CipherSuiteProvider,
{
    pub(super) fn sign(&self, package: &mut KeyPackage) -> Result<(), MlsError> {
        package
            .sign(self.cipher_suite_provider, self.signing_key, &())
            .map_err(Into::into)
    }

    pub async fn generate(
        &self,
        lifetime: Lifetime,
        capabilities: Capabilities,
        key_package_extensions: ExtensionList,
        leaf_node_extensions: ExtensionList,
    ) -> Result<KeyPackageGeneration, MlsError> {
        let (init_secret_key, public_init) = self
            .cipher_suite_provider
            .kem_generate()
            .map_err(|e| MlsError::CryptoProviderError(e.into_any_error()))?;

        let properties = ConfigProperties {
            capabilities,
            extensions: leaf_node_extensions,
        };

        let (leaf_node, leaf_node_secret) = LeafNode::generate(
            self.cipher_suite_provider,
            properties,
            self.signing_identity.clone(),
            self.signing_key,
            lifetime,
        )
        .await?;

        let mut package = KeyPackage {
            version: self.protocol_version,
            cipher_suite: self.cipher_suite_provider.cipher_suite(),
            hpke_init_key: public_init,
            leaf_node,
            extensions: key_package_extensions,
            signature: vec![],
        };

        package.grease(self.cipher_suite_provider)?;

        self.sign(&mut package)?;

        let reference = package.to_reference(self.cipher_suite_provider)?;

        Ok(KeyPackageGeneration {
            key_package: package,
            init_secret_key,
            leaf_node_secret_key: leaf_node_secret,
            reference,
        })
    }
}

#[cfg(test)]
mod tests {
    use assert_matches::assert_matches;
    use aws_mls_core::crypto::CipherSuiteProvider;

    use crate::{
        crypto::test_utils::{test_cipher_suite_provider, TestCryptoProvider},
        extension::test_utils::TestExtension,
        group::test_utils::random_bytes,
        identity::basic::BasicIdentityProvider,
        identity::test_utils::get_test_signing_identity,
        key_package::validate_key_package_properties,
        protocol_version::ProtocolVersion,
        tree_kem::{
            leaf_node::{test_utils::get_test_capabilities, LeafNodeSource},
            leaf_node_validator::{LeafNodeValidator, ValidationContext},
            Lifetime,
        },
        ExtensionList,
    };

    use super::KeyPackageGenerator;

    #[cfg(target_arch = "wasm32")]
    use wasm_bindgen_test::wasm_bindgen_test as test;

    #[cfg(not(target_arch = "wasm32"))]
    use futures_test::test;

    fn test_key_package_ext(val: u8) -> ExtensionList {
        let mut ext_list = ExtensionList::new();
        ext_list.set_from(TestExtension::from(val)).unwrap();
        ext_list
    }

    fn test_leaf_node_ext(val: u8) -> ExtensionList {
        let mut ext_list = ExtensionList::new();
        ext_list.set_from(TestExtension::from(val)).unwrap();
        ext_list
    }

    fn test_lifetime() -> Lifetime {
        Lifetime::years(1).unwrap()
    }

    #[test]
    async fn test_key_generation() {
        for (protocol_version, cipher_suite) in ProtocolVersion::all().flat_map(|p| {
            TestCryptoProvider::all_supported_cipher_suites()
                .into_iter()
                .map(move |cs| (p, cs))
        }) {
            let cipher_suite_provider = test_cipher_suite_provider(cipher_suite);

            let (signing_identity, signing_key) =
                get_test_signing_identity(cipher_suite, b"foo".to_vec());

            let key_package_ext = test_key_package_ext(32);
            let leaf_node_ext = test_leaf_node_ext(42);
            let lifetime = test_lifetime();

            let test_generator = KeyPackageGenerator {
                protocol_version,
                cipher_suite_provider: &cipher_suite_provider,
                signing_identity: &signing_identity,
                signing_key: &signing_key,
                identity_provider: &BasicIdentityProvider,
            };

            let mut capabilities = get_test_capabilities();
            capabilities.extensions.push(42.into());
            capabilities.extensions.push(43.into());
            capabilities.extensions.push(32.into());

            let generated = test_generator
                .generate(
                    lifetime.clone(),
                    capabilities.clone(),
                    key_package_ext.clone(),
                    leaf_node_ext.clone(),
                )
                .await
                .unwrap();

            assert_matches!(generated.key_package.leaf_node.leaf_node_source,
                            LeafNodeSource::KeyPackage(ref lt) if lt == &lifetime);

            assert_eq!(
                generated.key_package.leaf_node.ungreased_capabilities(),
                capabilities
            );

            assert_eq!(
                generated.key_package.leaf_node.ungreased_extensions(),
                leaf_node_ext
            );

            assert_eq!(
                generated.key_package.ungreased_extensions(),
                key_package_ext
            );

            assert_ne!(
                generated.key_package.hpke_init_key.as_ref(),
                generated.key_package.leaf_node.public_key.as_ref()
            );

            assert_eq!(generated.key_package.cipher_suite, cipher_suite);
            assert_eq!(generated.key_package.version, protocol_version);

            // Verify that the hpke key pair generated will work
            let test_data = random_bytes(32);

            let sealed = cipher_suite_provider
                .hpke_seal(&generated.key_package.hpke_init_key, &[], None, &test_data)
                .unwrap();

            let opened = cipher_suite_provider
                .hpke_open(&sealed, &generated.init_secret_key, &[], None)
                .unwrap();

            assert_eq!(opened, test_data);

            let validator =
                LeafNodeValidator::new(&cipher_suite_provider, None, &BasicIdentityProvider, None);

            validator
                .check_if_valid(
                    &generated.key_package.leaf_node,
                    ValidationContext::Add(None),
                )
                .await
                .unwrap();

            validate_key_package_properties(
                &generated.key_package,
                protocol_version,
                &cipher_suite_provider,
            )
            .await
            .unwrap();
        }
    }

    #[test]
    async fn test_randomness() {
        for (protocol_version, cipher_suite) in ProtocolVersion::all().flat_map(|p| {
            TestCryptoProvider::all_supported_cipher_suites()
                .into_iter()
                .map(move |cs| (p, cs))
        }) {
            let (signing_identity, signing_key) =
                get_test_signing_identity(cipher_suite, b"foo".to_vec());

            let test_generator = KeyPackageGenerator {
                protocol_version,
                cipher_suite_provider: &test_cipher_suite_provider(cipher_suite),
                signing_identity: &signing_identity,
                signing_key: &signing_key,
                identity_provider: &BasicIdentityProvider,
            };

            let first_key_package = test_generator
                .generate(
                    test_lifetime(),
                    get_test_capabilities(),
                    ExtensionList::default(),
                    ExtensionList::default(),
                )
                .await
                .unwrap();

            for _ in 0..100 {
                let next_key_package = test_generator
                    .generate(
                        test_lifetime(),
                        get_test_capabilities(),
                        ExtensionList::default(),
                        ExtensionList::default(),
                    )
                    .await
                    .unwrap();

                assert_ne!(
                    first_key_package.key_package.hpke_init_key,
                    next_key_package.key_package.hpke_init_key
                );

                assert_ne!(
                    first_key_package.key_package.leaf_node.public_key,
                    next_key_package.key_package.leaf_node.public_key
                );
            }
        }
    }
}
