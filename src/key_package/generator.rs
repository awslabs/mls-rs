use crate::{
    extension::{KeyPackageExtension, LeafNodeExtension},
    identity::SigningIdentity,
    provider::{
        crypto::{CipherSuiteProvider, HpkeSecretKey},
        identity::IdentityProvider,
    },
    signer::{SignatureError, Signer},
    tree_kem::{
        leaf_node::{ConfigProperties, LeafNodeError},
        Capabilities, Lifetime,
    },
};

use super::*;
use ferriscrypt::asym::ec_key::EcKeyError;

#[derive(Debug, Error)]
pub enum KeyPackageGenerationError {
    #[error("internal signer error: {0:?}")]
    SignerError(Box<dyn std::error::Error + Send + Sync>),
    #[error(transparent)]
    SignatureError(#[from] SignatureError),
    #[error(transparent)]
    EcKeyError(#[from] EcKeyError),
    #[error(transparent)]
    CredentialError(#[from] CredentialError),
    #[error(transparent)]
    KeyPackageError(#[from] KeyPackageError),
    #[error(transparent)]
    LeafNodeError(#[from] LeafNodeError),
    #[error(transparent)]
    CipherSuiteProviderError(Box<dyn std::error::Error + Send + Sync + 'static>),
}

#[derive(Clone, Debug)]
pub struct KeyPackageGenerator<'a, S, IP, CP>
where
    S: Signer,
    IP: IdentityProvider,
    CP: CipherSuiteProvider,
{
    pub protocol_version: ProtocolVersion,
    pub cipher_suite_provider: &'a CP,
    pub signing_identity: &'a SigningIdentity,
    pub signing_key: &'a S,
    pub identity_provider: &'a IP,
}

#[derive(Clone, Debug)]
#[cfg_attr(
    any(test, feature = "benchmark"),
    derive(serde::Deserialize, serde::Serialize)
)]
pub struct KeyPackageGeneration {
    pub(crate) key_package: KeyPackage,
    init_secret_key: HpkeSecretKey,
    pub(crate) leaf_node_secret_key: HpkeSecretKey,
}

impl KeyPackageGeneration {
    pub fn reference(&self) -> Result<KeyPackageRef, KeyPackageError> {
        self.key_package.to_reference()
    }

    pub fn init_secret(&self) -> &HpkeSecretKey {
        &self.init_secret_key
    }

    pub fn leaf_node_secret_key(&self) -> &[u8] {
        self.leaf_node_secret_key.as_ref()
    }
}

impl<'a, S, IP, CP> KeyPackageGenerator<'a, S, IP, CP>
where
    S: Signer,
    IP: IdentityProvider,
    CP: CipherSuiteProvider,
{
    pub(super) fn sign(&self, package: &mut KeyPackage) -> Result<(), KeyPackageGenerationError> {
        package.sign(self.signing_key, &()).map_err(Into::into)
    }

    pub fn generate(
        &self,
        lifetime: Lifetime,
        capabilities: Capabilities,
        key_package_extensions: ExtensionList<KeyPackageExtension>,
        leaf_node_extensions: ExtensionList<LeafNodeExtension>,
    ) -> Result<KeyPackageGeneration, KeyPackageGenerationError> {
        let (init_secret_key, public_init) = self
            .cipher_suite_provider
            .kem_generate()
            .map_err(|e| KeyPackageGenerationError::CipherSuiteProviderError(e.into()))?;

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
            self.identity_provider,
        )?;

        let mut package = KeyPackage {
            version: self.protocol_version.into(),
            cipher_suite: self.cipher_suite_provider.cipher_suite().into(),
            hpke_init_key: public_init,
            leaf_node,
            extensions: key_package_extensions,
            signature: vec![],
        };

        self.sign(&mut package)?;

        Ok(KeyPackageGeneration {
            key_package: package,
            init_secret_key,
            leaf_node_secret_key: leaf_node_secret,
        })
    }
}

#[cfg(test)]
mod tests {
    use assert_matches::assert_matches;
    use ferriscrypt::asym::ec_key::{PublicKey, SecretKey};
    use tls_codec_derive::{TlsDeserialize, TlsSerialize, TlsSize};

    use crate::{
        cipher_suite::CipherSuite,
        extension::{ExtensionList, KeyPackageExtension, LeafNodeExtension, MlsExtension},
        identity::test_utils::get_test_signing_identity,
        key_package::{KeyPackageGenerationError, KeyPackageValidator},
        protocol_version::ProtocolVersion,
        provider::{
            crypto::{test_utils::test_cipher_suite_provider, CipherSuiteProvider},
            identity::BasicIdentityProvider,
        },
        tree_kem::{
            leaf_node::{test_utils::get_test_capabilities, LeafNodeError, LeafNodeSource},
            leaf_node_validator::test_utils::FailureIdentityProvider,
            Lifetime,
        },
    };

    use super::KeyPackageGenerator;

    #[cfg(target_arch = "wasm32")]
    use wasm_bindgen_test::wasm_bindgen_test as test;

    #[derive(Debug, PartialEq, TlsSize, TlsSerialize, TlsDeserialize)]
    struct TestKpExt(u32);

    impl MlsExtension<KeyPackageExtension> for TestKpExt {
        const IDENTIFIER: crate::extension::ExtensionType = 42;
    }

    #[derive(Debug, PartialEq, TlsSize, TlsSerialize, TlsDeserialize)]
    struct TestLnExt(u32);

    impl MlsExtension<LeafNodeExtension> for TestLnExt {
        const IDENTIFIER: crate::extension::ExtensionType = 43;
    }

    fn test_key_package_ext(val: u32) -> ExtensionList<KeyPackageExtension> {
        let mut ext_list = ExtensionList::new();
        ext_list.set_extension(TestKpExt(val)).unwrap();
        ext_list
    }

    fn test_leaf_node_ext(val: u32) -> ExtensionList<LeafNodeExtension> {
        let mut ext_list = ExtensionList::new();
        ext_list.set_extension(TestLnExt(val)).unwrap();
        ext_list
    }

    fn test_lifetime() -> Lifetime {
        Lifetime::years(1).unwrap()
    }

    #[test]
    fn test_key_generation() {
        for (protocol_version, cipher_suite) in
            ProtocolVersion::all().flat_map(|p| CipherSuite::all().map(move |cs| (p, cs)))
        {
            let (signing_identity, signing_key) =
                get_test_signing_identity(cipher_suite, b"foo".to_vec());

            let key_package_ext = test_key_package_ext(32);
            let leaf_node_ext = test_leaf_node_ext(42);
            let lifetime = test_lifetime();

            let test_generator = KeyPackageGenerator {
                protocol_version,
                cipher_suite_provider: &test_cipher_suite_provider(cipher_suite),
                signing_identity: &signing_identity,
                signing_key: &signing_key,
                identity_provider: &BasicIdentityProvider::new(),
            };

            let mut capabilities = get_test_capabilities();
            capabilities.extensions.push(42);
            capabilities.extensions.push(43);
            capabilities.extensions.push(32);

            let generated = test_generator
                .generate(
                    lifetime.clone(),
                    capabilities.clone(),
                    key_package_ext.clone(),
                    leaf_node_ext.clone(),
                )
                .unwrap();

            assert_matches!(generated.key_package.leaf_node.leaf_node_source,
                            LeafNodeSource::KeyPackage(ref lt) if lt == &lifetime);

            assert_eq!(generated.key_package.leaf_node.capabilities, capabilities);
            assert_eq!(generated.key_package.leaf_node.extensions, leaf_node_ext);
            assert_eq!(generated.key_package.extensions, key_package_ext);

            assert_eq!(
                generated
                    .key_package
                    .leaf_node
                    .signing_identity
                    .public_key(cipher_suite)
                    .unwrap(),
                signing_identity.public_key(cipher_suite).unwrap()
            );

            assert_ne!(
                generated.key_package.hpke_init_key.as_ref(),
                generated.key_package.leaf_node.public_key.as_ref()
            );

            assert_eq!(generated.key_package.extensions, key_package_ext);
            assert_eq!(generated.key_package.cipher_suite, cipher_suite.into());
            assert_eq!(generated.key_package.version, protocol_version.into());

            let curve = test_generator
                .cipher_suite_provider
                .cipher_suite()
                .kem_type()
                .curve();

            let init_key_public = PublicKey::from_uncompressed_bytes(
                generated.key_package.hpke_init_key.as_ref(),
                curve,
            )
            .unwrap();

            let init_key_secret =
                SecretKey::from_bytes(generated.init_secret_key.as_ref(), curve).unwrap();

            assert_eq!(init_key_secret.curve(), curve);
            assert_eq!(init_key_public, init_key_secret.to_public().unwrap());

            let leaf_public = PublicKey::from_uncompressed_bytes(
                generated.key_package.leaf_node.public_key.as_ref(),
                curve,
            )
            .unwrap();

            let leaf_secret =
                SecretKey::from_bytes(generated.leaf_node_secret_key.as_ref(), curve).unwrap();

            assert_eq!(leaf_secret.curve(), curve);
            assert_eq!(leaf_public, leaf_secret.to_public().unwrap());

            let validator = KeyPackageValidator::new(
                protocol_version,
                cipher_suite,
                None,
                BasicIdentityProvider::new(),
            );

            validator
                .check_if_valid(&generated.key_package, Default::default())
                .unwrap();
        }
    }

    #[test]
    fn test_credential_signature_mismatch() {
        let protocol_version = ProtocolVersion::Mls10;
        let cipher_suite = CipherSuite::Curve25519Aes128;

        let signing_key = cipher_suite.generate_signing_key().unwrap();
        let (signing_identity, _) = get_test_signing_identity(cipher_suite, b"foo".to_vec());

        let test_generator = KeyPackageGenerator {
            protocol_version,
            cipher_suite_provider: &test_cipher_suite_provider(cipher_suite),
            signing_identity: &signing_identity,
            signing_key: &signing_key,
            identity_provider: &BasicIdentityProvider::new(),
        };

        let generated = test_generator.generate(
            test_lifetime(),
            get_test_capabilities(),
            ExtensionList::default(),
            ExtensionList::default(),
        );

        assert_matches!(
            generated,
            Err(KeyPackageGenerationError::LeafNodeError(
                LeafNodeError::InvalidSignerPublicKey
            ))
        );
    }

    #[test]
    fn test_randomness() {
        for (protocol_version, cipher_suite) in
            ProtocolVersion::all().flat_map(|p| CipherSuite::all().map(move |cs| (p, cs)))
        {
            let (signing_identity, signing_key) =
                get_test_signing_identity(cipher_suite, b"foo".to_vec());

            let test_generator = KeyPackageGenerator {
                protocol_version,
                cipher_suite_provider: &test_cipher_suite_provider(cipher_suite),
                signing_identity: &signing_identity,
                signing_key: &signing_key,
                identity_provider: &BasicIdentityProvider::new(),
            };

            let first_key_package = test_generator
                .generate(
                    test_lifetime(),
                    get_test_capabilities(),
                    ExtensionList::default(),
                    ExtensionList::default(),
                )
                .unwrap();

            (0..100).for_each(|_| {
                let next_key_package = test_generator
                    .generate(
                        test_lifetime(),
                        get_test_capabilities(),
                        ExtensionList::default(),
                        ExtensionList::default(),
                    )
                    .unwrap();

                assert_ne!(
                    first_key_package.key_package.hpke_init_key,
                    next_key_package.key_package.hpke_init_key
                );

                assert_ne!(
                    first_key_package.key_package.leaf_node.public_key,
                    next_key_package.key_package.leaf_node.public_key
                );
            })
        }
    }

    #[test]
    fn test_failure_when_credential_is_not_valid() {
        let cipher_suite = CipherSuite::Curve25519Aes128;
        let (signing_identity, signing_key) =
            get_test_signing_identity(cipher_suite, b"test".to_vec());

        let test_generator = KeyPackageGenerator {
            protocol_version: ProtocolVersion::Mls10,
            cipher_suite_provider: &test_cipher_suite_provider(cipher_suite),
            signing_identity: &signing_identity,
            signing_key: &signing_key,
            identity_provider: &FailureIdentityProvider,
        };

        assert_matches!(
            test_generator.generate(
                test_lifetime(),
                get_test_capabilities(),
                ExtensionList::default(),
                ExtensionList::default()
            ),
            Err(KeyPackageGenerationError::LeafNodeError(
                LeafNodeError::IdentityProviderError(_)
            ))
        );
    }
}
