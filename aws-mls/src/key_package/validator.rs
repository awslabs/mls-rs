use aws_mls_core::extension::ExtensionError;
use aws_mls_core::identity::IdentityProvider;

use super::*;
use crate::provider::crypto::CipherSuiteProvider;
use crate::tree_kem::leaf_node::LeafNodeSource;
use crate::tree_kem::Lifetime;
use crate::{
    signer::SignatureError,
    tree_kem::leaf_node_validator::{
        LeafNodeValidationError, LeafNodeValidator, ValidationContext,
    },
};

#[derive(Debug, Error)]
pub enum KeyPackageValidationError {
    #[error(transparent)]
    SerializationError(#[from] tls_codec::Error),
    #[error(transparent)]
    ExtensionError(#[from] ExtensionError),
    #[error(transparent)]
    KeyPackageError(#[from] KeyPackageError),
    #[error(transparent)]
    SignatureError(#[from] SignatureError),
    #[error(transparent)]
    LeafNodeValidationError(#[from] LeafNodeValidationError),
    #[error("key lifetime not found")]
    MissingKeyLifetime,
    #[error("{0:?} is not within lifetime {1:?}")]
    InvalidKeyLifetime(MlsTime, Lifetime),
    #[error("required extension not found")]
    RequiredExtensionNotFound(ExtensionType),
    #[error("required proposal not found")]
    RequiredProposalNotFound(ProposalType),
    #[error("found cipher suite {0:?} expected {1:?}")]
    InvalidCipherSuite(CipherSuite, CipherSuite),
    #[error("found protocol version {0:?} expected {1:?}")]
    InvalidProtocolVersion(ProtocolVersion, ProtocolVersion),
    #[error("init key is not valid for cipher suite")]
    InvalidInitKey,
    #[error("init key can not be equal to leaf node public key")]
    InitLeafKeyEquality,
}

#[derive(PartialEq, Eq, Hash, Debug, Clone, Copy, Default)]
pub struct KeyPackageValidationOptions {
    pub apply_lifetime_check: Option<MlsTime>,
}

#[derive(Debug)]
pub struct KeyPackageValidator<'a, C: IdentityProvider, CSP: CipherSuiteProvider> {
    pub protocol_version: ProtocolVersion,
    pub cipher_suite_provider: &'a CSP,
    leaf_node_validator: LeafNodeValidator<'a, C, CSP>,
}

#[derive(Debug)]
pub struct KeyPackageValidationOutput {
    pub expiration_timestamp: u64,
}

impl<'a, C: IdentityProvider, CSP: CipherSuiteProvider> KeyPackageValidator<'a, C, CSP> {
    pub fn new(
        protocol_version: ProtocolVersion,
        cipher_suite_provider: &'a CSP,
        required_capabilities: Option<&'a RequiredCapabilitiesExt>,
        identity_provider: C,
    ) -> KeyPackageValidator<'a, C, CSP> {
        KeyPackageValidator {
            protocol_version,
            cipher_suite_provider,
            leaf_node_validator: LeafNodeValidator::new(
                cipher_suite_provider,
                required_capabilities,
                identity_provider,
            ),
        }
    }

    fn check_signature(&self, package: &KeyPackage) -> Result<(), KeyPackageValidationError> {
        // Verify that the signature on the KeyPackage is valid using the public key in the contained LeafNode's credential
        package
            .verify(
                self.cipher_suite_provider,
                &package.leaf_node.signing_identity.signature_key,
                &(),
            )
            .map_err(Into::into)
    }

    pub async fn check_if_valid(
        &self,
        package: &KeyPackage,
        options: KeyPackageValidationOptions,
    ) -> Result<KeyPackageValidationOutput, KeyPackageValidationError> {
        self.validate_properties(package)?;

        self.leaf_node_validator
            .check_if_valid(&package.leaf_node, self.validation_context(options))
            .await?;

        let expiration_timestamp =
            if let LeafNodeSource::KeyPackage(lifetime) = &package.leaf_node.leaf_node_source {
                lifetime.not_after
            } else {
                return Err(KeyPackageValidationError::MissingKeyLifetime);
            };

        Ok(KeyPackageValidationOutput {
            expiration_timestamp,
        })
    }

    fn validate_properties(&self, package: &KeyPackage) -> Result<(), KeyPackageValidationError> {
        self.check_signature(package)?;

        // Verify that the protocol version matches
        if package.version != self.protocol_version {
            return Err(KeyPackageValidationError::InvalidProtocolVersion(
                package.version,
                self.protocol_version,
            ));
        }

        // Verify that the cipher suite matches
        if package.cipher_suite != self.cipher_suite_provider.cipher_suite() {
            return Err(KeyPackageValidationError::InvalidCipherSuite(
                package.cipher_suite,
                self.cipher_suite_provider.cipher_suite(),
            ));
        }

        // Verify that the public init key is a valid format for this cipher suite
        self.cipher_suite_provider
            .kem_public_key_validate(&package.hpke_init_key)
            .map_err(|_| KeyPackageValidationError::InvalidInitKey)?;

        // Verify that the init key and the leaf node public key are different
        if package.hpke_init_key.as_ref() == package.leaf_node.public_key.as_ref() {
            return Err(KeyPackageValidationError::InitLeafKeyEquality);
        }

        Ok(())
    }

    fn validation_context(&self, options: KeyPackageValidationOptions) -> ValidationContext {
        ValidationContext::Add(options.apply_lifetime_check)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::test_utils::TEST_CIPHER_SUITE;
    use crate::client::test_utils::TEST_PROTOCOL_VERSION;
    use crate::group::test_utils::random_bytes;
    use crate::identity::test_utils::get_test_signing_identity;
    use crate::key_package::test_utils::test_key_package;
    use crate::key_package::test_utils::test_key_package_custom;
    use crate::provider::crypto::test_utils::{test_cipher_suite_provider, TestCryptoProvider};
    use crate::provider::identity::BasicIdentityProvider;
    use crate::tree_kem::leaf_node::test_utils::get_test_capabilities;
    use assert_matches::assert_matches;
    use futures::FutureExt;

    #[cfg(target_arch = "wasm32")]
    use wasm_bindgen_test::wasm_bindgen_test as test;

    #[futures_test::test]
    async fn test_standard_validation() {
        for (protocol_version, cipher_suite) in ProtocolVersion::all().flat_map(|p| {
            TestCryptoProvider::all_supported_cipher_suites()
                .into_iter()
                .map(move |cs| (p, cs))
        }) {
            let cipher_suite_provider = test_cipher_suite_provider(cipher_suite);

            let test_package = test_key_package(
                protocol_version,
                cipher_suite,
                &format!("alice-{protocol_version:?}-{cipher_suite:?}"),
            )
            .await;

            let validator = KeyPackageValidator::new(
                protocol_version,
                &cipher_suite_provider,
                None,
                BasicIdentityProvider::new(),
            );

            assert_matches!(
                validator
                    .check_if_valid(&test_package, Default::default())
                    .await,
                Ok(_)
            );
        }
    }

    async fn invalid_signature_key_package(
        protocol_version: ProtocolVersion,
        cipher_suite: CipherSuite,
    ) -> KeyPackage {
        let mut test_package = test_key_package(protocol_version, cipher_suite, "mallory").await;
        test_package.signature = random_bytes(32);
        test_package
    }

    #[futures_test::test]
    async fn test_invalid_signature() {
        for (protocol_version, cipher_suite) in ProtocolVersion::all().flat_map(|p| {
            TestCryptoProvider::all_supported_cipher_suites()
                .into_iter()
                .map(move |cs| (p, cs))
        }) {
            let cipher_suite_provider = test_cipher_suite_provider(cipher_suite);

            let test_package = invalid_signature_key_package(protocol_version, cipher_suite).await;

            let validator = KeyPackageValidator::new(
                protocol_version,
                &cipher_suite_provider,
                None,
                BasicIdentityProvider::new(),
            );

            assert_matches!(
                validator
                    .check_if_valid(&test_package, Default::default())
                    .await,
                Err(KeyPackageValidationError::SignatureError(_))
            );
        }
    }

    #[futures_test::test]
    async fn test_invalid_cipher_suite() {
        let cipher_suite = TEST_CIPHER_SUITE;
        let version = TEST_PROTOCOL_VERSION;
        let test_package = test_key_package(version, cipher_suite, "mallory").await;

        let invalid_cipher_suite_provider =
            test_cipher_suite_provider(CipherSuite::CURVE25519_CHACHA);

        let validator = KeyPackageValidator::new(
            version,
            &invalid_cipher_suite_provider,
            None,
            BasicIdentityProvider::new(),
        );

        assert_matches!(
            validator
                .check_if_valid(&test_package, Default::default())
                .await,
            Err(KeyPackageValidationError::InvalidCipherSuite(
                TEST_CIPHER_SUITE,
                CipherSuite::CURVE25519_CHACHA
            ))
        );
    }

    async fn test_init_key_manipulation<F, CSP>(
        cipher_suite_provider: CSP,
        protocol_version: ProtocolVersion,
        mut edit: F,
    ) -> KeyPackage
    where
        CSP: CipherSuiteProvider + Clone,
        F: FnMut(&mut KeyPackage),
    {
        let (alternate_sining_id, secret) =
            get_test_signing_identity(cipher_suite_provider.cipher_suite(), b"test".to_vec());

        let mut test_package = {
            let cipher_suite_provider = cipher_suite_provider.clone();
            let signing_key = secret.clone();

            test_key_package_custom(
                &cipher_suite_provider.clone(),
                protocol_version,
                "test",
                move |_| {
                    async move {
                        let new_generator = KeyPackageGenerator {
                            protocol_version,
                            cipher_suite_provider: &cipher_suite_provider,
                            signing_identity: &alternate_sining_id,
                            signing_key: &signing_key,
                            identity_provider: &BasicIdentityProvider::new(),
                        };

                        new_generator
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
        };

        edit(&mut test_package);

        test_package
            .sign(&cipher_suite_provider, &secret, &())
            .unwrap();

        test_package
    }

    #[futures_test::test]
    async fn test_invalid_init_key() {
        let cipher_suite_provider = test_cipher_suite_provider(TEST_CIPHER_SUITE);
        let protocol_version = TEST_PROTOCOL_VERSION;

        let key_package = test_init_key_manipulation(
            cipher_suite_provider.clone(),
            protocol_version,
            |key_package| {
                key_package.hpke_init_key = HpkePublicKey::from(vec![42; 128]);
            },
        )
        .await;

        let validator = KeyPackageValidator::new(
            protocol_version,
            &cipher_suite_provider,
            None,
            BasicIdentityProvider::new(),
        );

        assert_matches!(
            validator
                .check_if_valid(&key_package, Default::default())
                .await,
            Err(KeyPackageValidationError::InvalidInitKey)
        );
    }

    #[futures_test::test]
    async fn test_matching_init_key() {
        let cipher_suite_provider = test_cipher_suite_provider(TEST_CIPHER_SUITE);
        let protocol_version = TEST_PROTOCOL_VERSION;

        let key_package = test_init_key_manipulation(
            cipher_suite_provider.clone(),
            protocol_version,
            |key_package| {
                key_package.hpke_init_key =
                    key_package.leaf_node.public_key.as_ref().to_vec().into();
            },
        )
        .await;

        let validator = KeyPackageValidator::new(
            protocol_version,
            &cipher_suite_provider,
            None,
            BasicIdentityProvider::new(),
        );

        assert_matches!(
            validator
                .check_if_valid(&key_package, Default::default())
                .await,
            Err(KeyPackageValidationError::InitLeafKeyEquality)
        );
    }

    async fn invalid_expiration_leaf_node<CSP>(
        protocol_version: ProtocolVersion,
        cipher_suite_provider: &CSP,
    ) -> KeyPackage
    where
        CSP: CipherSuiteProvider,
    {
        test_key_package_custom(
            cipher_suite_provider,
            protocol_version,
            "foo",
            |generator| {
                async move {
                    generator
                        .generate(
                            Lifetime {
                                not_before: 0,
                                not_after: 0,
                            },
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

    #[futures_test::test]
    async fn test_expired() {
        let cipher_suite_provider = test_cipher_suite_provider(TEST_CIPHER_SUITE);
        let protocol_version = TEST_PROTOCOL_VERSION;

        let test_package =
            invalid_expiration_leaf_node(protocol_version, &cipher_suite_provider).await;

        let validator = KeyPackageValidator::new(
            protocol_version,
            &cipher_suite_provider,
            None,
            BasicIdentityProvider::new(),
        );

        let options = KeyPackageValidationOptions {
            apply_lifetime_check: Some(MlsTime::now()),
        };

        assert_matches!(
            validator.check_if_valid(&test_package, options).await,
            Err(KeyPackageValidationError::LeafNodeValidationError(
                LeafNodeValidationError::InvalidLifetime(_, _)
            ))
        );
    }

    #[futures_test::test]
    async fn test_skip_expiration_check() {
        let cipher_suite_provider = test_cipher_suite_provider(TEST_CIPHER_SUITE);
        let protocol_version = TEST_PROTOCOL_VERSION;

        let test_package =
            invalid_expiration_leaf_node(protocol_version, &cipher_suite_provider).await;

        let validator = KeyPackageValidator::new(
            protocol_version,
            &cipher_suite_provider,
            None,
            BasicIdentityProvider::new(),
        );

        assert_matches!(
            validator
                .check_if_valid(
                    &test_package,
                    KeyPackageValidationOptions {
                        apply_lifetime_check: None
                    },
                )
                .await,
            Ok(_)
        );
    }

    #[futures_test::test]
    async fn test_required_capabilities_check() {
        let cipher_suite_provider = test_cipher_suite_provider(TEST_CIPHER_SUITE);
        let protocol_version = TEST_PROTOCOL_VERSION;

        let key_package = test_key_package_custom(
            &cipher_suite_provider,
            protocol_version,
            "test",
            |generator| {
                async move {
                    let mut capabilities = get_test_capabilities();
                    capabilities.extensions.push(42.into());

                    generator
                        .generate(
                            Lifetime::years(1).unwrap(),
                            capabilities,
                            ExtensionList::default(),
                            ExtensionList::default(),
                        )
                        .await
                        .unwrap()
                }
                .boxed()
            },
        )
        .await;

        let required_capabilities = RequiredCapabilitiesExt {
            extensions: vec![42.into()],
            proposals: vec![],
            credentials: vec![],
        };

        let validator = KeyPackageValidator::new(
            protocol_version,
            &cipher_suite_provider,
            Some(&required_capabilities),
            BasicIdentityProvider::new(),
        );

        assert_matches!(
            validator
                .check_if_valid(&key_package, Default::default())
                .await,
            Ok(_)
        );
    }

    #[futures_test::test]
    async fn test_required_capabilities_failure() {
        let cipher_suite_provider = test_cipher_suite_provider(TEST_CIPHER_SUITE);
        let protocol_version = TEST_PROTOCOL_VERSION;

        let key_package = test_key_package(
            protocol_version,
            cipher_suite_provider.cipher_suite(),
            "alice",
        )
        .await;

        let required_capabilities = RequiredCapabilitiesExt {
            extensions: vec![255.into()],
            proposals: vec![],
            credentials: vec![],
        };

        let validator = KeyPackageValidator::new(
            protocol_version,
            &cipher_suite_provider,
            Some(&required_capabilities),
            BasicIdentityProvider::new(),
        );

        assert_matches!(
            validator
                .check_if_valid(&key_package, Default::default())
                .await,
            Err(KeyPackageValidationError::LeafNodeValidationError(_))
        );
    }

    #[futures_test::test]
    async fn test_leaf_node_validation_failure() {
        let cipher_suite_provider = test_cipher_suite_provider(TEST_CIPHER_SUITE);
        let protocol_version = TEST_PROTOCOL_VERSION;

        let key_package = test_key_package_custom(
            &cipher_suite_provider,
            protocol_version,
            "foo",
            |generator| {
                async move {
                    let mut package_gen = generator
                        .generate(
                            Lifetime::years(1).unwrap(),
                            get_test_capabilities(),
                            ExtensionList::default(),
                            ExtensionList::default(),
                        )
                        .await
                        .unwrap();

                    package_gen.key_package.leaf_node.signature = random_bytes(32);
                    generator.sign(&mut package_gen.key_package).unwrap();
                    package_gen
                }
                .boxed()
            },
        )
        .await;

        let validator = KeyPackageValidator::new(
            protocol_version,
            &cipher_suite_provider,
            None,
            BasicIdentityProvider::new(),
        );

        assert_matches!(
            validator
                .check_if_valid(&key_package, Default::default())
                .await,
            Err(KeyPackageValidationError::LeafNodeValidationError(_))
        );
    }
}
