use super::leaf_node::{LeafNode, LeafNodeSigningContext, LeafNodeSource};
use super::{Lifetime, LifetimeError};
use crate::identity::CredentialType;
use crate::provider::crypto::CipherSuiteProvider;
use crate::provider::identity::IdentityProvider;
use crate::{
    extension::{ExtensionType, RequiredCapabilitiesExt},
    group::proposal::ProposalType,
    signer::{Signable, SignatureError},
    time::MlsTime,
};
use thiserror::Error;

pub enum ValidationContext<'a> {
    Add(Option<MlsTime>),
    Update((&'a [u8], u32, Option<MlsTime>)),
    Commit((&'a [u8], u32, Option<MlsTime>)),
}

impl<'a> ValidationContext<'a> {
    fn signing_context(&self) -> LeafNodeSigningContext {
        match *self {
            ValidationContext::Add(_) => Default::default(),
            ValidationContext::Update((group_id, leaf_index, _)) => (group_id, leaf_index).into(),
            ValidationContext::Commit((group_id, leaf_index, _)) => (group_id, leaf_index).into(),
        }
    }

    fn generation_time(&self) -> Option<MlsTime> {
        match *self {
            ValidationContext::Add(t) => t,
            ValidationContext::Update((_, _, t)) => t,
            ValidationContext::Commit((_, _, t)) => t,
        }
    }
}

#[derive(Debug, Error)]
pub enum LeafNodeValidationError {
    #[error(transparent)]
    LifetimeError(#[from] LifetimeError),
    #[error(transparent)]
    SerializationError(#[from] tls_codec::Error),
    #[error("invalid leaf_node_source")]
    InvalidLeafNodeSource,
    #[error(transparent)]
    SignatureError(#[from] SignatureError),
    #[error("{0:?} is not within lifetime {1:?}")]
    InvalidLifetime(MlsTime, Lifetime),
    #[error("required extension not found")]
    RequiredExtensionNotFound(ExtensionType),
    #[error("required proposal not found")]
    RequiredProposalNotFound(ProposalType),
    #[error("required credential not found")]
    RequiredCredentialNotFound(CredentialType),
    #[error("capabilities must describe extensions used")]
    ExtensionNotInCapabilities(ExtensionType),
    #[error("credential rejected by custom credential validator {0:?}")]
    IdentityProviderError(#[source] Box<dyn std::error::Error + Sync + Send>),
}

#[derive(Clone, Debug)]
pub struct LeafNodeValidator<'a, C, CP>
where
    C: IdentityProvider,
    CP: CipherSuiteProvider,
{
    cipher_suite_provider: &'a CP,
    identity_provider: C,
    required_capabilities: Option<&'a RequiredCapabilitiesExt>,
}

impl<'a, C: IdentityProvider, CP: CipherSuiteProvider> LeafNodeValidator<'a, C, CP> {
    pub fn new(
        cipher_suite_provider: &'a CP,
        required_capabilities: Option<&'a RequiredCapabilitiesExt>,
        identity_provider: C,
    ) -> Self {
        Self {
            cipher_suite_provider,
            required_capabilities,
            identity_provider,
        }
    }

    fn check_context(
        &self,
        leaf_node: &LeafNode,
        context: &ValidationContext,
    ) -> Result<(), LeafNodeValidationError> {
        // Context specific checks
        match context {
            ValidationContext::Add(time) => {
                // If the context is add, and we specified a time to check for lifetime, verify it
                if let LeafNodeSource::KeyPackage(lifetime) = &leaf_node.leaf_node_source {
                    if let Some(current_time) = time {
                        if !lifetime.within_lifetime(*current_time)? {
                            return Err(LeafNodeValidationError::InvalidLifetime(
                                *current_time,
                                lifetime.clone(),
                            ));
                        }
                    }
                } else {
                    // If the leaf_node_source is anything other than Add it is invalid
                    return Err(LeafNodeValidationError::InvalidLeafNodeSource);
                }
            }
            ValidationContext::Update(_) => {
                // If the leaf_node_source is anything other than Update it is invalid
                if !matches!(leaf_node.leaf_node_source, LeafNodeSource::Update) {
                    return Err(LeafNodeValidationError::InvalidLeafNodeSource);
                }
            }
            ValidationContext::Commit(_) => {
                // If the leaf_node_source is anything other than Commit it is invalid
                if !matches!(leaf_node.leaf_node_source, LeafNodeSource::Commit(_)) {
                    return Err(LeafNodeValidationError::InvalidLeafNodeSource);
                }
            }
        }

        Ok(())
    }

    pub fn revalidate(
        &self,
        leaf_node: &LeafNode,
        group_id: &[u8],
        leaf_index: u32,
    ) -> Result<(), LeafNodeValidationError> {
        let context = match leaf_node.leaf_node_source {
            LeafNodeSource::KeyPackage(_) => ValidationContext::Add(None),
            LeafNodeSource::Update => ValidationContext::Update((group_id, leaf_index, None)),
            LeafNodeSource::Commit(_) => ValidationContext::Commit((group_id, leaf_index, None)),
        };

        self.check_if_valid(leaf_node, context)
    }

    pub fn validate_required_capabilities(
        &self,
        leaf_node: &LeafNode,
    ) -> Result<(), LeafNodeValidationError> {
        if let Some(required_capabilities) = self.required_capabilities {
            for extension in &required_capabilities.extensions {
                if !leaf_node.capabilities.extensions.contains(extension) {
                    return Err(LeafNodeValidationError::RequiredExtensionNotFound(
                        *extension,
                    ));
                }
            }

            for proposal in &required_capabilities.proposals {
                if !leaf_node.capabilities.proposals.contains(proposal) {
                    return Err(LeafNodeValidationError::RequiredProposalNotFound(*proposal));
                }
            }

            for credential in &required_capabilities.credentials {
                if !leaf_node.capabilities.credentials.contains(credential) {
                    return Err(LeafNodeValidationError::RequiredCredentialNotFound(
                        *credential,
                    ));
                }
            }
        }

        Ok(())
    }

    pub(crate) fn check_if_valid(
        &self,
        leaf_node: &LeafNode,
        context: ValidationContext,
    ) -> Result<(), LeafNodeValidationError> {
        // Check that we are validating within the proper context
        self.check_context(leaf_node, &context)?;

        // Verify the credential
        self.identity_provider
            .validate(
                &leaf_node.signing_identity,
                self.cipher_suite_provider.cipher_suite(),
                context.generation_time(),
            )
            .map_err(|e| LeafNodeValidationError::IdentityProviderError(e.into()))?;

        // Verify that the credential signed the leaf node
        leaf_node.verify(
            self.cipher_suite_provider,
            &leaf_node.signing_identity.signature_key,
            &context.signing_context(),
        )?;

        // If required capabilities are specified, verify the leaf node meets the requirements
        self.validate_required_capabilities(leaf_node)?;

        // If there are extensions, make sure they are referenced in the capabilities field
        for one_ext in &leaf_node.extensions {
            if !leaf_node
                .capabilities
                .extensions
                .contains(&one_ext.extension_type)
            {
                return Err(LeafNodeValidationError::ExtensionNotInCapabilities(
                    one_ext.extension_type,
                ));
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use assert_matches::assert_matches;
    use ferriscrypt::rand::SecureRng;

    use super::*;

    use crate::cipher_suite::CipherSuite;
    use crate::extension::{ApplicationIdExt, ExtensionList, MlsExtension};
    use crate::identity::test_utils::get_test_signing_identity;
    use crate::identity::CREDENTIAL_TYPE_BASIC;
    use crate::provider::crypto::test_utils::test_cipher_suite_provider;
    use crate::provider::crypto::SignatureSecretKey;
    use crate::provider::identity::BasicIdentityProvider;
    use crate::tree_kem::leaf_node::test_utils::*;
    use crate::tree_kem::leaf_node_validator::test_utils::FailureIdentityProvider;
    use crate::tree_kem::parent_hash::ParentHash;
    use crate::tree_kem::Capabilities;

    #[cfg(target_arch = "wasm32")]
    use wasm_bindgen_test::wasm_bindgen_test as test;

    const TEST_CIPHER_SUITE: CipherSuite = CipherSuite::Curve25519Aes128;

    fn get_test_add_node() -> (LeafNode, SignatureSecretKey) {
        let (signing_identity, secret) =
            get_test_signing_identity(TEST_CIPHER_SUITE, b"foo".to_vec());

        let (leaf_node, _) =
            get_test_node(TEST_CIPHER_SUITE, signing_identity, &secret, None, None);

        (leaf_node, secret)
    }

    #[test]
    fn test_basic_add_validation() {
        let cipher_suite_provider = test_cipher_suite_provider(TEST_CIPHER_SUITE);

        let (leaf_node, _) = get_test_add_node();

        let test_validator =
            LeafNodeValidator::new(&cipher_suite_provider, None, BasicIdentityProvider::new());

        assert_matches!(
            test_validator.check_if_valid(&leaf_node, ValidationContext::Add(None)),
            Ok(_)
        );
    }

    #[test]
    fn test_failed_validation() {
        let cipher_suite_provider = test_cipher_suite_provider(TEST_CIPHER_SUITE);
        let (leaf_node, _) = get_test_add_node();

        let fail_test_validator =
            LeafNodeValidator::new(&cipher_suite_provider, None, FailureIdentityProvider::new());

        assert_matches!(
            fail_test_validator.check_if_valid(&leaf_node, ValidationContext::Add(None)),
            Err(LeafNodeValidationError::IdentityProviderError(_))
        );
    }

    #[test]
    fn test_basic_update_validation() {
        let cipher_suite_provider = test_cipher_suite_provider(TEST_CIPHER_SUITE);
        let group_id = b"group_id";

        let (mut leaf_node, secret) = get_test_add_node();

        leaf_node
            .update(
                &cipher_suite_provider,
                group_id,
                0,
                // TODO remove identity from input
                default_properties(),
                None,
                &secret,
            )
            .unwrap();

        let test_validator =
            LeafNodeValidator::new(&cipher_suite_provider, None, BasicIdentityProvider::new());

        assert_matches!(
            test_validator
                .check_if_valid(&leaf_node, ValidationContext::Update((group_id, 0, None))),
            Ok(_)
        );
    }

    #[test]
    fn test_basic_commit_validation() {
        let cipher_suite_provider = test_cipher_suite_provider(TEST_CIPHER_SUITE);
        let group_id = b"group_id";

        let (mut leaf_node, secret) = get_test_add_node();

        leaf_node
            .commit(
                &cipher_suite_provider,
                group_id,
                0,
                default_properties(),
                None,
                &secret,
                ParentHash::from(vec![0u8; 32]),
            )
            .unwrap();

        let test_validator =
            LeafNodeValidator::new(&cipher_suite_provider, None, BasicIdentityProvider::new());

        assert_matches!(
            test_validator
                .check_if_valid(&leaf_node, ValidationContext::Commit((group_id, 0, None))),
            Ok(_)
        );
    }

    #[test]
    fn test_incorrect_context() {
        let cipher_suite_provider = test_cipher_suite_provider(TEST_CIPHER_SUITE);

        let test_validator =
            LeafNodeValidator::new(&cipher_suite_provider, None, BasicIdentityProvider::new());

        let (mut leaf_node, secret) = get_test_add_node();

        assert_matches!(
            test_validator.check_if_valid(&leaf_node, ValidationContext::Update((b"foo", 0, None))),
            Err(LeafNodeValidationError::InvalidLeafNodeSource)
        );

        assert_matches!(
            test_validator.check_if_valid(&leaf_node, ValidationContext::Commit((b"foo", 0, None))),
            Err(LeafNodeValidationError::InvalidLeafNodeSource)
        );

        leaf_node
            .update(
                &cipher_suite_provider,
                b"foo",
                0,
                default_properties(),
                None,
                &secret,
            )
            .unwrap();

        assert_matches!(
            test_validator.check_if_valid(&leaf_node, ValidationContext::Add(None)),
            Err(LeafNodeValidationError::InvalidLeafNodeSource)
        );

        assert_matches!(
            test_validator.check_if_valid(&leaf_node, ValidationContext::Commit((b"foo", 0, None))),
            Err(LeafNodeValidationError::InvalidLeafNodeSource)
        );

        leaf_node
            .commit(
                &cipher_suite_provider,
                b"foo",
                0,
                default_properties(),
                None,
                &secret,
                ParentHash::from(vec![0u8; 32]),
            )
            .unwrap();

        assert_matches!(
            test_validator.check_if_valid(&leaf_node, ValidationContext::Add(None)),
            Err(LeafNodeValidationError::InvalidLeafNodeSource)
        );

        assert_matches!(
            test_validator.check_if_valid(&leaf_node, ValidationContext::Update((b"foo", 0, None))),
            Err(LeafNodeValidationError::InvalidLeafNodeSource)
        );
    }

    #[test]
    fn test_bad_signature() {
        for cipher_suite in CipherSuite::all() {
            let cipher_suite_provider = test_cipher_suite_provider(cipher_suite);

            let (signing_identity, secret) =
                get_test_signing_identity(cipher_suite, b"foo".to_vec());

            let (mut leaf_node, _) =
                get_test_node(cipher_suite, signing_identity, &secret, None, None);

            leaf_node.signature = SecureRng::gen(leaf_node.signature.len()).unwrap();

            let test_validator =
                LeafNodeValidator::new(&cipher_suite_provider, None, BasicIdentityProvider::new());

            assert_matches!(
                test_validator.check_if_valid(&leaf_node, ValidationContext::Add(None)),
                Err(LeafNodeValidationError::SignatureError(
                    SignatureError::SignatureValidationFailed(_)
                ))
            );
        }
    }

    #[test]
    fn test_capabilities_mismatch() {
        let (signing_identity, secret) =
            get_test_signing_identity(TEST_CIPHER_SUITE, b"foo".to_vec());

        let mut extensions = ExtensionList::new();

        extensions
            .set_extension(ApplicationIdExt {
                identifier: b"foo".to_vec(),
            })
            .unwrap();

        let capabilities = Capabilities {
            credentials: vec![CREDENTIAL_TYPE_BASIC],
            ..Default::default()
        };

        let (leaf_node, _) = get_test_node(
            TEST_CIPHER_SUITE,
            signing_identity,
            &secret,
            Some(capabilities),
            Some(extensions),
        );

        let cipher_suite_provider = test_cipher_suite_provider(TEST_CIPHER_SUITE);

        let test_validator =
            LeafNodeValidator::new(&cipher_suite_provider, None, BasicIdentityProvider::new());

        assert_matches!(test_validator.check_if_valid(&leaf_node, ValidationContext::Add(None)),
            Err(LeafNodeValidationError::ExtensionNotInCapabilities(ext)) if ext == ApplicationIdExt::IDENTIFIER);
    }

    #[test]
    fn test_cipher_suite_mismatch() {
        let cipher_suite_provider = test_cipher_suite_provider(CipherSuite::P256Aes128);

        let (leaf_node, _) = get_test_add_node();

        let test_validator =
            LeafNodeValidator::new(&cipher_suite_provider, None, BasicIdentityProvider::new());

        assert_matches!(
            test_validator.check_if_valid(&leaf_node, ValidationContext::Add(None)),
            Err(LeafNodeValidationError::SignatureError(_))
        );
    }

    #[test]
    fn test_required_extension() {
        let required_capabilities = RequiredCapabilitiesExt {
            extensions: vec![42u16],
            ..Default::default()
        };

        let (leaf_node, _) = get_test_add_node();

        let cipher_suite_provider = test_cipher_suite_provider(TEST_CIPHER_SUITE);

        let test_validator = LeafNodeValidator::new(
            &cipher_suite_provider,
            Some(&required_capabilities),
            BasicIdentityProvider::new(),
        );

        assert_matches!(
            test_validator.check_if_valid(&leaf_node, ValidationContext::Add(None)),
            Err(LeafNodeValidationError::RequiredExtensionNotFound(42))
        );
    }

    #[test]
    fn test_required_proposal() {
        let required_capabilities = RequiredCapabilitiesExt {
            proposals: vec![42.into()],
            ..Default::default()
        };

        let cipher_suite_provider = test_cipher_suite_provider(TEST_CIPHER_SUITE);

        let (leaf_node, _) = get_test_add_node();

        let test_validator = LeafNodeValidator::new(
            &cipher_suite_provider,
            Some(&required_capabilities),
            BasicIdentityProvider::new(),
        );

        assert_matches!(
            test_validator.check_if_valid(&leaf_node, ValidationContext::Add(None)),
            Err(LeafNodeValidationError::RequiredProposalNotFound(
                ProposalType(42)
            ))
        );
    }

    #[test]
    fn test_required_credential() {
        let required_capabilities = RequiredCapabilitiesExt {
            credentials: vec![42],
            ..Default::default()
        };

        let (leaf_node, _) = get_test_add_node();

        let cipher_suite_provider = test_cipher_suite_provider(TEST_CIPHER_SUITE);

        let test_validator = LeafNodeValidator::new(
            &cipher_suite_provider,
            Some(&required_capabilities),
            BasicIdentityProvider::new(),
        );

        assert_matches!(test_validator.check_if_valid(&leaf_node, ValidationContext::Add(None)),
            Err(LeafNodeValidationError::RequiredCredentialNotFound(ext)) if ext == 42u16
        );
    }

    #[test]
    fn test_add_lifetime() {
        let (leaf_node, _) = get_test_add_node();

        let cipher_suite_provider = test_cipher_suite_provider(TEST_CIPHER_SUITE);

        let test_validator =
            LeafNodeValidator::new(&cipher_suite_provider, None, BasicIdentityProvider::new());

        let good_lifetime = MlsTime::now();

        let over_one_year = good_lifetime.seconds_since_epoch().unwrap() + (86400 * 366);

        let bad_lifetime =
            MlsTime::from_duration_since_epoch(Duration::from_secs(over_one_year)).unwrap();

        assert_matches!(
            test_validator.check_if_valid(&leaf_node, ValidationContext::Add(Some(good_lifetime))),
            Ok(())
        );

        assert_matches!(
            test_validator.check_if_valid(&leaf_node, ValidationContext::Add(Some(bad_lifetime))),
            Err(LeafNodeValidationError::InvalidLifetime(_, _))
        );
    }
}

#[cfg(test)]
pub mod test_utils {
    use tls_codec::Serialize;

    use crate::{
        cipher_suite::CipherSuite,
        group::Member,
        identity::SigningIdentity,
        identity::{CredentialError, CREDENTIAL_TYPE_BASIC, CREDENTIAL_TYPE_X509},
        provider::identity::IdentityProvider,
        time::MlsTime,
    };

    #[derive(Clone, Debug, Default)]
    pub struct FailureIdentityProvider;

    impl FailureIdentityProvider {
        pub fn new() -> Self {
            Self::default()
        }
    }

    impl IdentityProvider for FailureIdentityProvider {
        type Error = CredentialError;
        type IdentityEvent = ();

        fn validate(
            &self,
            _signing_identity: &SigningIdentity,
            _cipher_suite: CipherSuite,
            _timestamp: Option<MlsTime>,
        ) -> Result<(), Self::Error> {
            Err(CredentialError::UnexpectedCredentialType(
                CREDENTIAL_TYPE_BASIC,
                CREDENTIAL_TYPE_BASIC,
            ))
        }

        fn identity(&self, signing_id: &SigningIdentity) -> Result<Vec<u8>, Self::Error> {
            Ok(signing_id.credential.tls_serialize_detached()?)
        }

        fn valid_successor(
            &self,
            _predecessor: &SigningIdentity,
            _successor: &SigningIdentity,
        ) -> Result<bool, Self::Error> {
            Err(CredentialError::UnexpectedCredentialType(
                CREDENTIAL_TYPE_BASIC,
                CREDENTIAL_TYPE_BASIC,
            ))
        }

        fn supported_types(&self) -> Vec<crate::identity::CredentialType> {
            vec![CREDENTIAL_TYPE_X509]
        }

        fn identity_events(
            &self,
            _update: &crate::group::RosterUpdate,
            _prior_roster: Vec<Member>,
        ) -> Result<Vec<Self::IdentityEvent>, Self::Error> {
            Ok(vec![])
        }
    }
}
