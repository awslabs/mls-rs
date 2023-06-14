use super::leaf_node::{LeafNode, LeafNodeSigningContext, LeafNodeSource};
use crate::client::MlsError;
use crate::CipherSuiteProvider;
use crate::{signer::Signable, time::MlsTime};
use aws_mls_core::{error::IntoAnyError, extension::ExtensionList, identity::IdentityProvider};

#[cfg(feature = "all_extensions")]
use crate::extension::RequiredCapabilitiesExt;

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

#[derive(Clone, Debug)]
pub struct LeafNodeValidator<'a, C, CP>
where
    C: IdentityProvider,
    CP: CipherSuiteProvider,
{
    cipher_suite_provider: &'a CP,
    identity_provider: &'a C,
    #[cfg(feature = "all_extensions")]
    required_capabilities: Option<&'a RequiredCapabilitiesExt>,
    group_context_extensions: Option<&'a ExtensionList>,
}

impl<'a, C: IdentityProvider, CP: CipherSuiteProvider> LeafNodeValidator<'a, C, CP> {
    pub fn new(
        cipher_suite_provider: &'a CP,
        #[cfg(feature = "all_extensions")] required_capabilities: Option<
            &'a RequiredCapabilitiesExt,
        >,
        identity_provider: &'a C,
        group_context_extensions: Option<&'a ExtensionList>,
    ) -> Self {
        Self {
            cipher_suite_provider,
            #[cfg(feature = "all_extensions")]
            required_capabilities,
            identity_provider,
            group_context_extensions,
        }
    }

    fn check_context(
        &self,
        leaf_node: &LeafNode,
        context: &ValidationContext,
    ) -> Result<(), MlsError> {
        // Context specific checks
        match context {
            ValidationContext::Add(time) => {
                // If the context is add, and we specified a time to check for lifetime, verify it
                if let LeafNodeSource::KeyPackage(lifetime) = &leaf_node.leaf_node_source {
                    if let Some(current_time) = time {
                        if !lifetime.within_lifetime(*current_time)? {
                            return Err(MlsError::InvalidLifetime);
                        }
                    }
                } else {
                    // If the leaf_node_source is anything other than Add it is invalid
                    return Err(MlsError::InvalidLeafNodeSource);
                }
            }
            ValidationContext::Update(_) => {
                // If the leaf_node_source is anything other than Update it is invalid
                if !matches!(leaf_node.leaf_node_source, LeafNodeSource::Update) {
                    return Err(MlsError::InvalidLeafNodeSource);
                }
            }
            ValidationContext::Commit(_) => {
                // If the leaf_node_source is anything other than Commit it is invalid
                if !matches!(leaf_node.leaf_node_source, LeafNodeSource::Commit(_)) {
                    return Err(MlsError::InvalidLeafNodeSource);
                }
            }
        }

        Ok(())
    }

    #[maybe_async::maybe_async]
    pub async fn revalidate(
        &self,
        leaf_node: &LeafNode,
        group_id: &[u8],
        leaf_index: u32,
    ) -> Result<(), MlsError> {
        let context = match leaf_node.leaf_node_source {
            LeafNodeSource::KeyPackage(_) => ValidationContext::Add(None),
            LeafNodeSource::Update => ValidationContext::Update((group_id, leaf_index, None)),
            LeafNodeSource::Commit(_) => ValidationContext::Commit((group_id, leaf_index, None)),
        };

        self.check_if_valid(leaf_node, context).await
    }

    #[cfg(feature = "all_extensions")]
    pub fn validate_required_capabilities(&self, leaf_node: &LeafNode) -> Result<(), MlsError> {
        if let Some(required_capabilities) = self.required_capabilities {
            for extension in &required_capabilities.extensions {
                if !leaf_node.capabilities.extensions.contains(extension) {
                    return Err(MlsError::RequiredExtensionNotFound(*extension));
                }
            }

            for proposal in &required_capabilities.proposals {
                if !leaf_node.capabilities.proposals.contains(proposal) {
                    return Err(MlsError::RequiredProposalNotFound(*proposal));
                }
            }

            for credential in &required_capabilities.credentials {
                if !leaf_node.capabilities.credentials.contains(credential) {
                    return Err(MlsError::RequiredCredentialNotFound(*credential));
                }
            }
        }

        Ok(())
    }

    #[maybe_async::maybe_async]
    pub(crate) async fn check_if_valid(
        &self,
        leaf_node: &LeafNode,
        context: ValidationContext<'_>,
    ) -> Result<(), MlsError> {
        // Check that we are validating within the proper context
        self.check_context(leaf_node, &context)?;

        // Verify the credential
        self.identity_provider
            .validate_member(
                &leaf_node.signing_identity,
                context.generation_time(),
                self.group_context_extensions,
            )
            .await
            .map_err(|e| MlsError::IdentityProviderError(e.into_any_error()))?;

        // Verify that the credential signed the leaf node
        leaf_node.verify(
            self.cipher_suite_provider,
            &leaf_node.signing_identity.signature_key,
            &context.signing_context(),
        )?;

        // If required capabilities are specified, verify the leaf node meets the requirements
        #[cfg(feature = "all_extensions")]
        self.validate_required_capabilities(leaf_node)?;

        // If there are extensions, make sure they are referenced in the capabilities field
        for one_ext in &*leaf_node.extensions {
            if !leaf_node
                .capabilities
                .extensions
                .contains(&one_ext.extension_type())
            {
                return Err(MlsError::ExtensionNotInCapabilities(
                    one_ext.extension_type(),
                ));
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec;
    use assert_matches::assert_matches;
    use aws_mls_core::crypto::CipherSuite;
    #[cfg(feature = "all_extensions")]
    use aws_mls_core::group::ProposalType;
    use core::time::Duration;

    use super::*;

    use crate::client::test_utils::TEST_CIPHER_SUITE;
    use crate::crypto::test_utils::test_cipher_suite_provider;
    use crate::crypto::test_utils::TestCryptoProvider;
    use crate::crypto::SignatureSecretKey;
    use crate::extension::test_utils::TestExtension;
    use crate::group::test_utils::random_bytes;
    use crate::identity::basic::BasicCredential;
    use crate::identity::basic::BasicIdentityProvider;
    use crate::identity::test_utils::get_test_signing_identity;
    use crate::tree_kem::leaf_node::test_utils::*;
    use crate::tree_kem::leaf_node_validator::test_utils::FailureIdentityProvider;
    use crate::tree_kem::parent_hash::ParentHash;
    use crate::tree_kem::Capabilities;
    use crate::ExtensionList;

    #[cfg(target_arch = "wasm32")]
    use wasm_bindgen_test::wasm_bindgen_test as test;

    #[maybe_async::maybe_async]
    async fn get_test_add_node() -> (LeafNode, SignatureSecretKey) {
        let (signing_identity, secret) =
            get_test_signing_identity(TEST_CIPHER_SUITE, b"foo".to_vec());

        let (leaf_node, _) =
            get_test_node(TEST_CIPHER_SUITE, signing_identity, &secret, None, None).await;

        (leaf_node, secret)
    }

    #[maybe_async::test(sync, async(not(sync), futures_test::test))]
    async fn test_basic_add_validation() {
        let cipher_suite_provider = test_cipher_suite_provider(TEST_CIPHER_SUITE);

        let (leaf_node, _) = get_test_add_node().await;

        let test_validator = LeafNodeValidator::new(
            &cipher_suite_provider,
            #[cfg(feature = "all_extensions")]
            None,
            &BasicIdentityProvider,
            None,
        );

        let res = test_validator
            .check_if_valid(&leaf_node, ValidationContext::Add(None))
            .await;

        assert_matches!(res, Ok(_));
    }

    #[maybe_async::test(sync, async(not(sync), futures_test::test))]
    async fn test_failed_validation() {
        let cipher_suite_provider = test_cipher_suite_provider(TEST_CIPHER_SUITE);
        let (leaf_node, _) = get_test_add_node().await;

        let fail_test_validator = LeafNodeValidator::new(
            &cipher_suite_provider,
            #[cfg(feature = "all_extensions")]
            None,
            &FailureIdentityProvider,
            None,
        );

        let res = fail_test_validator
            .check_if_valid(&leaf_node, ValidationContext::Add(None))
            .await;

        assert_matches!(res, Err(MlsError::IdentityProviderError(_)));
    }

    #[maybe_async::test(sync, async(not(sync), futures_test::test))]
    async fn test_basic_update_validation() {
        let cipher_suite_provider = test_cipher_suite_provider(TEST_CIPHER_SUITE);
        let group_id = b"group_id";

        let (mut leaf_node, secret) = get_test_add_node().await;

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

        let test_validator = LeafNodeValidator::new(
            &cipher_suite_provider,
            #[cfg(feature = "all_extensions")]
            None,
            &BasicIdentityProvider,
            None,
        );

        let res = test_validator
            .check_if_valid(&leaf_node, ValidationContext::Update((group_id, 0, None)))
            .await;

        assert_matches!(res, Ok(_));
    }

    #[maybe_async::test(sync, async(not(sync), futures_test::test))]
    async fn test_basic_commit_validation() {
        let cipher_suite_provider = test_cipher_suite_provider(TEST_CIPHER_SUITE);
        let group_id = b"group_id";

        let (mut leaf_node, secret) = get_test_add_node().await;

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

        let test_validator = LeafNodeValidator::new(
            &cipher_suite_provider,
            #[cfg(feature = "all_extensions")]
            None,
            &BasicIdentityProvider,
            None,
        );

        let res = test_validator
            .check_if_valid(&leaf_node, ValidationContext::Commit((group_id, 0, None)))
            .await;

        assert_matches!(res, Ok(_));
    }

    #[maybe_async::test(sync, async(not(sync), futures_test::test))]
    async fn test_incorrect_context() {
        let cipher_suite_provider = test_cipher_suite_provider(TEST_CIPHER_SUITE);

        let test_validator = LeafNodeValidator::new(
            &cipher_suite_provider,
            #[cfg(feature = "all_extensions")]
            None,
            &BasicIdentityProvider,
            None,
        );

        let (mut leaf_node, secret) = get_test_add_node().await;

        let res = test_validator
            .check_if_valid(&leaf_node, ValidationContext::Update((b"foo", 0, None)))
            .await;

        assert_matches!(res, Err(MlsError::InvalidLeafNodeSource));

        let res = test_validator
            .check_if_valid(&leaf_node, ValidationContext::Commit((b"foo", 0, None)))
            .await;

        assert_matches!(res, Err(MlsError::InvalidLeafNodeSource));

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

        let res = test_validator
            .check_if_valid(&leaf_node, ValidationContext::Add(None))
            .await;

        assert_matches!(res, Err(MlsError::InvalidLeafNodeSource));

        let res = test_validator
            .check_if_valid(&leaf_node, ValidationContext::Commit((b"foo", 0, None)))
            .await;

        assert_matches!(res, Err(MlsError::InvalidLeafNodeSource));

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

        let res = test_validator
            .check_if_valid(&leaf_node, ValidationContext::Add(None))
            .await;

        assert_matches!(res, Err(MlsError::InvalidLeafNodeSource));

        let res = test_validator
            .check_if_valid(&leaf_node, ValidationContext::Update((b"foo", 0, None)))
            .await;

        assert_matches!(res, Err(MlsError::InvalidLeafNodeSource));
    }

    #[maybe_async::test(sync, async(not(sync), futures_test::test))]
    async fn test_bad_signature() {
        for cipher_suite in TestCryptoProvider::all_supported_cipher_suites() {
            let cipher_suite_provider = test_cipher_suite_provider(cipher_suite);

            let (signing_identity, secret) =
                get_test_signing_identity(cipher_suite, b"foo".to_vec());

            let (mut leaf_node, _) =
                get_test_node(cipher_suite, signing_identity, &secret, None, None).await;

            leaf_node.signature = random_bytes(leaf_node.signature.len());

            let test_validator = LeafNodeValidator::new(
                &cipher_suite_provider,
                #[cfg(feature = "all_extensions")]
                None,
                &BasicIdentityProvider,
                None,
            );

            let res = test_validator
                .check_if_valid(&leaf_node, ValidationContext::Add(None))
                .await;

            assert_matches!(res, Err(MlsError::InvalidSignature));
        }
    }

    #[maybe_async::test(sync, async(not(sync), futures_test::test))]
    async fn test_capabilities_mismatch() {
        let (signing_identity, secret) =
            get_test_signing_identity(TEST_CIPHER_SUITE, b"foo".to_vec());

        let mut extensions = ExtensionList::new();

        extensions.set_from(TestExtension::from(0)).unwrap();

        let capabilities = Capabilities {
            credentials: vec![BasicCredential::credential_type()],
            ..Default::default()
        };

        let (leaf_node, _) = get_test_node(
            TEST_CIPHER_SUITE,
            signing_identity,
            &secret,
            Some(capabilities),
            Some(extensions),
        )
        .await;

        let cipher_suite_provider = test_cipher_suite_provider(TEST_CIPHER_SUITE);

        let test_validator = LeafNodeValidator::new(
            &cipher_suite_provider,
            #[cfg(feature = "all_extensions")]
            None,
            &BasicIdentityProvider,
            None,
        );

        let res = test_validator
            .check_if_valid(&leaf_node, ValidationContext::Add(None))
            .await;

        assert_matches!(res,
            Err(MlsError::ExtensionNotInCapabilities(ext)) if ext == 42.into());
    }

    #[maybe_async::test(sync, async(not(sync), futures_test::test))]
    async fn test_cipher_suite_mismatch() {
        let cipher_suite_provider = test_cipher_suite_provider(CipherSuite::P256_AES128);

        let (leaf_node, _) = get_test_add_node().await;

        let test_validator = LeafNodeValidator::new(
            &cipher_suite_provider,
            #[cfg(feature = "all_extensions")]
            None,
            &BasicIdentityProvider,
            None,
        );

        let res = test_validator
            .check_if_valid(&leaf_node, ValidationContext::Add(None))
            .await;

        assert_matches!(res, Err(MlsError::InvalidSignature));
    }

    #[cfg(feature = "all_extensions")]
    #[maybe_async::test(sync, async(not(sync), futures_test::test))]
    async fn test_required_extension() {
        let required_capabilities = RequiredCapabilitiesExt {
            extensions: vec![43.into()],
            ..Default::default()
        };

        let (leaf_node, _) = get_test_add_node().await;

        let cipher_suite_provider = test_cipher_suite_provider(TEST_CIPHER_SUITE);

        let test_validator = LeafNodeValidator::new(
            &cipher_suite_provider,
            Some(&required_capabilities),
            &BasicIdentityProvider,
            None,
        );

        let res = test_validator
            .check_if_valid(&leaf_node, ValidationContext::Add(None))
            .await;

        assert_matches!(
            res,
            Err(MlsError::RequiredExtensionNotFound(v)) if v == 43.into()
        );
    }

    #[cfg(feature = "all_extensions")]
    #[maybe_async::test(sync, async(not(sync), futures_test::test))]
    async fn test_required_proposal() {
        let required_capabilities = RequiredCapabilitiesExt {
            proposals: vec![42.into()],
            ..Default::default()
        };

        let cipher_suite_provider = test_cipher_suite_provider(TEST_CIPHER_SUITE);

        let (leaf_node, _) = get_test_add_node().await;

        let test_validator = LeafNodeValidator::new(
            &cipher_suite_provider,
            Some(&required_capabilities),
            &BasicIdentityProvider,
            None,
        );

        let res = test_validator
            .check_if_valid(&leaf_node, ValidationContext::Add(None))
            .await;

        assert_matches!(
            res,
            Err(MlsError::RequiredProposalNotFound(p)) if p == ProposalType::new(42)
        );
    }

    #[cfg(feature = "all_extensions")]
    #[maybe_async::test(sync, async(not(sync), futures_test::test))]
    async fn test_required_credential() {
        let required_capabilities = RequiredCapabilitiesExt {
            credentials: vec![0.into()],
            ..Default::default()
        };

        let (leaf_node, _) = get_test_add_node().await;

        let cipher_suite_provider = test_cipher_suite_provider(TEST_CIPHER_SUITE);

        let test_validator = LeafNodeValidator::new(
            &cipher_suite_provider,
            Some(&required_capabilities),
            &BasicIdentityProvider,
            None,
        );

        let res = test_validator
            .check_if_valid(&leaf_node, ValidationContext::Add(None))
            .await;

        assert_matches!(res,
            Err(MlsError::RequiredCredentialNotFound(ext)) if ext == 0.into()
        );
    }

    #[cfg(feature = "std")]
    #[maybe_async::test(sync, async(not(sync), futures_test::test))]
    async fn test_add_lifetime() {
        let (leaf_node, _) = get_test_add_node().await;

        let cipher_suite_provider = test_cipher_suite_provider(TEST_CIPHER_SUITE);

        let test_validator = LeafNodeValidator::new(
            &cipher_suite_provider,
            #[cfg(feature = "all_extensions")]
            None,
            &BasicIdentityProvider,
            None,
        );

        let good_lifetime = MlsTime::now();

        let over_one_year = good_lifetime.seconds_since_epoch().unwrap() + (86400 * 366);

        let bad_lifetime =
            MlsTime::from_duration_since_epoch(Duration::from_secs(over_one_year)).unwrap();

        let res = test_validator
            .check_if_valid(&leaf_node, ValidationContext::Add(Some(good_lifetime)))
            .await;

        assert_matches!(res, Ok(()));

        let res = test_validator
            .check_if_valid(&leaf_node, ValidationContext::Add(Some(bad_lifetime)))
            .await;

        assert_matches!(res, Err(MlsError::InvalidLifetime));
    }
}

#[cfg(test)]
pub(crate) mod test_utils {
    use alloc::vec;
    use alloc::{boxed::Box, vec::Vec};
    use aws_mls_codec::MlsEncode;
    use aws_mls_core::{
        error::IntoAnyError,
        extension::ExtensionList,
        group::RosterUpdate,
        identity::{BasicCredential, IdentityProvider, IdentityWarning},
    };

    use crate::{identity::SigningIdentity, time::MlsTime};

    #[derive(Clone, Debug, Default)]
    pub struct FailureIdentityProvider;

    #[cfg(feature = "external_proposal")]
    impl FailureIdentityProvider {
        pub fn new() -> Self {
            Self::default()
        }
    }

    #[derive(Debug)]
    #[cfg_attr(feature = "std", derive(thiserror::Error))]
    #[cfg_attr(feature = "std", error("test error"))]
    pub struct TestFailureError;

    impl IntoAnyError for TestFailureError {
        #[cfg(feature = "std")]
        fn into_dyn_error(self) -> Result<Box<dyn std::error::Error + Send + Sync>, Self> {
            Ok(self.into())
        }
    }

    #[maybe_async::maybe_async]
    impl IdentityProvider for FailureIdentityProvider {
        type Error = TestFailureError;

        async fn validate_member(
            &self,
            _signing_identity: &SigningIdentity,
            _timestamp: Option<MlsTime>,
            _extensions: Option<&ExtensionList>,
        ) -> Result<(), Self::Error> {
            Err(TestFailureError)
        }

        #[cfg(feature = "external_proposal")]
        async fn validate_external_sender(
            &self,
            _signing_identity: &SigningIdentity,
            _timestamp: Option<MlsTime>,
            _extensions: Option<&ExtensionList>,
        ) -> Result<(), Self::Error> {
            Err(TestFailureError)
        }

        async fn identity(&self, signing_id: &SigningIdentity) -> Result<Vec<u8>, Self::Error> {
            Ok(signing_id.credential.mls_encode_to_vec().unwrap())
        }

        async fn valid_successor(
            &self,
            _predecessor: &SigningIdentity,
            _successor: &SigningIdentity,
        ) -> Result<bool, Self::Error> {
            Err(TestFailureError)
        }

        fn supported_types(&self) -> Vec<crate::identity::CredentialType> {
            vec![BasicCredential::credential_type()]
        }

        async fn identity_warnings(
            &self,
            _update: &RosterUpdate,
        ) -> Result<Vec<IdentityWarning>, Self::Error> {
            Ok(vec![])
        }
    }
}
