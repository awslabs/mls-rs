//TODO: REMOVE
#![allow(dead_code)]

use std::ops::{Deref, DerefMut};

use super::leaf_node::{LeafNode, LeafNodeSource};
use crate::{
    cipher_suite::CipherSuite,
    credential::CredentialError,
    extension::{ExtensionError, ExtensionType, LifetimeExt, RequiredCapabilitiesExt},
    group::proposal::ProposalType,
    time::MlsTime,
};
use ferriscrypt::asym::ec_key::Curve;
use thiserror::Error;
use tls_codec_derive::{TlsDeserialize, TlsSerialize, TlsSize};

#[derive(Clone, Debug, PartialEq, TlsSize, TlsSerialize, TlsDeserialize)]
pub struct ValidatedLeafNode(LeafNode);

impl From<ValidatedLeafNode> for LeafNode {
    fn from(ln: ValidatedLeafNode) -> Self {
        ln.0
    }
}

impl Deref for ValidatedLeafNode {
    type Target = LeafNode;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for ValidatedLeafNode {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

pub enum ValidationContext<'a> {
    Add(Option<MlsTime>),
    Update(&'a [u8]),
    Commit(&'a [u8]),
}

impl<'a> ValidationContext<'a> {
    fn group_id(&self) -> Option<&[u8]> {
        match self {
            ValidationContext::Add(_) => None,
            ValidationContext::Update(group_id) => Some(group_id),
            ValidationContext::Commit(group_id) => Some(group_id),
        }
    }
}

#[derive(Debug, Error)]
pub enum LeafNodeValidationError {
    #[error(transparent)]
    ExtensionError(#[from] ExtensionError),
    #[error(transparent)]
    SerializationError(#[from] tls_codec::Error),
    #[error(transparent)]
    CredentialError(#[from] CredentialError),
    #[error("credential not supported for cipher suite")]
    InvalidCredentialForCipherSuite,
    #[error("invalid leaf_node_source")]
    InvalidLeafNodeSource,
    #[error("invalid signature")]
    InvalidSignature,
    #[error("{0:?} is not within lifetime {1:?}")]
    InvalidLifetime(MlsTime, LifetimeExt),
    #[error("required extension not found")]
    RequiredExtensionNotFound(ExtensionType),
    #[error("required proposal not found")]
    RequiredProposalNotFound(ProposalType),
    #[error("capabilities must describe extensions used")]
    ExtensionNotInCapabilities(ExtensionType),
}

#[derive(Clone, Debug)]
pub struct LeafNodeValidator<'a> {
    cipher_suite: CipherSuite,
    // TODO: Credential Authentication service
    required_capabilities: Option<&'a RequiredCapabilitiesExt>,
}

impl<'a> LeafNodeValidator<'a> {
    pub fn new(
        cipher_suite: CipherSuite,
        required_capabilities: Option<&'a RequiredCapabilitiesExt>,
    ) -> Self {
        Self {
            cipher_suite,
            required_capabilities,
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
                if let LeafNodeSource::Add(lifetime) = &leaf_node.leaf_node_source {
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

    pub fn validate(
        &self,
        leaf_node: LeafNode,
        context: ValidationContext,
    ) -> Result<ValidatedLeafNode, LeafNodeValidationError> {
        // TODO: Verify the credential with the credential validation service

        // Check that we are validating within the proper context
        self.check_context(&leaf_node, &context)?;

        // Verify that the credential provided matches the cipher suite that is in use
        if leaf_node.credential.public_key()?.curve()
            != Curve::from(self.cipher_suite.signature_scheme())
        {
            return Err(LeafNodeValidationError::InvalidCredentialForCipherSuite);
        }

        // Verify that the credential signed the leaf node
        if !leaf_node
            .credential
            .verify(
                &leaf_node.signature,
                &leaf_node.to_signable_bytes(context.group_id())?,
            )
            .map_err(|_| LeafNodeValidationError::InvalidSignature)?
        {
            return Err(LeafNodeValidationError::InvalidSignature);
        }

        // If required capabilities are specified, leaf node meets the requirements
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
        }

        // If there are extensions, make sure they are referenced in the capabilities field
        for one_ext in leaf_node.extensions.deref() {
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

        Ok(ValidatedLeafNode(leaf_node))
    }
}

#[cfg(test)]
mod test {
    use std::time::Duration;

    use assert_matches::assert_matches;
    use ferriscrypt::asym::ec_key::SecretKey;
    use ferriscrypt::rand::SecureRng;

    use super::*;
    use crate::client::test_util::get_test_credential;
    use crate::extension::{CapabilitiesExt, ExtensionList, ExternalKeyIdExt, MlsExtension};
    use crate::tree_kem::leaf_node::test_util::*;
    use crate::tree_kem::parent_hash::ParentHash;

    const TEST_CIPHER_SUITE: CipherSuite = CipherSuite::Curve25519Aes128V1;

    fn get_test_add_node() -> (LeafNode, SecretKey) {
        let (credential, secret) = get_test_credential(TEST_CIPHER_SUITE, b"foo".to_vec());
        let (leaf_node, _) = get_test_node(credential, &secret, None, None);

        (leaf_node, secret)
    }

    #[test]
    fn test_basic_add_validation() {
        let (leaf_node, _) = get_test_add_node();
        let test_validator = LeafNodeValidator::new(TEST_CIPHER_SUITE, None);

        let validated = test_validator
            .validate(leaf_node.clone(), ValidationContext::Add(None))
            .unwrap();

        assert_eq!(validated.0, leaf_node);
    }

    #[test]
    fn test_basic_update_validation() {
        let group_id = b"group_id";

        let (mut leaf_node, secret) = get_test_add_node();
        leaf_node.update(group_id, None, None, &secret).unwrap();

        let test_validator = LeafNodeValidator::new(TEST_CIPHER_SUITE, None);
        let validated = test_validator
            .validate(leaf_node.clone(), ValidationContext::Update(group_id))
            .unwrap();

        assert_eq!(validated.0, leaf_node);
    }

    #[test]
    fn test_basic_commit_validation() {
        let group_id = b"group_id";

        let (mut leaf_node, secret) = get_test_add_node();

        leaf_node
            .commit(group_id, None, None, &secret, |_| {
                Ok(ParentHash::from(vec![0u8; 32]))
            })
            .unwrap();

        let test_validator = LeafNodeValidator::new(TEST_CIPHER_SUITE, None);

        let validated = test_validator
            .validate(leaf_node.clone(), ValidationContext::Commit(group_id))
            .unwrap();

        assert_eq!(validated.0, leaf_node);
    }

    #[test]
    fn test_incorrect_context() {
        let test_validator = LeafNodeValidator::new(TEST_CIPHER_SUITE, None);
        let (mut leaf_node, secret) = get_test_add_node();

        assert_matches!(
            test_validator.validate(leaf_node.clone(), ValidationContext::Update(b"foo")),
            Err(LeafNodeValidationError::InvalidLeafNodeSource)
        );

        assert_matches!(
            test_validator.validate(leaf_node.clone(), ValidationContext::Commit(b"foo")),
            Err(LeafNodeValidationError::InvalidLeafNodeSource)
        );

        leaf_node.update(b"foo", None, None, &secret).unwrap();

        assert_matches!(
            test_validator.validate(leaf_node.clone(), ValidationContext::Add(None)),
            Err(LeafNodeValidationError::InvalidLeafNodeSource)
        );

        assert_matches!(
            test_validator.validate(leaf_node.clone(), ValidationContext::Commit(b"foo")),
            Err(LeafNodeValidationError::InvalidLeafNodeSource)
        );

        leaf_node
            .commit(b"foo", None, None, &secret, |_| {
                Ok(ParentHash::from(vec![0u8; 32]))
            })
            .unwrap();

        assert_matches!(
            test_validator.validate(leaf_node.clone(), ValidationContext::Add(None)),
            Err(LeafNodeValidationError::InvalidLeafNodeSource)
        );

        assert_matches!(
            test_validator.validate(leaf_node.clone(), ValidationContext::Update(b"foo")),
            Err(LeafNodeValidationError::InvalidLeafNodeSource)
        );
    }

    #[test]
    fn test_bad_signature() {
        for cipher_suite in CipherSuite::all() {
            let (credential, secret) = get_test_credential(cipher_suite, b"foo".to_vec());
            let (mut leaf_node, _) = get_test_node(credential, &secret, None, None);

            leaf_node.signature = SecureRng::gen(leaf_node.signature.len()).unwrap();

            let test_validator = LeafNodeValidator::new(cipher_suite, None);

            assert_matches!(
                test_validator.validate(leaf_node, ValidationContext::Add(None)),
                Err(LeafNodeValidationError::InvalidSignature)
            );
        }
    }

    #[test]
    fn test_capabilities_extension_mismatch() {
        let (credential, secret) = get_test_credential(TEST_CIPHER_SUITE, b"foo".to_vec());

        let mut extensions = ExtensionList::new();

        extensions
            .set_extension(ExternalKeyIdExt {
                identifier: b"foo".to_vec(),
            })
            .unwrap();

        let capabilities = CapabilitiesExt::default();

        let (leaf_node, _) =
            get_test_node(credential, &secret, Some(capabilities), Some(extensions));

        let test_validator = LeafNodeValidator::new(TEST_CIPHER_SUITE, None);

        assert_matches!(test_validator.validate(leaf_node, ValidationContext::Add(None)),
            Err(LeafNodeValidationError::ExtensionNotInCapabilities(ext)) if ext == ExternalKeyIdExt::IDENTIFIER);
    }

    #[test]
    fn test_cipher_suite_mismatch() {
        let (leaf_node, _) = get_test_add_node();

        let test_validator = LeafNodeValidator::new(CipherSuite::P256Aes128V1, None);

        assert_matches!(
            test_validator.validate(leaf_node, ValidationContext::Add(None)),
            Err(LeafNodeValidationError::InvalidCredentialForCipherSuite)
        );
    }

    #[test]
    fn test_required_extension() {
        let required_capabilities = RequiredCapabilitiesExt {
            extensions: vec![42u16],
            ..Default::default()
        };

        let (leaf_node, _) = get_test_add_node();

        let test_validator =
            LeafNodeValidator::new(TEST_CIPHER_SUITE, Some(&required_capabilities));

        assert_matches!(test_validator.validate(leaf_node, ValidationContext::Add(None)),
            Err(LeafNodeValidationError::RequiredExtensionNotFound(ext)) if ext == 42u16
        );
    }

    #[test]
    fn test_required_proposal() {
        let required_capabilities = RequiredCapabilitiesExt {
            proposals: vec![42u16],
            ..Default::default()
        };

        let (leaf_node, _) = get_test_add_node();

        let test_validator =
            LeafNodeValidator::new(TEST_CIPHER_SUITE, Some(&required_capabilities));

        assert_matches!(test_validator.validate(leaf_node, ValidationContext::Add(None)),
            Err(LeafNodeValidationError::RequiredProposalNotFound(ext)) if ext == 42u16
        );
    }

    #[test]
    fn test_add_lifetime() {
        let (leaf_node, _) = get_test_add_node();
        let test_validator = LeafNodeValidator::new(TEST_CIPHER_SUITE, None);

        let good_lifetime = MlsTime::now();

        let over_one_year = good_lifetime.seconds_since_epoch().unwrap() + (86400 * 366);

        let bad_lifetime =
            MlsTime::from_duration_since_epoch(Duration::from_secs(over_one_year)).unwrap();

        assert!(test_validator
            .validate(
                leaf_node.clone(),
                ValidationContext::Add(Some(good_lifetime))
            )
            .is_ok());

        assert_matches!(
            test_validator.validate(leaf_node, ValidationContext::Add(Some(bad_lifetime))),
            Err(LeafNodeValidationError::InvalidLifetime(_, _))
        );
    }
}
