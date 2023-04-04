use aws_mls_codec::{MlsDecode, MlsEncode, MlsSize};
use aws_mls_core::{
    crypto::HpkePublicKey,
    extension::{ExtensionList, ExtensionType, MlsCodecExtension},
    group::ProposalType,
    identity::{CredentialType, IdentityProvider, SigningIdentity},
    time::MlsTime,
};
use futures::TryStreamExt;

use crate::tree_kem::node::NodeVec;

/// Application specific identifier.
///
/// A custom application level identifier that can be optionally stored
/// within the `leaf_node_extensions` of a group [Member](crate::group::Member).
#[derive(Clone, Debug, PartialEq, Eq, MlsSize, MlsEncode, MlsDecode)]
pub struct ApplicationIdExt {
    #[mls_codec(with = "aws_mls_codec::byte_vec")]
    pub(crate) identifier: Vec<u8>,
}

impl ApplicationIdExt {
    /// Create a new application level identifier extension.
    pub fn new(identifier: Vec<u8>) -> Self {
        ApplicationIdExt { identifier }
    }

    /// Get the application level identifier presented by this extension.
    pub fn identifier(&self) -> &[u8] {
        &self.identifier
    }
}

impl MlsCodecExtension for ApplicationIdExt {
    fn extension_type() -> ExtensionType {
        ExtensionType::APPLICATION_ID
    }
}

/// Representation of an MLS ratchet tree.
///
/// Used to provide new members
/// a copy of the current group state in-band. This extension is enabled
/// via the `ratchet_tree_extension`
/// [Preferences](crate::client_builder::Preferences).
#[derive(Clone, Debug, PartialEq, MlsSize, MlsEncode, MlsDecode)]
pub struct RatchetTreeExt {
    pub(crate) tree_data: NodeVec,
}

impl MlsCodecExtension for RatchetTreeExt {
    fn extension_type() -> ExtensionType {
        ExtensionType::RATCHET_TREE
    }
}

/// Require members to have certain capabilities.
///
/// Used within a
/// [Group Context Extensions Proposal](crate::group::proposal::Proposal)
/// in order to require that all current and future members of a group MUST
/// support specific extensions, proposals, or credentials.
///
/// # Warning
///
/// Extension, proposal, and credential types defined by the MLS RFC and
/// provided are considered required by default and should NOT be used
/// within this extension.
#[derive(Clone, Debug, PartialEq, Eq, MlsSize, MlsEncode, MlsDecode, Default)]
pub struct RequiredCapabilitiesExt {
    pub extensions: Vec<ExtensionType>,
    pub proposals: Vec<ProposalType>,
    pub credentials: Vec<CredentialType>,
}

impl RequiredCapabilitiesExt {
    /// Create a required capabilities extension.
    pub fn new(
        extensions: Vec<ExtensionType>,
        proposals: Vec<ProposalType>,
        credentials: Vec<CredentialType>,
    ) -> Self {
        Self {
            extensions,
            proposals,
            credentials,
        }
    }

    /// Required custom extension types.
    pub fn extensions(&self) -> &[ExtensionType] {
        &self.extensions
    }

    /// Required custom proposal types.
    pub fn proposals(&self) -> &[ProposalType] {
        &self.proposals
    }

    /// Required custom credential types.
    pub fn credentials(&self) -> &[CredentialType] {
        &self.credentials
    }
}

impl MlsCodecExtension for RequiredCapabilitiesExt {
    fn extension_type() -> ExtensionType {
        ExtensionType::REQUIRED_CAPABILITIES
    }
}

/// External public key used for [External Commits](crate::Client::commit_external).
///
/// This proposal type is optionally provided as part of a
/// [Group Info](crate::group::Group::group_info_message).
#[derive(Clone, Debug, PartialEq, Eq, MlsSize, MlsEncode, MlsDecode)]
pub struct ExternalPubExt {
    #[mls_codec(with = "aws_mls_codec::byte_vec")]
    pub(crate) external_pub: HpkePublicKey,
}

impl ExternalPubExt {
    /// Get the public key to be used for an external commit.
    pub fn external_pub(&self) -> &HpkePublicKey {
        &self.external_pub
    }
}

impl MlsCodecExtension for ExternalPubExt {
    fn extension_type() -> ExtensionType {
        ExtensionType::EXTERNAL_PUB
    }
}

/// Enable proposals by an [ExternalClient](crate::external_client::ExternalClient).
#[derive(Clone, Debug, PartialEq, Eq, MlsSize, MlsEncode, MlsDecode)]
#[non_exhaustive]
pub struct ExternalSendersExt {
    pub(crate) allowed_senders: Vec<SigningIdentity>,
}

impl ExternalSendersExt {
    pub fn new(allowed_senders: Vec<SigningIdentity>) -> Self {
        Self { allowed_senders }
    }

    pub fn allowed_senders(&self) -> &[SigningIdentity] {
        &self.allowed_senders
    }

    pub(crate) async fn verify_all<I: IdentityProvider>(
        &self,
        provider: &I,
        timestamp: Option<MlsTime>,
        group_context_extensions: &ExtensionList,
    ) -> Result<(), I::Error> {
        futures::stream::iter(self.allowed_senders.iter().map(Ok))
            .try_for_each(|id| {
                provider.validate_external_sender(id, timestamp, Some(group_context_extensions))
            })
            .await
    }
}

impl MlsCodecExtension for ExternalSendersExt {
    fn extension_type() -> ExtensionType {
        ExtensionType::EXTERNAL_SENDERS
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        client::test_utils::TEST_CIPHER_SUITE, identity::test_utils::get_test_signing_identity,
    };

    use super::*;

    use aws_mls_core::{extension::MlsExtension, identity::BasicCredential};
    #[cfg(target_arch = "wasm32")]
    use wasm_bindgen_test::wasm_bindgen_test as test;

    #[test]
    fn test_application_id_extension() {
        let test_id = vec![0u8; 32];
        let test_extension = ApplicationIdExt {
            identifier: test_id.clone(),
        };

        let as_extension = test_extension.into_extension().unwrap();

        assert_eq!(as_extension.extension_type(), ExtensionType::APPLICATION_ID);

        let restored = ApplicationIdExt::from_extension(&as_extension).unwrap();
        assert_eq!(restored.identifier, test_id);
    }

    #[test]
    fn test_ratchet_tree() {
        let ext = RatchetTreeExt {
            tree_data: NodeVec::from(vec![None, None]),
        };

        let as_extension = ext.clone().into_extension().unwrap();
        assert_eq!(as_extension.extension_type(), ExtensionType::RATCHET_TREE);

        let restored = RatchetTreeExt::from_extension(&as_extension).unwrap();
        assert_eq!(ext, restored)
    }

    #[test]
    fn test_required_capabilities() {
        let ext = RequiredCapabilitiesExt {
            extensions: vec![0.into(), 1.into()],
            proposals: vec![42.into(), 43.into()],
            credentials: vec![BasicCredential::credential_type()],
        };

        let as_extension = ext.clone().into_extension().unwrap();

        assert_eq!(
            as_extension.extension_type(),
            ExtensionType::REQUIRED_CAPABILITIES
        );

        let restored = RequiredCapabilitiesExt::from_extension(&as_extension).unwrap();
        assert_eq!(ext, restored)
    }

    #[test]
    fn test_external_senders() {
        let ext = ExternalSendersExt::new(vec![
            get_test_signing_identity(TEST_CIPHER_SUITE, vec![1]).0,
        ]);

        let as_extension = ext.clone().into_extension().unwrap();

        assert_eq!(
            as_extension.extension_type(),
            ExtensionType::EXTERNAL_SENDERS
        );

        let restored = ExternalSendersExt::from_extension(&as_extension).unwrap();
        assert_eq!(ext, restored)
    }

    #[test]
    fn test_external_pub() {
        let ext = ExternalPubExt {
            external_pub: vec![0, 1, 2, 3].into(),
        };

        let as_extension = ext.clone().into_extension().unwrap();
        assert_eq!(as_extension.extension_type(), ExtensionType::EXTERNAL_PUB);

        let restored = ExternalPubExt::from_extension(&as_extension).unwrap();
        assert_eq!(ext, restored)
    }
}
