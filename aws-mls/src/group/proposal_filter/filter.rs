use crate::{
    extension::ExtensionType,
    group::{
        proposal::{CustomProposal, Proposal},
        proposal_filter::ProposalBundle,
        ProposalType, Sender,
    },
    key_package::KeyPackageValidationError,
    protocol_version::ProtocolVersion,
    tree_kem::{
        leaf_node::LeafNodeError, leaf_node_validator::LeafNodeValidationError, RatchetTreeError,
    },
};
use async_trait::async_trait;
use aws_mls_core::{
    extension::{ExtensionError, ExtensionList},
    group::Member,
};
use std::convert::Infallible;
use thiserror::Error;

use super::ProposalInfo;

/// A user controlled proposal rules that can pre-process a set of proposals
/// during commit processing.
///
/// Both proposals received during the current epoch and at the time of commit
/// will be presented for validation and filtering. Filter and validate will
/// present a raw list of proposals. Standard MLS rules are applied internally
/// on the result of these rules.
///
/// Each member of a group MUST apply the same proposal rules in order to
/// maintain a working group.
#[async_trait]
pub trait ProposalRules: Send + Sync {
    type Error: std::error::Error + Send + Sync + 'static;

    /// Treat a collection of custom proposals as a set of standard proposals.
    ///
    /// The proposals returned will not be sent over the wire. They will be considered as part of
    /// validating the resulting commit follows standard MLS rules, and will be applied to the
    /// tree.
    async fn expand_custom_proposals(
        &self,
        current_roster: &[Member],
        extension_list: &ExtensionList,
        proposals: &[ProposalInfo<CustomProposal>],
    ) -> Result<Vec<ProposalInfo<Proposal>>, Self::Error>;

    /// This is called to validate a received commit. It should report any error making the commit
    /// invalid.
    async fn validate(
        &self,
        commit_sender: Sender,
        current_roster: &[Member],
        extension_list: &ExtensionList,
        proposals: &ProposalBundle,
    ) -> Result<(), Self::Error>;

    /// This is called when preparing a commit. By-reference proposals causing the commit to be
    /// invalid should be filtered out. If a by-value proposal causes the commit to be invalid,
    /// an error should be returned.
    async fn filter(
        &self,
        commit_sender: Sender,
        current_roster: &[Member],
        extension_list: &ExtensionList,
        proposals: ProposalBundle,
    ) -> Result<ProposalBundle, Self::Error>;
}

macro_rules! delegate_proposal_rules {
    ($implementer:ty) => {
        #[async_trait]
        impl<T: ProposalRules + ?Sized> ProposalRules for $implementer {
            type Error = T::Error;

            async fn expand_custom_proposals(
                &self,
                current_roster: &[Member],
                extension_list: &ExtensionList,
                proposals: &[ProposalInfo<CustomProposal>],
            ) -> Result<Vec<ProposalInfo<Proposal>>, Self::Error> {
                (**self)
                    .expand_custom_proposals(current_roster, extension_list, proposals)
                    .await
            }

            async fn validate(
                &self,
                commit_sender: Sender,
                current_roster: &[Member],
                extension_list: &ExtensionList,
                proposals: &ProposalBundle,
            ) -> Result<(), Self::Error> {
                (**self)
                    .validate(commit_sender, current_roster, extension_list, proposals)
                    .await
            }

            async fn filter(
                &self,
                commit_sender: Sender,
                current_roster: &[Member],
                extension_list: &ExtensionList,
                proposals: ProposalBundle,
            ) -> Result<ProposalBundle, Self::Error> {
                (**self)
                    .filter(commit_sender, current_roster, extension_list, proposals)
                    .await
            }
        }
    };
}

delegate_proposal_rules!(Box<T>);
delegate_proposal_rules!(&T);

#[derive(Clone, Debug, Default)]
/// Default allow-all proposal filter.
pub struct PassThroughProposalRules;

impl PassThroughProposalRules {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl ProposalRules for PassThroughProposalRules {
    type Error = Infallible;

    async fn expand_custom_proposals(
        &self,
        _current_roster: &[Member],
        _extension_list: &ExtensionList,
        _proposals: &[ProposalInfo<CustomProposal>],
    ) -> Result<Vec<ProposalInfo<Proposal>>, Self::Error> {
        Ok(vec![])
    }

    async fn validate(
        &self,
        _commit_sender: Sender,
        _current_roster: &[Member],
        _extension_list: &ExtensionList,
        _proposals: &ProposalBundle,
    ) -> Result<(), Self::Error> {
        Ok(())
    }

    async fn filter(
        &self,
        _commit_sender: Sender,
        _current_roster: &[Member],
        _extension_list: &ExtensionList,
        proposals: ProposalBundle,
    ) -> Result<ProposalBundle, Self::Error> {
        Ok(proposals)
    }
}

#[derive(Debug, Error)]
pub enum ProposalRulesError {
    #[error(transparent)]
    KeyPackageValidationError(#[from] KeyPackageValidationError),
    #[error(transparent)]
    LeafNodeValidationError(#[from] LeafNodeValidationError),
    #[error(transparent)]
    RatchetTreeError(#[from] RatchetTreeError),
    #[error(transparent)]
    ExtensionError(#[from] ExtensionError),
    #[error(transparent)]
    LeafNodeError(#[from] LeafNodeError),
    #[error("Commiter must not include any update proposals generated by the commiter")]
    InvalidCommitSelfUpdate,
    #[error("A PreSharedKey proposal must have a PSK of type External or type Resumption and usage Application")]
    InvalidTypeOrUsageInPreSharedKeyProposal,
    #[error("Expected PSK nonce with length {expected} but found length {found}")]
    InvalidPskNonceLength { expected: usize, found: usize },
    #[error("Protocol version {proposed:?} in ReInit proposal is less than version {original:?} in original group")]
    InvalidProtocolVersionInReInit {
        proposed: ProtocolVersion,
        original: ProtocolVersion,
    },
    #[error("More than one proposal applying to leaf {0:?}")]
    MoreThanOneProposalForLeaf(u32),
    #[error("More than one GroupContextExtensions proposal")]
    MoreThanOneGroupContextExtensionsProposal,
    #[error("Invalid {} proposal of type {proposal_type:?} for sender {sender:?}", by_ref_or_value_str(*.by_ref))]
    InvalidProposalTypeForSender {
        proposal_type: ProposalType,
        sender: Sender,
        by_ref: bool,
    },
    #[error("External commit must have exactly one ExternalInit proposal")]
    ExternalCommitMustHaveExactlyOneExternalInit,
    #[error("External commit must have a new leaf")]
    ExternalCommitMustHaveNewLeaf,
    #[error("External sender cannot commit")]
    ExternalSenderCannotCommit,
    #[error("Missing update path in external commit")]
    MissingUpdatePathInExternalCommit,
    #[error("External commit contains removal of other identity")]
    ExternalCommitRemovesOtherIdentity,
    #[error("External commit contains more than one Remove proposal")]
    ExternalCommitWithMoreThanOneRemove,
    #[error("Duplicate PSK IDs")]
    DuplicatePskIds,
    #[error("Invalid proposal type {0:?} in external commit")]
    InvalidProposalTypeInExternalCommit(ProposalType),
    #[error("Committer can not remove themselves")]
    CommitterSelfRemoval,
    #[error(transparent)]
    UserDefined(Box<dyn std::error::Error + Send + Sync>),
    #[error("Only members can commit proposals by reference")]
    OnlyMembersCanCommitProposalsByRef,
    #[error("Other proposal with ReInit")]
    OtherProposalWithReInit,
    #[error("Removing blank node at index {0:?}")]
    RemovingBlankNode(u32),
    #[error("Unsupported group extension {0:?}")]
    UnsupportedGroupExtension(ExtensionType),
    #[error("Unsupported custom proposal type {0:?}")]
    UnsupportedCustomProposal(ProposalType),
    #[error(transparent)]
    PskIdValidationError(Box<dyn std::error::Error + Send + Sync>),
    #[error(transparent)]
    IdentityProviderError(Box<dyn std::error::Error + Send + Sync>),
    #[error("Invalid index {0:?} for member proposer")]
    InvalidMemberProposer(u32),
    #[error("Invalid external sender index {0}")]
    InvalidExternalSenderIndex(u32),
    #[error("External sender without External Senders extension")]
    ExternalSenderWithoutExternalSendersExtension,
}

impl ProposalRulesError {
    pub fn user_defined<E>(e: E) -> Self
    where
        E: Into<Box<dyn std::error::Error + Send + Sync>>,
    {
        Self::UserDefined(e.into())
    }
}

fn by_ref_or_value_str(by_ref: bool) -> &'static str {
    if by_ref {
        "by reference"
    } else {
        "by value"
    }
}
