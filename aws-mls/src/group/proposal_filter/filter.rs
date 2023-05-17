use crate::group::{proposal_filter::ProposalBundle, Sender};

#[cfg(feature = "custom_proposal")]
use crate::group::proposal::{CustomProposal, Proposal};

#[cfg(feature = "custom_proposal")]
use alloc::{vec, vec::Vec};

use alloc::boxed::Box;
use aws_mls_core::{error::IntoAnyError, extension::ExtensionList, group::Member};
use core::convert::Infallible;

#[cfg(feature = "custom_proposal")]
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
#[maybe_async::maybe_async]
pub trait ProposalRules: Send + Sync {
    type Error: IntoAnyError;

    /// Treat a collection of custom proposals as a set of standard proposals.
    ///
    /// The proposals returned will not be sent over the wire. They will be considered as part of
    /// validating the resulting commit follows standard MLS rules, and will be applied to the
    /// tree.
    #[cfg(feature = "custom_proposal")]
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
        #[maybe_async::maybe_async]
        impl<T: ProposalRules + ?Sized> ProposalRules for $implementer {
            type Error = T::Error;

            #[cfg(feature = "custom_proposal")]
            #[maybe_async::maybe_async]
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

            #[maybe_async::maybe_async]
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

            #[maybe_async::maybe_async]
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

#[maybe_async::maybe_async]
impl ProposalRules for PassThroughProposalRules {
    type Error = Infallible;

    #[cfg(feature = "custom_proposal")]
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
