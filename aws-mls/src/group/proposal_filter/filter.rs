use crate::group::{
    proposal::{CustomProposal, Proposal},
    proposal_filter::ProposalBundle,
    Sender,
};
use alloc::vec;
use alloc::{boxed::Box, vec::Vec};
use async_trait::async_trait;
use aws_mls_core::{extension::ExtensionList, group::Member};
use core::convert::Infallible;

use super::ProposalInfo;

#[cfg(feature = "std")]
use std::error::Error;

#[cfg(not(feature = "std"))]
use core::error::Error;

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
    type Error: Error + Send + Sync + 'static;

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
