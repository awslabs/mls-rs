// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// Copyright by contributors to this project.
// SPDX-License-Identifier: (Apache-2.0 OR MIT)

use crate::group::{proposal_filter::ProposalBundle, Roster};

use alloc::boxed::Box;
use aws_mls_core::{
    error::IntoAnyError, extension::ExtensionList, group::Member, identity::SigningIdentity,
};
use core::convert::Infallible;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum CommitDirection {
    Send,
    Receive,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CommitSource {
    ExistingMember(Member),
    NewMember(SigningIdentity),
}

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
#[cfg_attr(not(mls_build_async), maybe_async::must_be_sync)]
#[cfg_attr(mls_build_async, maybe_async::must_be_async)]
pub trait ProposalRules: Send + Sync {
    type Error: IntoAnyError;

    /// This is called when preparing or receiving a commit. By-reference proposals causing the commit to be
    /// invalid should be filtered out. If a by-value proposal causes the commit to be invalid,
    /// an error should be returned.
    async fn filter(
        &self,
        direction: CommitDirection,
        source: CommitSource,
        current_roster: &Roster,
        extension_list: &ExtensionList,
        proposals: ProposalBundle,
    ) -> Result<ProposalBundle, Self::Error>;
}

macro_rules! delegate_proposal_rules {
    ($implementer:ty) => {
        #[cfg_attr(not(mls_build_async), maybe_async::must_be_sync)]
        #[cfg_attr(mls_build_async, maybe_async::must_be_async)]
        impl<T: ProposalRules + ?Sized> ProposalRules for $implementer {
            type Error = T::Error;

            #[cfg_attr(not(mls_build_async), maybe_async::must_be_sync)]
            async fn filter(
                &self,
                direction: CommitDirection,
                source: CommitSource,
                current_roster: &Roster,
                extension_list: &ExtensionList,
                proposals: ProposalBundle,
            ) -> Result<ProposalBundle, Self::Error> {
                (**self)
                    .filter(direction, source, current_roster, extension_list, proposals)
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

#[cfg_attr(not(mls_build_async), maybe_async::must_be_sync)]
#[cfg_attr(mls_build_async, maybe_async::must_be_async)]
impl ProposalRules for PassThroughProposalRules {
    type Error = Infallible;

    async fn filter(
        &self,
        _direction: CommitDirection,
        _source: CommitSource,
        _current_roster: &Roster,
        _extension_list: &ExtensionList,
        proposals: ProposalBundle,
    ) -> Result<ProposalBundle, Self::Error> {
        Ok(proposals)
    }
}
