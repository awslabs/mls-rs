// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// Copyright by contributors to this project.
// SPDX-License-Identifier: (Apache-2.0 OR MIT)

use crate::{
    client::MlsError,
    group::{
        proposal::ReInitProposal,
        proposal_filter::{ProposalBundle, ProposalInfo},
        AddProposal, ProposalType, RemoveProposal, Sender, UpdateProposal,
    },
    iter::wrap_iter,
    mls_rules::CommitDirection,
    protocol_version::ProtocolVersion,
    time::MlsTime,
    tree_kem::{
        leaf_node_validator::{LeafNodeValidator, ValidationContext},
        node::LeafIndex,
        TreeKemPublic,
    },
    CipherSuiteProvider, ExtensionList,
};

use super::{
    filtering_common::{filter_out_invalid_psks, ApplyProposalsOutput, ProposalApplier},
    ProposalSource,
};

#[cfg(feature = "by_ref_proposal")]
use crate::extension::ExternalSendersExt;

#[cfg(all(
    feature = "by_ref_proposal",
    feature = "custom_proposal",
    feature = "self_remove_proposal"
))]
use crate::group::SelfRemoveProposal;

use alloc::vec::Vec;
use mls_rs_core::{
    error::IntoAnyError,
    identity::{IdentityProvider, MemberValidationContext},
    psk::PreSharedKeyStorage,
};

#[cfg(any(
    feature = "custom_proposal",
    not(any(mls_build_async, feature = "rayon"))
))]
use itertools::Itertools;

use crate::group::ExternalInit;

#[cfg(feature = "psk")]
use crate::group::proposal::PreSharedKeyProposal;

#[cfg(all(not(mls_build_async), feature = "rayon"))]
use {crate::iter::ParallelIteratorExt, rayon::prelude::*};

#[cfg(mls_build_async)]
use futures::{StreamExt, TryStreamExt};

/// An `UpdateProposal` names no leaf, so the leaf it replaces comes from its sender.
#[derive(Clone, Debug, Default)]
pub(crate) struct ProposalBundleWithUpdateSenders {
    pub(crate) proposals: ProposalBundle,
    /// Index-aligned with `proposals.updates`.
    pub(crate) update_senders: Vec<LeafIndex>,
}

impl<C, P, CSP> ProposalApplier<'_, C, P, CSP>
where
    C: IdentityProvider,
    P: PreSharedKeyStorage,
    CSP: CipherSuiteProvider,
{
    #[cfg_attr(not(mls_build_async), maybe_async::must_be_sync)]
    pub(super) async fn apply_proposals_from_member(
        &self,
        strategy: FilterStrategy,
        commit_sender: LeafIndex,
        proposals: ProposalBundle,
        commit_time: Option<MlsTime>,
    ) -> Result<ApplyProposalsOutput, MlsError> {
        let proposals = filter_out_invalid_proposers(strategy, proposals)?;
        let proposals = filter_out_update_for_committer(strategy, commit_sender, proposals)?;
        let mut proposals = filter_out_removal_of_committer(strategy, commit_sender, proposals)?;

        filter_out_invalid_psks(
            strategy,
            self.cipher_suite_provider,
            &mut proposals,
            self.psk_storage,
        )
        .await?;

        #[cfg(feature = "by_ref_proposal")]
        let proposals = filter_out_invalid_group_extensions(
            strategy,
            proposals,
            self.identity_provider,
            commit_time,
        )
        .await?;

        let proposals = filter_out_extra_group_context_extensions(strategy, proposals)?;

        let proposals =
            filter_out_invalid_reinit(strategy, proposals, self.original_context.protocol_version)?;

        let proposals = filter_out_reinit_if_other_proposals(strategy.is_ignore(), proposals)?;
        let proposals = filter_out_external_init(strategy, proposals)?;

        #[cfg(all(
            feature = "by_ref_proposal",
            feature = "custom_proposal",
            feature = "self_remove_proposal"
        ))]
        let proposals = filter_out_remove_if_self_remove_same_leaf(strategy, proposals)?;

        self.apply_proposal_changes(strategy, proposals, commit_time)
            .await
    }

    #[cfg_attr(not(mls_build_async), maybe_async::must_be_sync)]
    pub(super) async fn apply_proposal_changes(
        &self,
        strategy: FilterStrategy,
        proposals: ProposalBundle,
        commit_time: Option<MlsTime>,
    ) -> Result<ApplyProposalsOutput, MlsError> {
        match proposals.group_context_extensions_proposal().cloned() {
            Some(p) => {
                self.apply_proposals_with_new_capabilities(strategy, proposals, p, commit_time)
                    .await
            }
            None => {
                self.apply_tree_changes(
                    strategy,
                    proposals,
                    &self.original_context.extensions,
                    commit_time,
                )
                .await
            }
        }
    }

    #[cfg_attr(not(mls_build_async), maybe_async::must_be_sync)]
    pub(super) async fn apply_tree_changes(
        &self,
        strategy: FilterStrategy,
        proposals: ProposalBundle,
        new_extensions: &ExtensionList,
        commit_time: Option<MlsTime>,
    ) -> Result<ApplyProposalsOutput, MlsError> {
        let ProposalBundleWithUpdateSenders {
            proposals: mut applied_proposals,
            update_senders,
        } = self
            .validate_new_nodes(strategy, proposals, new_extensions, commit_time)
            .await?;

        let mut new_tree = self.original_tree.clone();

        let added = new_tree
            .batch_edit(
                &mut applied_proposals,
                new_extensions,
                self.identity_provider,
                self.cipher_suite_provider,
                strategy.is_ignore(),
                update_senders,
            )
            .await?;

        let new_context_extensions = applied_proposals
            .group_context_extensions_proposal()
            .map(|gce| gce.proposal.clone());

        Ok(ApplyProposalsOutput {
            applied_proposals,
            new_tree,
            indexes_of_added_kpkgs: added,
            external_init_index: None,
            new_context_extensions,
        })
    }

    #[cfg_attr(not(mls_build_async), maybe_async::must_be_sync)]
    async fn validate_new_nodes(
        &self,
        strategy: FilterStrategy,
        mut proposals: ProposalBundle,
        new_extensions: &ExtensionList,
        commit_time: Option<MlsTime>,
    ) -> Result<ProposalBundleWithUpdateSenders, MlsError> {
        let member_validation_context = MemberValidationContext::ForCommit {
            current_context: self.original_context,
            new_extensions,
        };

        let leaf_node_validator = &LeafNodeValidator::new(
            self.cipher_suite_provider,
            self.identity_provider,
            member_validation_context,
        );

        // `wrap_iter` needs an owned collection
        let proposed_updates = core::mem::take(&mut proposals.updates);
        let mut update_senders = Vec::new();

        let validated: Vec<_> = wrap_iter(proposed_updates)
            .map(|p| async {
                let res = self
                    .validate_update_proposal(leaf_node_validator, &p, new_extensions, commit_time)
                    .await;

                let sender_index = apply_strategy_with_return(strategy, p.is_by_reference(), res)?;

                Ok::<_, MlsError>((sender_index, p))
            })
            .try_collect()
            .await?;

        for (sender_index, proposal) in validated {
            if let Some(sender_index) = sender_index {
                update_senders.push(sender_index);
                proposals.updates.push(proposal);
            }
        }

        let bad_indices: Vec<_> = wrap_iter(proposals.add_proposals())
            .enumerate()
            .filter_map(|(i, p)| async move {
                let res = self
                    .validate_new_node(leaf_node_validator, &p.proposal.key_package, commit_time)
                    .await;

                apply_strategy(strategy, p.is_by_reference(), res)
                    .map(|b| (!b).then_some(i))
                    .transpose()
            })
            .try_collect()
            .await?;

        bad_indices
            .into_iter()
            .rev()
            .for_each(|i| proposals.remove::<AddProposal>(i));

        Ok(ProposalBundleWithUpdateSenders {
            proposals,
            update_senders,
        })
    }

    /// Returns the leaf index the update replaces, taken from the proposal's sender.
    #[cfg_attr(not(mls_build_async), maybe_async::must_be_sync)]
    async fn validate_update_proposal(
        &self,
        leaf_node_validator: &LeafNodeValidator<'_, C, CSP>,
        proposal_info: &ProposalInfo<UpdateProposal>,
        new_extensions: &ExtensionList,
        commit_time: Option<MlsTime>,
    ) -> Result<LeafIndex, MlsError> {
        let leaf = &proposal_info.proposal.leaf_node;
        let sender_index = leaf_index_of_update_sender(proposal_info)?;

        leaf_node_validator
            .check_if_valid(
                leaf,
                ValidationContext::Update((
                    &self.original_context.group_id,
                    *sender_index,
                    commit_time,
                )),
            )
            .await?;

        let old_leaf = self.original_tree.get_leaf_node(sender_index)?;

        self.identity_provider
            .valid_successor(
                &old_leaf.signing_identity,
                &leaf.signing_identity,
                new_extensions,
            )
            .await
            .map_err(|e| MlsError::IdentityProviderError(e.into_any_error()))?
            .then_some(())
            .ok_or(MlsError::InvalidSuccessor)?;

        Ok(sender_index)
    }
}

#[derive(Clone, Copy, Debug)]
pub enum FilterStrategy {
    IgnoreByRef,
    IgnoreNone,
}

impl From<CommitDirection> for FilterStrategy {
    fn from(value: CommitDirection) -> Self {
        match value {
            CommitDirection::Send => FilterStrategy::IgnoreByRef,
            CommitDirection::Receive => FilterStrategy::IgnoreNone,
        }
    }
}

impl FilterStrategy {
    pub(super) fn ignore(self, by_ref: bool) -> bool {
        match self {
            FilterStrategy::IgnoreByRef => by_ref,
            FilterStrategy::IgnoreNone => false,
        }
    }

    fn is_ignore(self) -> bool {
        match self {
            FilterStrategy::IgnoreByRef => true,
            FilterStrategy::IgnoreNone => false,
        }
    }
}

pub(crate) fn apply_strategy(
    strategy: FilterStrategy,
    by_ref: bool,
    r: Result<(), MlsError>,
) -> Result<bool, MlsError> {
    apply_strategy_with_return(strategy, by_ref, r).map(|opt| opt.is_some())
}

pub(crate) fn apply_strategy_with_return<T>(
    strategy: FilterStrategy,
    by_ref: bool,
    r: Result<T, MlsError>,
) -> Result<Option<T>, MlsError> {
    match r {
        Ok(x) => Ok(Some(x)),
        Err(_) if strategy.ignore(by_ref) => Ok(None),
        Err(error) => Err(error),
    }
}

#[cfg(all(
    feature = "by_ref_proposal",
    feature = "custom_proposal",
    feature = "self_remove_proposal"
))]
fn filter_out_remove_if_self_remove_same_leaf(
    strategy: FilterStrategy,
    mut proposals: ProposalBundle,
) -> Result<ProposalBundle, MlsError> {
    let self_removed_leaves: Vec<Option<u32>> = proposals
        .by_type::<SelfRemoveProposal>()
        .map(|p| match p.sender {
            Sender::Member(sender) => Some(sender),
            _ => None,
        })
        .collect();

    proposals.retain_by_type::<RemoveProposal, _, _>(|p| {
        apply_strategy(
            strategy,
            p.is_by_reference(),
            (!self_removed_leaves.contains(&Some(*p.proposal.to_remove)))
                .then_some(())
                .ok_or(MlsError::CommitterSelfRemoval),
        )
    })?;
    Ok(proposals)
}

fn filter_out_update_for_committer(
    strategy: FilterStrategy,
    commit_sender: LeafIndex,
    mut proposals: ProposalBundle,
) -> Result<ProposalBundle, MlsError> {
    proposals.retain_by_type::<UpdateProposal, _, _>(|p| {
        apply_strategy(
            strategy,
            p.is_by_reference(),
            (p.sender != Sender::Member(*commit_sender))
                .then_some(())
                .ok_or(MlsError::InvalidCommitSelfUpdate),
        )
    })?;
    Ok(proposals)
}

fn filter_out_removal_of_committer(
    strategy: FilterStrategy,
    commit_sender: LeafIndex,
    mut proposals: ProposalBundle,
) -> Result<ProposalBundle, MlsError> {
    proposals.retain_by_type::<RemoveProposal, _, _>(|p| {
        apply_strategy(
            strategy,
            p.is_by_reference(),
            (p.proposal.to_remove != commit_sender)
                .then_some(())
                .ok_or(MlsError::CommitterSelfRemoval),
        )
    })?;
    #[cfg(all(
        feature = "by_ref_proposal",
        feature = "custom_proposal",
        feature = "self_remove_proposal"
    ))]
    proposals.retain_by_type::<SelfRemoveProposal, _, _>(|p| {
        apply_strategy(
            strategy,
            p.is_by_reference(),
            match p.sender {
                Sender::Member(sender) => commit_sender != LeafIndex::try_from(sender)?,
                _ => false,
            }
            .then_some(())
            .ok_or(MlsError::CommitterSelfRemoval),
        )
    })?;
    Ok(proposals)
}

#[cfg(feature = "by_ref_proposal")]
#[cfg_attr(not(mls_build_async), maybe_async::must_be_sync)]
async fn filter_out_invalid_group_extensions<C>(
    strategy: FilterStrategy,
    mut proposals: ProposalBundle,
    identity_provider: &C,
    commit_time: Option<MlsTime>,
) -> Result<ProposalBundle, MlsError>
where
    C: IdentityProvider,
{
    let mut bad_indices = Vec::new();

    for (i, p) in proposals.by_type::<ExtensionList>().enumerate() {
        let ext = p.proposal.get_as::<ExternalSendersExt>();

        let res = match ext {
            Ok(None) => Ok(()),
            Ok(Some(extension)) => extension
                .verify_all(identity_provider, commit_time, &p.proposal)
                .await
                .map_err(|e| MlsError::IdentityProviderError(e.into_any_error())),
            Err(e) => Err(MlsError::from(e)),
        };

        if !apply_strategy(strategy, p.is_by_reference(), res)? {
            bad_indices.push(i);
        }
    }

    bad_indices
        .into_iter()
        .rev()
        .for_each(|i| proposals.remove::<ExtensionList>(i));

    Ok(proposals)
}

fn filter_out_extra_group_context_extensions(
    strategy: FilterStrategy,
    mut proposals: ProposalBundle,
) -> Result<ProposalBundle, MlsError> {
    let mut found = false;

    proposals.retain_by_type::<ExtensionList, _, _>(|p| {
        apply_strategy(
            strategy,
            p.is_by_reference(),
            (!core::mem::replace(&mut found, true))
                .then_some(())
                .ok_or(MlsError::MoreThanOneGroupContextExtensionsProposal),
        )
    })?;

    Ok(proposals)
}

fn filter_out_invalid_reinit(
    strategy: FilterStrategy,
    mut proposals: ProposalBundle,
    protocol_version: ProtocolVersion,
) -> Result<ProposalBundle, MlsError> {
    proposals.retain_by_type::<ReInitProposal, _, _>(|p| {
        apply_strategy(
            strategy,
            p.is_by_reference(),
            (p.proposal.version >= protocol_version)
                .then_some(())
                .ok_or(MlsError::InvalidProtocolVersionInReInit),
        )
    })?;

    Ok(proposals)
}

fn filter_out_reinit_if_other_proposals(
    filter: bool,
    mut proposals: ProposalBundle,
) -> Result<ProposalBundle, MlsError> {
    let proposal_count = proposals.length();

    let has_reinit_and_other_proposal =
        !proposals.reinit_proposals().is_empty() && proposal_count != 1;

    if has_reinit_and_other_proposal {
        let any_by_val = proposals.reinit_proposals().iter().any(|p| p.is_by_value());

        if any_by_val || !filter {
            return Err(MlsError::OtherProposalWithReInit);
        }

        let has_other_proposal_type = proposal_count > proposals.reinit_proposals().len();

        if has_other_proposal_type {
            proposals.reinitializations = Vec::new();
        } else {
            proposals.reinitializations.truncate(1);
        }
    }

    Ok(proposals)
}

fn filter_out_external_init(
    strategy: FilterStrategy,
    mut proposals: ProposalBundle,
) -> Result<ProposalBundle, MlsError> {
    proposals.retain_by_type::<ExternalInit, _, _>(|p| {
        apply_strategy(
            strategy,
            p.is_by_reference(),
            Err(MlsError::InvalidProposalTypeForSender),
        )
    })?;

    Ok(proposals)
}

// Validate that a given sender is allowed to propose a proposal of the given type,
// considering whether the proposal is by-value, by-reference, or locally injected.
// Returns Ok(()) if allowed, or Err(InvalidProposalTypeForSender) otherwise.
pub(crate) fn proposer_can_propose(
    proposer: Sender,
    proposal_type: ProposalType,
    source: &ProposalSource,
) -> Result<(), MlsError> {
    let can_propose = match (proposer, source) {
        // Local proposals are injected by MlsRules::filter_proposals and are not transmitted
        // on the wire. The proposer-can-propose rules enforced here apply to wire proposals;
        // for local proposals, validation is the application's responsibility via
        // [`MlsRules::filter_proposals`](crate::group::mls_rules::MlsRules::filter_proposals).
        //
        // The exception: a NewMemberProposal sender may only locally inject an Add,
        // because that is the only proposal type this sender is allowed to produce per the spec.
        (Sender::NewMemberProposal, ProposalSource::Local) => {
            matches!(proposal_type, ProposalType::ADD)
        }
        (_, ProposalSource::Local) => true,
        (Sender::Member(_), ProposalSource::ByValue) => matches!(
            proposal_type,
            ProposalType::ADD
                | ProposalType::REMOVE
                | ProposalType::PSK
                | ProposalType::RE_INIT
                | ProposalType::GROUP_CONTEXT_EXTENSIONS
        ),
        (Sender::Member(_), ProposalSource::ByReference(_)) => {
            let can_propose = matches!(
                proposal_type,
                ProposalType::ADD
                    | ProposalType::UPDATE
                    | ProposalType::REMOVE
                    | ProposalType::PSK
                    | ProposalType::RE_INIT
                    | ProposalType::GROUP_CONTEXT_EXTENSIONS
            );
            #[cfg(all(
                feature = "by_ref_proposal",
                feature = "custom_proposal",
                feature = "self_remove_proposal"
            ))]
            let can_propose = can_propose || matches!(proposal_type, ProposalType::SELF_REMOVE);
            can_propose
        }
        #[cfg(feature = "by_ref_proposal")]
        (Sender::External(_), ProposalSource::ByValue) => false,
        #[cfg(feature = "by_ref_proposal")]
        (Sender::External(_), _) => matches!(
            proposal_type,
            ProposalType::ADD
                | ProposalType::REMOVE
                | ProposalType::RE_INIT
                | ProposalType::PSK
                | ProposalType::GROUP_CONTEXT_EXTENSIONS
        ),
        (Sender::NewMemberCommit, ProposalSource::ByValue) => matches!(
            proposal_type,
            ProposalType::REMOVE | ProposalType::PSK | ProposalType::EXTERNAL_INIT
        ),
        (Sender::NewMemberCommit, ProposalSource::ByReference(_)) => false,
        (Sender::NewMemberProposal, ProposalSource::ByValue) => false,
        (Sender::NewMemberProposal, ProposalSource::ByReference(_)) => {
            matches!(proposal_type, ProposalType::ADD)
        }
    };

    can_propose
        .then_some(())
        .ok_or(MlsError::InvalidProposalTypeForSender)
}

pub(crate) fn filter_out_invalid_proposers(
    strategy: FilterStrategy,
    mut proposals: ProposalBundle,
) -> Result<ProposalBundle, MlsError> {
    for i in (0..proposals.add_proposals().len()).rev() {
        let p = &proposals.add_proposals()[i];
        let res = proposer_can_propose(p.sender, ProposalType::ADD, &p.source);

        if !apply_strategy(strategy, p.is_by_reference(), res)? {
            proposals.remove::<AddProposal>(i);
        }
    }

    for i in (0..proposals.update_proposals().len()).rev() {
        let p = &proposals.update_proposals()[i];
        let res = proposer_can_propose(p.sender, ProposalType::UPDATE, &p.source);

        if !apply_strategy(strategy, p.is_by_reference(), res)? {
            proposals.remove::<UpdateProposal>(i);
        }
    }

    for i in (0..proposals.remove_proposals().len()).rev() {
        let p = &proposals.remove_proposals()[i];
        let res = proposer_can_propose(p.sender, ProposalType::REMOVE, &p.source);

        if !apply_strategy(strategy, p.is_by_reference(), res)? {
            proposals.remove::<RemoveProposal>(i);
        }
    }

    #[cfg(all(
        feature = "by_ref_proposal",
        feature = "custom_proposal",
        feature = "self_remove_proposal"
    ))]
    for i in (0..proposals.self_remove_proposals().len()).rev() {
        let p = &proposals.self_remove_proposals()[i];
        let res = proposer_can_propose(p.sender, ProposalType::SELF_REMOVE, &p.source);

        if !apply_strategy(strategy, p.is_by_reference(), res)? {
            proposals.remove::<SelfRemoveProposal>(i);
        }
    }

    #[cfg(feature = "psk")]
    for i in (0..proposals.psk_proposals().len()).rev() {
        let p = &proposals.psk_proposals()[i];
        let res = proposer_can_propose(p.sender, ProposalType::PSK, &p.source);

        if !apply_strategy(strategy, p.is_by_reference(), res)? {
            proposals.remove::<PreSharedKeyProposal>(i);
        }
    }

    for i in (0..proposals.reinit_proposals().len()).rev() {
        let p = &proposals.reinit_proposals()[i];
        let res = proposer_can_propose(p.sender, ProposalType::RE_INIT, &p.source);

        if !apply_strategy(strategy, p.is_by_reference(), res)? {
            proposals.remove::<ReInitProposal>(i);
        }
    }

    for i in (0..proposals.external_init_proposals().len()).rev() {
        let p = &proposals.external_init_proposals()[i];
        let res = proposer_can_propose(p.sender, ProposalType::EXTERNAL_INIT, &p.source);

        if !apply_strategy(strategy, p.is_by_reference(), res)? {
            proposals.remove::<ExternalInit>(i);
        }
    }

    for i in (0..proposals.group_context_ext_proposals().len()).rev() {
        let p = &proposals.group_context_ext_proposals()[i];
        let gce_type = ProposalType::GROUP_CONTEXT_EXTENSIONS;
        let res = proposer_can_propose(p.sender, gce_type, &p.source);

        if !apply_strategy(strategy, p.is_by_reference(), res)? {
            proposals.remove::<ExtensionList>(i);
        }
    }

    Ok(proposals)
}

fn leaf_index_of_update_sender(p: &ProposalInfo<UpdateProposal>) -> Result<LeafIndex, MlsError> {
    match p.sender {
        Sender::Member(i) => LeafIndex::try_from(i),
        _ => Err(MlsError::InvalidProposalTypeForSender),
    }
}

#[cfg(feature = "custom_proposal")]
pub(super) fn filter_out_unsupported_custom_proposals(
    proposals: &mut ProposalBundle,
    tree: &TreeKemPublic,
    strategy: FilterStrategy,
) -> Result<(), MlsError> {
    let supported_types = proposals
        .custom_proposal_types()
        .filter(|t| tree.can_support_proposal(*t))
        .collect_vec();

    proposals.retain_custom(|p| {
        let proposal_type = p.proposal.proposal_type();

        apply_strategy(
            strategy,
            p.is_by_reference(),
            supported_types
                .contains(&proposal_type)
                .then_some(())
                .ok_or(MlsError::UnsupportedCustomProposal(proposal_type)),
        )
    })
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use super::*;
    use crate::{
        client::test_utils::TEST_CIPHER_SUITE,
        group::{proposal_ref::ProposalRef, ProposalType, Sender},
    };
    use assert_matches::assert_matches;

    #[cfg(feature = "by_ref_proposal")]
    use crate::{
        client::test_utils::TEST_PROTOCOL_VERSION,
        group::{
            message_processor::MessageProcessor,
            test_utils::{test_n_member_group, TestGroup},
            Proposal,
        },
        key_package::test_utils::test_key_package,
    };
    #[cfg(feature = "by_ref_proposal")]
    use alloc::boxed::Box;

    fn by_ref_source() -> ProposalSource {
        ProposalSource::ByReference(ProposalRef::new_fake(vec![1, 2, 3]))
    }

    // All proposal types relevant to the function under test.
    fn all_proposal_types() -> Vec<ProposalType> {
        let types = vec![
            ProposalType::ADD,
            ProposalType::UPDATE,
            ProposalType::REMOVE,
            ProposalType::PSK,
            ProposalType::RE_INIT,
            ProposalType::EXTERNAL_INIT,
            ProposalType::GROUP_CONTEXT_EXTENSIONS,
        ];
        #[cfg(all(
            feature = "by_ref_proposal",
            feature = "custom_proposal",
            feature = "self_remove_proposal"
        ))]
        let types = {
            let mut t = types;
            t.push(ProposalType::SELF_REMOVE);
            t
        };
        types
    }

    /// Helper that asserts proposer_can_propose returns Ok for `allowed` types
    /// and Err(InvalidProposalTypeForSender) for all others.
    fn assert_allowed(sender: Sender, source: &ProposalSource, allowed: &[ProposalType]) {
        for pt in all_proposal_types() {
            let result = proposer_can_propose(sender, pt, source);
            if allowed.contains(&pt) {
                assert!(
                    result.is_ok(),
                    "Expected {:?} with {:?} source to be allowed for {:?}, but got Err",
                    sender,
                    source,
                    pt
                );
            } else {
                assert_matches!(result, Err(MlsError::InvalidProposalTypeForSender));
            }
        }
    }

    // --- Local source tests ---

    #[test]
    fn member_local_allows_all_proposal_types() {
        let allowed = all_proposal_types();
        assert_allowed(Sender::Member(0), &ProposalSource::Local, &allowed);
    }

    #[test]
    fn new_member_commit_local_allows_all_proposal_types() {
        let allowed = all_proposal_types();
        assert_allowed(Sender::NewMemberCommit, &ProposalSource::Local, &allowed);
    }

    #[cfg(feature = "by_ref_proposal")]
    #[test]
    fn external_local_allows_all_proposal_types() {
        let allowed = all_proposal_types();
        assert_allowed(Sender::External(0), &ProposalSource::Local, &allowed);
    }

    #[cfg(feature = "by_ref_proposal")]
    #[test]
    fn new_member_proposal_local_allows_only_add() {
        assert_allowed(
            Sender::NewMemberProposal,
            &ProposalSource::Local,
            &[ProposalType::ADD],
        );
    }

    #[test]
    fn member_by_value_allows_correct_types() {
        let allowed = vec![
            ProposalType::ADD,
            ProposalType::REMOVE,
            ProposalType::PSK,
            ProposalType::RE_INIT,
            ProposalType::GROUP_CONTEXT_EXTENSIONS,
        ];
        assert_allowed(Sender::Member(0), &ProposalSource::ByValue, &allowed);
    }

    #[cfg(feature = "by_ref_proposal")]
    #[test]
    fn member_by_reference_allows_correct_types() {
        let allowed = vec![
            ProposalType::ADD,
            ProposalType::UPDATE,
            ProposalType::REMOVE,
            ProposalType::PSK,
            ProposalType::RE_INIT,
            ProposalType::GROUP_CONTEXT_EXTENSIONS,
            #[cfg(all(
                feature = "by_ref_proposal",
                feature = "custom_proposal",
                feature = "self_remove_proposal"
            ))]
            ProposalType::SELF_REMOVE,
        ];

        assert_allowed(Sender::Member(0), &by_ref_source(), &allowed);
    }

    #[cfg(feature = "by_ref_proposal")]
    #[test]
    fn external_by_value_rejects_all() {
        assert_allowed(Sender::External(0), &ProposalSource::ByValue, &[]);
    }

    #[cfg(feature = "by_ref_proposal")]
    #[test]
    fn external_by_reference_allows_correct_types() {
        let allowed = vec![
            ProposalType::ADD,
            ProposalType::REMOVE,
            ProposalType::RE_INIT,
            ProposalType::PSK,
            ProposalType::GROUP_CONTEXT_EXTENSIONS,
        ];
        assert_allowed(Sender::External(0), &by_ref_source(), &allowed);
    }

    #[test]
    fn new_member_commit_by_value_allows_correct_types() {
        let allowed = vec![
            ProposalType::REMOVE,
            ProposalType::PSK,
            ProposalType::EXTERNAL_INIT,
        ];
        assert_allowed(Sender::NewMemberCommit, &ProposalSource::ByValue, &allowed);
    }

    #[cfg(feature = "by_ref_proposal")]
    #[test]
    fn new_member_commit_by_reference_rejects_all() {
        assert_allowed(Sender::NewMemberCommit, &by_ref_source(), &[]);
    }

    #[cfg(feature = "by_ref_proposal")]
    #[test]
    fn new_member_proposal_by_value_rejects_all() {
        assert_allowed(Sender::NewMemberProposal, &ProposalSource::ByValue, &[]);
    }

    #[cfg(feature = "by_ref_proposal")]
    #[test]
    fn new_member_proposal_by_reference_allows_only_add() {
        assert_allowed(
            Sender::NewMemberProposal,
            &by_ref_source(),
            &[ProposalType::ADD],
        );
    }

    /// Returns a 3-member group and one update proposal per member, in leaf order.
    #[cfg(feature = "by_ref_proposal")]
    #[cfg_attr(not(mls_build_async), maybe_async::must_be_sync)]
    async fn group_with_update_proposals() -> (TestGroup, [Proposal; 3]) {
        let [mut alice, mut bob, mut carl] =
            test_n_member_group(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE, 3)
                .await
                .try_into()
                .unwrap();

        let updates = [
            alice.update_proposal().await,
            bob.update_proposal().await,
            carl.update_proposal().await,
        ];

        (alice, updates)
    }

    #[cfg(feature = "by_ref_proposal")]
    #[maybe_async::test(not(mls_build_async), async(mls_build_async, crate::futures_test))]
    async fn validate_new_nodes_with_invalid_update() {
        let (alice, [alice_update, bob_update, carl_update]) = group_with_update_proposals().await;

        let applier = ProposalApplier {
            original_tree: alice.current_epoch_tree(),
            cipher_suite_provider: alice.cipher_suite_provider(),
            original_context: alice.context(),
            external_leaf: None,
            identity_provider: &alice.identity_provider(),
            psk_storage: &alice.psk_storage(),
        };

        // Bob's leaf is signed for leaf 1, so claiming leaf 2 makes the proposal invalid.
        let mut bundle = ProposalBundle::default();
        bundle.add(alice_update, Sender::Member(0), by_ref_source());
        bundle.add(bob_update, Sender::Member(2), by_ref_source());
        bundle.add(carl_update.clone(), Sender::Member(2), by_ref_source());

        let result_bundle = applier
            .validate_new_nodes(
                FilterStrategy::IgnoreByRef,
                bundle.clone(),
                &Default::default(),
                None,
            )
            .await
            .unwrap();

        assert_eq!(
            result_bundle.update_senders,
            vec![LeafIndex::unchecked(0), LeafIndex::unchecked(2)]
        );

        assert_matches!(
            &carl_update,
            Proposal::Update(carl) if result_bundle.proposals.updates[1].proposal == *carl
        );

        let res = applier
            .validate_new_nodes(
                FilterStrategy::IgnoreNone,
                bundle,
                &Default::default(),
                None,
            )
            .await;

        assert_matches!(res, Err(MlsError::InvalidSignature));
    }

    #[cfg(feature = "by_ref_proposal")]
    #[maybe_async::test(not(mls_build_async), async(mls_build_async, crate::futures_test))]
    async fn validate_new_nodes_with_invalid_add() {
        let (alice, _) = group_with_update_proposals().await;

        let applier = ProposalApplier {
            original_tree: alice.current_epoch_tree(),
            cipher_suite_provider: alice.cipher_suite_provider(),
            original_context: alice.context(),
            external_leaf: None,
            identity_provider: &alice.identity_provider(),
            psk_storage: &alice.psk_storage(),
        };

        let valid_kp = test_key_package(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE, "dave").await;

        let mut invalid_kp =
            test_key_package(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE, "mallory").await;

        invalid_kp.signature = vec![1, 2, 3];

        let mut bundle = ProposalBundle::default();

        bundle.add(
            Proposal::Add(Box::new(AddProposal::from(invalid_kp))),
            Sender::Member(0),
            by_ref_source(),
        );

        bundle.add(
            Proposal::Add(Box::new(AddProposal::from(valid_kp.clone()))),
            Sender::Member(0),
            by_ref_source(),
        );

        let result_bundle = applier
            .validate_new_nodes(
                FilterStrategy::IgnoreByRef,
                bundle.clone(),
                &Default::default(),
                None,
            )
            .await
            .unwrap();

        assert_eq!(result_bundle.proposals.additions.len(), 1);

        assert_eq!(
            result_bundle.proposals.additions[0].proposal.key_package,
            valid_kp
        );

        let res = applier
            .validate_new_nodes(
                FilterStrategy::IgnoreNone,
                bundle,
                &Default::default(),
                None,
            )
            .await;

        assert_matches!(res, Err(MlsError::InvalidSignature));
    }
}
