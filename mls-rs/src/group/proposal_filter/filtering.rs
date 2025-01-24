// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// Copyright by contributors to this project.
// SPDX-License-Identifier: (Apache-2.0 OR MIT)

use crate::{
    client::MlsError,
    group::{proposal_filter::ProposalBundle, ProposalType, Sender},
    iter::wrap_iter,
    protocol_version::ProtocolVersion,
    time::MlsTime,
    tree_kem::{leaf_node_validator::LeafNodeValidator, node::LeafIndex},
    CipherSuiteProvider, ExtensionList,
};

use super::{
    filtering_common::{ApplyProposalsOutput, ProposalApplier},
    ProposalSource,
};

#[cfg(feature = "psk")]
use super::filtering_common::filter_out_invalid_psks;

#[cfg(feature = "by_ref_proposal")]
use crate::extension::ExternalSendersExt;

#[cfg(feature = "by_ref_proposal")]
use crate::group::UpdateProposal;

use mls_rs_core::identity::{IdentityProvider, MemberValidationContext};

#[cfg(feature = "by_ref_proposal")]
use mls_rs_core::error::IntoAnyError;

#[cfg(all(not(mls_build_async), feature = "rayon"))]
use rayon::prelude::*;

#[cfg(mls_build_async)]
use futures::{StreamExt, TryStreamExt};

impl<C, CSP> ProposalApplier<'_, C, CSP>
where
    C: IdentityProvider,
    CSP: CipherSuiteProvider,
{
    #[cfg_attr(not(mls_build_async), maybe_async::must_be_sync)]
    pub(super) async fn apply_proposals_from_member(
        &self,
        commit_sender: LeafIndex,
        #[cfg(feature = "by_ref_proposal")] mut proposals: ProposalBundle,
        #[cfg(not(feature = "by_ref_proposal"))] proposals: ProposalBundle,
        commit_time: Option<MlsTime>,
    ) -> Result<ApplyProposalsOutput, MlsError> {
        filter_out_invalid_proposers(&proposals)?;

        #[cfg(feature = "by_ref_proposal")]
        {
            filter_out_update_for_committer(commit_sender, &proposals)?;

            proposals.update_senders = proposals
                .updates
                .iter()
                .map(leaf_index_of_update_sender)
                .collect::<Result<_, _>>()?;

            filter_out_invalid_group_extensions(&proposals, self.identity_provider, commit_time)
                .await?;
        }

        filter_out_removal_of_committer(commit_sender, &proposals)?;

        #[cfg(feature = "psk")]
        filter_out_invalid_psks(self.cipher_suite_provider, &proposals, self.psks).await?;

        filter_out_extra_group_context_extensions(&proposals)?;
        filter_out_invalid_reinit(&proposals, self.original_context.protocol_version)?;
        filter_out_reinit_if_other_proposals(&proposals)?;
        filter_out_external_init(&proposals)?;

        self.apply_proposal_changes(proposals, commit_time).await
    }

    #[cfg_attr(not(mls_build_async), maybe_async::must_be_sync)]
    pub(super) async fn apply_proposal_changes(
        &self,
        proposals: ProposalBundle,
        commit_time: Option<MlsTime>,
    ) -> Result<ApplyProposalsOutput, MlsError> {
        match proposals.group_context_extensions_proposal().cloned() {
            Some(p) => {
                self.apply_proposals_with_new_capabilities(proposals, p, commit_time)
                    .await
            }
            None => {
                self.apply_tree_changes(proposals, &self.original_context.extensions, commit_time)
                    .await
            }
        }
    }

    #[cfg_attr(not(mls_build_async), maybe_async::must_be_sync)]
    pub(super) async fn apply_tree_changes(
        &self,
        proposals: ProposalBundle,
        new_extensions: &ExtensionList,
        commit_time: Option<MlsTime>,
    ) -> Result<ApplyProposalsOutput, MlsError> {
        self.validate_new_nodes(&proposals, new_extensions, commit_time)
            .await?;

        let mut new_tree = self.original_tree.clone();

        let added = new_tree
            .batch_edit(
                &proposals,
                new_extensions,
                self.identity_provider,
                self.cipher_suite_provider,
            )
            .await?;

        let new_context_extensions = proposals
            .group_context_extensions_proposal()
            .map(|gce| gce.proposal.clone());

        Ok(ApplyProposalsOutput {
            applied_proposals: proposals,
            new_tree,
            indexes_of_added_kpkgs: added,
            external_init_index: None,
            new_context_extensions,
        })
    }

    #[cfg_attr(not(mls_build_async), maybe_async::must_be_sync)]
    async fn validate_new_nodes(
        &self,
        proposals: &ProposalBundle,
        new_extensions: &ExtensionList,
        commit_time: Option<MlsTime>,
    ) -> Result<(), MlsError> {
        let member_validation_context = MemberValidationContext::ForCommit {
            current_context: self.original_context,
            new_extensions,
        };

        let leaf_node_validator = &LeafNodeValidator::new(
            self.cipher_suite_provider,
            self.identity_provider,
            member_validation_context,
        );

        #[cfg(feature = "by_ref_proposal")]
        {
            #[cfg(mls_build_async)]
            let iter = wrap_iter(proposals.update_proposals())
                .zip(wrap_iter(proposals.update_proposal_senders()))
                .map(Ok);

            #[cfg(not(mls_build_async))]
            #[allow(unused_mut)]
            let mut iter = wrap_iter(proposals.update_proposals())
                .zip(wrap_iter(proposals.update_proposal_senders()));

            iter.try_for_each(|(p, &sender_index)| async move {
                let leaf = &p.proposal.leaf_node;

                leaf_node_validator
                    .check_if_valid(
                        leaf,
                        crate::tree_kem::leaf_node_validator::ValidationContext::Update((
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
                    .map_err(|e| MlsError::IdentityProviderError(e.into_any_error()))
                    .and_then(|valid| valid.then_some(()).ok_or(MlsError::InvalidSuccessor))
            })
            .await?;
        }

        #[cfg(not(mls_build_async))]
        #[allow(unused_mut)]
        let mut iter = wrap_iter(proposals.add_proposals());

        #[cfg(mls_build_async)]
        let iter = wrap_iter(proposals.add_proposals()).map(Ok);

        iter.try_for_each(|p| async move {
            self.validate_new_node(leaf_node_validator, &p.proposal.key_package, commit_time)
                .await
        })
        .await?;

        Ok(())
    }
}

#[cfg(feature = "by_ref_proposal")]
fn filter_out_update_for_committer(
    commit_sender: LeafIndex,
    proposals: &ProposalBundle,
) -> Result<(), MlsError> {
    proposals.updates.iter().try_for_each(|p| {
        (p.sender != Sender::Member(*commit_sender))
            .then_some(())
            .ok_or(MlsError::InvalidCommitSelfUpdate)
    })
}

fn filter_out_removal_of_committer(
    commit_sender: LeafIndex,
    proposals: &ProposalBundle,
) -> Result<(), MlsError> {
    proposals.removals.iter().try_for_each(|p| {
        (p.proposal.to_remove != commit_sender)
            .then_some(())
            .ok_or(MlsError::CommitterSelfRemoval)
    })
}

#[cfg(feature = "by_ref_proposal")]
#[cfg_attr(not(mls_build_async), maybe_async::must_be_sync)]
async fn filter_out_invalid_group_extensions<I>(
    proposals: &ProposalBundle,
    identity_provider: &I,
    commit_time: Option<MlsTime>,
) -> Result<(), MlsError>
where
    I: IdentityProvider,
{
    for p in proposals.by_type::<ExtensionList>() {
        if let Some(ext) = p
            .proposal
            .get_as::<ExternalSendersExt>()
            .map_err(MlsError::from)?
        {
            ext.verify_all(identity_provider, commit_time, &p.proposal)
                .await
                .map_err(|e| MlsError::IdentityProviderError(e.into_any_error()))?;
        }
    }

    Ok(())
}

fn filter_out_extra_group_context_extensions(proposals: &ProposalBundle) -> Result<(), MlsError> {
    if proposals.group_context_extensions.len() > 1 {
        return Err(MlsError::MoreThanOneGroupContextExtensionsProposal);
    }

    Ok(())
}

fn filter_out_invalid_reinit(
    proposals: &ProposalBundle,
    protocol_version: ProtocolVersion,
) -> Result<(), MlsError> {
    proposals.reinitializations.iter().try_for_each(|p| {
        (p.proposal.version >= protocol_version)
            .then_some(())
            .ok_or(MlsError::InvalidProtocolVersionInReInit)
    })
}

fn filter_out_reinit_if_other_proposals(proposals: &ProposalBundle) -> Result<(), MlsError> {
    let proposal_count = proposals.length();

    if !proposals.reinit_proposals().is_empty() && proposal_count != 1 {
        return Err(MlsError::OtherProposalWithReInit);
    }

    Ok(())
}

fn filter_out_external_init(proposals: &ProposalBundle) -> Result<(), MlsError> {
    if !proposals.external_initializations.is_empty() {
        return Err(MlsError::InvalidProposalTypeForSender);
    }

    Ok(())
}

pub(crate) fn proposer_can_propose(
    proposer: Sender,
    proposal_type: ProposalType,
    source: &ProposalSource,
) -> Result<(), MlsError> {
    let can_propose = match (proposer, source) {
        (Sender::Member(_), ProposalSource::ByValue | ProposalSource::Local) => matches!(
            proposal_type,
            ProposalType::ADD
                | ProposalType::REMOVE
                | ProposalType::PSK
                | ProposalType::RE_INIT
                | ProposalType::GROUP_CONTEXT_EXTENSIONS
        ),
        #[cfg(feature = "by_ref_proposal")]
        (Sender::Member(_), ProposalSource::ByReference(_)) => matches!(
            proposal_type,
            ProposalType::ADD
                | ProposalType::UPDATE
                | ProposalType::REMOVE
                | ProposalType::PSK
                | ProposalType::RE_INIT
                | ProposalType::GROUP_CONTEXT_EXTENSIONS
        ),
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
        (Sender::NewMemberCommit, ProposalSource::ByValue | ProposalSource::Local) => matches!(
            proposal_type,
            ProposalType::REMOVE | ProposalType::PSK | ProposalType::EXTERNAL_INIT
        ),
        #[cfg(feature = "by_ref_proposal")]
        (Sender::NewMemberCommit, ProposalSource::ByReference(_)) => false,
        #[cfg(feature = "by_ref_proposal")]
        (Sender::NewMemberProposal, ProposalSource::ByValue | ProposalSource::Local) => false,
        #[cfg(feature = "by_ref_proposal")]
        (Sender::NewMemberProposal, ProposalSource::ByReference(_)) => {
            matches!(proposal_type, ProposalType::ADD)
        }
    };

    can_propose
        .then_some(())
        .ok_or(MlsError::InvalidProposalTypeForSender)
}

pub(crate) fn filter_out_invalid_proposers(proposals: &ProposalBundle) -> Result<(), MlsError> {
    for i in (0..proposals.add_proposals().len()).rev() {
        let p = &proposals.add_proposals()[i];
        proposer_can_propose(p.sender, ProposalType::ADD, &p.source)?;
    }

    #[cfg(feature = "by_ref_proposal")]
    for i in (0..proposals.update_proposals().len()).rev() {
        let p = &proposals.update_proposals()[i];
        proposer_can_propose(p.sender, ProposalType::UPDATE, &p.source)?;
    }

    for i in (0..proposals.remove_proposals().len()).rev() {
        let p = &proposals.remove_proposals()[i];
        proposer_can_propose(p.sender, ProposalType::REMOVE, &p.source)?;
    }

    #[cfg(feature = "psk")]
    for i in (0..proposals.psk_proposals().len()).rev() {
        let p = &proposals.psk_proposals()[i];
        proposer_can_propose(p.sender, ProposalType::PSK, &p.source)?;
    }

    for i in (0..proposals.reinit_proposals().len()).rev() {
        let p = &proposals.reinit_proposals()[i];
        proposer_can_propose(p.sender, ProposalType::RE_INIT, &p.source)?;
    }

    for i in (0..proposals.external_init_proposals().len()).rev() {
        let p = &proposals.external_init_proposals()[i];
        proposer_can_propose(p.sender, ProposalType::EXTERNAL_INIT, &p.source)?;
    }

    for i in (0..proposals.group_context_ext_proposals().len()).rev() {
        let p = &proposals.group_context_ext_proposals()[i];
        let gce_type = ProposalType::GROUP_CONTEXT_EXTENSIONS;
        proposer_can_propose(p.sender, gce_type, &p.source)?;
    }

    Ok(())
}

#[cfg(feature = "by_ref_proposal")]
fn leaf_index_of_update_sender(
    p: &super::ProposalInfo<UpdateProposal>,
) -> Result<LeafIndex, MlsError> {
    match p.sender {
        Sender::Member(i) => Ok(LeafIndex(i)),
        _ => Err(MlsError::InvalidProposalTypeForSender),
    }
}
