// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// Copyright by contributors to this project.
// SPDX-License-Identifier: (Apache-2.0 OR MIT)

use crate::{
    client::MlsError,
    group::{proposal_filter::ProposalBundle, AddProposal},
    key_package::validate_key_package_properties,
    protocol_version::ProtocolVersion,
    time::MlsTime,
    tree_kem::{
        leaf_node_validator::{LeafNodeValidator, ValidationContext},
        node::LeafIndex,
    },
    CipherSuiteProvider, ExtensionList,
};

#[cfg(feature = "all_extensions")]
use crate::extension::RequiredCapabilitiesExt;

#[cfg(feature = "all_extensions")]
use super::filtering_common::leaf_supports_extensions;

use super::filtering_common::{filter_out_invalid_psks, ApplyProposalsOutput, ProposalApplier};

#[cfg(feature = "external_proposal")]
use crate::extension::ExternalSendersExt;

#[cfg(any(
    feature = "external_proposal",
    feature = "external_commit",
    feature = "psk"
))]
use aws_mls_core::error::IntoAnyError;

use aws_mls_core::{identity::IdentityProvider, psk::PreSharedKeyStorage};

#[cfg(feature = "custom_proposal")]
use itertools::Itertools;

#[cfg(feature = "custom_proposal")]
use crate::tree_kem::TreeKemPublic;

#[cfg(feature = "external_commit")]
use crate::group::{ExternalInit, ProposalType, RemoveProposal};

#[cfg(feature = "psk")]
use crate::group::{
    proposal::PreSharedKeyProposal, JustPreSharedKeyID, ResumptionPSKUsage, ResumptionPsk,
};

#[cfg(all(feature = "std", feature = "psk"))]
use std::collections::HashSet;

impl<'a, C, P, CSP> ProposalApplier<'a, C, P, CSP>
where
    C: IdentityProvider,
    P: PreSharedKeyStorage,
    CSP: CipherSuiteProvider,
{
    #[cfg_attr(not(mls_build_async), maybe_async::must_be_sync)]
    pub(super) async fn apply_proposals_from_member(
        &self,
        commit_sender: LeafIndex,
        proposals: &ProposalBundle,
        commit_time: Option<MlsTime>,
    ) -> Result<ApplyProposalsOutput, MlsError> {
        filter_out_removal_of_committer(commit_sender, proposals)?;
        filter_out_invalid_psks(self.cipher_suite_provider, proposals, self.psk_storage).await?;

        #[cfg(feature = "external_proposal")]
        filter_out_invalid_group_extensions(proposals, self.identity_provider, commit_time).await?;

        filter_out_extra_group_context_extensions(proposals)?;
        filter_out_invalid_reinit(proposals, self.protocol_version)?;
        filter_out_reinit_if_other_proposals(proposals)?;

        self.apply_proposal_changes(proposals, commit_time).await
    }

    #[cfg_attr(not(mls_build_async), maybe_async::must_be_sync)]
    pub(super) async fn apply_proposal_changes(
        &self,
        proposals: &ProposalBundle,
        commit_time: Option<MlsTime>,
    ) -> Result<ApplyProposalsOutput, MlsError> {
        match proposals.group_context_extensions_proposal().cloned() {
            Some(p) => {
                #[cfg(feature = "all_extensions")]
                {
                    let ext = p.proposal.get_as::<RequiredCapabilitiesExt>()?;
                    self.apply_proposals_with_new_capabilities(proposals, p, ext, commit_time)
                        .await
                }

                #[cfg(not(feature = "all_extensions"))]
                {
                    self.apply_tree_changes(proposals, &p.proposal, commit_time)
                        .await
                }
            }
            None => {
                self.apply_tree_changes(proposals, self.original_group_extensions, commit_time)
                    .await
            }
        }
    }

    #[cfg_attr(not(mls_build_async), maybe_async::must_be_sync)]
    pub(super) async fn apply_tree_changes(
        &self,
        proposals: &ProposalBundle,
        group_extensions_in_use: &ExtensionList,
        commit_time: Option<MlsTime>,
    ) -> Result<ApplyProposalsOutput, MlsError> {
        self.validate_new_nodes(proposals, group_extensions_in_use, commit_time)
            .await?;

        let mut new_tree = self.original_tree.clone();

        let added = new_tree
            .batch_edit_lite(
                proposals,
                self.identity_provider,
                self.cipher_suite_provider,
            )
            .await?;

        Ok(ApplyProposalsOutput {
            new_tree,
            indexes_of_added_kpkgs: added,
            #[cfg(feature = "external_commit")]
            external_init_index: None,
        })
    }

    #[cfg_attr(not(mls_build_async), maybe_async::must_be_sync)]
    async fn validate_new_nodes(
        &self,
        proposals: &ProposalBundle,
        group_extensions_in_use: &ExtensionList,
        commit_time: Option<MlsTime>,
    ) -> Result<(), MlsError> {
        #[cfg(feature = "all_extensions")]
        let capabilities = group_extensions_in_use.get_as()?;

        let leaf_node_validator = LeafNodeValidator::new(
            self.cipher_suite_provider,
            #[cfg(feature = "all_extensions")]
            capabilities.as_ref(),
            self.identity_provider,
            Some(group_extensions_in_use),
        );

        for p in proposals.by_type::<AddProposal>() {
            leaf_node_validator
                .check_if_valid(
                    &p.proposal.key_package.leaf_node,
                    ValidationContext::Add(commit_time),
                )
                .await?;

            #[cfg(feature = "all_extensions")]
            leaf_supports_extensions(&p.proposal.key_package.leaf_node, group_extensions_in_use)?;

            validate_key_package_properties(
                &p.proposal.key_package,
                self.protocol_version,
                self.cipher_suite_provider,
            )
            .await?;
        }

        Ok(())
    }
}

fn filter_out_removal_of_committer(
    commit_sender: LeafIndex,
    proposals: &ProposalBundle,
) -> Result<(), MlsError> {
    for p in &proposals.removals {
        (p.proposal.to_remove != commit_sender)
            .then_some(())
            .ok_or(MlsError::CommitterSelfRemoval)?;
    }

    Ok(())
}

#[cfg(feature = "external_proposal")]
#[cfg_attr(not(mls_build_async), maybe_async::must_be_sync)]
async fn filter_out_invalid_group_extensions<C>(
    proposals: &ProposalBundle,
    identity_provider: &C,
    commit_time: Option<MlsTime>,
) -> Result<(), MlsError>
where
    C: IdentityProvider,
{
    if let Some(p) = proposals.group_context_extensions.first() {
        if let Some(ext) = p.proposal.get_as::<ExternalSendersExt>()? {
            ext.verify_all(identity_provider, commit_time, p.proposal())
                .await
                .map_err(|e| MlsError::IdentityProviderError(e.into_any_error()))?;
        }
    }

    Ok(())
}

fn filter_out_extra_group_context_extensions(proposals: &ProposalBundle) -> Result<(), MlsError> {
    (proposals.group_context_extensions.len() < 2)
        .then_some(())
        .ok_or(MlsError::MoreThanOneGroupContextExtensionsProposal)
}

fn filter_out_invalid_reinit(
    proposals: &ProposalBundle,
    protocol_version: ProtocolVersion,
) -> Result<(), MlsError> {
    if let Some(p) = proposals.reinitializations.first() {
        (p.proposal.version >= protocol_version)
            .then_some(())
            .ok_or(MlsError::InvalidProtocolVersionInReInit)?;
    }

    Ok(())
}

fn filter_out_reinit_if_other_proposals(proposals: &ProposalBundle) -> Result<(), MlsError> {
    (proposals.reinitializations.is_empty() || proposals.length() == 1)
        .then_some(())
        .ok_or(MlsError::OtherProposalWithReInit)
}

#[cfg(feature = "custom_proposal")]
pub(super) fn filter_out_unsupported_custom_proposals(
    proposals: &ProposalBundle,
    tree: &TreeKemPublic,
) -> Result<(), MlsError> {
    let supported_types = proposals
        .custom_proposal_types()
        .filter(|t| tree.can_support_proposal(*t))
        .collect_vec();

    for p in &proposals.custom_proposals {
        let proposal_type = p.proposal.proposal_type();

        supported_types
            .contains(&proposal_type)
            .then_some(())
            .ok_or(MlsError::UnsupportedCustomProposal(proposal_type))?;
    }

    Ok(())
}
