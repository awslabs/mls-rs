// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// Copyright by contributors to this project.
// SPDX-License-Identifier: (Apache-2.0 OR MIT)

use crate::{
    client::MlsError,
    group::commit::CommitSource,
    group::{proposal_filter::ProposalBundle, GroupContext},
    key_package::{validate_key_package_properties, KeyPackage},
    time::MlsTime,
    tree_kem::{
        leaf_node_validator::{LeafNodeValidator, ValidationContext},
        node::LeafIndex,
        TreeKemPublic,
    },
    CipherSuiteProvider, ExtensionList,
};

use crate::tree_kem::leaf_node::LeafNode;

use super::ProposalInfo;

use crate::extension::{MlsExtension, RequiredCapabilitiesExt};

#[cfg(feature = "by_ref_proposal")]
use crate::extension::ExternalSendersExt;

use mls_rs_core::{error::IntoAnyError, identity::MemberValidationContext};

use alloc::vec::Vec;
use mls_rs_core::identity::IdentityProvider;

use crate::group::{ExternalInit, ProposalType, RemoveProposal};

#[cfg(feature = "psk")]
use crate::group::{JustPreSharedKeyID, ResumptionPSKUsage, ResumptionPsk};

#[cfg(all(feature = "std", feature = "psk"))]
use std::collections::HashSet;

#[cfg(feature = "by_ref_proposal")]
use super::filtering::filter_out_invalid_proposers;

#[derive(Debug)]
pub(crate) struct ProposalApplier<'a, C, CSP> {
    pub original_tree: &'a TreeKemPublic,
    pub cipher_suite_provider: &'a CSP,
    pub original_context: &'a GroupContext,
    pub external_leaf: Option<&'a LeafNode>,
    pub identity_provider: &'a C,
    #[cfg(feature = "psk")]
    pub psks: &'a [JustPreSharedKeyID],
}

#[derive(Debug)]
pub(crate) struct ApplyProposalsOutput {
    pub(crate) new_tree: TreeKemPublic,
    pub(crate) indexes_of_added_kpkgs: Vec<LeafIndex>,
    pub(crate) external_init_index: Option<LeafIndex>,
    pub(crate) applied_proposals: ProposalBundle,
    pub(crate) new_context_extensions: Option<ExtensionList>,
}

impl<'a, C, CSP> ProposalApplier<'a, C, CSP>
where
    C: IdentityProvider,
    CSP: CipherSuiteProvider,
{
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        original_tree: &'a TreeKemPublic,
        cipher_suite_provider: &'a CSP,
        original_context: &'a GroupContext,
        external_leaf: Option<&'a LeafNode>,
        identity_provider: &'a C,
        #[cfg(feature = "psk")] psks: &'a [JustPreSharedKeyID],
    ) -> Self {
        Self {
            original_tree,
            cipher_suite_provider,
            original_context,
            external_leaf,
            identity_provider,
            #[cfg(feature = "psk")]
            psks,
        }
    }

    #[cfg_attr(not(mls_build_async), maybe_async::must_be_sync)]
    pub(crate) async fn apply_proposals(
        &self,
        commit_sender: &CommitSource,
        proposals: ProposalBundle,
        commit_time: Option<MlsTime>,
    ) -> Result<ApplyProposalsOutput, MlsError> {
        let output = match commit_sender {
            CommitSource::ExistingMember(sender) => {
                self.apply_proposals_from_member(LeafIndex(sender.index), proposals, commit_time)
                    .await
            }
            CommitSource::NewMember(_) => {
                self.apply_proposals_from_new_member(proposals, commit_time)
                    .await
            }
        }?;

        Ok(output)
    }

    #[cfg_attr(not(mls_build_async), maybe_async::must_be_sync)]
    // The lint below is triggered by the `proposals` parameter which may or may not be a borrow.
    #[allow(clippy::needless_borrow)]
    async fn apply_proposals_from_new_member(
        &self,
        proposals: ProposalBundle,
        commit_time: Option<MlsTime>,
    ) -> Result<ApplyProposalsOutput, MlsError> {
        let external_leaf = self
            .external_leaf
            .ok_or(MlsError::ExternalCommitMustHaveNewLeaf)?;

        ensure_exactly_one_external_init(&proposals)?;

        ensure_at_most_one_removal_for_self(
            &proposals,
            external_leaf,
            self.original_tree,
            self.identity_provider,
            &self.original_context.extensions,
        )
        .await?;

        ensure_proposals_in_external_commit_are_allowed(&proposals)?;
        ensure_no_proposal_by_ref(&proposals)?;

        #[cfg(feature = "by_ref_proposal")]
        filter_out_invalid_proposers(&proposals)?;

        #[cfg(feature = "psk")]
        filter_out_invalid_psks(self.cipher_suite_provider, &proposals, self.psks).await?;

        let mut output = self.apply_proposal_changes(proposals, commit_time).await?;

        output.external_init_index = Some(
            insert_external_leaf(
                &mut output.new_tree,
                external_leaf.clone(),
                self.identity_provider,
                &self.original_context.extensions,
            )
            .await?,
        );

        Ok(output)
    }

    #[cfg_attr(not(mls_build_async), maybe_async::must_be_sync)]
    pub(super) async fn apply_proposals_with_new_capabilities(
        &self,
        proposals: ProposalBundle,
        group_context_extensions_proposal: ProposalInfo<ExtensionList>,
        commit_time: Option<MlsTime>,
    ) -> Result<ApplyProposalsOutput, MlsError>
    where
        C: IdentityProvider,
    {
        // Apply adds, updates etc. in the context of new extensions
        let output = self
            .apply_tree_changes(
                proposals,
                &group_context_extensions_proposal.proposal,
                commit_time,
            )
            .await?;

        // Verify that capabilities and extensions are supported after modifications.
        // TODO: The newly inserted nodes have already been validated by `apply_tree_changes`
        // above. We should investigate if there is an easy way to avoid the double check.
        let must_check = group_context_extensions_proposal
            .proposal
            .has_extension(RequiredCapabilitiesExt::extension_type());

        #[cfg(feature = "by_ref_proposal")]
        let must_check = must_check
            || group_context_extensions_proposal
                .proposal
                .has_extension(ExternalSendersExt::extension_type());

        if must_check {
            let member_validation_context = MemberValidationContext::ForCommit {
                current_context: self.original_context,
                new_extensions: &group_context_extensions_proposal.proposal,
            };

            let leaf_validator = LeafNodeValidator::new(
                self.cipher_suite_provider,
                self.identity_provider,
                member_validation_context,
            );

            output
                .new_tree
                .non_empty_leaves()
                .try_for_each(|(_, leaf)| {
                    leaf_validator.validate_required_capabilities(leaf)?;

                    #[cfg(feature = "by_ref_proposal")]
                    leaf_validator.validate_external_senders_ext_credentials(leaf)?;

                    Ok::<_, MlsError>(())
                })?;
        }

        group_context_extensions_proposal
            .proposal
            .iter()
            .map(|extension| extension.extension_type)
            .filter(|&ext_type| !ext_type.is_default())
            .find(|ext_type| {
                !output
                    .new_tree
                    .non_empty_leaves()
                    .all(|(_, leaf)| leaf.capabilities.extensions.contains(ext_type))
            })
            .map_or(Ok(()), |ext| Err(MlsError::UnsupportedGroupExtension(ext)))?;

        Ok(output)
    }

    #[cfg(any(mls_build_async, not(feature = "rayon")))]
    #[cfg_attr(not(mls_build_async), maybe_async::must_be_sync)]
    pub async fn validate_new_node<Ip: IdentityProvider, Cp: CipherSuiteProvider>(
        &self,
        leaf_node_validator: &LeafNodeValidator<'_, Ip, Cp>,
        key_package: &KeyPackage,
        commit_time: Option<MlsTime>,
    ) -> Result<(), MlsError> {
        leaf_node_validator
            .check_if_valid(&key_package.leaf_node, ValidationContext::Add(commit_time))
            .await?;

        validate_key_package_properties(
            key_package,
            self.original_context.protocol_version,
            self.cipher_suite_provider,
        )
        .await
    }

    #[cfg(all(not(mls_build_async), feature = "rayon"))]
    pub fn validate_new_node<Ip: IdentityProvider, Cp: CipherSuiteProvider>(
        &self,
        leaf_node_validator: &LeafNodeValidator<'_, Ip, Cp>,
        key_package: &KeyPackage,
        commit_time: Option<MlsTime>,
    ) -> Result<(), MlsError> {
        let (a, b) = rayon::join(
            || {
                leaf_node_validator
                    .check_if_valid(&key_package.leaf_node, ValidationContext::Add(commit_time))
            },
            || {
                validate_key_package_properties(
                    key_package,
                    self.original_context.protocol_version,
                    self.cipher_suite_provider,
                )
            },
        );
        a?;
        b
    }
}

#[cfg(feature = "psk")]
#[cfg_attr(not(mls_build_async), maybe_async::must_be_sync)]
pub(crate) async fn filter_out_invalid_psks<CP>(
    cipher_suite_provider: &CP,
    proposals: &ProposalBundle,
    psks: &[crate::psk::JustPreSharedKeyID],
) -> Result<(), MlsError>
where
    CP: CipherSuiteProvider,
{
    let kdf_extract_size = cipher_suite_provider.kdf_extract_size();

    #[cfg(feature = "std")]
    let mut ids_seen = HashSet::new();

    #[cfg(not(feature = "std"))]
    let mut ids_seen = Vec::new();

    for i in 0..proposals.psk_proposals().len() {
        let p = &proposals.psks[i];

        if !matches!(
            p.proposal.psk.key_id,
            JustPreSharedKeyID::External(_)
                | JustPreSharedKeyID::Resumption(ResumptionPsk {
                    usage: ResumptionPSKUsage::Application,
                    ..
                })
        ) {
            return Err(MlsError::InvalidTypeOrUsageInPreSharedKeyProposal);
        };

        if p.proposal.psk.psk_nonce.0.len() != kdf_extract_size {
            return Err(MlsError::InvalidPskNonceLength);
        }

        #[cfg(feature = "std")]
        if !ids_seen.insert(p.proposal.psk.clone()) {
            return Err(MlsError::DuplicatePskIds);
        }

        #[cfg(not(feature = "std"))]
        if ids_seen.contains(&p.proposal.psk) {
            return Err(MlsError::DuplicatePskIds);
        }

        if !psks.contains(&p.proposal.psk.key_id) {
            return Err(MlsError::MissingRequiredPsk);
        }

        #[cfg(not(feature = "std"))]
        ids_seen.push(p.proposal.psk.clone());
    }

    Ok(())
}

fn ensure_exactly_one_external_init(proposals: &ProposalBundle) -> Result<(), MlsError> {
    (proposals.by_type::<ExternalInit>().count() == 1)
        .then_some(())
        .ok_or(MlsError::ExternalCommitMustHaveExactlyOneExternalInit)
}

/// Non-default proposal types are by default allowed. Custom MlsRules may disallow
/// specific custom proposals in external commits
fn ensure_proposals_in_external_commit_are_allowed(
    proposals: &ProposalBundle,
) -> Result<(), MlsError> {
    let supported_default_types = [
        ProposalType::EXTERNAL_INIT,
        ProposalType::REMOVE,
        ProposalType::PSK,
    ];

    let unsupported_type = proposals
        .proposal_types()
        .find(|ty| !supported_default_types.contains(ty) && ProposalType::DEFAULT.contains(ty));

    match unsupported_type {
        Some(kind) => Err(MlsError::InvalidProposalTypeInExternalCommit(kind)),
        None => Ok(()),
    }
}

#[cfg_attr(not(mls_build_async), maybe_async::must_be_sync)]
async fn ensure_at_most_one_removal_for_self<C>(
    proposals: &ProposalBundle,
    external_leaf: &LeafNode,
    tree: &TreeKemPublic,
    identity_provider: &C,
    extensions: &ExtensionList,
) -> Result<(), MlsError>
where
    C: IdentityProvider,
{
    let mut removals = proposals.by_type::<RemoveProposal>();

    match (removals.next(), removals.next()) {
        (Some(removal), None) => {
            ensure_removal_is_for_self(
                &removal.proposal,
                external_leaf,
                tree,
                identity_provider,
                extensions,
            )
            .await
        }
        (Some(_), Some(_)) => Err(MlsError::ExternalCommitWithMoreThanOneRemove),
        (None, _) => Ok(()),
    }
}

#[cfg_attr(not(mls_build_async), maybe_async::must_be_sync)]
async fn ensure_removal_is_for_self<C>(
    removal: &RemoveProposal,
    external_leaf: &LeafNode,
    tree: &TreeKemPublic,
    identity_provider: &C,
    extensions: &ExtensionList,
) -> Result<(), MlsError>
where
    C: IdentityProvider,
{
    let existing_signing_id = &tree.get_leaf_node(removal.to_remove)?.signing_identity;

    identity_provider
        .valid_successor(
            existing_signing_id,
            &external_leaf.signing_identity,
            extensions,
        )
        .await
        .map_err(|e| MlsError::IdentityProviderError(e.into_any_error()))?
        .then_some(())
        .ok_or(MlsError::ExternalCommitRemovesOtherIdentity)
}

/// Non-default by-ref proposal types are by default allowed. Custom MlsRules may disallow
/// specific custom by-ref proposals.
fn ensure_no_proposal_by_ref(proposals: &ProposalBundle) -> Result<(), MlsError> {
    proposals
        .iter_proposals()
        .all(|p| !ProposalType::DEFAULT.contains(&p.proposal.proposal_type()) || p.is_by_value())
        .then_some(())
        .ok_or(MlsError::OnlyMembersCanCommitProposalsByRef)
}

#[cfg_attr(not(mls_build_async), maybe_async::must_be_sync)]
async fn insert_external_leaf<I: IdentityProvider>(
    tree: &mut TreeKemPublic,
    leaf_node: LeafNode,
    identity_provider: &I,
    extensions: &ExtensionList,
) -> Result<LeafIndex, MlsError> {
    tree.add_leaf(leaf_node, identity_provider, extensions, None)
        .await
}

#[cfg(feature = "custom_proposal")]
pub fn filter_out_unsupported_custom_proposals(
    proposals: &ProposalBundle,
    tree: &TreeKemPublic,
) -> Result<(), MlsError> {
    let supported_types = proposals
        .custom_proposal_types()
        .filter(|t| tree.can_support_proposal(*t))
        .collect::<Vec<_>>();

    proposals
        .custom_proposal_types()
        .try_for_each(|proposal_type| {
            supported_types
                .contains(&proposal_type)
                .then_some(())
                .ok_or(MlsError::UnsupportedCustomProposal(proposal_type))
        })
}
