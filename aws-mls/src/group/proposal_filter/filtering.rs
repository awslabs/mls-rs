use crate::{
    client::MlsError,
    extension::RequiredCapabilitiesExt,
    group::{
        proposal_filter::{Proposable, ProposalBundle, ProposalInfo},
        AddProposal, BorrowedProposal, JustPreSharedKeyID, PreSharedKeyProposal, ProposalType,
        ReInitProposal, RemoveProposal, ResumptionPSKUsage, ResumptionPsk, Sender, UpdateProposal,
    },
    key_package::{KeyPackageValidationOptions, KeyPackageValidator},
    protocol_version::ProtocolVersion,
    psk::PreSharedKeyID,
    time::MlsTime,
    tree_kem::{
        leaf_node::LeafNode,
        leaf_node_validator::{LeafNodeValidator, ValidationContext},
        node::LeafIndex,
        AccumulateBatchResults, TreeKemPublic,
    },
    CipherSuiteProvider, ExtensionList,
};

#[cfg(feature = "external_proposal")]
use crate::extension::ExternalSendersExt;

#[cfg(feature = "external_commit")]
use alloc::vec;

use alloc::vec::Vec;
use aws_mls_core::{identity::IdentityProvider, psk::PreSharedKeyStorage};
use futures::TryStreamExt;

#[cfg(feature = "custom_proposal")]
use itertools::Itertools;

#[cfg(feature = "external_commit")]
use crate::group::ExternalInit;

#[cfg(feature = "std")]
use std::collections::{HashMap, HashSet};

#[cfg(not(feature = "std"))]
use alloc::collections::BTreeMap;

use alloc::collections::BTreeSet;

#[derive(Clone, Debug)]
pub(crate) struct ProposalState {
    pub(crate) tree: TreeKemPublic,
    pub(crate) proposals: ProposalBundle,
    pub(crate) added_indexes: Vec<LeafIndex>,
    pub(crate) removed_leaves: Vec<(LeafIndex, LeafNode)>,
    #[cfg(feature = "external_commit")]
    pub(crate) external_leaf_index: Option<LeafIndex>,
}

impl ProposalState {
    fn new(tree: TreeKemPublic, proposals: ProposalBundle) -> Self {
        Self {
            tree,
            proposals,
            added_indexes: Vec::new(),
            removed_leaves: Vec::new(),
            #[cfg(feature = "external_commit")]
            external_leaf_index: None,
        }
    }
}

#[derive(Debug)]
pub(crate) struct ProposalApplier<'a, C, P, CSP> {
    original_tree: &'a TreeKemPublic,
    protocol_version: ProtocolVersion,
    cipher_suite_provider: &'a CSP,
    group_id: &'a [u8],
    original_group_extensions: &'a ExtensionList,
    original_required_capabilities: Option<&'a RequiredCapabilitiesExt>,
    #[cfg(feature = "external_commit")]
    external_leaf: Option<&'a LeafNode>,
    identity_provider: &'a C,
    psk_storage: &'a P,
}

impl<'a, C, P, CSP> ProposalApplier<'a, C, P, CSP>
where
    C: IdentityProvider,
    P: PreSharedKeyStorage,
    CSP: CipherSuiteProvider,
{
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        original_tree: &'a TreeKemPublic,
        protocol_version: ProtocolVersion,
        cipher_suite_provider: &'a CSP,
        group_id: &'a [u8],
        original_group_extensions: &'a ExtensionList,
        original_required_capabilities: Option<&'a RequiredCapabilitiesExt>,
        #[cfg(feature = "external_commit")] external_leaf: Option<&'a LeafNode>,
        identity_provider: &'a C,
        psk_storage: &'a P,
    ) -> Self {
        Self {
            original_tree,
            protocol_version,
            cipher_suite_provider,
            group_id,
            original_group_extensions,
            original_required_capabilities,
            #[cfg(feature = "external_commit")]
            external_leaf,
            identity_provider,
            psk_storage,
        }
    }

    pub(crate) async fn apply_proposals<F>(
        &self,
        strategy: &F,
        commit_sender: &Sender,
        proposals: ProposalBundle,
        commit_time: Option<MlsTime>,
    ) -> Result<ProposalState, MlsError>
    where
        F: FilterStrategy,
    {
        let state = match commit_sender {
            Sender::Member(sender) => {
                self.apply_proposals_from_member(
                    strategy,
                    LeafIndex(*sender),
                    proposals,
                    commit_time,
                )
                .await
            }
            #[cfg(feature = "external_commit")]
            Sender::NewMemberCommit => {
                self.apply_proposals_from_new_member(proposals, commit_time)
                    .await
            }
            #[cfg(feature = "external_proposal")]
            Sender::External(_) => Err(MlsError::ExternalSenderCannotCommit),
            Sender::NewMemberProposal => Err(MlsError::ExternalSenderCannotCommit),
        }?;

        #[cfg(feature = "custom_proposal")]
        let state = filter_out_unsupported_custom_proposals(state, strategy)?;

        Ok(state)
    }

    async fn apply_proposals_from_member<F>(
        &self,
        strategy: &F,
        commit_sender: LeafIndex,
        proposals: ProposalBundle,
        commit_time: Option<MlsTime>,
    ) -> Result<ProposalState, MlsError>
    where
        F: FilterStrategy,
    {
        let proposals = filter_out_invalid_proposers(
            strategy,
            self.original_tree,
            #[cfg(feature = "external_proposal")]
            self.original_group_extensions,
            proposals,
        )?;

        let proposals = filter_out_update_for_committer(strategy, commit_sender, proposals)?;
        let proposals = filter_out_removal_of_committer(strategy, commit_sender, proposals)?;
        let proposals = filter_out_extra_removal_or_update_for_same_leaf(strategy, proposals)?;

        let proposals = filter_out_invalid_psks(
            strategy,
            self.cipher_suite_provider,
            proposals,
            self.psk_storage,
        )
        .await?;

        #[cfg(feature = "external_proposal")]
        let proposals = filter_out_invalid_group_extensions(
            strategy,
            proposals,
            self.identity_provider,
            commit_time,
        )
        .await?;

        let proposals = filter_out_extra_group_context_extensions(strategy, proposals)?;
        let proposals = filter_out_invalid_reinit(strategy, proposals, self.protocol_version)?;
        let proposals = filter_out_reinit_if_other_proposals(strategy, proposals)?;

        #[cfg(feature = "external_commit")]
        let proposals = filter_out_external_init(strategy, commit_sender, proposals)?;

        let state = ProposalState::new(self.original_tree.clone(), proposals);
        let state = self
            .apply_proposal_changes(strategy, state, commit_time)
            .await?;
        Ok(state)
    }

    #[cfg(feature = "external_commit")]
    async fn apply_proposals_from_new_member(
        &self,
        proposals: ProposalBundle,
        commit_time: Option<MlsTime>,
    ) -> Result<ProposalState, MlsError> {
        let external_leaf = self
            .external_leaf
            .ok_or(MlsError::ExternalCommitMustHaveNewLeaf)?;

        ensure_exactly_one_external_init(&proposals)?;

        ensure_at_most_one_removal_for_self(
            &proposals,
            external_leaf,
            self.original_tree,
            self.identity_provider,
        )
        .await?;

        ensure_proposals_in_external_commit_are_allowed(&proposals)?;
        ensure_no_proposal_by_ref(&proposals)?;

        let proposals = filter_out_invalid_proposers(
            &FailInvalidProposal,
            self.original_tree,
            #[cfg(feature = "external_proposal")]
            self.original_group_extensions,
            proposals,
        )?;

        let proposals = filter_out_invalid_psks(
            &FailInvalidProposal,
            self.cipher_suite_provider,
            proposals,
            self.psk_storage,
        )
        .await?;

        let state = ProposalState::new(self.original_tree.clone(), proposals);

        let state = self
            .apply_proposal_changes(&FailInvalidProposal, state, commit_time)
            .await?;

        let state = insert_external_leaf(
            state,
            external_leaf.clone(),
            self.identity_provider,
            self.cipher_suite_provider,
        )
        .await?;

        Ok(state)
    }

    async fn apply_proposal_changes<F>(
        &self,
        strategy: &F,
        mut state: ProposalState,
        commit_time: Option<MlsTime>,
    ) -> Result<ProposalState, MlsError>
    where
        F: FilterStrategy,
    {
        let extensions_proposal_and_capabilities = state
            .proposals
            .group_context_extensions_proposal()
            .cloned()
            .and_then(|p| match p.proposal.get_as().map_err(MlsError::from) {
                Ok(capabilities) => Some(Ok((p, capabilities))),
                Err(e) => {
                    if strategy.ignore(&p.by_ref().map(Into::into)) {
                        None
                    } else {
                        Some(Err(e))
                    }
                }
            })
            .transpose()?;

        // If the extensions proposal is ignored, remove it from the list of proposals.
        if extensions_proposal_and_capabilities.is_none() {
            state.proposals.clear_group_context_extensions();
        }

        match extensions_proposal_and_capabilities {
            Some((group_context_extensions_proposal, new_required_capabilities)) => {
                self.apply_proposals_with_new_capabilities(
                    strategy,
                    state,
                    group_context_extensions_proposal,
                    new_required_capabilities,
                    commit_time,
                )
                .await
            }
            None => {
                self.apply_tree_changes(
                    strategy,
                    state,
                    self.original_group_extensions,
                    self.original_required_capabilities,
                    commit_time,
                )
                .await
            }
        }
    }

    async fn apply_proposals_with_new_capabilities<F>(
        &self,
        strategy: &F,
        mut state: ProposalState,
        group_context_extensions_proposal: ProposalInfo<ExtensionList>,
        new_required_capabilities: Option<RequiredCapabilitiesExt>,
        commit_time: Option<MlsTime>,
    ) -> Result<ProposalState, MlsError>
    where
        F: FilterStrategy,
        C: IdentityProvider,
    {
        // Apply adds, updates etc. in the context of new extensions
        let new_state = self
            .apply_tree_changes(
                strategy,
                state.clone(),
                group_context_extensions_proposal.proposal(),
                new_required_capabilities.as_ref(),
                commit_time,
            )
            .await?;

        // Verify that capabilities and extensions are supported after modifications.
        // TODO: The newly inserted nodes have already been validated by `apply_tree_changes`
        // above. We should investigate if there is an easy way to avoid the double check.
        let new_capabilities_supported =
            new_required_capabilities.map_or(Ok(()), |new_required_capabilities| {
                let leaf_validator = LeafNodeValidator::new(
                    self.cipher_suite_provider,
                    Some(&new_required_capabilities),
                    self.identity_provider,
                    Some(group_context_extensions_proposal.proposal()),
                );

                new_state
                    .tree
                    .non_empty_leaves()
                    .try_for_each(|(_, leaf)| leaf_validator.validate_required_capabilities(leaf))
                    .map_err(MlsError::from)
            });

        let new_extensions_supported = group_context_extensions_proposal
            .proposal
            .iter()
            .map(|extension| extension.extension_type())
            .filter(|&ext_type| !ext_type.is_default())
            .find(|ext_type| {
                !new_state
                    .tree
                    .non_empty_leaves()
                    .all(|(_, leaf)| leaf.capabilities.extensions.contains(ext_type))
            })
            .map_or(Ok(()), |ext_type| {
                Err(MlsError::UnsupportedGroupExtension(ext_type))
            });

        let group_extensions_supported = new_capabilities_supported.and(new_extensions_supported);

        // If extensions are good, return `Ok`. If not and the strategy is to filter, remove the group
        // context extensions proposal and try applying all proposals again in the context of the old
        // extensions. Else, return an error.
        match group_extensions_supported {
            Ok(()) => Ok(new_state),
            Err(e) => {
                if strategy.ignore(&group_context_extensions_proposal.by_ref().map(Into::into)) {
                    state.proposals.clear_group_context_extensions();

                    self.apply_tree_changes(
                        strategy,
                        state,
                        self.original_group_extensions,
                        self.original_required_capabilities,
                        commit_time,
                    )
                    .await
                } else {
                    Err(e)
                }
            }
        }
    }

    async fn apply_tree_changes<F>(
        &self,
        strategy: &F,
        state: ProposalState,
        group_extensions_in_use: &ExtensionList,
        required_capabilities: Option<&RequiredCapabilitiesExt>,
        commit_time: Option<MlsTime>,
    ) -> Result<ProposalState, MlsError>
    where
        F: FilterStrategy,
    {
        let mut state = self
            .validate_new_nodes(
                strategy,
                state,
                group_extensions_in_use,
                required_capabilities,
                commit_time,
            )
            .await?;

        let mut updates = Vec::new();
        state
            .proposals
            .retain_by_type::<UpdateProposal, _, _>(|p| {
                let r = leaf_index_of_update_sender(p);

                if let Ok(leaf_index) = r {
                    updates.push((leaf_index, p.proposal.leaf_node.clone()));
                }

                apply_strategy(strategy, p, r.map(|_| ()))
            })?;

        let removals = state
            .proposals
            .by_type::<RemoveProposal>()
            .map(|p| p.proposal.to_remove)
            .collect::<Vec<_>>();

        let additions = state
            .proposals
            .by_type::<AddProposal>()
            .map(|p| p.proposal.key_package.leaf_node.clone())
            .collect::<Vec<_>>();

        let accumulator = TreeBatchEditAccumulator::new(strategy, &state.proposals);

        let accumulator = state
            .tree
            .batch_edit(
                accumulator,
                &updates,
                &removals,
                &additions,
                self.identity_provider,
                self.cipher_suite_provider,
            )
            .await?;

        let TreeBatchEditAccumulator {
            strategy: _,
            proposals: _,
            new_leaf_indexes,
            removed_leaves,
            invalid_additions,
            invalid_removals,
            invalid_updates,
        } = accumulator;

        state.added_indexes = new_leaf_indexes;
        state.removed_leaves = removed_leaves;

        invalid_additions
            .iter()
            .rev()
            .copied()
            .for_each(|i| state.proposals.remove::<AddProposal>(i));

        invalid_removals
            .iter()
            .rev()
            .copied()
            .for_each(|i| state.proposals.remove::<RemoveProposal>(i));

        invalid_updates
            .iter()
            .rev()
            .copied()
            .for_each(|i| state.proposals.remove::<UpdateProposal>(i));

        Ok(state)
    }

    async fn validate_new_nodes<F>(
        &self,
        strategy: &F,
        state: ProposalState,
        group_extensions_in_use: &ExtensionList,
        required_capabilities: Option<&RequiredCapabilitiesExt>,
        commit_time: Option<MlsTime>,
    ) -> Result<ProposalState, MlsError>
    where
        F: FilterStrategy,
    {
        let state = self
            .validate_new_update_nodes(
                strategy,
                state,
                group_extensions_in_use,
                required_capabilities,
                commit_time,
            )
            .await?;

        let state = self
            .validate_new_key_packages(
                strategy,
                state,
                group_extensions_in_use,
                required_capabilities,
                commit_time,
            )
            .await?;

        Ok(state)
    }

    async fn validate_new_update_nodes<F>(
        &self,
        strategy: &F,
        mut state: ProposalState,
        group_extensions_in_use: &ExtensionList,
        required_capabilities: Option<&RequiredCapabilitiesExt>,
        commit_time: Option<MlsTime>,
    ) -> Result<ProposalState, MlsError>
    where
        F: FilterStrategy,
    {
        let leaf_node_validator = &LeafNodeValidator::new(
            self.cipher_suite_provider,
            required_capabilities,
            self.identity_provider,
            Some(self.original_group_extensions),
        );

        let proposals = &mut state.proposals;

        let bad_update_indices =
            futures::stream::iter(proposals.by_type::<UpdateProposal>().enumerate().map(Ok))
                .try_filter_map(|(i, p)| async move {
                    let sender_index = leaf_index_of_update_sender(p)?;

                    let valid = leaf_node_validator
                        .check_if_valid(
                            &p.proposal.leaf_node,
                            ValidationContext::Update((self.group_id, *sender_index, commit_time)),
                        )
                        .await
                        .map_err(Into::into);

                    let extensions_are_supported =
                        leaf_supports_extensions(&p.proposal.leaf_node, group_extensions_in_use);

                    let res = valid.and(extensions_are_supported);
                    apply_strategy(strategy, p, res).map(|keep| (!keep).then_some(i))
                })
                .try_collect::<Vec<_>>()
                .await?;

        bad_update_indices
            .into_iter()
            .rev()
            .for_each(|i| proposals.remove::<UpdateProposal>(i));

        Ok(state)
    }

    async fn validate_new_key_packages<F>(
        &self,
        strategy: &F,
        mut state: ProposalState,
        group_extensions_in_use: &ExtensionList,
        required_capabilities: Option<&RequiredCapabilitiesExt>,
        commit_time: Option<MlsTime>,
    ) -> Result<ProposalState, MlsError>
    where
        F: FilterStrategy,
    {
        let package_validator = &KeyPackageValidator::new(
            self.protocol_version,
            self.cipher_suite_provider,
            required_capabilities,
            self.identity_provider,
            Some(group_extensions_in_use),
        );

        let proposals = &mut state.proposals;

        let bad_add_indices =
            futures::stream::iter(proposals.by_type::<AddProposal>().enumerate().map(Ok))
                .try_filter_map(|(i, p)| async move {
                    let options = KeyPackageValidationOptions {
                        apply_lifetime_check: commit_time,
                    };

                    let valid = package_validator
                        .check_if_valid(&p.proposal.key_package, options)
                        .await
                        .map_err(Into::into);

                    let extensions_are_supported = leaf_supports_extensions(
                        &p.proposal.key_package.leaf_node,
                        group_extensions_in_use,
                    );

                    let res = valid.and(extensions_are_supported);
                    apply_strategy(strategy, p, res).map(|keep| (!keep).then_some(i))
                })
                .try_collect::<Vec<_>>()
                .await?;

        bad_add_indices
            .into_iter()
            .rev()
            .for_each(|i| proposals.remove::<AddProposal>(i));

        Ok(state)
    }
}

fn leaf_supports_extensions(leaf: &LeafNode, extensions: &ExtensionList) -> Result<(), MlsError> {
    extensions
        .iter()
        .map(|ext| ext.extension_type())
        .filter(|&ext_type| !ext_type.is_default())
        .find(|ext_type| !leaf.capabilities.extensions.contains(ext_type))
        .map_or(Ok(()), |ext_type| {
            Err(MlsError::UnsupportedGroupExtension(ext_type))
        })
}

pub trait FilterStrategy {
    fn ignore(&self, proposal: &ProposalInfo<BorrowedProposal<'_>>) -> bool;
}

#[derive(Clone, Copy, Debug)]
pub struct IgnoreInvalidByRefProposal;

impl FilterStrategy for IgnoreInvalidByRefProposal {
    fn ignore(&self, p: &ProposalInfo<BorrowedProposal<'_>>) -> bool {
        p.is_by_reference()
    }
}

#[derive(Clone, Copy, Debug)]
pub struct FailInvalidProposal;

impl FilterStrategy for FailInvalidProposal {
    fn ignore(&self, _: &ProposalInfo<BorrowedProposal<'_>>) -> bool {
        false
    }
}

fn apply_strategy<F, P>(
    strategy: &F,
    proposal: &ProposalInfo<P>,
    r: Result<(), MlsError>,
) -> Result<bool, MlsError>
where
    F: FilterStrategy,
    for<'a> &'a P: Into<BorrowedProposal<'a>>,
{
    let p = proposal.by_ref().map(Into::into);
    r.map(|_| true)
        .or_else(|error| strategy.ignore(&p).then_some(false).ok_or(error))
}

fn filter_out_update_for_committer<F>(
    strategy: &F,
    commit_sender: LeafIndex,
    mut proposals: ProposalBundle,
) -> Result<ProposalBundle, MlsError>
where
    F: FilterStrategy,
{
    proposals.retain_by_type::<UpdateProposal, _, _>(|p| {
        apply_strategy(
            strategy,
            p,
            (p.sender != Sender::Member(*commit_sender))
                .then_some(())
                .ok_or(MlsError::InvalidCommitSelfUpdate),
        )
    })?;
    Ok(proposals)
}

fn filter_out_removal_of_committer<F>(
    strategy: &F,
    commit_sender: LeafIndex,
    mut proposals: ProposalBundle,
) -> Result<ProposalBundle, MlsError>
where
    F: FilterStrategy,
{
    proposals.retain_by_type::<RemoveProposal, _, _>(|p| {
        apply_strategy(
            strategy,
            p,
            (p.proposal.to_remove != commit_sender)
                .then_some(())
                .ok_or(MlsError::CommitterSelfRemoval),
        )
    })?;
    Ok(proposals)
}

fn filter_out_extra_removal_or_update_for_same_leaf<F>(
    strategy: &F,
    mut proposals: ProposalBundle,
) -> Result<ProposalBundle, MlsError>
where
    F: FilterStrategy,
{
    #[cfg(feature = "std")]
    let mut indexes = HashSet::new();

    #[cfg(not(feature = "std"))]
    let mut indexes = BTreeSet::new();

    proposals.retain_by_type::<RemoveProposal, _, _>(|p| {
        apply_strategy(
            strategy,
            p,
            indexes
                .insert(p.proposal.to_remove)
                .then_some(())
                .ok_or(MlsError::MoreThanOneProposalForLeaf(*p.proposal.to_remove)),
        )
    })?;

    #[cfg(feature = "std")]
    let per_leaf = HashMap::new();

    #[cfg(not(feature = "std"))]
    let per_leaf = BTreeMap::new();

    let last_update_indexes_per_leaf = proposals.by_type::<UpdateProposal>().enumerate().fold(
        per_leaf,
        |mut last_per_leaf, (i, p)| {
            if let Sender::Member(leaf_index) = p.sender {
                last_per_leaf.insert(leaf_index, i);
            }
            last_per_leaf
        },
    );

    let mut update_index = 0;

    proposals.retain_by_type::<UpdateProposal, _, _>(|p| {
        let index = update_index;
        update_index += 1;
        let leaf_index = match p.sender {
            Sender::Member(i) => LeafIndex(i),
            _ => return Ok(true),
        };

        let is_last_update = last_update_indexes_per_leaf.get(&leaf_index) == Some(&index);

        apply_strategy(
            strategy,
            p,
            (is_last_update && indexes.insert(leaf_index))
                .then_some(())
                .ok_or(MlsError::MoreThanOneProposalForLeaf(*leaf_index)),
        )
    })?;

    Ok(proposals)
}

#[cfg(feature = "external_proposal")]
async fn filter_out_invalid_group_extensions<F, C>(
    strategy: &F,
    mut proposals: ProposalBundle,
    identity_provider: &C,
    commit_time: Option<MlsTime>,
) -> Result<ProposalBundle, MlsError>
where
    F: FilterStrategy,
    C: IdentityProvider,
{
    let bad_indices =
        futures::stream::iter(proposals.by_type::<ExtensionList>().enumerate().map(Ok))
            .try_filter_map(|(i, p)| async move {
                let res = match p
                    .proposal
                    .get_as::<ExternalSendersExt>()
                    .map_err(Into::into)
                {
                    Ok(None) => Ok(()),
                    Ok(Some(extension)) => extension
                        .verify_all(identity_provider, commit_time, p.proposal())
                        .await
                        .map_err(|e| MlsError::IdentityProviderError(e.into())),
                    Err(e) => Err(e),
                };

                apply_strategy(strategy, p, res).map(|keep| (!keep).then_some(i))
            })
            .try_collect::<Vec<_>>()
            .await?;

    bad_indices
        .into_iter()
        .rev()
        .for_each(|i| proposals.remove::<ExtensionList>(i));

    Ok(proposals)
}

fn filter_out_extra_group_context_extensions<F>(
    strategy: &F,
    mut proposals: ProposalBundle,
) -> Result<ProposalBundle, MlsError>
where
    F: FilterStrategy,
{
    let mut found = false;

    proposals.retain_by_type::<ExtensionList, _, _>(|p| {
        apply_strategy(
            strategy,
            p,
            (!core::mem::replace(&mut found, true))
                .then_some(())
                .ok_or(MlsError::MoreThanOneGroupContextExtensionsProposal),
        )
    })?;

    Ok(proposals)
}

fn filter_out_invalid_reinit<F>(
    strategy: &F,
    mut proposals: ProposalBundle,
    protocol_version: ProtocolVersion,
) -> Result<ProposalBundle, MlsError>
where
    F: FilterStrategy,
{
    proposals.retain_by_type::<ReInitProposal, _, _>(|p| {
        apply_strategy(
            strategy,
            p,
            (p.proposal.version >= protocol_version)
                .then_some(())
                .ok_or(MlsError::InvalidProtocolVersionInReInit {
                    proposed: p.proposal.version,
                    original: protocol_version,
                }),
        )
    })?;

    Ok(proposals)
}

fn filter_out_reinit_if_other_proposals<F>(
    strategy: &F,
    mut proposals: ProposalBundle,
) -> Result<ProposalBundle, MlsError>
where
    F: FilterStrategy,
{
    let has_only_reinit = proposals
        .proposal_types()
        .all(|t| t == ProposalType::RE_INIT);

    let mut found = false;

    proposals.retain_by_type::<ReInitProposal, _, _>(|p| {
        apply_strategy(
            strategy,
            p,
            (has_only_reinit && !core::mem::replace(&mut found, true))
                .then_some(())
                .ok_or(MlsError::OtherProposalWithReInit),
        )
    })?;

    Ok(proposals)
}

#[cfg(feature = "external_commit")]
fn filter_out_external_init<F>(
    strategy: &F,
    commit_sender: LeafIndex,
    mut proposals: ProposalBundle,
) -> Result<ProposalBundle, MlsError>
where
    F: FilterStrategy,
{
    proposals.retain_by_type::<ExternalInit, _, _>(|p| {
        apply_strategy(
            strategy,
            p,
            Err(MlsError::InvalidProposalTypeForSender {
                proposal_type: ProposalType::EXTERNAL_INIT,
                sender: Sender::Member(*commit_sender),
                by_ref: p.is_by_reference(),
            }),
        )
    })?;

    Ok(proposals)
}

async fn filter_out_invalid_psks<F, P, CP>(
    strategy: &F,
    cipher_suite_provider: &CP,
    mut proposals: ProposalBundle,
    psk_storage: &P,
) -> Result<ProposalBundle, MlsError>
where
    F: FilterStrategy,
    P: PreSharedKeyStorage,
    CP: CipherSuiteProvider,
{
    let kdf_extract_size = cipher_suite_provider.kdf_extract_size();

    #[derive(Default)]
    struct ValidationState {
        #[cfg(feature = "std")]
        ids_seen: HashSet<PreSharedKeyID>,
        #[cfg(not(feature = "std"))]
        ids_seen: BTreeSet<PreSharedKeyID>,
        bad_indices: Vec<usize>,
    }

    let state = futures::stream::iter(
        proposals
            .by_type::<PreSharedKeyProposal>()
            .enumerate()
            .map(Ok),
    )
    .try_fold(ValidationState::default(), |mut state, (i, p)| async move {
        let valid = matches!(
            p.proposal.psk.key_id,
            JustPreSharedKeyID::External(_)
                | JustPreSharedKeyID::Resumption(ResumptionPsk {
                    usage: ResumptionPSKUsage::Application,
                    ..
                })
        );

        let nonce_length = p.proposal.psk.psk_nonce.0.len();
        let nonce_valid = nonce_length == kdf_extract_size;
        let is_new_id = state.ids_seen.insert(p.proposal.psk.clone());

        let external_id_is_valid = match &p.proposal.psk.key_id {
            JustPreSharedKeyID::External(id) => psk_storage
                .contains(id)
                .await
                .map_err(|e| MlsError::PskStoreError(e.into()))
                .and_then(|found| {
                    if found {
                        Ok(())
                    } else {
                        Err(MlsError::NoPskForId(id.clone()))
                    }
                }),
            JustPreSharedKeyID::Resumption(_) => Ok(()),
        };

        let res = if !valid {
            Err(MlsError::InvalidTypeOrUsageInPreSharedKeyProposal)
        } else if !nonce_valid {
            Err(MlsError::InvalidPskNonceLength {
                expected: kdf_extract_size,
                found: nonce_length,
            })
        } else if !is_new_id {
            Err(MlsError::DuplicatePskIds)
        } else {
            external_id_is_valid
        };

        let is_invalid_index = apply_strategy(strategy, p, res)?;

        if !is_invalid_index {
            state.bad_indices.push(i)
        }

        Ok::<_, MlsError>(state)
    })
    .await?;

    state
        .bad_indices
        .into_iter()
        .rev()
        .for_each(|i| proposals.remove::<PreSharedKeyProposal>(i));

    Ok(proposals)
}

fn validate_proposer<P, F>(
    strategy: &F,
    tree: &TreeKemPublic,
    #[cfg(feature = "external_proposal")] external_senders: Option<&ExternalSendersExt>,
    proposals: &mut ProposalBundle,
) -> Result<(), MlsError>
where
    P: Proposable,
    for<'a> &'a P: Into<BorrowedProposal<'a>>,
    F: FilterStrategy,
{
    proposals.retain_by_type::<P, _, _>(|p| {
        let res = proposer_can_propose(&p.sender, P::TYPE, p.is_by_reference())
            .then_some(())
            .ok_or_else(|| MlsError::InvalidProposalTypeForSender {
                proposal_type: P::TYPE,
                sender: p.sender,
                by_ref: p.is_by_reference(),
            })
            .and_then(|_| {
                validate_sender(
                    tree,
                    #[cfg(feature = "external_proposal")]
                    external_senders,
                    &p.sender,
                )
            });
        apply_strategy(strategy, p, res)
    })
}

fn validate_sender(
    tree: &TreeKemPublic,
    #[cfg(feature = "external_proposal")] external_senders: Option<&ExternalSendersExt>,
    sender: &Sender,
) -> Result<(), MlsError> {
    match *sender {
        Sender::Member(i) => tree
            .get_leaf_node(LeafIndex(i))
            .map(|_| ())
            .map_err(|_| MlsError::InvalidMemberProposer(i)),
        #[cfg(feature = "external_proposal")]
        Sender::External(i) => external_senders
            .ok_or(MlsError::ExternalProposalsDisabled)
            .and_then(|ext| {
                (ext.allowed_senders.len() > i as usize)
                    .then_some(())
                    .ok_or(MlsError::InvalidExternalSenderIndex(i))
            }),
        _ => Ok(()),
    }
}

pub(crate) fn proposer_can_propose(
    proposer: &Sender,
    proposal_type: ProposalType,
    by_ref: bool,
) -> bool {
    match (proposer, by_ref) {
        (Sender::Member(_), false) => matches!(
            proposal_type,
            ProposalType::ADD
                | ProposalType::REMOVE
                | ProposalType::PSK
                | ProposalType::RE_INIT
                | ProposalType::GROUP_CONTEXT_EXTENSIONS
        ),
        (Sender::Member(_), true) => matches!(
            proposal_type,
            ProposalType::ADD
                | ProposalType::UPDATE
                | ProposalType::REMOVE
                | ProposalType::PSK
                | ProposalType::RE_INIT
                | ProposalType::GROUP_CONTEXT_EXTENSIONS
        ),
        #[cfg(feature = "external_proposal")]
        (Sender::External(_), false) => false,
        #[cfg(feature = "external_proposal")]
        (Sender::External(_), true) => matches!(
            proposal_type,
            ProposalType::ADD
                | ProposalType::REMOVE
                | ProposalType::RE_INIT
                | ProposalType::PSK
                | ProposalType::GROUP_CONTEXT_EXTENSIONS
        ),
        #[cfg(feature = "external_commit")]
        (Sender::NewMemberCommit, false) => matches!(
            proposal_type,
            ProposalType::REMOVE | ProposalType::PSK | ProposalType::EXTERNAL_INIT
        ),
        #[cfg(feature = "external_commit")]
        (Sender::NewMemberCommit, true) => false,
        (Sender::NewMemberProposal, false) => false,
        (Sender::NewMemberProposal, true) => matches!(proposal_type, ProposalType::ADD),
    }
}

fn filter_out_invalid_proposers<F>(
    strategy: &F,
    tree: &TreeKemPublic,
    #[cfg(feature = "external_proposal")] group_context_extensions: &ExtensionList,
    mut proposals: ProposalBundle,
) -> Result<ProposalBundle, MlsError>
where
    F: FilterStrategy,
{
    #[cfg(feature = "external_proposal")]
    let external_senders = group_context_extensions.get_as().ok().flatten();

    #[cfg(feature = "external_proposal")]
    let external_senders = external_senders.as_ref();

    validate_proposer::<AddProposal, _>(
        strategy,
        tree,
        #[cfg(feature = "external_proposal")]
        external_senders,
        &mut proposals,
    )?;

    validate_proposer::<UpdateProposal, _>(
        strategy,
        tree,
        #[cfg(feature = "external_proposal")]
        external_senders,
        &mut proposals,
    )?;

    validate_proposer::<RemoveProposal, _>(
        strategy,
        tree,
        #[cfg(feature = "external_proposal")]
        external_senders,
        &mut proposals,
    )?;

    validate_proposer::<PreSharedKeyProposal, _>(
        strategy,
        tree,
        #[cfg(feature = "external_proposal")]
        external_senders,
        &mut proposals,
    )?;

    validate_proposer::<ReInitProposal, _>(
        strategy,
        tree,
        #[cfg(feature = "external_proposal")]
        external_senders,
        &mut proposals,
    )?;

    #[cfg(feature = "external_commit")]
    validate_proposer::<ExternalInit, _>(
        strategy,
        tree,
        #[cfg(feature = "external_proposal")]
        external_senders,
        &mut proposals,
    )?;

    validate_proposer::<ExtensionList, _>(
        strategy,
        tree,
        #[cfg(feature = "external_proposal")]
        external_senders,
        &mut proposals,
    )?;

    Ok(proposals)
}

#[cfg(feature = "external_commit")]
fn ensure_exactly_one_external_init(proposals: &ProposalBundle) -> Result<(), MlsError> {
    (proposals.by_type::<ExternalInit>().count() == 1)
        .then_some(())
        .ok_or(MlsError::ExternalCommitMustHaveExactlyOneExternalInit)
}

#[cfg(feature = "external_commit")]
fn ensure_proposals_in_external_commit_are_allowed(
    proposals: &ProposalBundle,
) -> Result<(), MlsError> {
    let unsupported_type = proposals.proposal_types().find(|ty| {
        ![
            ProposalType::EXTERNAL_INIT,
            ProposalType::REMOVE,
            ProposalType::PSK,
        ]
        .contains(ty)
    });

    match unsupported_type {
        Some(kind) => Err(MlsError::InvalidProposalTypeInExternalCommit(kind)),
        None => Ok(()),
    }
}

#[cfg(feature = "external_commit")]
async fn ensure_at_most_one_removal_for_self<C>(
    proposals: &ProposalBundle,
    external_leaf: &LeafNode,
    tree: &TreeKemPublic,
    identity_provider: &C,
) -> Result<(), MlsError>
where
    C: IdentityProvider,
{
    let mut removals = proposals.by_type::<RemoveProposal>();

    match (removals.next(), removals.next()) {
        (Some(removal), None) => {
            ensure_removal_is_for_self(&removal.proposal, external_leaf, tree, identity_provider)
                .await
        }
        (Some(_), Some(_)) => Err(MlsError::ExternalCommitWithMoreThanOneRemove),
        (None, _) => Ok(()),
    }
}

#[cfg(feature = "external_commit")]
async fn ensure_removal_is_for_self<C>(
    removal: &RemoveProposal,
    external_leaf: &LeafNode,
    tree: &TreeKemPublic,
    identity_provider: &C,
) -> Result<(), MlsError>
where
    C: IdentityProvider,
{
    let existing_signing_id = &tree.get_leaf_node(removal.to_remove)?.signing_identity;

    identity_provider
        .valid_successor(existing_signing_id, &external_leaf.signing_identity)
        .await
        .map_err(|e| MlsError::IdentityProviderError(e.into()))?
        .then_some(())
        .ok_or(MlsError::ExternalCommitRemovesOtherIdentity)
}

#[cfg(feature = "external_commit")]
fn ensure_no_proposal_by_ref(proposals: &ProposalBundle) -> Result<(), MlsError> {
    proposals
        .iter_proposals()
        .all(|p| p.is_by_value())
        .then_some(())
        .ok_or(MlsError::OnlyMembersCanCommitProposalsByRef)
}

fn leaf_index_of_update_sender(p: &ProposalInfo<UpdateProposal>) -> Result<LeafIndex, MlsError> {
    match p.sender {
        Sender::Member(i) => Ok(LeafIndex(i)),
        _ => Err(MlsError::InvalidProposalTypeForSender {
            proposal_type: ProposalType::UPDATE,
            sender: p.sender,
            by_ref: p.is_by_reference(),
        }),
    }
}

#[cfg(feature = "external_commit")]
async fn insert_external_leaf<I, CP>(
    mut state: ProposalState,
    leaf_node: LeafNode,
    identity_provider: &I,
    cipher_suite_provider: &CP,
) -> Result<ProposalState, MlsError>
where
    I: IdentityProvider,
    CP: CipherSuiteProvider,
{
    let leaf_indexes = state
        .tree
        .add_leaves(vec![leaf_node], identity_provider, cipher_suite_provider)
        .await?;

    state.external_leaf_index = leaf_indexes.first().copied();
    Ok(state)
}

#[cfg(feature = "custom_proposal")]
fn filter_out_unsupported_custom_proposals<F>(
    mut state: ProposalState,
    strategy: &F,
) -> Result<ProposalState, MlsError>
where
    F: FilterStrategy,
{
    let supported_types = state
        .proposals
        .custom_proposal_types()
        .filter(|t| state.tree.can_support_proposal(*t))
        .collect_vec();

    state.proposals.retain_custom(|p| {
        apply_strategy(
            strategy,
            p,
            supported_types
                .contains(&p.proposal.proposal_type())
                .then_some(())
                .ok_or_else(|| MlsError::UnsupportedCustomProposal(p.proposal.proposal_type())),
        )
    })?;

    Ok(state)
}

struct TreeBatchEditAccumulator<'a, F> {
    strategy: &'a F,
    proposals: &'a ProposalBundle,
    new_leaf_indexes: Vec<LeafIndex>,
    removed_leaves: Vec<(LeafIndex, LeafNode)>,
    invalid_additions: BTreeSet<usize>,
    invalid_removals: BTreeSet<usize>,
    invalid_updates: BTreeSet<usize>,
}

impl<'a, F: FilterStrategy> TreeBatchEditAccumulator<'a, F> {
    fn new(strategy: &'a F, proposals: &'a ProposalBundle) -> Self {
        Self {
            strategy,
            proposals,
            new_leaf_indexes: Default::default(),
            removed_leaves: Default::default(),
            invalid_additions: Default::default(),
            invalid_removals: Default::default(),
            invalid_updates: Default::default(),
        }
    }

    fn apply_strategy<T>(&self, index: usize, r: Result<(), MlsError>) -> Result<(), MlsError>
    where
        T: Proposable,
        for<'b> BorrowedProposal<'b>: From<&'b T>,
    {
        match r {
            Ok(()) => Ok(()),
            Err(e) => {
                if self.strategy.ignore(
                    &self.proposals.by_index::<T>()[index]
                        .by_ref()
                        .map(Into::into),
                ) {
                    Ok(())
                } else {
                    Err(e)
                }
            }
        }
    }
}

impl<F: FilterStrategy> AccumulateBatchResults for TreeBatchEditAccumulator<'_, F> {
    type Output = Self;

    fn on_update(&mut self, index: usize, r: Result<LeafIndex, MlsError>) -> Result<(), MlsError> {
        if r.is_err() {
            self.invalid_updates.insert(index);
        }
        self.apply_strategy::<UpdateProposal>(index, r.map(|_| ()))
    }

    fn on_remove(
        &mut self,
        index: usize,
        r: Result<(LeafIndex, LeafNode), MlsError>,
    ) -> Result<(), MlsError> {
        let r = match r {
            Ok(leaf) => {
                self.removed_leaves.push(leaf);
                Ok(())
            }
            Err(e) => {
                self.invalid_removals.insert(index);
                Err(e)
            }
        };
        self.apply_strategy::<RemoveProposal>(index, r)
    }

    fn on_add(&mut self, index: usize, r: Result<LeafIndex, MlsError>) -> Result<(), MlsError> {
        match r {
            Ok(leaf_index) => self.new_leaf_indexes.push(leaf_index),
            Err(_) => {
                self.invalid_additions.insert(index);
            }
        }
        self.apply_strategy::<AddProposal>(index, r.map(|_| ()))
    }

    fn finish(self) -> Result<Self::Output, MlsError> {
        Ok(self)
    }
}
