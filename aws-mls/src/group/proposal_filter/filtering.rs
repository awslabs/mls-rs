use crate::{
    client::MlsError,
    extension::RequiredCapabilitiesExt,
    group::{
        proposal::ReInitProposal,
        proposal_filter::{ProposalBundle, ProposalInfo},
        AddProposal, ProposalType, RemoveProposal, Sender, UpdateProposal,
    },
    key_package::validate_key_package_properties,
    protocol_version::ProtocolVersion,
    time::MlsTime,
    tree_kem::{
        leaf_node::LeafNode,
        leaf_node_validator::{LeafNodeValidator, ValidationContext},
        node::LeafIndex,
        TreeKemPublic,
    },
    CipherSuiteProvider, ExtensionList,
};

#[cfg(feature = "external_proposal")]
use crate::extension::ExternalSendersExt;

#[cfg(feature = "external_commit")]
use alloc::vec;

use alloc::vec::Vec;
use aws_mls_core::{identity::IdentityProvider, psk::PreSharedKeyStorage};

#[cfg(feature = "custom_proposal")]
use itertools::Itertools;

#[cfg(feature = "external_commit")]
use crate::group::ExternalInit;

#[cfg(feature = "psk")]
use crate::group::{
    proposal::PreSharedKeyProposal, JustPreSharedKeyID, ResumptionPSKUsage, ResumptionPsk,
};

#[cfg(all(feature = "std", feature = "psk"))]
use std::collections::HashSet;

#[cfg(any(
    feature = "external_commit",
    feature = "external_proposal",
    feature = "psk"
))]
use aws_mls_core::error::IntoAnyError;

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

    #[maybe_async::maybe_async]
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

    #[maybe_async::maybe_async]
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
        let proposals = filter_out_invalid_proposers(strategy, proposals)?;
        let proposals = filter_out_update_for_committer(strategy, commit_sender, proposals)?;
        let proposals = filter_out_removal_of_committer(strategy, commit_sender, proposals)?;

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
        let proposals = filter_out_reinit_if_other_proposals(F::is_ignore(), proposals)?;

        #[cfg(feature = "external_commit")]
        let proposals = filter_out_external_init(strategy, commit_sender, proposals)?;

        let state = ProposalState::new(self.original_tree.clone(), proposals);
        let state = self
            .apply_proposal_changes(strategy, state, commit_time)
            .await?;
        Ok(state)
    }

    #[cfg(feature = "external_commit")]
    #[maybe_async::maybe_async]
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

        let proposals = filter_out_invalid_proposers(&FailInvalidProposal, proposals)?;

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

    #[maybe_async::maybe_async]
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
                    if strategy.ignore(p.is_by_reference()) {
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

    #[maybe_async::maybe_async]
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
                if strategy.ignore(group_context_extensions_proposal.is_by_reference()) {
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

    #[maybe_async::maybe_async]
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

        let res = state
            .tree
            .batch_edit(
                &mut state.proposals,
                self.identity_provider,
                self.cipher_suite_provider,
                F::is_ignore(),
            )
            .await?;

        (state.removed_leaves, state.added_indexes) = (res.removed, res.added);

        Ok(state)
    }

    #[maybe_async::maybe_async]
    async fn validate_new_nodes<F>(
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
            Some(group_extensions_in_use),
        );

        let mut bad_indices = Vec::new();

        for (i, p) in state.proposals.by_type::<UpdateProposal>().enumerate() {
            let sender_index = leaf_index_of_update_sender(p)?;

            let valid = leaf_node_validator
                .check_if_valid(
                    &p.proposal.leaf_node,
                    ValidationContext::Update((self.group_id, *sender_index, commit_time)),
                )
                .await;

            let extensions_are_supported =
                leaf_supports_extensions(&p.proposal.leaf_node, group_extensions_in_use);

            let res = valid.and(extensions_are_supported);

            if !apply_strategy(strategy, p.is_by_reference(), res)? {
                bad_indices.push(i);
            }
        }

        bad_indices
            .into_iter()
            .rev()
            .for_each(|i| state.proposals.remove::<UpdateProposal>(i));

        let mut bad_indices = Vec::new();

        for (i, p) in state.proposals.by_type::<AddProposal>().enumerate() {
            let valid = leaf_node_validator
                .check_if_valid(
                    &p.proposal.key_package.leaf_node,
                    ValidationContext::Add(commit_time),
                )
                .await;

            let extensions_are_supported = leaf_supports_extensions(
                &p.proposal.key_package.leaf_node,
                group_extensions_in_use,
            );

            let res = valid.and(extensions_are_supported).and(
                validate_key_package_properties(
                    &p.proposal.key_package,
                    self.protocol_version,
                    self.cipher_suite_provider,
                )
                .await,
            );

            if !apply_strategy(strategy, p.is_by_reference(), res)? {
                bad_indices.push(i);
            }
        }

        bad_indices
            .into_iter()
            .rev()
            .for_each(|i| state.proposals.remove::<AddProposal>(i));

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
    fn ignore(&self, by_ref: bool) -> bool;
    fn is_ignore() -> bool;
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct IgnoreInvalidByRefProposal;

impl FilterStrategy for IgnoreInvalidByRefProposal {
    fn ignore(&self, by_ref: bool) -> bool {
        by_ref
    }

    fn is_ignore() -> bool {
        true
    }
}

#[derive(Clone, Copy, Debug)]
pub struct FailInvalidProposal;

impl FilterStrategy for FailInvalidProposal {
    fn ignore(&self, _: bool) -> bool {
        false
    }

    fn is_ignore() -> bool {
        false
    }
}

fn apply_strategy<F>(strategy: &F, by_ref: bool, r: Result<(), MlsError>) -> Result<bool, MlsError>
where
    F: FilterStrategy,
{
    r.map(|_| true)
        .or_else(|error| strategy.ignore(by_ref).then_some(false).ok_or(error))
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
            p.is_by_reference(),
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
            p.is_by_reference(),
            (p.proposal.to_remove != commit_sender)
                .then_some(())
                .ok_or(MlsError::CommitterSelfRemoval),
        )
    })?;
    Ok(proposals)
}

#[cfg(feature = "external_proposal")]
#[maybe_async::maybe_async]
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
    let mut bad_indices = Vec::new();

    for (i, p) in proposals.by_type::<ExtensionList>().enumerate() {
        let ext = p.proposal.get_as::<ExternalSendersExt>();

        let res = match ext {
            Ok(None) => Ok(()),
            Ok(Some(extension)) => extension
                .verify_all(identity_provider, commit_time, p.proposal())
                .await
                .map_err(|e| MlsError::IdentityProviderError(e.into_any_error())),
            Err(e) => Err(MlsError::ExtensionError(e)),
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
            p.is_by_reference(),
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
            p.is_by_reference(),
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

fn filter_out_reinit_if_other_proposals(
    filter: bool,
    mut proposals: ProposalBundle,
) -> Result<ProposalBundle, MlsError> {
    let has_other_types = proposals
        .proposal_types()
        .any(|t| t != ProposalType::RE_INIT);

    if has_other_types {
        let any_by_val = proposals.reinit_proposals().iter().any(|p| p.is_by_value());

        if any_by_val || (!proposals.reinit_proposals().is_empty() && !filter) {
            return Err(MlsError::OtherProposalWithReInit);
        }

        proposals.reinitializations = Vec::new();
    }

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
            p.is_by_reference(),
            Err(MlsError::InvalidProposalTypeForSender {
                proposal_type: ProposalType::EXTERNAL_INIT,
                sender: Sender::Member(*commit_sender),
                by_ref: p.is_by_reference(),
            }),
        )
    })?;

    Ok(proposals)
}

#[cfg(feature = "psk")]
#[maybe_async::maybe_async]
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

    #[cfg(feature = "std")]
    let mut ids_seen = HashSet::new();

    #[cfg(not(feature = "std"))]
    let mut ids_seen = Vec::new();

    let mut bad_indices = Vec::new();

    for (i, p) in proposals.by_type::<PreSharedKeyProposal>().enumerate() {
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

        #[cfg(feature = "std")]
        let is_new_id = ids_seen.insert(p.proposal.psk.clone());

        #[cfg(not(feature = "std"))]
        let is_new_id = ids_seen.contains(&p.proposal.psk);

        let external_id_is_valid = match &p.proposal.psk.key_id {
            JustPreSharedKeyID::External(id) => psk_storage
                .contains(id)
                .await
                .map_err(|e| MlsError::PskStoreError(e.into_any_error()))
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

        if !apply_strategy(strategy, p.is_by_reference(), res)? {
            bad_indices.push(i)
        }

        #[cfg(not(feature = "std"))]
        ids_seen.push(p.proposal.psk.clone());
    }

    bad_indices
        .into_iter()
        .rev()
        .for_each(|i| proposals.remove::<PreSharedKeyProposal>(i));

    Ok(proposals)
}

#[cfg(not(feature = "psk"))]
#[maybe_async::maybe_async]
async fn filter_out_invalid_psks<F, P, CP>(
    _: &F,
    _: &CP,
    proposals: ProposalBundle,
    _: &P,
) -> Result<ProposalBundle, MlsError>
where
    F: FilterStrategy,
    P: PreSharedKeyStorage,
    CP: CipherSuiteProvider,
{
    Ok(proposals)
}

pub(crate) fn proposer_can_propose(
    proposer: Sender,
    proposal_type: ProposalType,
    by_ref: bool,
) -> Result<(), MlsError> {
    let can_propose = match (proposer, by_ref) {
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
    };

    can_propose
        .then_some(())
        .ok_or(MlsError::InvalidProposalTypeForSender {
            proposal_type,
            sender: proposer,
            by_ref,
        })
}

fn filter_out_invalid_proposers<F>(
    strategy: &F,
    mut proposals: ProposalBundle,
) -> Result<ProposalBundle, MlsError>
where
    F: FilterStrategy,
{
    for i in (0..proposals.add_proposals().len()).rev() {
        let p = &proposals.add_proposals()[i];
        let res = proposer_can_propose(p.sender, ProposalType::ADD, p.is_by_reference());

        if !apply_strategy(strategy, p.is_by_reference(), res)? {
            proposals.remove::<AddProposal>(i);
        }
    }

    for i in (0..proposals.update_proposals().len()).rev() {
        let p = &proposals.update_proposals()[i];
        let res = proposer_can_propose(p.sender, ProposalType::UPDATE, p.is_by_reference());

        if !apply_strategy(strategy, p.is_by_reference(), res)? {
            proposals.remove::<UpdateProposal>(i);
        }
    }

    for i in (0..proposals.remove_proposals().len()).rev() {
        let p = &proposals.remove_proposals()[i];
        let res = proposer_can_propose(p.sender, ProposalType::REMOVE, p.is_by_reference());

        if !apply_strategy(strategy, p.is_by_reference(), res)? {
            proposals.remove::<RemoveProposal>(i);
        }
    }

    #[cfg(feature = "psk")]
    for i in (0..proposals.psk_proposals().len()).rev() {
        let p = &proposals.psk_proposals()[i];
        let res = proposer_can_propose(p.sender, ProposalType::PSK, p.is_by_reference());

        if !apply_strategy(strategy, p.is_by_reference(), res)? {
            proposals.remove::<PreSharedKeyProposal>(i);
        }
    }

    for i in (0..proposals.reinit_proposals().len()).rev() {
        let p = &proposals.reinit_proposals()[i];
        let res = proposer_can_propose(p.sender, ProposalType::RE_INIT, p.is_by_reference());

        if !apply_strategy(strategy, p.is_by_reference(), res)? {
            proposals.remove::<ReInitProposal>(i);
        }
    }

    #[cfg(feature = "external_commit")]
    for i in (0..proposals.external_init_proposals().len()).rev() {
        let p = &proposals.external_init_proposals()[i];
        let res = proposer_can_propose(p.sender, ProposalType::EXTERNAL_INIT, p.is_by_reference());

        if !apply_strategy(strategy, p.is_by_reference(), res)? {
            proposals.remove::<ExternalInit>(i);
        }
    }

    for i in (0..proposals.group_context_ext_proposals().len()).rev() {
        let p = &proposals.group_context_ext_proposals()[i];
        let gce_type = ProposalType::GROUP_CONTEXT_EXTENSIONS;
        let res = proposer_can_propose(p.sender, gce_type, p.is_by_reference());

        if !apply_strategy(strategy, p.is_by_reference(), res)? {
            proposals.remove::<ExtensionList>(i);
        }
    }

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
#[maybe_async::maybe_async]
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
#[maybe_async::maybe_async]
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
        .map_err(|e| MlsError::IdentityProviderError(e.into_any_error()))?
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
#[maybe_async::maybe_async]
async fn insert_external_leaf<I: IdentityProvider, CP: CipherSuiteProvider>(
    mut state: ProposalState,
    leaf_node: LeafNode,
    identity_provider: &I,
    cipher_suite_provider: &CP,
) -> Result<ProposalState, MlsError> {
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
            p.is_by_reference(),
            supported_types
                .contains(&p.proposal.proposal_type())
                .then_some(())
                .ok_or_else(|| MlsError::UnsupportedCustomProposal(p.proposal.proposal_type())),
        )
    })?;

    Ok(state)
}
