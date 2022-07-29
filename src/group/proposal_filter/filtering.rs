use crate::{
    cipher_suite::CipherSuite,
    client_config::CredentialValidator,
    extension::{ExtensionList, ExternalSendersExt, RequiredCapabilitiesExt},
    group::{
        proposal_filter::{Proposable, ProposalBundle, ProposalFilterError, ProposalInfo},
        AddProposal, BorrowedProposal, ExternalInit, JustPreSharedKeyID, KeyScheduleKdf,
        PreSharedKey, ProposalType, ReInit, RemoveProposal, ResumptionPSKUsage, ResumptionPsk,
        Sender, UpdateProposal,
    },
    key_package::KeyPackageValidator,
    tree_kem::{
        leaf_node::LeafNode,
        leaf_node_validator::{LeafNodeValidator, ValidationContext},
        node::LeafIndex,
        AccumulateBatchResults, RatchetTreeError, TreeKemPublic,
    },
    ProtocolVersion,
};
use std::{
    collections::{HashMap, HashSet},
    convert::Infallible,
};

#[derive(Clone, Debug)]
pub(crate) struct ProposalState {
    pub(crate) tree: TreeKemPublic,
    pub(crate) proposals: ProposalBundle,
    pub(crate) added_indexes: Vec<LeafIndex>,
    pub(crate) removed_leaves: Vec<(LeafIndex, LeafNode)>,
    pub(crate) external_leaf_index: Option<LeafIndex>,
}

impl ProposalState {
    fn new(tree: TreeKemPublic, proposals: ProposalBundle) -> Self {
        Self {
            tree,
            proposals,
            added_indexes: Vec::new(),
            removed_leaves: Vec::new(),
            external_leaf_index: None,
        }
    }
}

#[derive(Debug)]
pub(crate) struct ProposalApplier<'a, C> {
    original_tree: &'a TreeKemPublic,
    protocol_version: ProtocolVersion,
    cipher_suite: CipherSuite,
    group_id: &'a [u8],
    original_required_capabilities: Option<&'a RequiredCapabilitiesExt>,
    external_leaf: Option<&'a LeafNode>,
    credential_validator: C,
}

impl<'a, C> ProposalApplier<'a, C>
where
    C: CredentialValidator,
{
    pub(crate) fn new(
        original_tree: &'a TreeKemPublic,
        protocol_version: ProtocolVersion,
        cipher_suite: CipherSuite,
        group_id: &'a [u8],
        original_required_capabilities: Option<&'a RequiredCapabilitiesExt>,
        external_leaf: Option<&'a LeafNode>,
        credential_validator: C,
    ) -> Self {
        Self {
            original_tree,
            protocol_version,
            cipher_suite,
            group_id,
            original_required_capabilities,
            external_leaf,
            credential_validator,
        }
    }

    pub(crate) fn apply_proposals<F>(
        &self,
        strategy: F,
        commit_sender: &Sender,
        proposals: ProposalBundle,
    ) -> Result<ProposalState, ProposalFilterError>
    where
        F: FilterStrategy,
    {
        match commit_sender {
            Sender::Member(sender) => {
                self.apply_proposals_from_member(strategy, *sender, proposals)
            }
            Sender::NewMemberCommit => self.apply_proposals_from_new_member(proposals),
            Sender::External(_) | Sender::NewMemberProposal => {
                Err(ProposalFilterError::ExternalSenderCannotCommit)
            }
        }
    }

    fn apply_proposals_from_member<F>(
        &self,
        strategy: F,
        commit_sender: LeafIndex,
        proposals: ProposalBundle,
    ) -> Result<ProposalState, ProposalFilterError>
    where
        F: FilterStrategy,
    {
        let proposals = filter_out_update_for_committer(&strategy, commit_sender, proposals)?;
        let proposals = filter_out_removal_of_committer(&strategy, commit_sender, proposals)?;
        let proposals = filter_out_extra_removal_or_update_for_same_leaf(&strategy, proposals)?;
        let proposals = filter_out_invalid_psks(&strategy, self.cipher_suite, proposals)?;

        let proposals = filter_out_invalid_group_extensions(
            &strategy,
            proposals,
            self.cipher_suite,
            &self.credential_validator,
        )?;

        let proposals = filter_out_extra_group_context_extensions(&strategy, proposals)?;
        let proposals = filter_out_invalid_reinit(&strategy, proposals, self.protocol_version)?;
        let proposals = filter_out_reinit_if_other_proposals(&strategy, proposals)?;
        let proposals = filter_out_external_init(&strategy, proposals)?;

        let state = ProposalState::new(self.original_tree.clone(), proposals);
        let state = self.apply_proposal_changes(&strategy, state)?;
        Ok(state)
    }

    fn apply_proposals_from_new_member(
        &self,
        proposals: ProposalBundle,
    ) -> Result<ProposalState, ProposalFilterError> {
        let external_leaf = self
            .external_leaf
            .ok_or(ProposalFilterError::ExternalCommitMustHaveNewLeaf)?;

        ensure_exactly_one_external_init(&proposals)?;

        ensure_at_most_one_removal_for_self(
            &proposals,
            external_leaf,
            self.original_tree,
            &self.credential_validator,
        )?;

        ensure_proposals_in_external_commit_are_allowed(&proposals)?;
        ensure_no_proposal_by_ref(&proposals)?;
        let proposals = filter_out_invalid_psks(FailInvalidProposal, self.cipher_suite, proposals)?;
        let state = ProposalState::new(self.original_tree.clone(), proposals);

        let state = self.apply_proposal_changes(&FailInvalidProposal, state)?;

        let state = insert_external_leaf(state, external_leaf.clone())?;
        Ok(state)
    }

    fn apply_proposal_changes<F>(
        &self,
        strategy: F,
        state: ProposalState,
    ) -> Result<ProposalState, ProposalFilterError>
    where
        F: FilterStrategy,
    {
        let extensions_proposal_and_capabilities = state
            .proposals
            .by_type::<ExtensionList>()
            .next()
            .cloned()
            .and_then(|p| {
                match p
                    .proposal
                    .get_extension()
                    .map_err(ProposalFilterError::from)
                {
                    Ok(capabilities) => capabilities.map(|c| Ok((p, c))),
                    Err(e) => {
                        if strategy.ignore(&p.by_ref().map(Into::into)) {
                            None
                        } else {
                            Some(Err(e))
                        }
                    }
                }
            })
            .transpose()?;

        match extensions_proposal_and_capabilities {
            Some((group_context_extensions_proposal, new_required_capabilities)) => self
                .apply_proposals_with_new_capabilities(
                    strategy,
                    state,
                    group_context_extensions_proposal,
                    &new_required_capabilities,
                ),
            None => self.apply_tree_changes(strategy, state, self.original_required_capabilities),
        }
    }

    fn apply_proposals_with_new_capabilities<F>(
        &self,
        strategy: F,
        state: ProposalState,
        group_context_extensions_proposal: ProposalInfo<ExtensionList>,
        new_required_capabilities: &RequiredCapabilitiesExt,
    ) -> Result<ProposalState, ProposalFilterError>
    where
        F: FilterStrategy,
        C: CredentialValidator,
    {
        let new_state = self.apply_tree_changes(&strategy, state.clone(), None)?;

        let leaf_validator = LeafNodeValidator::new(
            self.cipher_suite,
            Some(new_required_capabilities),
            &self.credential_validator,
        );

        let new_capabilities_supported = new_state
            .tree
            .non_empty_leaves()
            .try_for_each(|(_, leaf)| leaf_validator.validate_required_capabilities(leaf))
            .map_err(Into::into);

        match new_capabilities_supported {
            Ok(()) => Ok(new_state),
            Err(e) => {
                let ignored =
                    strategy.ignore(&group_context_extensions_proposal.by_ref().map(Into::into));
                match (ignored, self.original_required_capabilities) {
                    (false, _) => Err(e),
                    (true, Some(required_capabilities)) => {
                        self.apply_tree_changes(&strategy, state, Some(required_capabilities))
                    }
                    (true, None) => Ok(new_state),
                }
            }
        }
    }

    fn apply_tree_changes<F>(
        &self,
        strategy: F,
        state: ProposalState,
        required_capabilities: Option<&RequiredCapabilitiesExt>,
    ) -> Result<ProposalState, ProposalFilterError>
    where
        F: FilterStrategy,
    {
        let mut state = self.validate_new_nodes(&strategy, state, required_capabilities)?;

        let mut updates = Vec::new();
        state
            .proposals
            .retain_by_type::<UpdateProposal, _, _>(|p| {
                let r = update_sender_leaf_index(&p.sender);

                if let Ok(leaf_index) = r {
                    updates.push((leaf_index, p.proposal.leaf_node.clone()));
                }

                apply_strategy(&strategy, p, r.map(|_| ()))
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

        let accumulator = TreeBatchEditAccumulator::new(&strategy, &state.proposals);

        let accumulator = state
            .tree
            .batch_edit(accumulator, &updates, &removals, &additions)?;

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

        let mut i = 0;
        let _ = state
            .proposals
            .retain_by_type::<AddProposal, _, Infallible>(|_| {
                let keep = !invalid_additions.contains(&i);
                i += 1;
                Ok(keep)
            });

        let mut i = 0;
        let _ = state
            .proposals
            .retain_by_type::<RemoveProposal, _, Infallible>(|_| {
                let keep = !invalid_removals.contains(&i);
                i += 1;
                Ok(keep)
            });

        let mut i = 0;
        let _ = state
            .proposals
            .retain_by_type::<UpdateProposal, _, Infallible>(|_| {
                let keep = !invalid_updates.contains(&i);
                i += 1;
                Ok(keep)
            });

        Ok(state)
    }

    fn validate_new_nodes<F>(
        &self,
        strategy: F,
        state: ProposalState,
        required_capabilities: Option<&RequiredCapabilitiesExt>,
    ) -> Result<ProposalState, ProposalFilterError>
    where
        F: FilterStrategy,
    {
        let state = self.validate_new_update_nodes(&strategy, state, required_capabilities)?;

        let state = self.validate_new_key_packages(&strategy, state, required_capabilities)?;

        Ok(state)
    }

    fn validate_new_update_nodes<F>(
        &self,
        strategy: F,
        mut state: ProposalState,
        required_capabilities: Option<&RequiredCapabilitiesExt>,
    ) -> Result<ProposalState, ProposalFilterError>
    where
        F: FilterStrategy,
    {
        let leaf_node_validator = LeafNodeValidator::new(
            self.cipher_suite,
            required_capabilities,
            &self.credential_validator,
        );

        let proposals = &mut state.proposals;

        proposals.retain_by_type::<UpdateProposal, _, _>(|p| {
            let res = leaf_node_validator
                .check_if_valid(
                    &p.proposal.leaf_node,
                    ValidationContext::Update(self.group_id),
                )
                .map_err(Into::into);

            apply_strategy(&strategy, p, res)
        })?;

        Ok(state)
    }

    fn validate_new_key_packages<F>(
        &self,
        strategy: F,
        mut state: ProposalState,
        required_capabilities: Option<&RequiredCapabilitiesExt>,
    ) -> Result<ProposalState, ProposalFilterError>
    where
        F: FilterStrategy,
    {
        let package_validator = KeyPackageValidator::new(
            self.protocol_version,
            self.cipher_suite,
            required_capabilities,
            &self.credential_validator,
        );

        let proposals = &mut state.proposals;

        proposals.retain_by_type::<AddProposal, _, _>(|p| {
            let res = package_validator
                .check_if_valid(&p.proposal.key_package, Default::default())
                .map_err(Into::into);

            apply_strategy(&strategy, p, res)
        })?;

        Ok(state)
    }
}

pub trait FilterStrategy {
    fn ignore(&self, proposal: &ProposalInfo<BorrowedProposal<'_>>) -> bool;
}

impl<T: FilterStrategy + ?Sized> FilterStrategy for &T {
    fn ignore(&self, proposal: &ProposalInfo<BorrowedProposal<'_>>) -> bool {
        (*self).ignore(proposal)
    }
}

#[derive(Clone, Copy, Debug)]
pub struct IgnoreInvalidByRefProposal;

impl FilterStrategy for IgnoreInvalidByRefProposal {
    fn ignore(&self, p: &ProposalInfo<BorrowedProposal<'_>>) -> bool {
        p.proposal_ref.is_some()
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
    strategy: F,
    proposal: &ProposalInfo<P>,
    r: Result<(), ProposalFilterError>,
) -> Result<bool, ProposalFilterError>
where
    F: FilterStrategy,
    for<'a> &'a P: Into<BorrowedProposal<'a>>,
{
    let p = proposal.by_ref().map(Into::into);
    r.map(|_| true)
        .or_else(|error| strategy.ignore(&p).then_some(false).ok_or(error))
}

fn filter_out_update_for_committer<F>(
    strategy: F,
    commit_sender: LeafIndex,
    mut proposals: ProposalBundle,
) -> Result<ProposalBundle, ProposalFilterError>
where
    F: FilterStrategy,
{
    proposals.retain_by_type::<UpdateProposal, _, _>(|p| {
        apply_strategy(
            &strategy,
            p,
            (p.sender != Sender::Member(commit_sender))
                .then_some(())
                .ok_or(ProposalFilterError::InvalidCommitSelfUpdate),
        )
    })?;
    Ok(proposals)
}

fn filter_out_removal_of_committer<F>(
    strategy: F,
    commit_sender: LeafIndex,
    mut proposals: ProposalBundle,
) -> Result<ProposalBundle, ProposalFilterError>
where
    F: FilterStrategy,
{
    proposals.retain_by_type::<RemoveProposal, _, _>(|p| {
        apply_strategy(
            &strategy,
            p,
            (p.proposal.to_remove != commit_sender)
                .then_some(())
                .ok_or(ProposalFilterError::CommitterSelfRemoval),
        )
    })?;
    Ok(proposals)
}

fn filter_out_extra_removal_or_update_for_same_leaf<F>(
    strategy: F,
    mut proposals: ProposalBundle,
) -> Result<ProposalBundle, ProposalFilterError>
where
    F: FilterStrategy,
{
    let mut indexes = HashSet::new();

    proposals.retain_by_type::<RemoveProposal, _, _>(|p| {
        apply_strategy(
            &strategy,
            p,
            indexes.insert(p.proposal.to_remove).then_some(()).ok_or(
                ProposalFilterError::MoreThanOneProposalForLeaf(p.proposal.to_remove),
            ),
        )
    })?;

    let last_update_indexes_per_leaf = proposals.by_type::<UpdateProposal>().enumerate().fold(
        HashMap::new(),
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
            Sender::Member(i) => i,
            _ => return Ok(true),
        };

        let is_last_update = last_update_indexes_per_leaf.get(&leaf_index) == Some(&index);

        apply_strategy(
            &strategy,
            p,
            (is_last_update && indexes.insert(leaf_index))
                .then_some(())
                .ok_or(ProposalFilterError::MoreThanOneProposalForLeaf(leaf_index)),
        )
    })?;

    Ok(proposals)
}

fn filter_out_invalid_group_extensions<F, C>(
    strategy: F,
    mut proposals: ProposalBundle,
    cipher_suite: CipherSuite,
    credential_validator: C,
) -> Result<ProposalBundle, ProposalFilterError>
where
    F: FilterStrategy,
    C: CredentialValidator,
{
    proposals.retain_by_type::<ExtensionList, _, _>(|p| {
        let res = p
            .proposal
            .get_extension::<ExternalSendersExt>()
            .map_err(Into::into)
            .and_then(|extension| {
                extension.map_or(Ok(()), |extension| {
                    extension
                        .verify_all(&credential_validator, cipher_suite)
                        .map_err(Into::into)
                })
            });

        apply_strategy(&strategy, p, res)
    })?;

    Ok(proposals)
}

fn filter_out_extra_group_context_extensions<F>(
    strategy: F,
    mut proposals: ProposalBundle,
) -> Result<ProposalBundle, ProposalFilterError>
where
    F: FilterStrategy,
{
    let mut found = false;

    proposals.retain_by_type::<ExtensionList, _, _>(|p| {
        apply_strategy(
            &strategy,
            p,
            (!std::mem::replace(&mut found, true))
                .then_some(())
                .ok_or(ProposalFilterError::MoreThanOneGroupContextExtensionsProposal),
        )
    })?;

    Ok(proposals)
}

fn filter_out_invalid_reinit<F>(
    strategy: F,
    mut proposals: ProposalBundle,
    protocol_version: ProtocolVersion,
) -> Result<ProposalBundle, ProposalFilterError>
where
    F: FilterStrategy,
{
    proposals.retain_by_type::<ReInit, _, _>(|p| {
        apply_strategy(
            &strategy,
            p,
            (p.proposal.version >= protocol_version)
                .then_some(())
                .ok_or(ProposalFilterError::InvalidProtocolVersionInReInit {
                    proposed: p.proposal.version,
                    original: protocol_version,
                }),
        )
    })?;

    Ok(proposals)
}

fn filter_out_reinit_if_other_proposals<F>(
    strategy: F,
    mut proposals: ProposalBundle,
) -> Result<ProposalBundle, ProposalFilterError>
where
    F: FilterStrategy,
{
    let has_only_reinit = proposals
        .proposal_types()
        .all(|t| t == ProposalType::RE_INIT);

    let mut found = false;

    proposals.retain_by_type::<ReInit, _, _>(|p| {
        apply_strategy(
            &strategy,
            p,
            (has_only_reinit && !std::mem::replace(&mut found, true))
                .then_some(())
                .ok_or(ProposalFilterError::OtherProposalWithReInit),
        )
    })?;

    Ok(proposals)
}

fn filter_out_external_init<F>(
    strategy: F,
    mut proposals: ProposalBundle,
) -> Result<ProposalBundle, ProposalFilterError>
where
    F: FilterStrategy,
{
    proposals.retain_by_type::<ExternalInit, _, _>(|p| {
        apply_strategy(
            &strategy,
            p,
            Err(ProposalFilterError::ExternalInitMustBeCommittedByNewMember),
        )
    })?;

    Ok(proposals)
}

fn filter_out_invalid_psks<F>(
    strategy: F,
    cipher_suite: CipherSuite,
    mut proposals: ProposalBundle,
) -> Result<ProposalBundle, ProposalFilterError>
where
    F: FilterStrategy,
{
    let mut ids = HashSet::new();
    let kdf_extract_size = KeyScheduleKdf::new(cipher_suite.kdf_type()).extract_size();

    proposals.retain_by_type::<PreSharedKey, _, _>(|p| {
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
        let is_new_id = ids.insert(p.proposal.psk.clone());

        let res = if !valid {
            Err(ProposalFilterError::InvalidTypeOrUsageInPreSharedKeyProposal)
        } else if !nonce_valid {
            Err(ProposalFilterError::InvalidPskNonceLength {
                expected: kdf_extract_size,
                found: nonce_length,
            })
        } else if !is_new_id {
            Err(ProposalFilterError::DuplicatePskIds)
        } else {
            Ok(())
        };

        apply_strategy(&strategy, p, res)
    })?;

    Ok(proposals)
}

fn ensure_exactly_one_external_init(proposals: &ProposalBundle) -> Result<(), ProposalFilterError> {
    (proposals.by_type::<ExternalInit>().count() == 1)
        .then_some(())
        .ok_or(ProposalFilterError::ExternalCommitMustHaveExactlyOneExternalInit)
}

fn ensure_proposals_in_external_commit_are_allowed(
    proposals: &ProposalBundle,
) -> Result<(), ProposalFilterError> {
    let unsupported_type = proposals.proposal_types().find(|ty| {
        ![
            ProposalType::EXTERNAL_INIT,
            ProposalType::REMOVE,
            ProposalType::PSK,
        ]
        .contains(ty)
    });

    match unsupported_type {
        Some(kind) => Err(ProposalFilterError::InvalidProposalTypeInExternalCommit(
            kind,
        )),
        None => Ok(()),
    }
}

fn ensure_at_most_one_removal_for_self<C>(
    proposals: &ProposalBundle,
    external_leaf: &LeafNode,
    tree: &TreeKemPublic,
    credential_validator: C,
) -> Result<(), ProposalFilterError>
where
    C: CredentialValidator,
{
    let mut removals = proposals.by_type::<RemoveProposal>();

    match (removals.next(), removals.next()) {
        (Some(removal), None) => {
            ensure_removal_is_for_self(&removal.proposal, external_leaf, tree, credential_validator)
        }
        (Some(_), Some(_)) => Err(ProposalFilterError::ExternalCommitWithMoreThanOneRemove),
        (None, _) => Ok(()),
    }
}

fn ensure_removal_is_for_self<C>(
    removal: &RemoveProposal,
    external_leaf: &LeafNode,
    tree: &TreeKemPublic,
    credential_validator: C,
) -> Result<(), ProposalFilterError>
where
    C: CredentialValidator,
{
    let credential = &tree
        .get_leaf_node(removal.to_remove)?
        .signing_identity
        .credential;

    credential_validator
        .is_equal_identity(&external_leaf.signing_identity.credential, credential)
        .then_some(())
        .ok_or(ProposalFilterError::ExternalCommitRemovesOtherIdentity)
}

fn ensure_no_proposal_by_ref(proposals: &ProposalBundle) -> Result<(), ProposalFilterError> {
    proposals
        .iter_proposals()
        .try_fold((), |_, p| match p.proposal_ref {
            Some(_) => Err(ProposalFilterError::OnlyMembersCanCommitProposalsByRef),
            None => Ok(()),
        })
}

fn update_sender_leaf_index(sender: &Sender) -> Result<LeafIndex, ProposalFilterError> {
    match *sender {
        Sender::Member(i) => Ok(i),
        _ => Err(ProposalFilterError::InvalidProposalTypeForProposer(
            ProposalType::UPDATE,
            sender.clone(),
        )),
    }
}

fn insert_external_leaf(
    mut state: ProposalState,
    leaf_node: LeafNode,
) -> Result<ProposalState, ProposalFilterError> {
    let leaf_indexes = state.tree.add_leaves(vec![leaf_node])?;
    state.external_leaf_index = leaf_indexes.first().copied();
    Ok(state)
}

struct TreeBatchEditAccumulator<'a, F> {
    strategy: F,
    proposals: &'a ProposalBundle,
    new_leaf_indexes: Vec<LeafIndex>,
    removed_leaves: Vec<(LeafIndex, LeafNode)>,
    invalid_additions: HashSet<usize>,
    invalid_removals: HashSet<usize>,
    invalid_updates: HashSet<usize>,
}

impl<'a, F: FilterStrategy> TreeBatchEditAccumulator<'a, F> {
    fn new(strategy: F, proposals: &'a ProposalBundle) -> Self {
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

    fn apply_strategy<T>(
        &self,
        index: usize,
        r: Result<(), RatchetTreeError>,
    ) -> Result<(), RatchetTreeError>
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

    fn on_update(
        &mut self,
        index: usize,
        r: Result<LeafIndex, RatchetTreeError>,
    ) -> Result<(), RatchetTreeError> {
        if r.is_err() {
            self.invalid_updates.insert(index);
        }
        self.apply_strategy::<UpdateProposal>(index, r.map(|_| ()))
    }

    fn on_remove(
        &mut self,
        index: usize,
        r: Result<(LeafIndex, LeafNode), RatchetTreeError>,
    ) -> Result<(), RatchetTreeError> {
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

    fn on_add(
        &mut self,
        index: usize,
        r: Result<LeafIndex, RatchetTreeError>,
    ) -> Result<(), RatchetTreeError> {
        match r {
            Ok(leaf_index) => self.new_leaf_indexes.push(leaf_index),
            Err(_) => {
                self.invalid_additions.insert(index);
            }
        }
        self.apply_strategy::<AddProposal>(index, r.map(|_| ()))
    }

    fn finish(self) -> Result<Self::Output, RatchetTreeError> {
        Ok(self)
    }
}
