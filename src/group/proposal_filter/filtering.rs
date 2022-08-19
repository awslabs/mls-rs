use crate::{
    cipher_suite::CipherSuite,
    client_config::CredentialValidator,
    extension::{
        is_default_extension, ExtensionList, ExternalSendersExt, GroupContextExtension,
        RequiredCapabilitiesExt,
    },
    group::{
        proposal_filter::{Proposable, ProposalBundle, ProposalFilterError, ProposalInfo},
        AddProposal, BorrowedProposal, ExternalInit, JustPreSharedKeyID, KeyScheduleKdf,
        PreSharedKey, ProposalType, ReInit, RemoveProposal, ResumptionPSKUsage, ResumptionPsk,
        Sender, UpdateProposal,
    },
    key_package::KeyPackageValidator,
    protocol_version::ProtocolVersion,
    psk::ExternalPskIdValidator,
    tree_kem::{
        leaf_node::LeafNode,
        leaf_node_validator::{LeafNodeValidator, ValidationContext},
        node::LeafIndex,
        AccumulateBatchResults, RatchetTreeError, TreeKemPublic,
    },
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
pub(crate) struct ProposalApplier<'a, C, P> {
    original_tree: &'a TreeKemPublic,
    protocol_version: ProtocolVersion,
    cipher_suite: CipherSuite,
    group_id: &'a [u8],
    original_group_extensions: &'a ExtensionList<GroupContextExtension>,
    original_required_capabilities: Option<&'a RequiredCapabilitiesExt>,
    external_leaf: Option<&'a LeafNode>,
    credential_validator: C,
    external_psk_id_validator: P,
}

impl<'a, C, P> ProposalApplier<'a, C, P>
where
    C: CredentialValidator,
    P: ExternalPskIdValidator,
{
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        original_tree: &'a TreeKemPublic,
        protocol_version: ProtocolVersion,
        cipher_suite: CipherSuite,
        group_id: &'a [u8],
        original_group_extensions: &'a ExtensionList<GroupContextExtension>,
        original_required_capabilities: Option<&'a RequiredCapabilitiesExt>,
        external_leaf: Option<&'a LeafNode>,
        credential_validator: C,
        external_psk_id_validator: P,
    ) -> Self {
        Self {
            original_tree,
            protocol_version,
            cipher_suite,
            group_id,
            original_group_extensions,
            original_required_capabilities,
            external_leaf,
            credential_validator,
            external_psk_id_validator,
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
        let proposals = filter_out_invalid_proposers(
            &strategy,
            self.original_tree,
            self.original_group_extensions,
            proposals,
        )?;

        let proposals = filter_out_update_for_committer(&strategy, commit_sender, proposals)?;
        let proposals = filter_out_removal_of_committer(&strategy, commit_sender, proposals)?;
        let proposals = filter_out_extra_removal_or_update_for_same_leaf(&strategy, proposals)?;
        let proposals = filter_out_invalid_psks(
            &strategy,
            self.cipher_suite,
            proposals,
            &self.external_psk_id_validator,
        )?;

        let proposals = filter_out_invalid_group_extensions(
            &strategy,
            proposals,
            self.cipher_suite,
            &self.credential_validator,
        )?;

        let proposals = filter_out_extra_group_context_extensions(&strategy, proposals)?;
        let proposals = filter_out_invalid_reinit(&strategy, proposals, self.protocol_version)?;
        let proposals = filter_out_reinit_if_other_proposals(&strategy, proposals)?;
        let proposals = filter_out_external_init(&strategy, commit_sender, proposals)?;

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

        let proposals = filter_out_invalid_proposers(
            FailInvalidProposal,
            self.original_tree,
            self.original_group_extensions,
            proposals,
        )?;

        let proposals = filter_out_invalid_psks(
            FailInvalidProposal,
            self.cipher_suite,
            proposals,
            &self.external_psk_id_validator,
        )?;
        let state = ProposalState::new(self.original_tree.clone(), proposals);

        let state = self.apply_proposal_changes(&FailInvalidProposal, state)?;

        let state = insert_external_leaf(state, external_leaf.clone())?;
        Ok(state)
    }

    fn apply_proposal_changes<F>(
        &self,
        strategy: F,
        mut state: ProposalState,
    ) -> Result<ProposalState, ProposalFilterError>
    where
        F: FilterStrategy,
    {
        let extensions_proposal_and_capabilities = state
            .proposals
            .group_context_extensions_proposal()
            .cloned()
            .and_then(|p| {
                match p
                    .proposal
                    .get_extension()
                    .map_err(ProposalFilterError::from)
                {
                    Ok(capabilities) => Some(Ok((p, capabilities))),
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

        // If the extensions proposal is ignored, remove it from the list of proposals.
        if extensions_proposal_and_capabilities.is_none() {
            state.proposals.clear_group_context_extensions();
        }

        match extensions_proposal_and_capabilities {
            Some((group_context_extensions_proposal, new_required_capabilities)) => self
                .apply_proposals_with_new_capabilities(
                    strategy,
                    state,
                    group_context_extensions_proposal,
                    new_required_capabilities,
                ),
            None => self.apply_tree_changes(
                strategy,
                state,
                self.original_group_extensions,
                self.original_required_capabilities,
            ),
        }
    }

    fn apply_proposals_with_new_capabilities<F>(
        &self,
        strategy: F,
        mut state: ProposalState,
        group_context_extensions_proposal: ProposalInfo<ExtensionList<GroupContextExtension>>,
        new_required_capabilities: Option<RequiredCapabilitiesExt>,
    ) -> Result<ProposalState, ProposalFilterError>
    where
        F: FilterStrategy,
        C: CredentialValidator,
    {
        let mut new_state =
            self.apply_tree_changes(&strategy, state.clone(), &ExtensionList::new(), None)?;

        let new_capabilities_supported =
            new_required_capabilities.map_or(Ok(()), |new_required_capabilities| {
                let leaf_validator = LeafNodeValidator::new(
                    self.cipher_suite,
                    Some(&new_required_capabilities),
                    &self.credential_validator,
                );

                new_state
                    .tree
                    .non_empty_leaves()
                    .try_for_each(|(_, leaf)| leaf_validator.validate_required_capabilities(leaf))
                    .map_err(ProposalFilterError::from)
            });

        let new_extensions_supported = group_context_extensions_proposal
            .proposal
            .iter()
            .map(|extension| extension.extension_type)
            .filter(|&ext_type| !is_default_extension(ext_type))
            .find(|ext_type| {
                !new_state
                    .tree
                    .non_empty_leaves()
                    .all(|(_, leaf)| leaf.capabilities.extensions.contains(ext_type))
            })
            .map_or(Ok(()), |ext_type| {
                Err(ProposalFilterError::UnsupportedGroupExtension(ext_type))
            });

        let group_extensions_supported = new_capabilities_supported.and(new_extensions_supported);

        match group_extensions_supported {
            Ok(()) => Ok(new_state),
            Err(e) => {
                let ignored =
                    strategy.ignore(&group_context_extensions_proposal.by_ref().map(Into::into));

                if ignored {
                    state.proposals.clear_group_context_extensions();
                    new_state.proposals.clear_group_context_extensions();
                }

                match (
                    ignored,
                    self.original_required_capabilities,
                    self.original_group_extensions.is_empty(),
                ) {
                    (false, ..) => Err(e),
                    (true, None, true) => Ok(new_state),
                    (true, ..) => self.apply_tree_changes(
                        &strategy,
                        state,
                        self.original_group_extensions,
                        self.original_required_capabilities,
                    ),
                }
            }
        }
    }

    fn apply_tree_changes<F>(
        &self,
        strategy: F,
        state: ProposalState,
        group_extensions_in_use: &ExtensionList<GroupContextExtension>,
        required_capabilities: Option<&RequiredCapabilitiesExt>,
    ) -> Result<ProposalState, ProposalFilterError>
    where
        F: FilterStrategy,
    {
        let mut state = self.validate_new_nodes(
            &strategy,
            state,
            group_extensions_in_use,
            required_capabilities,
        )?;

        let mut updates = Vec::new();
        state
            .proposals
            .retain_by_type::<UpdateProposal, _, _>(|p| {
                let r = leaf_index_of_update_sender(p);

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
        group_extensions_in_use: &ExtensionList<GroupContextExtension>,
        required_capabilities: Option<&RequiredCapabilitiesExt>,
    ) -> Result<ProposalState, ProposalFilterError>
    where
        F: FilterStrategy,
    {
        let state = self.validate_new_update_nodes(
            &strategy,
            state,
            group_extensions_in_use,
            required_capabilities,
        )?;

        let state = self.validate_new_key_packages(
            &strategy,
            state,
            group_extensions_in_use,
            required_capabilities,
        )?;

        Ok(state)
    }

    fn validate_new_update_nodes<F>(
        &self,
        strategy: F,
        mut state: ProposalState,
        group_extensions_in_use: &ExtensionList<GroupContextExtension>,
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
            let valid = leaf_node_validator
                .check_if_valid(
                    &p.proposal.leaf_node,
                    ValidationContext::Update(self.group_id),
                )
                .map_err(Into::into);

            let extensions_are_supported =
                leaf_supports_extensions(&p.proposal.leaf_node, group_extensions_in_use);

            let res = valid.and(extensions_are_supported);
            apply_strategy(&strategy, p, res)
        })?;

        Ok(state)
    }

    fn validate_new_key_packages<F>(
        &self,
        strategy: F,
        mut state: ProposalState,
        group_extensions_in_use: &ExtensionList<GroupContextExtension>,
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
            let valid = package_validator
                .check_if_valid(&p.proposal.key_package, Default::default())
                .map_err(Into::into);

            let extensions_are_supported = leaf_supports_extensions(
                &p.proposal.key_package.leaf_node,
                group_extensions_in_use,
            );

            let res = valid.and(extensions_are_supported);
            apply_strategy(&strategy, p, res)
        })?;

        Ok(state)
    }
}

fn leaf_supports_extensions(
    leaf: &LeafNode,
    extensions: &ExtensionList<GroupContextExtension>,
) -> Result<(), ProposalFilterError> {
    extensions
        .iter()
        .map(|ext| ext.extension_type)
        .filter(|&ext_type| !is_default_extension(ext_type))
        .find(|ext_type| !leaf.capabilities.extensions.contains(ext_type))
        .map_or(Ok(()), |ext_type| {
            Err(ProposalFilterError::UnsupportedGroupExtension(ext_type))
        })
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
    proposals.retain_by_type::<ExtensionList<GroupContextExtension>, _, _>(|p| {
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

    proposals.retain_by_type::<ExtensionList<GroupContextExtension>, _, _>(|p| {
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
    commit_sender: LeafIndex,
    mut proposals: ProposalBundle,
) -> Result<ProposalBundle, ProposalFilterError>
where
    F: FilterStrategy,
{
    proposals.retain_by_type::<ExternalInit, _, _>(|p| {
        apply_strategy(
            &strategy,
            p,
            Err(ProposalFilterError::InvalidProposalTypeForSender {
                proposal_type: ProposalType::EXTERNAL_INIT,
                sender: Sender::Member(commit_sender),
                by_ref: p.proposal_ref.is_some(),
            }),
        )
    })?;

    Ok(proposals)
}

fn filter_out_invalid_psks<F, P>(
    strategy: F,
    cipher_suite: CipherSuite,
    mut proposals: ProposalBundle,
    external_psk_id_validator: &P,
) -> Result<ProposalBundle, ProposalFilterError>
where
    F: FilterStrategy,
    P: ExternalPskIdValidator,
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

        let external_id_is_valid = match &p.proposal.psk.key_id {
            JustPreSharedKeyID::External(id) => external_psk_id_validator
                .validate(id)
                .map_err(|e| ProposalFilterError::PskIdValidationError(e.into())),
            JustPreSharedKeyID::Resumption(_) => Ok(()),
        };

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
            external_id_is_valid
        };

        apply_strategy(&strategy, p, res)
    })?;

    Ok(proposals)
}

fn validate_proposer<P, F>(
    strategy: F,
    tree: &TreeKemPublic,
    external_senders: Option<&ExternalSendersExt>,
    proposals: &mut ProposalBundle,
) -> Result<(), ProposalFilterError>
where
    P: Proposable,
    for<'a> &'a P: Into<BorrowedProposal<'a>>,
    F: FilterStrategy,
{
    proposals.retain_by_type::<P, _, _>(|p| {
        let res = proposer_can_propose(&p.sender, P::TYPE, p.proposal_ref.is_some())
            .then_some(())
            .ok_or_else(|| ProposalFilterError::InvalidProposalTypeForSender {
                proposal_type: P::TYPE,
                sender: p.sender.clone(),
                by_ref: p.proposal_ref.is_some(),
            })
            .and_then(|_| validate_sender(tree, external_senders, &p.sender));
        apply_strategy(&strategy, p, res)
    })
}

fn validate_sender(
    tree: &TreeKemPublic,
    external_senders: Option<&ExternalSendersExt>,
    sender: &Sender,
) -> Result<(), ProposalFilterError> {
    match sender {
        &Sender::Member(i) => tree
            .get_leaf_node(i)
            .map(|_| ())
            .map_err(|_| ProposalFilterError::InvalidMemberProposer(i)),
        &Sender::External(i) => external_senders
            .ok_or(ProposalFilterError::ExternalSenderWithoutExternalSendersExtension)
            .and_then(|ext| {
                (ext.allowed_senders.len() > i as usize)
                    .then_some(())
                    .ok_or(ProposalFilterError::InvalidExternalSenderIndex(i))
            }),
        Sender::NewMemberCommit | Sender::NewMemberProposal => Ok(()),
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
        (Sender::External(_), false) => false,
        (Sender::External(_), true) => matches!(
            proposal_type,
            ProposalType::ADD | ProposalType::REMOVE | ProposalType::RE_INIT
        ),
        (Sender::NewMemberCommit, false) => matches!(
            proposal_type,
            ProposalType::REMOVE | ProposalType::PSK | ProposalType::EXTERNAL_INIT
        ),
        (Sender::NewMemberCommit, true) => false,
        (Sender::NewMemberProposal, false) => false,
        (Sender::NewMemberProposal, true) => matches!(proposal_type, ProposalType::ADD),
    }
}

fn filter_out_invalid_proposers<F>(
    strategy: F,
    tree: &TreeKemPublic,
    group_context_extensions: &ExtensionList<GroupContextExtension>,
    mut proposals: ProposalBundle,
) -> Result<ProposalBundle, ProposalFilterError>
where
    F: FilterStrategy,
{
    let external_senders = group_context_extensions.get_extension().ok().flatten();
    let external_senders = external_senders.as_ref();

    validate_proposer::<AddProposal, _>(&strategy, tree, external_senders, &mut proposals)?;
    validate_proposer::<UpdateProposal, _>(&strategy, tree, external_senders, &mut proposals)?;
    validate_proposer::<RemoveProposal, _>(&strategy, tree, external_senders, &mut proposals)?;
    validate_proposer::<PreSharedKey, _>(&strategy, tree, external_senders, &mut proposals)?;
    validate_proposer::<ReInit, _>(&strategy, tree, external_senders, &mut proposals)?;
    validate_proposer::<ExternalInit, _>(&strategy, tree, external_senders, &mut proposals)?;

    validate_proposer::<ExtensionList<GroupContextExtension>, _>(
        &strategy,
        tree,
        external_senders,
        &mut proposals,
    )?;

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

fn leaf_index_of_update_sender(
    p: &ProposalInfo<UpdateProposal>,
) -> Result<LeafIndex, ProposalFilterError> {
    match p.sender {
        Sender::Member(i) => Ok(i),
        _ => Err(ProposalFilterError::InvalidProposalTypeForSender {
            proposal_type: ProposalType::UPDATE,
            sender: p.sender.clone(),
            by_ref: p.proposal_ref.is_some(),
        }),
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
