use crate::{
    group::{GroupContext, InterimTranscriptHash},
    tree_kem::{node::NodeVec, TreeKemPrivate, TreeKemPublic},
};
use ferriscrypt::hpke::kem::HpkeSecretKey;
use std::collections::HashMap;
use tls_codec::{Deserialize, Serialize};

use super::{
    confirmation_tag::ConfirmationTag, group_core::GroupCore, key_schedule::KeySchedule,
    proposal_cache::CachedProposal, Group, GroupConfig, GroupError, ProposalRef, PublicEpoch,
};

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub(crate) struct CurrentEpochState {
    pub(crate) identifier: u64,
    pub(crate) tree_data: Vec<u8>,
}

impl TryFrom<&PublicEpoch> for CurrentEpochState {
    type Error = GroupError;

    fn try_from(value: &PublicEpoch) -> Result<Self, Self::Error> {
        Ok(CurrentEpochState {
            identifier: value.identifier,
            tree_data: value
                .public_tree
                .export_node_data()
                .tls_serialize_detached()?,
        })
    }
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub struct GroupState {
    pub(crate) context: GroupContext,
    pub(crate) private_tree: TreeKemPrivate,
    pub(crate) current_epoch_data: CurrentEpochState,
    pub(crate) key_schedule: KeySchedule,
    pub(crate) interim_transcript_hash: InterimTranscriptHash,
    pub(crate) confirmation_tag: ConfirmationTag,
    #[serde(with = "crate::serde_utils::map_as_seq")]
    proposals: HashMap<ProposalRef, CachedProposal>,
    #[serde(with = "crate::serde_utils::map_as_seq")]
    pub(crate) pending_updates: HashMap<Vec<u8>, HpkeSecretKey>,
}

impl<C: GroupConfig> Group<C> {
    pub fn export(&self) -> Result<GroupState, GroupError> {
        Ok(GroupState {
            context: self.core.context.clone(),
            private_tree: self.private_tree.clone(),
            current_epoch_data: CurrentEpochState::try_from(&self.core.current_epoch)?,
            key_schedule: self.key_schedule.clone(),
            interim_transcript_hash: self.core.interim_transcript_hash.clone(),
            confirmation_tag: self.confirmation_tag.clone(),
            proposals: self.core.proposals.proposals().clone(),
            pending_updates: self.pending_updates.clone(),
        })
    }

    pub fn import(config: C, state: GroupState) -> Result<Self, GroupError> {
        let imported_tree = TreeKemPublic::import_node_data(
            state.context.cipher_suite,
            NodeVec::tls_deserialize(&mut &*state.current_epoch_data.tree_data)?,
        )?;

        let current_epoch = PublicEpoch {
            identifier: state.current_epoch_data.identifier,
            cipher_suite: state.context.cipher_suite,
            public_tree: imported_tree,
        };

        let core = GroupCore::import(
            state.context,
            current_epoch,
            state.interim_transcript_hash,
            state.proposals,
        );

        Ok(Self {
            config,
            core,
            private_tree: state.private_tree,
            key_schedule: state.key_schedule,
            confirmation_tag: state.confirmation_tag,
            pending_updates: state.pending_updates,
        })
    }
}
