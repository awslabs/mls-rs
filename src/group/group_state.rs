use crate::{
    client_config::ClientConfig,
    group::{GroupContext, InterimTranscriptHash},
    tree_kem::{node::NodeVec, TreeKemPrivate, TreeKemPublic},
};
use ferriscrypt::hpke::kem::HpkeSecretKey;
use std::collections::HashMap;
use tls_codec::{Deserialize, Serialize};

use super::{
    confirmation_tag::ConfirmationTag, group_core::GroupCore, key_schedule::KeySchedule,
    proposal_cache::CachedProposal, Group, GroupError, ProposalRef,
};

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub struct GroupState {
    pub(crate) context: GroupContext,
    pub(crate) private_tree: TreeKemPrivate,
    // TODO: This should be base64
    pub(crate) current_tree_data: Vec<u8>,
    pub(crate) key_schedule: KeySchedule,
    pub(crate) interim_transcript_hash: InterimTranscriptHash,
    pub(crate) confirmation_tag: ConfirmationTag,
    #[serde(with = "crate::serde_utils::map_as_seq")]
    proposals: HashMap<ProposalRef, CachedProposal>,
    #[serde(with = "crate::serde_utils::map_as_seq")]
    pub(crate) pending_updates: HashMap<Vec<u8>, HpkeSecretKey>,
}

impl<C> Group<C>
where
    C: ClientConfig + Clone,
{
    pub fn export(&self) -> Result<GroupState, GroupError> {
        Ok(GroupState {
            context: self.core.context.clone(),
            private_tree: self.private_tree.clone(),
            current_tree_data: self
                .core
                .current_tree
                .export_node_data()
                .tls_serialize_detached()?,
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
            NodeVec::tls_deserialize(&mut &*state.current_tree_data)?,
        )?;

        let core = GroupCore::import(
            state.context,
            imported_tree,
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
