use serde_with::serde_as;

use super::{
    confirmation_tag::ConfirmationTag, proposal::ReInit, proposal_cache::CachedProposal,
    transcript_hash::InterimTranscriptHash, ProposalRef,
};
use crate::{
    cipher_suite::CipherSuite,
    group::{GroupContext, ProposalCache, TreeKemPublic},
    tree_kem::node::NodeVec,
    ProtocolVersion,
};
use std::collections::HashMap;

#[derive(Clone, Debug, PartialEq)]
#[non_exhaustive]
pub struct GroupState {
    pub(crate) proposals: ProposalCache,
    pub(crate) context: GroupContext,
    pub(crate) public_tree: TreeKemPublic,
    pub(crate) interim_transcript_hash: InterimTranscriptHash,
    pub(crate) pending_reinit: Option<ReInit>,
    pub(crate) confirmation_tag: ConfirmationTag,
}

impl serde::Serialize for GroupState {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        #[serde_as]
        #[derive(serde::Serialize)]
        struct GroupStateData<'a> {
            context: &'a GroupContext,
            proposals: &'a HashMap<ProposalRef, CachedProposal>,
            tree_data: NodeVec,
            interim_transcript_hash: &'a InterimTranscriptHash,
            pending_reinit: Option<&'a ReInit>,
            confirmation_tag: &'a ConfirmationTag,
        }

        let state_data = GroupStateData {
            context: &self.context,
            proposals: self.proposals.proposals(),
            tree_data: self.public_tree.export_node_data(),
            interim_transcript_hash: &self.interim_transcript_hash,
            pending_reinit: self.pending_reinit.as_ref(),
            confirmation_tag: &self.confirmation_tag,
        };

        state_data.serialize(serializer)
    }
}

impl<'de> serde::Deserialize<'de> for GroupState {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(serde::Deserialize)]
        struct GroupStateData {
            context: GroupContext,
            proposals: HashMap<ProposalRef, CachedProposal>,
            tree_data: NodeVec,
            interim_transcript_hash: InterimTranscriptHash,
            pending_reinit: Option<ReInit>,
            confirmation_tag: ConfirmationTag,
        }

        let group_state_data = GroupStateData::deserialize(deserializer)?;
        let context = group_state_data.context;

        let proposals = ProposalCache::import(
            context.protocol_version,
            context.cipher_suite,
            context.group_id.clone(),
            group_state_data.proposals,
        );

        let current_tree =
            TreeKemPublic::import_node_data(context.cipher_suite, group_state_data.tree_data)
                .map_err(serde::de::Error::custom)?;

        Ok(GroupState {
            proposals,
            context,
            public_tree: current_tree,
            interim_transcript_hash: group_state_data.interim_transcript_hash,
            pending_reinit: group_state_data.pending_reinit,
            confirmation_tag: group_state_data.confirmation_tag,
        })
    }
}

impl GroupState {
    pub(super) fn new(
        context: GroupContext,
        current_tree: TreeKemPublic,
        interim_transcript_hash: InterimTranscriptHash,
        confirmation_tag: ConfirmationTag,
    ) -> Self {
        Self {
            proposals: ProposalCache::new(
                context.protocol_version,
                context.cipher_suite,
                context.group_id.clone(),
            ),
            context,
            public_tree: current_tree,
            interim_transcript_hash,
            pending_reinit: None,
            confirmation_tag,
        }
    }

    #[inline(always)]
    pub(super) fn cipher_suite(&self) -> CipherSuite {
        self.context.cipher_suite
    }

    #[inline(always)]
    pub(super) fn protocol_version(&self) -> ProtocolVersion {
        self.context.protocol_version
    }
}
