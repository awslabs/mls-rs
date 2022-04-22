use crate::{
    cipher_suite::CipherSuite,
    group::{Epoch, GroupContext, InterimTranscriptHash, ProposalCache},
    tree_kem::{leaf_node_ref::LeafNodeRef, TreeKemPrivate},
    ProtocolVersion,
};
use ferriscrypt::hpke::kem::HpkeSecretKey;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct GroupState {
    pub(crate) protocol_version: ProtocolVersion,
    pub(crate) cipher_suite: CipherSuite,
    pub(crate) context: GroupContext,
    pub(crate) private_tree: TreeKemPrivate,
    pub(crate) current_epoch: Epoch,
    pub(crate) interim_transcript_hash: InterimTranscriptHash,
    pub(crate) proposals: ProposalCache,
    #[serde(with = "crate::serde_utils::map_as_seq")]
    pub(crate) pending_updates: HashMap<LeafNodeRef, HpkeSecretKey>,
}
