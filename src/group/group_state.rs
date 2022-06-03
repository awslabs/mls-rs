use crate::{
    cipher_suite::CipherSuite,
    group::{GroupContext, InterimTranscriptHash, ProposalCache},
    tree_kem::TreeKemPrivate,
    ProtocolVersion,
};
use ferriscrypt::hpke::kem::HpkeSecretKey;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use super::{confirmation_tag::ConfirmationTag, key_schedule::KeySchedule, PublicEpoch};

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct GroupState {
    pub(crate) protocol_version: ProtocolVersion,
    pub(crate) cipher_suite: CipherSuite,
    pub(crate) context: GroupContext,
    pub(crate) private_tree: TreeKemPrivate,
    pub(crate) current_public_epoch: PublicEpoch,
    pub(crate) key_schedule: KeySchedule,
    pub(crate) interim_transcript_hash: InterimTranscriptHash,
    pub(crate) confirmation_tag: ConfirmationTag,
    pub(crate) proposals: ProposalCache,
    #[serde(with = "crate::serde_utils::map_as_seq")]
    pub(crate) pending_updates: HashMap<Vec<u8>, HpkeSecretKey>,
}
