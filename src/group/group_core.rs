use std::collections::HashMap;

use ferriscrypt::hpke::kem::HpkeSecretKey;

use crate::{
    cipher_suite::CipherSuite,
    group::{GroupContext, ProposalCache, TreeKemPublic},
    ProtocolVersion,
};

use super::{
    confirmation_tag::ConfirmationTag, proposal::ReInit, proposal_cache::CachedProposal,
    transcript_hash::InterimTranscriptHash, CommitGeneration, ProposalRef,
};

#[derive(Clone, Debug, PartialEq)]
#[non_exhaustive]
pub struct GroupCore {
    pub(crate) proposals: ProposalCache,
    pub(crate) context: GroupContext,
    pub(crate) current_tree: TreeKemPublic,
    pub(crate) interim_transcript_hash: InterimTranscriptHash,
    pub(crate) pending_reinit: Option<ReInit>,
    // TODO: HpkePublicKey does not have Eq and Hash
    pub(crate) pending_updates: HashMap<Vec<u8>, HpkeSecretKey>, // Hash of leaf node hpke public key to secret key
    pub(crate) pending_commit: Option<CommitGeneration>,
    pub(crate) confirmation_tag: ConfirmationTag,
}

impl GroupCore {
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
            current_tree,
            interim_transcript_hash,
            pending_reinit: None,
            pending_updates: Default::default(),
            pending_commit: None,
            confirmation_tag,
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn import(
        context: GroupContext,
        current_tree: TreeKemPublic,
        interim_transcript_hash: InterimTranscriptHash,
        proposals: HashMap<ProposalRef, CachedProposal>,
        pending_reinit: Option<ReInit>,
        pending_updates: HashMap<Vec<u8>, HpkeSecretKey>,
        pending_commit: Option<CommitGeneration>,
        confirmation_tag: ConfirmationTag,
    ) -> Self {
        Self {
            proposals: ProposalCache::import(
                context.protocol_version,
                context.cipher_suite,
                context.group_id.clone(),
                proposals,
            ),
            context,
            current_tree,
            interim_transcript_hash,
            pending_reinit,
            pending_updates,
            pending_commit,
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
