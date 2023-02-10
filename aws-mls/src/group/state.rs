use super::{
    confirmation_tag::ConfirmationTag, proposal::ReInitProposal,
    transcript_hash::InterimTranscriptHash,
};
use crate::{
    cipher_suite::CipherSuite,
    group::{GroupContext, ProposalCache, TreeKemPublic},
    protocol_version::ProtocolVersion,
};

#[derive(Clone, Debug, PartialEq)]
#[non_exhaustive]
pub struct GroupState {
    pub(crate) proposals: ProposalCache,
    pub(crate) context: GroupContext,
    pub(crate) public_tree: TreeKemPublic,
    pub(crate) interim_transcript_hash: InterimTranscriptHash,
    pub(crate) pending_reinit: Option<ReInitProposal>,
    pub(crate) confirmation_tag: ConfirmationTag,
}

impl GroupState {
    pub(crate) fn new(
        context: GroupContext,
        current_tree: TreeKemPublic,
        interim_transcript_hash: InterimTranscriptHash,
        confirmation_tag: ConfirmationTag,
    ) -> Self {
        Self {
            proposals: ProposalCache::new(context.protocol_version, context.group_id.clone()),
            context,
            public_tree: current_tree,
            interim_transcript_hash,
            pending_reinit: None,
            confirmation_tag,
        }
    }

    #[inline(always)]
    pub(crate) fn cipher_suite(&self) -> CipherSuite {
        self.context.cipher_suite
    }

    #[inline(always)]
    pub(crate) fn protocol_version(&self) -> ProtocolVersion {
        self.context.protocol_version
    }
}
