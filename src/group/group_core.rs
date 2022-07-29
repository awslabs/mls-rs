use std::collections::HashMap;

use crate::{
    cipher_suite::CipherSuite,
    extension::ExternalSendersExt,
    group::{
        Content, GroupContext, GroupError, PreSharedKey, Proposal, ProposalCache,
        ProposalSetEffects, ProvisionalPublicState, TreeKemPublic, VerifiedPlaintext,
    },
    psk::{JustPreSharedKeyID, PreSharedKeyID},
    signing_identity::SigningIdentity,
    ProtocolVersion,
};

use super::{
    proposal::ReInit, proposal_cache::CachedProposal, transcript_hash::InterimTranscriptHash,
    ProposalRef,
};

#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct GroupCore {
    pub(crate) proposals: ProposalCache,
    pub(crate) context: GroupContext,
    pub(crate) current_tree: TreeKemPublic,
    pub(crate) interim_transcript_hash: InterimTranscriptHash,
    pub(crate) pending_reinit: Option<ReInit>,
}

impl GroupCore {
    pub(super) fn new(
        context: GroupContext,
        current_tree: TreeKemPublic,
        interim_transcript_hash: InterimTranscriptHash,
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
        }
    }

    pub(super) fn import(
        context: GroupContext,
        current_tree: TreeKemPublic,
        interim_transcript_hash: InterimTranscriptHash,
        proposals: HashMap<ProposalRef, CachedProposal>,
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
            pending_reinit: None,
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

    pub(super) fn apply_proposals(
        &self,
        proposals: ProposalSetEffects,
    ) -> Result<ProvisionalPublicState, GroupError> {
        if self.pending_reinit.is_some() {
            return Err(GroupError::GroupUsedAfterReInit);
        }

        let mut provisional_group_context = self.context.clone();

        // Determine if a path update is required
        let path_update_required = proposals.path_update_required();

        // Locate a group context extension
        if let Some(group_context_extensions) = proposals.group_context_ext {
            // Group context extensions are a full replacement and not a merge
            provisional_group_context.extensions = group_context_extensions;
        }

        Ok(ProvisionalPublicState {
            public_tree: proposals.tree,
            added_leaves: proposals
                .adds
                .into_iter()
                .zip(proposals.added_leaf_indexes)
                .collect(),
            removed_leaves: proposals.removed_leaves,
            updated_leaves: proposals
                .updates
                .iter()
                .map(|&(leaf_index, _)| leaf_index)
                .collect(),
            epoch: self.context.epoch + 1,
            path_update_required,
            group_context: provisional_group_context,
            psks: proposals.psks,
            reinit: proposals.reinit,
            external_init: proposals.external_init,
            rejected_proposals: proposals.rejected_proposals,
        })
    }

    pub(super) fn validate_incoming_message(
        &self,
        plaintext: VerifiedPlaintext,
    ) -> Result<VerifiedPlaintext, GroupError> {
        if plaintext.content.group_id != self.context.group_id {
            return Err(GroupError::InvalidGroupId(
                plaintext.plaintext.content.group_id,
            ));
        }

        let epoch = plaintext.content.epoch;

        match &plaintext.plaintext.content.content {
            Content::Application(_) if plaintext.encrypted => Ok(plaintext),
            Content::Application(_) => Err(GroupError::UnencryptedApplicationMessage),
            Content::Commit(_) => (epoch == self.context.epoch)
                .then(|| plaintext)
                .ok_or(GroupError::InvalidPlaintextEpoch(epoch)),
            Content::Proposal(p) => {
                (epoch == self.context.epoch)
                    .then(|| ())
                    .ok_or(GroupError::InvalidPlaintextEpoch(epoch))?;
                match p {
                    Proposal::Psk(PreSharedKey {
                        psk: PreSharedKeyID { key_id, .. },
                    }) => matches!(key_id, JustPreSharedKeyID::External(_))
                        .then(|| plaintext)
                        .ok_or(GroupError::PskProposalMustContainExternalPsk),
                    _ => Ok(plaintext),
                }
            }
        }
    }

    pub fn external_signers(&self) -> Vec<SigningIdentity> {
        self.context
            .extensions
            .get_extension::<ExternalSendersExt>()
            .unwrap_or(None)
            .map_or(vec![], |extern_senders_ext| {
                extern_senders_ext.allowed_senders
            })
    }
}
