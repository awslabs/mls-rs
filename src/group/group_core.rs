use std::collections::HashMap;

use crate::{
    cipher_suite::CipherSuite,
    extension::ExternalSendersExt,
    group::{
        GroupContext, GroupError, ProposalCache, ProposalSetEffects, ProvisionalPublicState,
        TreeKemPublic,
    },
    signing_identity::SigningIdentity,
    tree_kem::node::LeafIndex,
    ProtocolVersion,
};

use super::{
    framing::{ContentType, MLSMessage, MLSMessagePayload, MLSPlaintext, WireFormat},
    key_schedule::KeySchedule,
    message_signature::MLSAuthenticatedContent,
    message_verifier::verify_plaintext_authentication,
    proposal::ReInit,
    proposal_cache::CachedProposal,
    transcript_hash::InterimTranscriptHash,
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

    pub(super) fn check_metadata(&self, message: &MLSMessage) -> Result<(), GroupError> {
        if message.version != self.protocol_version() {
            return Err(GroupError::InvalidProtocolVersion(
                self.protocol_version(),
                message.version,
            ));
        }

        if let Some((group_id, epoch, content_type, wire_format)) = match &message.payload {
            MLSMessagePayload::Plain(plaintext) => Some((
                &plaintext.content.group_id,
                plaintext.content.epoch,
                plaintext.content.content_type(),
                WireFormat::Plain,
            )),
            MLSMessagePayload::Cipher(ciphertext) => Some((
                &ciphertext.group_id,
                ciphertext.epoch,
                ciphertext.content_type,
                WireFormat::Cipher,
            )),
            _ => None,
        } {
            if group_id != &self.context.group_id {
                return Err(GroupError::InvalidGroupId(group_id.clone()));
            }

            // Proposal and commit messages must be sent in the current epoch
            if (content_type == ContentType::Proposal || content_type == ContentType::Commit)
                && epoch != self.context.epoch
            {
                return Err(GroupError::InvalidEpoch(epoch));
            }

            // Unencrypted application messages are not allowed
            if wire_format == WireFormat::Plain && content_type == ContentType::Application {
                return Err(GroupError::UnencryptedApplicationMessage);
            }
        }

        Ok(())
    }

    pub(super) fn verify_plaintext_authentication(
        &mut self,
        key_schedule: Option<&KeySchedule>,
        self_index: Option<LeafIndex>,
        message: MLSPlaintext,
    ) -> Result<MLSAuthenticatedContent, GroupError> {
        verify_plaintext_authentication(
            message,
            key_schedule,
            self_index,
            &self.current_tree,
            &self.context,
            &self.external_signers(),
        )
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
