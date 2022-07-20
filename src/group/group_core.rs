use std::collections::HashMap;

use crate::{
    cipher_suite::CipherSuite,
    client_config::CredentialValidator,
    extension::{ExtensionList, ExternalSendersExt, RequiredCapabilitiesExt},
    group::{
        Content, GroupContext, GroupError, PreSharedKey, Proposal, ProposalCache,
        ProposalSetEffects, ProvisionalPublicState, TreeKemPublic, VerifiedPlaintext,
    },
    psk::{JustPreSharedKeyID, PreSharedKeyID},
    signing_identity::SigningIdentity,
    tree_kem::{leaf_node_validator::LeafNodeValidator, node::LeafIndex},
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

    pub(super) fn apply_proposals<C>(
        &self,
        current_public_tree: &TreeKemPublic,
        proposals: ProposalSetEffects,
        credential_validator: C,
    ) -> Result<ProvisionalPublicState, GroupError>
    where
        C: CredentialValidator,
    {
        if self.pending_reinit.is_some() {
            return Err(GroupError::GroupUsedAfterReInit);
        }

        let mut provisional_tree = current_public_tree.clone();
        let mut provisional_group_context = self.context.clone();

        // Determine if a path update is required
        let path_update_required = proposals.path_update_required();

        // Locate a group context extension
        if let Some(group_context_extensions) = proposals.group_context_ext {
            // Group context extensions are a full replacement and not a merge
            provisional_group_context.extensions = group_context_extensions;
        }

        // Apply updates
        let updated_leaves = proposals
            .updates
            .iter()
            .map(|(leaf_index, _)| *leaf_index)
            .collect::<Vec<LeafIndex>>();

        for (update_sender, leaf_node) in proposals.updates {
            // Update the leaf in the provisional tree
            provisional_tree.update_leaf(update_sender, leaf_node)?;
        }

        // Apply removes
        // If there is only one user in the tree, they can't be removed
        if !proposals.removes.is_empty() && provisional_tree.occupied_leaf_count() == 1 {
            return Err(GroupError::RemoveNotAllowed);
        }

        // Remove elements from the public tree
        let removed_leaves = provisional_tree.remove_leaves(proposals.removes)?;

        // Apply adds
        let adds = proposals
            .adds
            .iter()
            .cloned()
            .map(|p| p.leaf_node)
            .collect();

        let added_leaves = provisional_tree.add_leaves(adds)?;

        // Apply add by external init
        let external_init = proposals
            .external_init
            .map(|(external_add_leaf, ext_init)| {
                let index = provisional_tree.add_leaves(vec![external_add_leaf])?[0];
                Ok::<_, GroupError>((index, ext_init))
            })
            .transpose()?;

        // Now that the tree is updated we can check required capabilities if needed
        self.check_required_capabilities(
            &provisional_tree,
            &provisional_group_context.extensions,
            &credential_validator,
        )?;

        let mut path_blanked = removed_leaves
            .iter()
            .cloned()
            .map(|(index, _)| index)
            .chain(updated_leaves.iter().cloned())
            .collect::<Vec<_>>();

        provisional_tree.update_hashes(&mut path_blanked, &added_leaves)?;

        Ok(ProvisionalPublicState {
            public_tree: provisional_tree,
            added_leaves: proposals.adds.into_iter().zip(added_leaves).collect(),
            removed_leaves,
            updated_leaves,
            epoch: self.context.epoch + 1,
            path_update_required,
            group_context: provisional_group_context,
            psks: proposals.psks,
            reinit: proposals.reinit,
            external_init,
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

    fn check_required_capabilities<C>(
        &self,
        tree: &TreeKemPublic,
        group_context_extensions: &ExtensionList,
        credential_validator: C,
    ) -> Result<(), GroupError>
    where
        C: CredentialValidator,
    {
        let existing_required_capabilities = self
            .context
            .extensions
            .get_extension::<RequiredCapabilitiesExt>()?;

        let new_required_capabilities =
            group_context_extensions.get_extension::<RequiredCapabilitiesExt>()?;

        if existing_required_capabilities != new_required_capabilities {
            let leaf_node_validator = LeafNodeValidator::new(
                self.cipher_suite(),
                new_required_capabilities.as_ref(),
                credential_validator,
            );

            tree.get_leaf_nodes()
                .iter()
                .try_for_each(|ln| leaf_node_validator.validate_required_capabilities(ln))
                .map_err(|_| GroupError::UnsupportedRequiredCapabilities)
        } else {
            Ok(())
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
