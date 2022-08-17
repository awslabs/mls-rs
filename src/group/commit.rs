use tls_codec_derive::{TlsDeserialize, TlsSerialize, TlsSize};

use crate::{
    client_config::{ClientConfig, ProposalFilterInit, PskStore},
    extension::{ExtensionList, LeafNodeExtension, RatchetTreeExt},
    keychain::Keychain,
    signer::Signable,
    tree_kem::{
        kem::TreeKem, leaf_node::LeafNode, node::LeafIndex, path_secret::PathSecret, Capabilities,
        TreeKemPrivate, UpdatePath,
    },
};

use super::{
    confirmation_tag::ConfirmationTag,
    framing::{Content, MLSMessage, Sender},
    key_schedule::{CommitSecret, KeySchedule},
    message_processor::MessageProcessor,
    message_signature::MLSAuthenticatedContent,
    proposal::{Proposal, ProposalOrRef},
    ConfirmedTranscriptHash, ControlEncryptionMode, Group, GroupError, GroupInfo,
};

#[derive(Clone, Debug, PartialEq, TlsDeserialize, TlsSerialize, TlsSize)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct Commit {
    #[tls_codec(with = "crate::tls::DefVec")]
    pub proposals: Vec<ProposalOrRef>,
    pub path: Option<UpdatePath>,
}

#[derive(
    Clone,
    PartialEq,
    Debug,
    serde::Serialize,
    serde::Deserialize,
    TlsSerialize,
    TlsDeserialize,
    TlsSize,
)]
pub(super) struct CommitGeneration {
    pub content: MLSAuthenticatedContent,
    pub pending_secrets: Option<(TreeKemPrivate, PathSecret)>,
}

#[derive(Clone, Debug)]
struct CommitOptions {
    pub prefer_path_update: bool,
    pub extension_update: Option<ExtensionList<LeafNodeExtension>>,
    pub capabilities_update: Option<Capabilities>,
    pub encryption_mode: ControlEncryptionMode,
    pub ratchet_tree_extension: bool,
}

impl<C> Group<C>
where
    C: ClientConfig + Clone,
{
    pub fn commit_proposals(
        &mut self,
        proposals: Vec<Proposal>,
        authenticated_data: Vec<u8>,
    ) -> Result<(MLSMessage, Option<MLSMessage>), GroupError> {
        self.commit_internal(proposals, None, authenticated_data)
    }

    /// Returns commit and optional `MLSMessage` containing a `Welcome`
    pub(super) fn commit_internal(
        &mut self,
        proposals: Vec<Proposal>,
        external_leaf: Option<&LeafNode>,
        authenticated_data: Vec<u8>,
    ) -> Result<(MLSMessage, Option<MLSMessage>), GroupError> {
        if self.pending_commit.is_some() {
            return Err(GroupError::ExistingPendingCommit);
        }

        let preferences = self.config.preferences();

        let options = CommitOptions {
            prefer_path_update: preferences.force_commit_path_update,
            extension_update: Some(self.config.leaf_node_extensions()),
            capabilities_update: Some(self.config.capabilities()),
            encryption_mode: preferences.encryption_mode(),
            ratchet_tree_extension: preferences.ratchet_tree_extension,
        };

        // Construct an initial Commit object with the proposals field populated from Proposals
        // received during the current epoch, and an empty path field. Add passed in proposals
        // by value
        let is_external = external_leaf.is_some();

        let sender = if is_external {
            Sender::NewMemberCommit
        } else {
            Sender::Member(self.private_tree.self_index)
        };

        let signer = match external_leaf {
            Some(leaf_node) => self
                .config
                .keychain()
                .signer(&leaf_node.signing_identity)
                .ok_or(GroupError::NoCredentialFound),
            None => self.signer(),
        }?;

        let (commit_proposals, proposal_effects) = self.state.proposals.prepare_commit(
            sender.clone(),
            proposals,
            &self.context().extensions,
            self.config.credential_validator(),
            &self.state.public_tree,
            external_leaf,
            self.config.secret_store().into_external_id_validator(),
            self.config.proposal_filter(ProposalFilterInit::new(
                &self.state.public_tree,
                self.context(),
                sender.clone(),
            )),
        )?;

        let mut provisional_state = self.calculate_provisional_state(proposal_effects)?;
        let mut provisional_private_tree = self.provisional_private_tree(&provisional_state)?;

        if is_external {
            provisional_private_tree.self_index = provisional_state
                .external_init
                .ok_or(GroupError::ExternalCommitMissingExternalInit)?
                .0;

            self.private_tree.self_index = provisional_private_tree.self_index;
        }

        let mut provisional_group_context = provisional_state.group_context;
        provisional_group_context.epoch += 1;

        // Decide whether to populate the path field: If the path field is required based on the
        // proposals that are in the commit (see above), then it MUST be populated. Otherwise, the
        // sender MAY omit the path field at its discretion.
        let perform_path_update =
            options.prefer_path_update || provisional_state.path_update_required;

        let added_leaves = provisional_state.added_leaves;

        let (update_path, path_secrets, root_secret) = if perform_path_update {
            // If populating the path field: Create an UpdatePath using the new tree. Any new
            // member (from an add proposal) MUST be excluded from the resolution during the
            // computation of the UpdatePath. The GroupContext for this operation uses the
            // group_id, epoch, tree_hash, and confirmed_transcript_hash values in the initial
            // GroupContext object. The leaf_key_package for this UpdatePath must have a
            // parent_hash extension.
            let encap_gen = TreeKem::new(
                &mut provisional_state.public_tree,
                &mut provisional_private_tree,
            )
            .encap(
                &self.context().group_id,
                &mut provisional_group_context,
                &added_leaves
                    .iter()
                    .map(|(_, leaf_index)| *leaf_index)
                    .collect::<Vec<LeafIndex>>(),
                &signer,
                options.capabilities_update,
                options.extension_update,
                #[cfg(test)]
                &self.commit_modifiers,
            )?;

            (
                Some(encap_gen.update_path),
                Some(encap_gen.path_secrets),
                Some(encap_gen.root_secret),
            )
        } else {
            // Update the tree hash, since it was not updated by encap.
            provisional_state
                .public_tree
                .update_hashes(&mut vec![provisional_private_tree.self_index], &[])?;

            provisional_group_context.tree_hash = provisional_state.public_tree.tree_hash()?;
            (None, None, None)
        };

        let commit_secret =
            CommitSecret::from_root_secret(self.state.cipher_suite(), root_secret.as_ref())?;

        let epoch_repo = self.config.epoch_repo();
        let psk_store = self.config.secret_store();

        let psk_secret = crate::psk::psk_secret(
            self.state.cipher_suite(),
            Some(&psk_store),
            Some((&self.context().group_id, &epoch_repo)),
            &provisional_state.psks,
        )?;

        let commit = Commit {
            proposals: commit_proposals,
            path: update_path,
        };

        let mut auth_content = MLSAuthenticatedContent::new_signed(
            self.context(),
            sender,
            Content::Commit(commit),
            &signer,
            options.encryption_mode.into(),
            authenticated_data,
        )?;

        // Use the signature, the commit_secret and the psk_secret to advance the key schedule and
        // compute the confirmation_tag value in the MLSPlaintext.
        let confirmed_transcript_hash = ConfirmedTranscriptHash::create(
            self.state.cipher_suite(),
            &self.state.interim_transcript_hash,
            &auth_content,
        )?;

        provisional_group_context.confirmed_transcript_hash = confirmed_transcript_hash;

        let mut extensions = ExtensionList::new();

        if options.ratchet_tree_extension {
            let ratchet_tree_ext = RatchetTreeExt {
                tree_data: provisional_state.public_tree.export_node_data(),
            };

            extensions.set_extension(ratchet_tree_ext)?;
        }

        let key_schedule_result = KeySchedule::derive(
            &self.key_schedule,
            &commit_secret,
            &provisional_group_context,
            provisional_private_tree.self_index,
            &self.state.public_tree,
            &psk_secret,
        )?;

        let confirmation_tag = ConfirmationTag::create(
            &key_schedule_result.confirmation_key,
            &provisional_group_context.confirmed_transcript_hash,
            &self.state.cipher_suite(),
        )?;

        auth_content.auth.confirmation_tag = Some(confirmation_tag.clone());

        // Construct a GroupInfo reflecting the new state
        // Group ID, epoch, tree, and confirmed transcript hash from the new state
        let mut group_info = GroupInfo {
            group_context: provisional_group_context.clone().into(),
            extensions,
            confirmation_tag, // The confirmation_tag from the MLSPlaintext object
            signer: provisional_private_tree.self_index,
            signature: vec![],
        };

        // Sign the GroupInfo using the member's private signing key
        group_info.sign(&signer, &())?;

        let welcome = self.make_welcome_message(
            added_leaves,
            &key_schedule_result.joiner_secret,
            &psk_secret,
            path_secrets.as_ref(),
            provisional_state.psks,
            &group_info,
        )?;

        let commit_message = self.format_for_wire(auth_content.clone())?;

        let pending_commit = CommitGeneration {
            content: auth_content,
            pending_secrets: root_secret.map(|rs| (provisional_private_tree, rs)),
        };

        self.pending_commit = Some(pending_commit);

        Ok((commit_message, welcome))
    }
}
