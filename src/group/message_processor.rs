use crate::{
    client_config::ProposalFilterInit,
    credential::CredentialValidator,
    key_package::KeyPackage,
    psk::{ExternalPskIdValidator, JustPreSharedKeyID, PreSharedKeyID},
    tree_kem::{
        leaf_node::LeafNode, leaf_node_validator::LeafNodeValidator, node::LeafIndex,
        path_secret::PathSecret, TreeKemPrivate, TreeKemPublic, UpdatePath, UpdatePathValidator,
        ValidatedUpdatePath,
    },
};

use super::{
    commit_sender,
    confirmation_tag::ConfirmationTag,
    framing::{
        ApplicationData, Content, ContentType, MLSCiphertext, MLSMessage, MLSMessagePayload,
        MLSPlaintext, Sender, WireFormat,
    },
    message_signature::MLSAuthenticatedContent,
    proposal::{ExternalInit, Proposal, ReInit},
    proposal_cache::ProposalSetEffects,
    proposal_effects,
    state::GroupState,
    transcript_hash::InterimTranscriptHash,
    transcript_hashes, GroupContext, GroupError, Member, ProposalFilter, ProposalRef,
};

#[derive(Debug)]
pub(crate) struct ProvisionalState {
    pub(crate) public_tree: TreeKemPublic,
    pub(crate) added_leaves: Vec<(KeyPackage, LeafIndex)>,
    pub(crate) removed_leaves: Vec<(LeafIndex, LeafNode)>,
    pub(crate) updated_leaves: Vec<(LeafIndex, LeafNode)>,
    pub(crate) group_context: GroupContext,
    pub(crate) epoch: u64,
    pub(crate) path_update_required: bool,
    pub(crate) psks: Vec<PreSharedKeyID>,
    pub(crate) reinit: Option<ReInit>,
    pub(crate) external_init: Option<(LeafIndex, ExternalInit)>,
    pub(crate) rejected_proposals: Vec<(ProposalRef, Proposal)>,
}

#[derive(Clone, Debug)]
pub struct StateUpdate {
    pub added: Vec<u32>,
    pub removed: Vec<Member>,
    pub updated: Vec<u32>,
    pub psks: Vec<JustPreSharedKeyID>,
    pub reinit: Option<ReInit>,
    pub external_init: Option<u32>,
    pub active: bool,
    pub epoch: u64,
    pub rejected_proposals: Vec<(ProposalRef, Proposal)>,
}

impl From<&ProvisionalState> for StateUpdate {
    fn from(provisional: &ProvisionalState) -> Self {
        let added = provisional
            .added_leaves
            .iter()
            .map(|(_, leaf_index)| leaf_index.0)
            .collect::<Vec<_>>();

        let removed = provisional
            .removed_leaves
            .iter()
            .map(From::from)
            .collect::<Vec<_>>();

        let external_init_leaf = provisional
            .external_init
            .as_ref()
            .map(|(leaf_index, _)| *leaf_index);

        let psks = provisional
            .psks
            .iter()
            .map(|psk_id| psk_id.key_id.clone())
            .collect::<Vec<_>>();

        StateUpdate {
            added,
            removed,
            updated: provisional
                .updated_leaves
                .iter()
                .map(|(i, _)| i.0)
                .collect(),
            psks,
            reinit: provisional.reinit.clone(),
            external_init: external_init_leaf.map(|i| i.0),
            active: true,
            epoch: provisional.epoch,
            rejected_proposals: provisional.rejected_proposals.clone(),
        }
    }
}

#[derive(Debug)]
#[allow(clippy::large_enum_variant)]
pub enum Event {
    ApplicationMessage(Vec<u8>),
    Commit(StateUpdate),
    Proposal(Proposal),
}

#[derive(Clone, Debug)]
pub struct ProcessedMessage<E> {
    pub event: E,
    pub sender_index: Option<u32>,
    pub authenticated_data: Vec<u8>,
}

#[derive(Clone, Debug)]
#[allow(clippy::large_enum_variant)]
pub enum ExternalEvent {
    Commit(StateUpdate),
    Proposal(Proposal),
    Ciphertext(MLSCiphertext),
}

impl<E> From<E> for ProcessedMessage<E> {
    fn from(event: E) -> Self {
        ProcessedMessage {
            event,
            sender_index: None,
            authenticated_data: vec![],
        }
    }
}

impl From<StateUpdate> for Event {
    fn from(update: StateUpdate) -> Self {
        Event::Commit(update)
    }
}

impl From<StateUpdate> for ExternalEvent {
    fn from(state_update: StateUpdate) -> Self {
        ExternalEvent::Commit(state_update)
    }
}

impl TryFrom<ApplicationData> for ExternalEvent {
    type Error = GroupError;

    fn try_from(_: ApplicationData) -> Result<Self, Self::Error> {
        Err(GroupError::UnencryptedApplicationMessage)
    }
}

impl From<Proposal> for Event {
    fn from(proposal: Proposal) -> Self {
        Event::Proposal(proposal)
    }
}

impl From<Proposal> for ExternalEvent {
    fn from(proposal: Proposal) -> Self {
        ExternalEvent::Proposal(proposal)
    }
}

pub(crate) enum EventOrContent<E> {
    Event(E),
    Content(MLSAuthenticatedContent),
}

pub(crate) trait MessageProcessor<E>
where
    E: From<Proposal> + TryFrom<ApplicationData, Error = GroupError> + From<StateUpdate>,
{
    type ProposalFilter: ProposalFilter;
    type CredentialValidator: CredentialValidator;
    type ExternalPskIdValidator: ExternalPskIdValidator;

    fn process_incoming_message(
        &mut self,
        message: MLSMessage,
    ) -> Result<ProcessedMessage<E>, GroupError> {
        self.check_metadata(&message)?;

        let wire_format = message.wire_format();

        let event_or_content = match message.payload {
            MLSMessagePayload::Plain(plaintext) => self.verify_plaintext_authentication(plaintext),
            MLSMessagePayload::Cipher(cipher_text) => self.process_ciphertext(cipher_text),
            _ => Err(GroupError::UnexpectedMessageType(
                vec![WireFormat::Plain, WireFormat::Cipher],
                wire_format,
            )),
        }?;

        let msg = match event_or_content {
            EventOrContent::Event(event) => ProcessedMessage::from(event),
            EventOrContent::Content(content) => self.process_auth_content(content)?,
        };

        Ok(msg)
    }

    fn process_auth_content(
        &mut self,
        auth_content: MLSAuthenticatedContent,
    ) -> Result<ProcessedMessage<E>, GroupError> {
        let authenticated_data = auth_content.content.authenticated_data.clone();

        let sender_index = match auth_content.content.sender {
            Sender::Member(index) => Some(index.0),
            _ => None,
        };

        let event = match auth_content.content.content {
            Content::Application(data) => E::try_from(data),
            Content::Commit(_) => self.process_commit(auth_content).map(E::from),
            Content::Proposal(ref proposal) => self
                .process_proposal(&auth_content, proposal)
                .map(|_| E::from(proposal.clone())),
        }?;

        Ok(ProcessedMessage {
            event,
            sender_index,
            authenticated_data,
        })
    }

    fn process_proposal(
        &mut self,
        auth_content: &MLSAuthenticatedContent,
        proposal: &Proposal,
    ) -> Result<(), GroupError> {
        let group_state = self.group_state_mut();

        let proposal_ref =
            ProposalRef::from_content(group_state.context.cipher_suite, auth_content)?;

        group_state.proposals.insert(
            proposal_ref,
            proposal.clone(),
            auth_content.content.sender.clone(),
        );

        Ok(())
    }

    fn process_commit(
        &mut self,
        auth_content: MLSAuthenticatedContent,
    ) -> Result<StateUpdate, GroupError> {
        let commit = match auth_content.content.content {
            Content::Commit(ref commit) => Ok(commit),
            _ => Err(GroupError::NotCommitContent(
                auth_content.content.content_type(),
            )),
        }?;

        let group_state = self.group_state();

        // Calculate the diff that the commit will apply
        let proposal_effects = proposal_effects(
            self.self_index(),
            &group_state.proposals,
            commit,
            &auth_content.content.sender,
            &group_state.context.extensions,
            self.credential_validator(),
            &group_state.public_tree,
            self.external_psk_id_validator(),
            self.proposal_filter(ProposalFilterInit::new(auth_content.content.sender.clone())),
        )?;

        let mut provisional_state = self.calculate_provisional_state(proposal_effects)?;

        let sender = commit_sender(&auth_content.content.sender, &provisional_state)?;
        let mut state_update = StateUpdate::from(&provisional_state);

        //Verify that the path value is populated if the proposals vector contains any Update
        // or Remove proposals, or if it's empty. Otherwise, the path value MAY be omitted.
        if provisional_state.path_update_required && commit.path.is_none() {
            return Err(GroupError::CommitMissingPath);
        }

        if !self.can_continue_processing(&provisional_state) {
            state_update.active = false;
            return Ok(state_update);
        }

        if let Some(reinit) = provisional_state.reinit {
            self.group_state_mut().pending_reinit = Some(reinit);
            state_update.active = false;
            return Ok(state_update);
        }

        let update_path = commit
            .path
            .as_ref()
            .map(|update_path| self.validate_update_path(&provisional_state, update_path))
            .transpose()?;

        provisional_state.group_context.epoch = provisional_state.epoch;

        let new_secrets = update_path
            .and_then(|update_path| {
                self.apply_update_path(sender, update_path, &mut provisional_state)
                    .transpose()
            })
            .transpose()?;

        // Update the new GroupContext's confirmed and interim transcript hashes using the new Commit.
        let (interim_transcript_hash, confirmed_transcript_hash) = transcript_hashes(
            provisional_state.group_context.cipher_suite,
            &self.group_state().interim_transcript_hash,
            &auth_content,
        )?;

        // Update the transcript hash to get the new context.
        provisional_state.group_context.confirmed_transcript_hash = confirmed_transcript_hash;

        // Update the parent hashes in the new context
        provisional_state
            .public_tree
            .update_hashes(&mut vec![sender], &[])?;

        // Update the tree hash in the new context
        provisional_state.group_context.tree_hash = provisional_state.public_tree.tree_hash()?;

        if let Some(confirmation_tag) = auth_content.auth.confirmation_tag {
            // Update the key schedule to calculate new private keys
            self.update_key_schedule(
                new_secrets,
                interim_transcript_hash,
                confirmation_tag,
                provisional_state,
            )?;

            Ok(state_update)
        } else {
            Err(GroupError::InvalidConfirmationTag)
        }
    }

    fn group_state(&self) -> &GroupState;
    fn group_state_mut(&mut self) -> &mut GroupState;
    fn self_index(&self) -> Option<LeafIndex>;
    fn proposal_filter(&self, init: ProposalFilterInit) -> Self::ProposalFilter;
    fn credential_validator(&self) -> Self::CredentialValidator;
    fn external_psk_id_validator(&self) -> Self::ExternalPskIdValidator;
    fn can_continue_processing(&self, provisional_state: &ProvisionalState) -> bool;
    fn min_epoch_available(&self) -> Option<u64>;

    fn check_metadata(&self, message: &MLSMessage) -> Result<(), GroupError> {
        let context = &self.group_state().context;

        message
            .version
            .into_enum()
            .filter(|&v| v == context.protocol_version)
            .ok_or({
                GroupError::InvalidProtocolVersion(context.protocol_version, message.version)
            })?;

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
            if group_id != &context.group_id {
                return Err(GroupError::InvalidGroupId(group_id.clone()));
            }

            match content_type {
                ContentType::Proposal | ContentType::Commit => {
                    if context.epoch != epoch {
                        Err(GroupError::InvalidEpoch(epoch))
                    } else {
                        Ok(())
                    }
                }
                ContentType::Application => {
                    if let Some(min) = self.min_epoch_available() {
                        if epoch < min {
                            Err(GroupError::InvalidEpoch(epoch))
                        } else {
                            Ok(())
                        }
                    } else {
                        Ok(())
                    }
                }
            }?;

            // Proposal and commit messages must be sent in the current epoch
            if (content_type == ContentType::Proposal || content_type == ContentType::Commit)
                && epoch != context.epoch
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

    fn process_ciphertext(
        &mut self,
        cipher_text: MLSCiphertext,
    ) -> Result<EventOrContent<E>, GroupError>;

    fn verify_plaintext_authentication(
        &self,
        message: MLSPlaintext,
    ) -> Result<EventOrContent<E>, GroupError>;

    fn calculate_provisional_state(
        &self,
        proposals: ProposalSetEffects,
    ) -> Result<ProvisionalState, GroupError> {
        let group_state = self.group_state();

        if group_state.pending_reinit.is_some() {
            return Err(GroupError::GroupUsedAfterReInit);
        }

        let mut provisional_group_context = group_state.context.clone();

        // Determine if a path update is required
        let path_update_required = proposals.path_update_required();

        // Locate a group context extension
        if let Some(group_context_extensions) = proposals.group_context_ext {
            // Group context extensions are a full replacement and not a merge
            provisional_group_context.extensions = group_context_extensions;
        }

        Ok(ProvisionalState {
            public_tree: proposals.tree,
            added_leaves: proposals
                .adds
                .into_iter()
                .zip(proposals.added_leaf_indexes)
                .collect(),
            removed_leaves: proposals.removed_leaves,
            updated_leaves: proposals.updates,
            epoch: provisional_group_context.epoch + 1,
            path_update_required,
            group_context: provisional_group_context,
            psks: proposals.psks,
            reinit: proposals.reinit,
            external_init: proposals.external_init,
            rejected_proposals: proposals.rejected_proposals,
        })
    }

    fn validate_update_path(
        &self,
        provisional_public_state: &ProvisionalState,
        update_path: &UpdatePath,
    ) -> Result<ValidatedUpdatePath, GroupError> {
        let required_capabilities = provisional_public_state
            .group_context
            .extensions
            .get_extension()?;

        let leaf_validator = LeafNodeValidator::new(
            provisional_public_state.group_context.cipher_suite,
            required_capabilities.as_ref(),
            self.credential_validator(),
        );

        let update_path_validator = UpdatePathValidator::new(leaf_validator);

        let validated_update_path = update_path_validator.validate(
            update_path.clone(),
            &provisional_public_state.group_context.group_id,
        )?;

        Ok(validated_update_path)
    }

    fn apply_update_path(
        &mut self,
        sender: LeafIndex,
        update_path: ValidatedUpdatePath,
        provisional_state: &mut ProvisionalState,
    ) -> Result<Option<(TreeKemPrivate, PathSecret)>, GroupError> {
        provisional_state
            .public_tree
            .apply_update_path(sender, &update_path, self.credential_validator())
            .map(|_| None)
            .map_err(Into::into)
    }

    fn update_key_schedule(
        &mut self,
        secrets: Option<(TreeKemPrivate, PathSecret)>,
        interim_transcript_hash: InterimTranscriptHash,
        confirmation_tag: ConfirmationTag,
        provisional_public_state: ProvisionalState,
    ) -> Result<(), GroupError>;
}
