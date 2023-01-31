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
use crate::{
    client_config::ProposalFilterInit,
    key_package::KeyPackage,
    provider::crypto::CipherSuiteProvider,
    psk::{ExternalPskIdValidator, JustPreSharedKeyID, PreSharedKeyID},
    time::MlsTime,
    tree_kem::{
        leaf_node::LeafNode, node::LeafIndex, path_secret::PathSecret, validate_update_path,
        TreeKemPrivate, TreeKemPublic, UpdatePath, ValidatedUpdatePath,
    },
};
use async_trait::async_trait;
use aws_mls_core::{group::RosterUpdate, identity::IdentityProvider};

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

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct StateUpdate<IE> {
    pub roster_update: RosterUpdate<Member>,
    pub identity_events: Vec<IE>,
    pub added_psks: Vec<JustPreSharedKeyID>,
    pub pending_reinit: bool,
    pub active: bool,
    pub epoch: u64,
    pub rejected_proposals: Vec<(ProposalRef, Proposal)>,
}

#[derive(Debug, Clone)]
#[allow(clippy::large_enum_variant)]
pub enum Event<IE> {
    ApplicationMessage(Vec<u8>),
    Commit(StateUpdate<IE>),
    Proposal((Proposal, ProposalRef)),
}

#[derive(Clone, Debug)]
pub struct ProcessedMessage<E> {
    pub event: E,
    pub sender: Option<Sender>,
    pub authenticated_data: Vec<u8>,
}

#[derive(Clone, Debug)]
#[allow(clippy::large_enum_variant)]
pub enum ExternalEvent<IE> {
    Commit(StateUpdate<IE>),
    Proposal((Proposal, ProposalRef)),
    Ciphertext(MLSCiphertext),
}

impl<E> From<E> for ProcessedMessage<E> {
    fn from(event: E) -> Self {
        ProcessedMessage {
            event,
            sender: None,
            authenticated_data: vec![],
        }
    }
}

impl<IE> From<StateUpdate<IE>> for Event<IE> {
    fn from(update: StateUpdate<IE>) -> Self {
        Event::Commit(update)
    }
}

impl<IE> From<StateUpdate<IE>> for ExternalEvent<IE> {
    fn from(state_update: StateUpdate<IE>) -> Self {
        ExternalEvent::Commit(state_update)
    }
}

impl<IE> TryFrom<ApplicationData> for ExternalEvent<IE> {
    type Error = GroupError;

    fn try_from(_: ApplicationData) -> Result<Self, Self::Error> {
        Err(GroupError::UnencryptedApplicationMessage)
    }
}

impl<IE> From<(Proposal, ProposalRef)> for Event<IE> {
    fn from(proposal_and_ref: (Proposal, ProposalRef)) -> Self {
        Event::Proposal(proposal_and_ref)
    }
}

impl<IE> From<(Proposal, ProposalRef)> for ExternalEvent<IE> {
    fn from(proposal_and_ref: (Proposal, ProposalRef)) -> Self {
        ExternalEvent::Proposal(proposal_and_ref)
    }
}

#[allow(clippy::large_enum_variant)]
pub(crate) enum EventOrContent<E> {
    Event(E),
    Content(MLSAuthenticatedContent),
}

#[async_trait]
pub(crate) trait MessageProcessor: Send + Sync {
    type EventType: From<(Proposal, ProposalRef)>
        + TryFrom<ApplicationData, Error = GroupError>
        + From<StateUpdate<<Self::IdentityProvider as IdentityProvider>::IdentityEvent>>
        + Send;

    type ProposalFilter: ProposalFilter;
    type IdentityProvider: IdentityProvider;
    type CipherSuiteProvider: CipherSuiteProvider;
    type ExternalPskIdValidator: ExternalPskIdValidator;

    async fn process_incoming_message(
        &mut self,
        message: MLSMessage,
        cache_proposal: bool,
    ) -> Result<ProcessedMessage<Self::EventType>, GroupError> {
        self.process_incoming_message_with_time(message, cache_proposal, None)
            .await
    }

    async fn process_incoming_message_with_time(
        &mut self,
        message: MLSMessage,
        cache_proposal: bool,
        time_sent: Option<MlsTime>,
    ) -> Result<ProcessedMessage<Self::EventType>, GroupError> {
        self.check_metadata(&message)?;

        let wire_format = message.wire_format();

        let event_or_content = match message.payload {
            MLSMessagePayload::Plain(plaintext) => self.verify_plaintext_authentication(plaintext),
            MLSMessagePayload::Cipher(cipher_text) => self.process_ciphertext(cipher_text).await,
            _ => Err(GroupError::UnexpectedMessageType(
                vec![WireFormat::Plain, WireFormat::Cipher],
                wire_format,
            )),
        }?;

        let msg = match event_or_content {
            EventOrContent::Event(event) => ProcessedMessage::from(event),
            EventOrContent::Content(content) => {
                self.process_auth_content(content, cache_proposal, time_sent)
                    .await?
            }
        };

        Ok(msg)
    }

    async fn process_auth_content(
        &mut self,
        auth_content: MLSAuthenticatedContent,
        cache_proposal: bool,
        time_sent: Option<MlsTime>,
    ) -> Result<ProcessedMessage<Self::EventType>, GroupError> {
        let authenticated_data = auth_content.content.authenticated_data.clone();

        let sender = Some(auth_content.content.sender.clone());

        let event = match auth_content.content.content {
            Content::Application(data) => Self::EventType::try_from(data),
            Content::Commit(_) => self
                .process_commit(auth_content, time_sent)
                .await
                .map(Self::EventType::from),
            Content::Proposal(ref proposal) => self
                .process_proposal(&auth_content, proposal, cache_proposal)
                .map(|p_ref| Self::EventType::from((proposal.clone(), p_ref))),
        }?;

        Ok(ProcessedMessage {
            event,
            sender,
            authenticated_data,
        })
    }

    fn process_proposal(
        &mut self,
        auth_content: &MLSAuthenticatedContent,
        proposal: &Proposal,
        cache_proposal: bool,
    ) -> Result<ProposalRef, GroupError> {
        let proposal_ref = ProposalRef::from_content(self.cipher_suite_provider(), auth_content)?;

        let group_state = self.group_state_mut();

        cache_proposal.then(|| {
            group_state.proposals.insert(
                proposal_ref.clone(),
                proposal.clone(),
                auth_content.content.sender.clone(),
            )
        });

        Ok(proposal_ref)
    }

    async fn make_state_update(
        &self,
        provisional: &ProvisionalState,
        path: Option<&UpdatePath>,
        sender: LeafIndex,
    ) -> Result<StateUpdate<<Self::IdentityProvider as IdentityProvider>::IdentityEvent>, GroupError>
    {
        let mut added = provisional
            .added_leaves
            .iter()
            .map(Member::from)
            .collect::<Vec<_>>();

        let removed = provisional
            .removed_leaves
            .iter()
            .map(From::from)
            .collect::<Vec<_>>();

        let mut updated = provisional
            .updated_leaves
            .iter()
            .map(Member::from)
            .collect::<Vec<_>>();

        if let Some(path) = path {
            if provisional.external_init.is_some() {
                added.push((sender, &path.leaf_node).into())
            } else {
                updated.push((sender, &path.leaf_node).into())
            }
        }

        let psks = provisional
            .psks
            .iter()
            .map(|psk_id| psk_id.key_id.clone())
            .collect::<Vec<_>>();

        let roster_update = RosterUpdate {
            added,
            removed,
            updated,
        };

        let identity_events = self
            .identity_provider()
            .identity_events(&roster_update, self.group_state().roster())
            .await
            .map_err(|e| GroupError::IdentityProviderError(e.into()))?;

        let update = StateUpdate {
            roster_update,
            added_psks: psks,
            pending_reinit: provisional.reinit.is_some(),
            active: true,
            epoch: provisional.epoch,
            rejected_proposals: provisional.rejected_proposals.clone(),
            identity_events,
        };

        Ok(update)
    }

    async fn process_commit(
        &mut self,
        auth_content: MLSAuthenticatedContent,
        time_sent: Option<MlsTime>,
    ) -> Result<StateUpdate<<Self::IdentityProvider as IdentityProvider>::IdentityEvent>, GroupError>
    {
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
            self.identity_provider(),
            self.cipher_suite_provider(),
            &group_state.public_tree,
            self.external_psk_id_validator(),
            self.proposal_filter(ProposalFilterInit::new(auth_content.content.sender.clone())),
            time_sent,
        )
        .await?;

        let mut provisional_state = self.calculate_provisional_state(proposal_effects)?;

        let sender = commit_sender(&auth_content.content.sender, &provisional_state)?;

        let mut state_update = self
            .make_state_update(&provisional_state, commit.path.as_ref(), sender)
            .await?;

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

        let update_path = match commit.path.as_ref() {
            Some(update_path) => validate_update_path(
                &self.identity_provider(),
                self.cipher_suite_provider(),
                update_path,
                &provisional_state,
                sender,
                time_sent,
            )
            .await
            .map(Some),
            None => Ok(None),
        }?;

        provisional_state.group_context.epoch = provisional_state.epoch;

        let new_secrets = match update_path {
            Some(update_path) => {
                self.apply_update_path(sender, update_path, &mut provisional_state)
                    .await
            }
            None => Ok(None),
        }?;

        // Update the new GroupContext's confirmed and interim transcript hashes using the new Commit.
        let (interim_transcript_hash, confirmed_transcript_hash) = transcript_hashes(
            self.cipher_suite_provider(),
            &self.group_state().interim_transcript_hash,
            &auth_content,
        )?;

        // Update the transcript hash to get the new context.
        provisional_state.group_context.confirmed_transcript_hash = confirmed_transcript_hash;

        // Update the parent hashes in the new context
        provisional_state.public_tree.update_hashes(
            &mut vec![sender],
            &[],
            self.cipher_suite_provider(),
        )?;

        // Update the tree hash in the new context
        provisional_state.group_context.tree_hash = provisional_state
            .public_tree
            .tree_hash(self.cipher_suite_provider())?;

        if let Some(confirmation_tag) = auth_content.auth.confirmation_tag {
            // Update the key schedule to calculate new private keys
            self.update_key_schedule(
                new_secrets,
                interim_transcript_hash,
                confirmation_tag,
                provisional_state,
            )
            .await?;

            Ok(state_update)
        } else {
            Err(GroupError::InvalidConfirmationTag)
        }
    }

    fn group_state(&self) -> &GroupState;
    fn group_state_mut(&mut self) -> &mut GroupState;
    fn self_index(&self) -> Option<LeafIndex>;
    fn proposal_filter(&self, init: ProposalFilterInit) -> Self::ProposalFilter;
    fn identity_provider(&self) -> Self::IdentityProvider;
    fn cipher_suite_provider(&self) -> &Self::CipherSuiteProvider;
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

    async fn process_ciphertext(
        &mut self,
        cipher_text: MLSCiphertext,
    ) -> Result<EventOrContent<Self::EventType>, GroupError>;

    fn verify_plaintext_authentication(
        &self,
        message: MLSPlaintext,
    ) -> Result<EventOrContent<Self::EventType>, GroupError>;

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

    async fn apply_update_path(
        &mut self,
        sender: LeafIndex,
        update_path: ValidatedUpdatePath,
        provisional_state: &mut ProvisionalState,
    ) -> Result<Option<(TreeKemPrivate, PathSecret)>, GroupError> {
        provisional_state
            .public_tree
            .apply_update_path(
                sender,
                &update_path,
                self.identity_provider(),
                self.cipher_suite_provider(),
            )
            .await
            .map(|_| None)
            .map_err(Into::into)
    }

    async fn update_key_schedule(
        &mut self,
        secrets: Option<(TreeKemPrivate, PathSecret)>,
        interim_transcript_hash: InterimTranscriptHash,
        confirmation_tag: ConfirmationTag,
        provisional_public_state: ProvisionalState,
    ) -> Result<(), GroupError>;
}
