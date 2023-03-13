use super::{
    commit_sender,
    confirmation_tag::ConfirmationTag,
    framing::{
        ApplicationData, Content, ContentType, MLSMessage, MLSMessagePayload, PrivateMessage,
        PublicMessage, Sender, WireFormat,
    },
    member_from_key_package, member_from_leaf_node,
    message_signature::AuthenticatedContent,
    proposal::{CustomProposal, ExternalInit, Proposal, ReInitProposal},
    proposal_cache::ProposalSetEffects,
    proposal_effects,
    proposal_filter::ProposalFilter,
    proposal_ref::ProposalRef,
    state::GroupState,
    transcript_hash::InterimTranscriptHash,
    transcript_hashes, GroupContext,
};
use crate::{
    client::MlsError,
    key_package::KeyPackage,
    psk::{ExternalPskIdValidator, JustPreSharedKeyID, PreSharedKeyID},
    time::MlsTime,
    tree_kem::{
        leaf_node::LeafNode, node::LeafIndex, path_secret::PathSecret, validate_update_path,
        TreeKemPrivate, TreeKemPublic, UpdatePath, ValidatedUpdatePath,
    },
    CipherSuiteProvider,
};
use async_trait::async_trait;
use aws_mls_core::{
    group::{MemberUpdate, RosterUpdate},
    identity::{IdentityProvider, IdentityWarning},
    psk::ExternalPskId,
};
use itertools::Itertools;

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
    pub(crate) reinit: Option<ReInitProposal>,
    pub(crate) external_init: Option<(LeafIndex, ExternalInit)>,
    pub(crate) custom_proposals: Vec<CustomProposal>,
    pub(crate) rejected_proposals: Vec<(ProposalRef, Proposal)>,
}

/// Representation of changes made by a [commit](crate::Group::commit).
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct StateUpdate {
    pub(crate) roster_update: RosterUpdate,
    pub(crate) identity_warnings: Vec<IdentityWarning>,
    pub(crate) added_psks: Vec<ExternalPskId>,
    pub(crate) pending_reinit: bool,
    pub(crate) active: bool,
    pub(crate) epoch: u64,
    pub(crate) custom_proposals: Vec<CustomProposal>,
    pub(crate) unused_proposals: Vec<Proposal>,
}

impl StateUpdate {
    /// Changes to the roster as a result of proposals.
    pub fn roster_update(&self) -> &RosterUpdate {
        &self.roster_update
    }

    /// Warnings about roster changes produced by the
    /// [`IdentityProvider`](crate::IdentityProvider)
    /// currently in use by the group.
    pub fn identity_warnings(&self) -> &[IdentityWarning] {
        &self.identity_warnings
    }

    /// Pre-shared keys that have been added to the group.
    pub fn added_psks(&self) -> &[ExternalPskId] {
        &self.added_psks
    }

    /// Flag to indicate if the group is now pending reinitialization due to
    /// receiving a [`ReInit`](crate::group::proposal::Proposal::ReInit)
    /// proposal.
    pub fn is_pending_reinit(&self) -> bool {
        self.pending_reinit
    }

    /// Flag to indicate the group is still active. This will be false if the
    /// member processing the commit has been removed from the group.
    pub fn is_active(&self) -> bool {
        self.active
    }

    /// The new epoch of the group state.
    pub fn new_epoch(&self) -> u64 {
        self.epoch
    }

    /// Custom proposals that were committed to.
    pub fn custom_proposals(&self) -> &[CustomProposal] {
        &self.custom_proposals
    }

    /// Proposals that were received in the prior epoch but not committed to.
    pub fn unused_proposals(&self) -> &[Proposal] {
        &self.unused_proposals
    }
}

#[derive(Debug, Clone)]
#[allow(clippy::large_enum_variant)]
/// An event generated as a result of processing a message for a group with
/// [`Group::process_incoming_message`](crate::group::Group::process_incoming_message).
pub enum Event {
    /// An application message was decrypted.
    ApplicationMessage(Vec<u8>),
    /// A new commit was processed creating a new group state.
    Commit(StateUpdate),
    /// A proposal was received.
    Proposal((Proposal, ProposalRef)),
}

/// Result of calling
/// [`Group::process_incoming_message`](crate::group::Group::process_incoming_message)
#[derive(Clone, Debug)]
pub struct ProcessedMessage<E> {
    /// The [`Event`] produced by processing the message.
    pub event: E,
    /// Sender description of the message processed.
    pub sender: Option<Sender>, //TODO: Find a way to get rid of Option here
    /// Unencrypted authenticated data sent with the processed message.
    pub authenticated_data: Vec<u8>,
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

impl From<StateUpdate> for Event {
    fn from(update: StateUpdate) -> Self {
        Event::Commit(update)
    }
}

impl From<(Proposal, ProposalRef)> for Event {
    fn from(proposal_and_ref: (Proposal, ProposalRef)) -> Self {
        Event::Proposal(proposal_and_ref)
    }
}

#[allow(clippy::large_enum_variant)]
pub(crate) enum EventOrContent<E> {
    Event(E),
    Content(AuthenticatedContent),
}

#[async_trait]
pub(crate) trait MessageProcessor: Send + Sync {
    type EventType: From<(Proposal, ProposalRef)>
        + TryFrom<ApplicationData, Error = MlsError>
        + From<StateUpdate>
        + Send;

    type ProposalFilter: ProposalFilter;
    type IdentityProvider: IdentityProvider;
    type CipherSuiteProvider: CipherSuiteProvider;
    type ExternalPskIdValidator: ExternalPskIdValidator;

    async fn process_incoming_message(
        &mut self,
        message: MLSMessage,
        cache_proposal: bool,
    ) -> Result<ProcessedMessage<Self::EventType>, MlsError> {
        self.process_incoming_message_with_time(message, cache_proposal, None)
            .await
    }

    async fn process_incoming_message_with_time(
        &mut self,
        message: MLSMessage,
        cache_proposal: bool,
        time_sent: Option<MlsTime>,
    ) -> Result<ProcessedMessage<Self::EventType>, MlsError> {
        let event_or_content = self.get_event_from_incoming_message(message).await?;

        self.process_event_or_content(event_or_content, cache_proposal, time_sent)
            .await
    }

    async fn get_event_from_incoming_message(
        &mut self,
        message: MLSMessage,
    ) -> Result<EventOrContent<Self::EventType>, MlsError> {
        self.check_metadata(&message)?;

        let wire_format = message.wire_format();

        match message.payload {
            MLSMessagePayload::Plain(plaintext) => self.verify_plaintext_authentication(plaintext),
            MLSMessagePayload::Cipher(cipher_text) => self.process_ciphertext(cipher_text).await,
            _ => Err(MlsError::UnexpectedMessageType(
                vec![WireFormat::PublicMessage, WireFormat::PrivateMessage],
                wire_format,
            )),
        }
    }

    async fn process_event_or_content(
        &mut self,
        event_or_content: EventOrContent<Self::EventType>,
        cache_proposal: bool,
        time_sent: Option<MlsTime>,
    ) -> Result<ProcessedMessage<Self::EventType>, MlsError> {
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
        auth_content: AuthenticatedContent,
        cache_proposal: bool,
        time_sent: Option<MlsTime>,
    ) -> Result<ProcessedMessage<Self::EventType>, MlsError> {
        let authenticated_data = auth_content.content.authenticated_data.clone();

        let sender = Some(auth_content.content.sender);

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
        auth_content: &AuthenticatedContent,
        proposal: &Proposal,
        cache_proposal: bool,
    ) -> Result<ProposalRef, MlsError> {
        let proposal_ref = ProposalRef::from_content(self.cipher_suite_provider(), auth_content)?;

        let group_state = self.group_state_mut();

        cache_proposal.then(|| {
            group_state.proposals.insert(
                proposal_ref.clone(),
                proposal.clone(),
                auth_content.content.sender,
            )
        });

        Ok(proposal_ref)
    }

    async fn make_state_update(
        &self,
        provisional: &ProvisionalState,
        path: Option<&UpdatePath>,
        sender: LeafIndex,
    ) -> Result<StateUpdate, MlsError> {
        let mut added = provisional
            .added_leaves
            .iter()
            .map(|(kp, index)| member_from_key_package(kp, *index))
            .collect::<Vec<_>>();

        let removed = provisional
            .removed_leaves
            .iter()
            .map(|(index, node)| member_from_leaf_node(node, *index))
            .collect::<Vec<_>>();

        let old_tree = &self.group_state().public_tree;

        let mut updated = provisional
            .updated_leaves
            .iter()
            .map(|(index, node)| {
                let prior = old_tree
                    .get_leaf_node(*index)
                    .map(|n| member_from_leaf_node(n, *index))?;

                let new = member_from_leaf_node(node, *index);

                Ok::<_, MlsError>(MemberUpdate::new(prior, new))
            })
            .collect::<Result<Vec<_>, _>>()?;

        if let Some(path) = path {
            if provisional.external_init.is_some() {
                added.push(member_from_leaf_node(&path.leaf_node, sender))
            } else {
                let prior = old_tree
                    .get_leaf_node(sender)
                    .map(|n| member_from_leaf_node(n, sender))?;

                let new = member_from_leaf_node(&path.leaf_node, sender);

                updated.push(MemberUpdate::new(prior, new))
            }
        }

        let psks = provisional
            .psks
            .iter()
            .filter_map(|psk_id| match &psk_id.key_id {
                JustPreSharedKeyID::External(e) => Some(e.clone()),
                _ => None,
            })
            .collect::<Vec<_>>();

        let roster_update = RosterUpdate::new(added, removed, updated);

        let identity_warnings = self
            .identity_provider()
            .identity_warnings(&roster_update)
            .await
            .map_err(|e| MlsError::IdentityProviderError(e.into()))?;

        let update = StateUpdate {
            roster_update,
            identity_warnings,
            added_psks: psks,
            pending_reinit: provisional.reinit.is_some(),
            active: true,
            epoch: provisional.epoch,
            custom_proposals: provisional.custom_proposals.clone(),
            unused_proposals: provisional
                .rejected_proposals
                .iter()
                .map(|(_, p)| p.clone())
                .collect_vec(),
        };

        Ok(update)
    }

    async fn process_commit(
        &mut self,
        auth_content: AuthenticatedContent,
        time_sent: Option<MlsTime>,
    ) -> Result<StateUpdate, MlsError> {
        let commit = match auth_content.content.content {
            Content::Commit(ref commit) => Ok(commit),
            _ => Err(MlsError::NotCommitContent(
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
            self.proposal_filter(),
            time_sent,
            &group_state.roster(),
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
            return Err(MlsError::CommitMissingPath);
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
            Err(MlsError::InvalidConfirmationTag)
        }
    }

    fn group_state(&self) -> &GroupState;
    fn group_state_mut(&mut self) -> &mut GroupState;
    fn self_index(&self) -> Option<LeafIndex>;
    fn proposal_filter(&self) -> Self::ProposalFilter;
    fn identity_provider(&self) -> Self::IdentityProvider;
    fn cipher_suite_provider(&self) -> &Self::CipherSuiteProvider;
    fn external_psk_id_validator(&self) -> Self::ExternalPskIdValidator;
    fn can_continue_processing(&self, provisional_state: &ProvisionalState) -> bool;
    fn min_epoch_available(&self) -> Option<u64>;

    fn check_metadata(&self, message: &MLSMessage) -> Result<(), MlsError> {
        let context = &self.group_state().context;

        if message.version != context.protocol_version {
            return Err(MlsError::InvalidProtocolVersion(
                context.protocol_version,
                message.version,
            ));
        }

        if let Some((group_id, epoch, content_type, wire_format)) = match &message.payload {
            MLSMessagePayload::Plain(plaintext) => Some((
                &plaintext.content.group_id,
                plaintext.content.epoch,
                plaintext.content.content_type(),
                WireFormat::PublicMessage,
            )),
            MLSMessagePayload::Cipher(ciphertext) => Some((
                &ciphertext.group_id,
                ciphertext.epoch,
                ciphertext.content_type,
                WireFormat::PrivateMessage,
            )),
            _ => None,
        } {
            if group_id != &context.group_id {
                return Err(MlsError::InvalidGroupId(group_id.clone()));
            }

            match content_type {
                ContentType::Proposal | ContentType::Commit => {
                    if context.epoch != epoch {
                        Err(MlsError::InvalidEpoch(epoch))
                    } else {
                        Ok(())
                    }
                }
                ContentType::Application => {
                    if let Some(min) = self.min_epoch_available() {
                        if epoch < min {
                            Err(MlsError::InvalidEpoch(epoch))
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
                return Err(MlsError::InvalidEpoch(epoch));
            }

            // Unencrypted application messages are not allowed
            if wire_format == WireFormat::PublicMessage && content_type == ContentType::Application
            {
                return Err(MlsError::UnencryptedApplicationMessage);
            }
        }

        Ok(())
    }

    async fn process_ciphertext(
        &mut self,
        cipher_text: PrivateMessage,
    ) -> Result<EventOrContent<Self::EventType>, MlsError>;

    fn verify_plaintext_authentication(
        &self,
        message: PublicMessage,
    ) -> Result<EventOrContent<Self::EventType>, MlsError>;

    fn calculate_provisional_state(
        &self,
        proposals: ProposalSetEffects,
    ) -> Result<ProvisionalState, MlsError> {
        let group_state = self.group_state();

        if group_state.pending_reinit.is_some() {
            return Err(MlsError::GroupUsedAfterReInit);
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
            custom_proposals: proposals.custom_proposals,
            rejected_proposals: proposals.rejected_proposals,
        })
    }

    async fn apply_update_path(
        &mut self,
        sender: LeafIndex,
        update_path: ValidatedUpdatePath,
        provisional_state: &mut ProvisionalState,
    ) -> Result<Option<(TreeKemPrivate, PathSecret)>, MlsError> {
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
    ) -> Result<(), MlsError>;
}
