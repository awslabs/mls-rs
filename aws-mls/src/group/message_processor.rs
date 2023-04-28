#[cfg(feature = "external_commit")]
use super::proposal::ExternalInit;
use super::{
    commit_sender,
    confirmation_tag::ConfirmationTag,
    framing::{
        ApplicationData, Content, ContentType, MLSMessage, MLSMessagePayload, PublicMessage,
        Sender, WireFormat,
    },
    message_signature::AuthenticatedContent,
    proposal::{Proposal, ReInitProposal},
    proposal_cache::ProposalSetEffects,
    proposal_effects,
    proposal_filter::ProposalRules,
    proposal_ref::ProposalRef,
    state::GroupState,
    transcript_hash::InterimTranscriptHash,
    transcript_hashes, GroupContext,
};
use crate::{
    client::MlsError,
    key_package::KeyPackage,
    psk::PreSharedKeyID,
    time::MlsTime,
    tree_kem::{
        leaf_node::LeafNode, node::LeafIndex, path_secret::PathSecret, validate_update_path,
        TreeKemPrivate, TreeKemPublic, ValidatedUpdatePath,
    },
    CipherSuiteProvider,
};
use alloc::vec;
use alloc::{boxed::Box, vec::Vec};
use async_trait::async_trait;
use aws_mls_core::{identity::IdentityProvider, psk::PreSharedKeyStorage};

#[cfg(feature = "state_update")]
use itertools::Itertools;

#[cfg(feature = "state_update")]
use aws_mls_core::{
    crypto::CipherSuite,
    group::{MemberUpdate, RosterUpdate},
    identity::IdentityWarning,
    psk::ExternalPskId,
};

#[cfg(feature = "state_update")]
use crate::{psk::JustPreSharedKeyID, tree_kem::UpdatePath};

#[cfg(feature = "state_update")]
use super::{member_from_key_package, member_from_leaf_node};

#[cfg(all(feature = "state_update", feature = "custom_proposal"))]
use super::proposal::CustomProposal;

#[cfg(feature = "private_message")]
use crate::group::framing::PrivateMessage;

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
    #[cfg(feature = "external_commit")]
    pub(crate) external_init: Option<(LeafIndex, ExternalInit)>,
    #[cfg(all(feature = "state_update", feature = "custom_proposal"))]
    pub(crate) custom_proposals: Vec<CustomProposal>,
    #[cfg(feature = "state_update")]
    pub(crate) rejected_proposals: Vec<(ProposalRef, Proposal)>,
}

/// Representation of changes made by a [commit](crate::Group::commit).
#[cfg(feature = "state_update")]
#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct StateUpdate {
    pub(crate) roster_update: RosterUpdate,
    pub(crate) identity_warnings: Vec<IdentityWarning>,
    pub(crate) added_psks: Vec<ExternalPskId>,
    pub(crate) pending_reinit: Option<CipherSuite>,
    pub(crate) active: bool,
    pub(crate) epoch: u64,
    #[cfg(feature = "custom_proposal")]
    pub(crate) custom_proposals: Vec<CustomProposal>,
    pub(crate) unused_proposals: Vec<Proposal>,
}

#[cfg(not(feature = "state_update"))]
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq)]
pub struct StateUpdate {}

#[cfg(feature = "state_update")]
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
        self.pending_reinit.is_some()
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
    #[cfg(feature = "custom_proposal")]
    pub fn custom_proposals(&self) -> &[CustomProposal] {
        &self.custom_proposals
    }

    /// Proposals that were received in the prior epoch but not committed to.
    pub fn unused_proposals(&self) -> &[Proposal] {
        &self.unused_proposals
    }

    pub fn pending_reinit_ciphersuite(&self) -> Option<CipherSuite> {
        self.pending_reinit
    }
}

#[derive(Debug, Clone)]
#[allow(clippy::large_enum_variant)]
/// An event generated as a result of processing a message for a group with
/// [`Group::process_incoming_message`](crate::group::Group::process_incoming_message).
pub enum ReceivedMessage {
    /// An application message was decrypted.
    ApplicationMessage(ApplicationMessageDescription),
    /// A new commit was processed creating a new group state.
    Commit(CommitMessageDescription),
    /// A proposal was received.
    Proposal(ProposalMessageDescription),
}

impl TryFrom<ApplicationMessageDescription> for ReceivedMessage {
    type Error = MlsError;

    fn try_from(value: ApplicationMessageDescription) -> Result<Self, Self::Error> {
        Ok(ReceivedMessage::ApplicationMessage(value))
    }
}

impl From<CommitMessageDescription> for ReceivedMessage {
    fn from(value: CommitMessageDescription) -> Self {
        ReceivedMessage::Commit(value)
    }
}

impl From<ProposalMessageDescription> for ReceivedMessage {
    fn from(value: ProposalMessageDescription) -> Self {
        ReceivedMessage::Proposal(value)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
/// Description of a MLS application message.
pub struct ApplicationMessageDescription {
    /// Index of this user in the group state.
    pub sender_index: u32,
    /// Received application data.
    data: ApplicationData,
    /// Plaintext authenticated data in the received MLS packet.
    pub authenticated_data: Vec<u8>,
}

impl ApplicationMessageDescription {
    pub fn data(&self) -> &[u8] {
        self.data.as_bytes()
    }
}

#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
/// Description of a processed MLS commit message.
pub struct CommitMessageDescription {
    /// True if this is the result of an external commit.
    #[cfg(feature = "external_commit")]
    pub is_external: bool,
    /// The index in the group state of the member who performed this commit.
    pub committer: u32,
    /// A full description of group state changes as a result of this commit.
    pub state_update: StateUpdate,
    /// Plaintext authenticated data in the received MLS packet.   
    pub authenticated_data: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// Proposal sender type.
pub enum ProposalSender {
    /// A current member of the group by index in the group state.
    Member(u32),
    /// An external entity by index within an
    /// [`ExternalSendersExt`](crate::extension::built_in::ExternalSendersExt).
    External(u32),
    /// A new member proposing their addition to the group.
    NewMember,
}

impl TryFrom<Sender> for ProposalSender {
    type Error = MlsError;

    fn try_from(value: Sender) -> Result<Self, Self::Error> {
        match value {
            Sender::Member(index) => Ok(Self::Member(index)),
            #[cfg(feature = "external_proposal")]
            Sender::External(index) => Ok(Self::External(index)),
            Sender::NewMemberProposal => Ok(Self::NewMember),
            #[cfg(feature = "external_commit")]
            Sender::NewMemberCommit => Err(MlsError::InvalidSender(value, ContentType::Proposal)),
        }
    }
}

#[derive(Debug, Clone)]
/// Description of a processed MLS proposal message.
pub struct ProposalMessageDescription {
    /// Sender of the proposal.
    pub sender: ProposalSender,
    /// Proposal content.
    pub proposal: Proposal,
    /// Plaintext authenticated data in the received MLS packet.    
    pub authenticated_data: Vec<u8>,
}

#[allow(clippy::large_enum_variant)]
pub(crate) enum EventOrContent<E> {
    #[cfg_attr(not(feature = "external_client"), allow(dead_code))]
    Event(E),
    Content(AuthenticatedContent),
}

#[async_trait]
pub(crate) trait MessageProcessor: Send + Sync {
    type OutputType: TryFrom<ApplicationMessageDescription, Error = MlsError>
        + From<CommitMessageDescription>
        + From<ProposalMessageDescription>
        + Send;

    type ProposalRules: ProposalRules;
    type IdentityProvider: IdentityProvider;
    type CipherSuiteProvider: CipherSuiteProvider;
    type PreSharedKeyStorage: PreSharedKeyStorage;

    async fn process_incoming_message(
        &mut self,
        message: MLSMessage,
        cache_proposal: bool,
    ) -> Result<Self::OutputType, MlsError> {
        self.process_incoming_message_with_time(message, cache_proposal, None)
            .await
    }

    async fn process_incoming_message_with_time(
        &mut self,
        message: MLSMessage,
        cache_proposal: bool,
        time_sent: Option<MlsTime>,
    ) -> Result<Self::OutputType, MlsError> {
        let event_or_content = self.get_event_from_incoming_message(message).await?;

        self.process_event_or_content(event_or_content, cache_proposal, time_sent)
            .await
    }

    async fn get_event_from_incoming_message(
        &mut self,
        message: MLSMessage,
    ) -> Result<EventOrContent<Self::OutputType>, MlsError> {
        self.check_metadata(&message)?;

        let wire_format = message.wire_format();

        match message.payload {
            MLSMessagePayload::Plain(plaintext) => self.verify_plaintext_authentication(plaintext),
            #[cfg(feature = "private_message")]
            MLSMessagePayload::Cipher(cipher_text) => self.process_ciphertext(cipher_text).await,
            _ => Err(MlsError::UnexpectedMessageType(
                vec![
                    WireFormat::PublicMessage,
                    #[cfg(feature = "private_message")]
                    WireFormat::PrivateMessage,
                ],
                wire_format,
            )),
        }
    }

    async fn process_event_or_content(
        &mut self,
        event_or_content: EventOrContent<Self::OutputType>,
        cache_proposal: bool,
        time_sent: Option<MlsTime>,
    ) -> Result<Self::OutputType, MlsError> {
        let msg = match event_or_content {
            EventOrContent::Event(event) => event,
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
    ) -> Result<Self::OutputType, MlsError> {
        let authenticated_data = auth_content.content.authenticated_data.clone();

        let sender = auth_content.content.sender;

        let event = match auth_content.content.content {
            Content::Application(data) => self
                .process_application_message(data, sender, authenticated_data)
                .and_then(Self::OutputType::try_from),
            Content::Commit(_) => self
                .process_commit(auth_content, time_sent)
                .await
                .map(Self::OutputType::from),
            Content::Proposal(ref proposal) => self
                .process_proposal(&auth_content, proposal, cache_proposal)
                .map(Self::OutputType::from),
        }?;

        Ok(event)
    }

    fn process_application_message(
        &self,
        data: ApplicationData,
        sender: Sender,
        authenticated_data: Vec<u8>,
    ) -> Result<ApplicationMessageDescription, MlsError> {
        let Sender::Member(sender_index) = sender else {
            return Err(MlsError::InvalidSender(sender, ContentType::Application));
        };

        Ok(ApplicationMessageDescription {
            authenticated_data,
            sender_index,
            data,
        })
    }

    fn process_proposal(
        &mut self,
        auth_content: &AuthenticatedContent,
        proposal: &Proposal,
        cache_proposal: bool,
    ) -> Result<ProposalMessageDescription, MlsError> {
        let proposal_ref = ProposalRef::from_content(self.cipher_suite_provider(), auth_content)?;

        let group_state = self.group_state_mut();

        cache_proposal.then(|| {
            group_state.proposals.insert(
                proposal_ref.clone(),
                proposal.clone(),
                auth_content.content.sender,
            )
        });

        Ok(ProposalMessageDescription {
            authenticated_data: auth_content.content.authenticated_data.clone(),
            proposal: proposal.clone(),
            sender: auth_content.content.sender.try_into()?,
        })
    }

    #[cfg(feature = "state_update")]
    async fn make_state_update(
        &self,
        provisional: &ProvisionalState,
        path: Option<&UpdatePath>,
        sender: LeafIndex,
    ) -> Result<StateUpdate, MlsError> {
        let added = provisional
            .added_leaves
            .iter()
            .map(|(kp, index)| member_from_key_package(kp, *index))
            .collect::<Vec<_>>();

        #[cfg(feature = "external_commit")]
        let mut added = added;

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
            #[cfg(feature = "external_commit")]
            if provisional.external_init.is_some() {
                added.push(member_from_leaf_node(&path.leaf_node, sender))
            } else {
                let prior = old_tree
                    .get_leaf_node(sender)
                    .map(|n| member_from_leaf_node(n, sender))?;

                let new = member_from_leaf_node(&path.leaf_node, sender);

                updated.push(MemberUpdate::new(prior, new))
            }

            #[cfg(not(feature = "external_commit"))]
            {
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
            pending_reinit: provisional.reinit.as_ref().map(|ri| ri.new_cipher_suite()),
            active: true,
            epoch: provisional.epoch,
            #[cfg(feature = "custom_proposal")]
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
    ) -> Result<CommitMessageDescription, MlsError> {
        let commit = match auth_content.content.content {
            Content::Commit(ref commit) => Ok(commit),
            _ => Err(MlsError::NotCommitContent(
                auth_content.content.content_type(),
            )),
        }?;

        let group_state = self.group_state();
        let id_provider = self.identity_provider();

        // Calculate the diff that the commit will apply
        let proposal_effects = proposal_effects(
            #[cfg(feature = "state_update")]
            self.self_index(),
            &group_state.proposals,
            commit,
            &auth_content.content.sender,
            &group_state.context.extensions,
            &id_provider,
            self.cipher_suite_provider(),
            &group_state.public_tree,
            self.psk_storage(),
            self.proposal_rules(),
            time_sent,
            &group_state.roster(),
        )
        .await?;

        let mut provisional_state = self.calculate_provisional_state(proposal_effects)?;

        let sender = commit_sender(
            &auth_content.content.sender,
            #[cfg(feature = "external_commit")]
            &provisional_state,
        )?;

        #[cfg(feature = "state_update")]
        let mut state_update = self
            .make_state_update(&provisional_state, commit.path.as_ref(), sender)
            .await?;

        #[cfg(not(feature = "state_update"))]
        let state_update = StateUpdate {};

        //Verify that the path value is populated if the proposals vector contains any Update
        // or Remove proposals, or if it's empty. Otherwise, the path value MAY be omitted.
        if provisional_state.path_update_required && commit.path.is_none() {
            return Err(MlsError::CommitMissingPath);
        }

        if !self.can_continue_processing(&provisional_state) {
            #[cfg(feature = "state_update")]
            {
                state_update.active = false;
            }

            return Ok(CommitMessageDescription {
                #[cfg(feature = "external_commit")]
                is_external: matches!(auth_content.content.sender, Sender::NewMemberCommit),
                authenticated_data: auth_content.content.authenticated_data.clone(),
                committer: *sender,
                state_update,
            });
        }

        let update_path = match commit.path.as_ref() {
            Some(update_path) => validate_update_path(
                &self.identity_provider(),
                self.cipher_suite_provider(),
                update_path,
                &provisional_state,
                sender,
                time_sent,
                &provisional_state.group_context.extensions,
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

        if let Some(reinit) = provisional_state.reinit.take() {
            self.group_state_mut().pending_reinit = Some(reinit);

            #[cfg(feature = "state_update")]
            {
                state_update.active = false;
            }
        }

        if let Some(confirmation_tag) = auth_content.auth.confirmation_tag {
            // Update the key schedule to calculate new private keys
            self.update_key_schedule(
                new_secrets,
                interim_transcript_hash,
                confirmation_tag,
                provisional_state,
            )
            .await?;

            Ok(CommitMessageDescription {
                #[cfg(feature = "external_commit")]
                is_external: matches!(auth_content.content.sender, Sender::NewMemberCommit),
                authenticated_data: auth_content.content.authenticated_data.clone(),
                committer: *sender,
                state_update,
            })
        } else {
            Err(MlsError::InvalidConfirmationTag)
        }
    }

    fn group_state(&self) -> &GroupState;
    fn group_state_mut(&mut self) -> &mut GroupState;
    fn self_index(&self) -> Option<LeafIndex>;
    fn proposal_rules(&self) -> Self::ProposalRules;
    fn identity_provider(&self) -> Self::IdentityProvider;
    fn cipher_suite_provider(&self) -> &Self::CipherSuiteProvider;
    fn psk_storage(&self) -> Self::PreSharedKeyStorage;
    fn can_continue_processing(&self, provisional_state: &ProvisionalState) -> bool;
    fn min_epoch_available(&self) -> Option<u64>;

    fn check_metadata(&self, message: &MLSMessage) -> Result<(), MlsError> {
        let context = &self.group_state().context;

        if message.version != context.protocol_version {
            return Err(MlsError::ProtocolVersionMismatch);
        }

        if let Some((group_id, epoch, content_type, wire_format)) = match &message.payload {
            MLSMessagePayload::Plain(plaintext) => Some((
                &plaintext.content.group_id,
                plaintext.content.epoch,
                plaintext.content.content_type(),
                WireFormat::PublicMessage,
            )),
            #[cfg(feature = "private_message")]
            MLSMessagePayload::Cipher(ciphertext) => Some((
                &ciphertext.group_id,
                ciphertext.epoch,
                ciphertext.content_type,
                WireFormat::PrivateMessage,
            )),
            _ => None,
        } {
            if group_id != &context.group_id {
                return Err(MlsError::GroupIdMismatch);
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

    #[cfg(feature = "private_message")]
    async fn process_ciphertext(
        &mut self,
        cipher_text: PrivateMessage,
    ) -> Result<EventOrContent<Self::OutputType>, MlsError>;

    fn verify_plaintext_authentication(
        &self,
        message: PublicMessage,
    ) -> Result<EventOrContent<Self::OutputType>, MlsError>;

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
            #[cfg(feature = "external_commit")]
            external_init: proposals.external_init,
            #[cfg(all(feature = "custom_proposal", feature = "state_update"))]
            custom_proposals: proposals.custom_proposals,
            #[cfg(feature = "state_update")]
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
