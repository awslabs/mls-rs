use crate::cipher_suite::CipherSuite;
use crate::client_config::{ClientConfig, ClientGroupConfig};
use crate::extension::ExtensionList;
use crate::group::{
    framing::Content, proposal::Proposal, CommitGeneration, Group, GroupContext, GroupInfo,
    GroupState, OutboundMessage, VerifiedPlaintext, Welcome,
};
use crate::key_package::{
    KeyPackage, KeyPackageGeneration, KeyPackageGenerationError, KeyPackageRef,
    KeyPackageRepository,
};
use crate::message::{ProcessedMessage, ProcessedMessagePayload};
use crate::psk::ExternalPskId;
use crate::signer::Signer;
use crate::tree_kem::leaf_node::{LeafNode, LeafNodeError};
use crate::tree_kem::leaf_node_ref::LeafNodeRef;
use crate::tree_kem::node::LeafIndex;
use crate::tree_kem::{RatchetTreeError, TreeKemPublic};
use crate::{keychain::Keychain, ProtocolVersion};
use ferriscrypt::hpke::kem::{HpkePublicKey, HpkeSecretKey};
use std::fmt::{self, Debug};
use thiserror::Error;
use tls_codec::{Deserialize, Serialize};
use tls_codec_derive::{TlsDeserialize, TlsSerialize, TlsSize};

pub use crate::group::{
    framing::{ContentType, MLSMessage, MLSMessagePayload},
    GroupError, StateUpdate,
};

#[derive(Error, Debug)]
pub enum SessionError {
    #[error(transparent)]
    ProtocolError(#[from] GroupError),
    #[error(transparent)]
    Serialization(#[from] tls_codec::Error),
    #[error(transparent)]
    RatchetTreeError(#[from] RatchetTreeError),
    #[error(transparent)]
    KeyPackageGenerationError(#[from] KeyPackageGenerationError),
    #[error(transparent)]
    LeafNodeError(#[from] LeafNodeError),
    #[error("commit already pending, please wait")]
    ExistingPendingCommit,
    #[error("pending commit not found")]
    PendingCommitNotFound,
    #[error("pending commit mismatch")]
    PendingCommitMismatch,
    #[error("key package not found")]
    KeyPackageNotFound,
    #[error("signer not found")]
    SignerNotFound,
    #[error(transparent)]
    KeyPackageRepoError(Box<dyn std::error::Error + Send + Sync>),
    #[error(transparent)]
    ProposalRejected(Box<dyn std::error::Error + Send + Sync>),
    #[error("expected MLSMessage containing a Welcome")]
    ExpectedWelcomeMessage,
    #[error("expected protocol version {0:?}, found version {1:?}")]
    InvalidProtocol(ProtocolVersion, ProtocolVersion),
}

#[derive(Clone, Debug, TlsDeserialize, TlsSerialize, TlsSize)]
struct PendingCommit {
    #[tls_codec(with = "crate::tls::ByteVec")]
    packet_data: Vec<u8>,
    commit: CommitGeneration,
}

#[derive(Clone, Debug)]
pub struct CommitResult {
    pub commit_packet: Vec<u8>,
    pub welcome_packet: Option<Vec<u8>>,
}

pub struct Session<C>
where
    C: ClientConfig,
    C::EpochRepository: Clone,
    C::CredentialValidator: Clone,
{
    protocol: Group<ClientGroupConfig<C>>,
    pending_commit: Option<PendingCommit>,
    config: C,
}

impl<C> Debug for Session<C>
where
    C: ClientConfig + Debug,
    C::EpochRepository: Clone + Debug,
    C::CredentialValidator: Clone + Debug,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Session")
            .field("protocol", &self.protocol)
            .field("pending_comming", &self.pending_commit)
            .field("config", &self.config)
            .finish()
    }
}

#[derive(Clone, Debug)]
pub struct GroupStats {
    pub total_leaves: u32,
    pub current_index: u32,
    pub direct_path: Vec<HpkePublicKey>,
    pub epoch: u64,
}

impl<C> Session<C>
where
    C: ClientConfig + Clone,
    C::EpochRepository: Clone,
    C::CredentialValidator: Clone,
{
    pub(crate) fn create(
        group_id: Vec<u8>,
        cipher_suite: CipherSuite,
        protocol_version: ProtocolVersion,
        leaf_node: LeafNode,
        leaf_node_secret: HpkeSecretKey,
        group_context_extensions: ExtensionList,
        config: C,
    ) -> Result<Self, SessionError> {
        let group = Group::new(
            ClientGroupConfig::new(&config, &group_id),
            group_id,
            cipher_suite,
            protocol_version,
            leaf_node,
            leaf_node_secret,
            group_context_extensions,
        )?;

        Ok(Session {
            protocol: group,
            pending_commit: None,
            config,
        })
    }

    pub(crate) fn join(
        key_package: Option<&KeyPackageRef>,
        ratchet_tree_data: Option<&[u8]>,
        welcome_message: &[u8],
        config: C,
    ) -> Result<Self, SessionError> {
        let welcome_message = MLSMessage::tls_deserialize(&mut &*welcome_message)?;
        let protocol_version = welcome_message.version;
        let welcome_message = match welcome_message.payload {
            MLSMessagePayload::Welcome(w) => Ok(w),
            _ => Err(SessionError::ExpectedWelcomeMessage),
        }?;

        let key_package_generation =
            find_key_package_generation(&config, key_package, &welcome_message)?;

        let ratchet_tree = ratchet_tree_data
            .map(|rt| Self::import_ratchet_tree(welcome_message.cipher_suite, rt))
            .transpose()?;

        let group = Group::from_welcome_message(
            protocol_version,
            welcome_message,
            ratchet_tree,
            key_package_generation,
            &config.secret_store(),
            |group_id| ClientGroupConfig::new(&config, group_id),
            version_and_cipher_filter(&config),
            config.credential_validator(),
        )?;

        Ok(Session {
            protocol: group,
            pending_commit: None,
            config,
        })
    }

    pub fn join_subgroup(
        &self,
        key_package: Option<&KeyPackageRef>,
        welcome: Welcome,
        ratchet_tree_data: Option<&[u8]>,
    ) -> Result<Self, SessionError> {
        let public_tree = ratchet_tree_data
            .map(|rt| Self::import_ratchet_tree(welcome.cipher_suite, rt))
            .transpose()?;

        let key_package_generation =
            find_key_package_generation(&self.config, key_package, &welcome)?;

        Ok(Session {
            protocol: self.protocol.join_subgroup(
                welcome,
                public_tree,
                key_package_generation,
                &self.config.secret_store(),
                |group_id| ClientGroupConfig::new(&self.config, group_id),
                version_and_cipher_filter(&self.config),
            )?,
            pending_commit: None,
            config: self.config.clone(),
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new_external<S: Signer>(
        config: C,
        protocol_version: ProtocolVersion,
        group_info: GroupInfo,
        tree_data: Option<&[u8]>,
        leaf_node: LeafNode,
        leaf_node_secret: HpkeSecretKey,
        signer: &S,
        authenticated_data: Vec<u8>,
    ) -> Result<(Self, Vec<u8>), SessionError> {
        let tree = tree_data
            .map(|t| Self::import_ratchet_tree(group_info.cipher_suite, t))
            .transpose()?;

        let (protocol, commit_message) = Group::new_external(
            ClientGroupConfig::new(&config, &group_info.group_id),
            protocol_version,
            group_info,
            tree,
            leaf_node,
            leaf_node_secret,
            version_and_cipher_filter(&config),
            signer,
            authenticated_data,
        )?;

        let session = Session {
            protocol,
            pending_commit: None,
            config,
        };

        let commit_message = session.serialize_control(commit_message)?;
        Ok((session, commit_message))
    }

    pub fn group_context(&self) -> GroupContext {
        self.protocol.context().clone()
    }

    pub fn group_info_message(&self) -> Result<MLSMessage, SessionError> {
        Ok(MLSMessage {
            version: self.protocol.protocol_version(),
            payload: MLSMessagePayload::GroupInfo(
                self.protocol.external_commit_info(&self.signer()?)?,
            ),
        })
    }

    fn import_ratchet_tree(
        cipher_suite: CipherSuite,
        tree_data: &[u8],
    ) -> Result<TreeKemPublic, SessionError> {
        let nodes = Deserialize::tls_deserialize(&mut &*tree_data)?;
        TreeKemPublic::import_node_data(cipher_suite, nodes).map_err(Into::into)
    }

    pub fn participant_count(&self) -> u32 {
        self.protocol
            .current_epoch_tree()
            .map_or(0, |t| t.occupied_leaf_count())
    }

    pub fn roster(&self) -> Vec<&LeafNode> {
        self.protocol
            .current_epoch_tree()
            .map_or(vec![], |t| t.get_leaf_nodes())
    }

    pub fn current_key_package(&self) -> Result<&LeafNode, GroupError> {
        self.protocol.current_user_leaf_node().map_err(Into::into)
    }

    pub fn current_user_ref(&self) -> &LeafNodeRef {
        self.protocol.current_user_ref()
    }

    #[inline]
    pub fn add_proposal(&mut self, key_package_data: &[u8]) -> Result<Proposal, SessionError> {
        let key_package = Deserialize::tls_deserialize(&mut &*key_package_data)?;
        self.protocol.add_proposal(key_package).map_err(Into::into)
    }

    #[inline(always)]
    pub fn update_proposal(&mut self) -> Result<Proposal, SessionError> {
        let leaf_node = self.protocol.current_user_leaf_node()?;

        let signing_key = self
            .config
            .keychain()
            .signer(&leaf_node.signing_identity)
            .ok_or(SessionError::SignerNotFound)?;

        self.protocol
            .update_proposal(
                &signing_key,
                Some(self.config.leaf_node_extensions()),
                Some(self.config.capabilities()),
            )
            .map_err(Into::into)
    }

    #[inline(always)]
    pub fn remove_proposal(&mut self, leaf_index: u32) -> Result<Proposal, SessionError> {
        self.protocol
            .remove_proposal(LeafIndex(leaf_index))
            .map_err(Into::into)
    }

    #[inline(always)]
    pub fn psk_proposal(&mut self, psk: ExternalPskId) -> Result<Proposal, SessionError> {
        Ok(self.protocol.psk_proposal(psk)?)
    }

    #[inline(always)]
    pub fn reinit_proposal(
        &mut self,
        group_id: Vec<u8>,
        protocol_version: ProtocolVersion,
        cipher_suite: CipherSuite,
        extensions: ExtensionList,
    ) -> Result<Proposal, SessionError> {
        Ok(self
            .protocol
            .reinit_proposal(group_id, protocol_version, cipher_suite, extensions)?)
    }

    #[inline(always)]
    pub fn propose_add(
        &mut self,
        key_package_data: &[u8],
        authenticated_data: Vec<u8>,
    ) -> Result<Vec<u8>, SessionError> {
        let key_package = KeyPackage::tls_deserialize(&mut &*key_package_data)?;
        self.send_proposal(self.protocol.add_proposal(key_package)?, authenticated_data)
    }

    #[inline(always)]
    pub fn propose_update(&mut self, authenticated_data: Vec<u8>) -> Result<Vec<u8>, SessionError> {
        let proposal = self.update_proposal()?;
        self.send_proposal(proposal, authenticated_data)
    }

    #[inline(always)]
    pub fn propose_remove(
        &mut self,
        leaf_index: u32,
        authenticated_data: Vec<u8>,
    ) -> Result<Vec<u8>, SessionError> {
        let remove = self.remove_proposal(leaf_index)?;
        self.send_proposal(remove, authenticated_data)
    }

    #[inline(always)]
    pub fn group_context_extension_proposal(&self, extension_list: ExtensionList) -> Proposal {
        self.protocol
            .group_context_extensions_proposal(extension_list)
    }

    #[inline(always)]
    pub fn propose_group_context_extension_update(
        &mut self,
        extension_list: ExtensionList,
        authenticated_data: Vec<u8>,
    ) -> Result<Vec<u8>, SessionError> {
        let extension_update = self.group_context_extension_proposal(extension_list);
        self.send_proposal(extension_update, authenticated_data)
    }

    #[inline(always)]
    pub fn propose_psk(
        &mut self,
        psk: ExternalPskId,
        authenticated_data: Vec<u8>,
    ) -> Result<Vec<u8>, SessionError> {
        let proposal = self.protocol.psk_proposal(psk)?;
        self.send_proposal(proposal, authenticated_data)
    }

    #[inline(always)]
    fn serialize_control(&self, plaintext: OutboundMessage) -> Result<Vec<u8>, SessionError> {
        Ok(plaintext
            .into_message(self.protocol.protocol_version())
            .tls_serialize_detached()?)
    }

    fn send_proposal(
        &mut self,
        proposal: Proposal,
        authenticated_data: Vec<u8>,
    ) -> Result<Vec<u8>, SessionError> {
        let leaf_node = self.protocol.current_user_leaf_node()?;

        let signer = self
            .config
            .keychain()
            .signer(&leaf_node.signing_identity)
            .ok_or(SessionError::SignerNotFound)?;

        let packet = self.protocol.create_proposal(
            proposal,
            &signer,
            self.config.preferences().encryption_mode(),
            authenticated_data,
        )?;

        self.serialize_control(packet)
    }

    pub fn commit(
        &mut self,
        proposals: Vec<Proposal>,
        authenticated_data: Vec<u8>,
    ) -> Result<CommitResult, SessionError> {
        if self.pending_commit.is_some() {
            return Err(SessionError::ExistingPendingCommit);
        }

        let leaf_node = self.protocol.current_user_leaf_node()?;

        let signer = self
            .config
            .keychain()
            .signer(&leaf_node.signing_identity)
            .ok_or(SessionError::SignerNotFound)?;

        let (commit_data, welcome) = self.protocol.commit_proposals(
            proposals,
            self.config.commit_options(),
            &self.config.secret_store(),
            &signer,
            authenticated_data,
        )?;

        let serialized_commit = self.serialize_control(commit_data.plaintext.clone())?;

        self.pending_commit = Some(PendingCommit {
            packet_data: serialized_commit.clone(),
            commit: commit_data,
        });

        Ok(CommitResult {
            commit_packet: serialized_commit,
            welcome_packet: welcome.map(|w| w.tls_serialize_detached()).transpose()?,
        })
    }

    pub fn process_incoming_bytes(
        &mut self,
        data: &[u8],
    ) -> Result<ProcessedMessage, SessionError> {
        self.process_incoming_message(MLSMessage::tls_deserialize(&mut &*data)?)
    }

    pub fn process_incoming_message(
        &mut self,
        message: MLSMessage,
    ) -> Result<ProcessedMessage, SessionError> {
        if message.version != self.protocol.protocol_version() {
            return Err(SessionError::InvalidProtocol(
                self.protocol.protocol_version(),
                message.version,
            ));
        }

        let (message_payload, sender_credential, authenticated_data) = match message.payload {
            MLSMessagePayload::Plain(message) => {
                let message = self.protocol.verify_incoming_plaintext(message, |id| {
                    self.config.external_signing_key(id)
                })?;
                let credential = message
                    .plaintext
                    .credential(self.protocol.current_epoch_tree()?)?;
                let authenticated_data = message.content.authenticated_data.clone();
                (
                    self.process_incoming_plaintext(message)?,
                    credential,
                    authenticated_data,
                )
            }
            MLSMessagePayload::Cipher(message) => {
                let message = self.protocol.verify_incoming_ciphertext(message, |id| {
                    self.config.external_signing_key(id)
                })?;
                let credential = message
                    .plaintext
                    .credential(self.protocol.current_epoch_tree()?)?;
                let authenticated_data = message.content.authenticated_data.clone();
                (
                    self.process_incoming_plaintext(message)?,
                    credential,
                    authenticated_data,
                )
            }
            MLSMessagePayload::Welcome(message) => {
                (ProcessedMessagePayload::Welcome(message), None, vec![])
            }
            MLSMessagePayload::GroupInfo(message) => {
                (ProcessedMessagePayload::GroupInfo(message), None, vec![])
            }
            MLSMessagePayload::KeyPackage(message) => {
                let credential = message.leaf_node.signing_identity.credential.clone();
                (
                    ProcessedMessagePayload::KeyPackage(message),
                    Some(credential),
                    vec![],
                )
            }
        };

        Ok(ProcessedMessage {
            message: message_payload,
            sender_credential,
            authenticated_data,
        })
    }

    fn process_incoming_plaintext(
        &mut self,
        message: VerifiedPlaintext,
    ) -> Result<ProcessedMessagePayload, SessionError> {
        match &message.content.content {
            Content::Proposal(p) => self
                .config
                .filter_proposal(p)
                .map_err(|e| SessionError::ProposalRejected(e.into())),
            Content::Application(_) | Content::Commit(_) => Ok(()),
        }?;
        let res = self
            .protocol
            .process_incoming_message(message, &self.config.secret_store())?;

        // This commit beat our current pending commit to the server, our commit is no longer
        // relevant
        if let ProcessedMessagePayload::Commit(_) = res {
            self.pending_commit = None;
        }
        Ok(res)
    }

    pub fn apply_pending_commit(&mut self) -> Result<StateUpdate, SessionError> {
        // take() will give us the value and set it to None in the session
        let pending = self
            .pending_commit
            .take()
            .ok_or(SessionError::PendingCommitNotFound)?;

        self.protocol
            .process_pending_commit(pending.commit, &self.config.secret_store())
            .map_err(Into::into)
    }

    pub fn clear_pending_commit(&mut self) {
        self.pending_commit = None
    }

    fn signer(&self) -> Result<<<C as ClientConfig>::Keychain as Keychain>::Signer, SessionError> {
        let key_package = self.protocol.current_user_leaf_node()?;

        self.config
            .keychain()
            .signer(&key_package.signing_identity)
            .ok_or(SessionError::SignerNotFound)
    }

    pub fn encrypt_application_data(
        &mut self,
        data: &[u8],
        authenticated_data: Vec<u8>,
    ) -> Result<Vec<u8>, SessionError> {
        let ciphertext = self.protocol.encrypt_application_message(
            data,
            &self.signer()?,
            self.config.preferences().padding_mode,
            authenticated_data,
        )?;

        let msg = MLSMessage {
            version: self.protocol.protocol_version(),
            payload: MLSMessagePayload::Cipher(ciphertext),
        };
        Ok(msg.tls_serialize_detached()?)
    }

    pub fn export_tree(&self) -> Result<Vec<u8>, GroupError> {
        self.protocol
            .current_epoch_tree()?
            .export_node_data()
            .tls_serialize_detached()
            .map_err(Into::into)
    }

    pub fn has_equal_state(&self, other: &Self) -> bool {
        self.protocol == other.protocol
    }

    pub fn group_stats(&self) -> Result<GroupStats, SessionError> {
        let direct_path = self
            .protocol
            .current_direct_path()?
            .iter()
            .map(|p| p.as_ref().unwrap_or(&vec![].into()).clone())
            .collect();

        Ok(GroupStats {
            total_leaves: self.participant_count(),
            current_index: self.protocol.current_user_index(),
            direct_path,
            epoch: self.protocol.current_epoch(),
        })
    }

    pub fn branch<F>(
        &self,
        sub_group_id: Vec<u8>,
        resumption_psk_epoch: Option<u64>,
        get_new_key_package: F,
    ) -> Result<(Self, Option<Welcome>), SessionError>
    where
        F: FnMut(&LeafNode) -> Option<KeyPackage>,
    {
        let signer = self.signer()?;

        let (new_group, welcome) = self.protocol.branch(
            sub_group_id,
            resumption_psk_epoch,
            self.config.lifetime(),
            &self.config.secret_store(),
            &signer,
            |group_id| ClientGroupConfig::new(&self.config, group_id),
            get_new_key_package,
        )?;

        let new_session = Session {
            protocol: new_group,
            pending_commit: None,
            config: self.config.clone(),
        };

        Ok((new_session, welcome))
    }

    pub fn authentication_secret(&self) -> Result<Vec<u8>, SessionError> {
        Ok(self.protocol.authentication_secret()?)
    }

    pub fn export_secret(
        &self,
        label: &str,
        context: &[u8],
        len: usize,
    ) -> Result<Vec<u8>, SessionError> {
        Ok(self.protocol.export_secret(label, context, len)?)
    }

    pub fn export(&self) -> GroupState {
        self.protocol.export()
    }

    pub(crate) fn import(config: C, state: GroupState) -> Result<Self, SessionError> {
        Ok(Self {
            protocol: Group::import(
                ClientGroupConfig::new(&config, &state.context.group_id),
                state,
            )?,
            pending_commit: None,
            config,
        })
    }
}

fn version_and_cipher_filter<C: ClientConfig>(
    config: &C,
) -> impl Fn(ProtocolVersion, CipherSuite) -> bool + '_ {
    move |version, cipher_suite| {
        config.supported_protocol_versions().contains(&version)
            && config.supported_cipher_suites().contains(&cipher_suite)
    }
}

fn find_key_package_generation<C>(
    config: &C,
    key_package_ref: Option<&KeyPackageRef>,
    welcome_message: &Welcome,
) -> Result<KeyPackageGeneration, SessionError>
where
    C: ClientConfig,
{
    match key_package_ref {
        Some(r) => config.key_package_repo().get(r),
        None => welcome_message
            .secrets
            .iter()
            .find_map(|secrets| {
                config
                    .key_package_repo()
                    .get(&secrets.new_member)
                    .transpose()
            })
            .transpose(),
    }
    .map_err(|e| SessionError::KeyPackageRepoError(e.into()))?
    .ok_or(SessionError::KeyPackageNotFound)
}
