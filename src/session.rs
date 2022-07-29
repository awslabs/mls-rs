use crate::cipher_suite::CipherSuite;
use crate::client_config::ClientConfig;
use crate::extension::ExtensionList;
use crate::group::{
    proposal::Proposal, CommitGeneration, Group, GroupInfo, GroupState, OutboundMessage,
    ProposalCacheError, ProposalFilterError, ProposalRef, VerifiedPlaintext, Welcome,
};
use crate::key_package::{KeyPackage, KeyPackageGenerationError};
use crate::message::{ProcessedMessage, ProcessedMessagePayload};
pub use crate::psk::{ExternalPskId, JustPreSharedKeyID, Psk};
use crate::signing_identity::SigningIdentity;
use crate::tree_kem::leaf_node::{LeafNode, LeafNodeError};
use crate::tree_kem::node::LeafIndex;
use crate::tree_kem::{Capabilities, RatchetTreeError, TreeKemPublic};
use crate::ProtocolVersion;
use ferriscrypt::hpke::kem::HpkePublicKey;
use ferriscrypt::rand::{SecureRng, SecureRngError};
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
    ProtocolError(GroupError),
    #[error(transparent)]
    Serialization(#[from] tls_codec::Error),
    #[error(transparent)]
    RatchetTreeError(#[from] RatchetTreeError),
    #[error(transparent)]
    KeyPackageGenerationError(#[from] KeyPackageGenerationError),
    #[error(transparent)]
    LeafNodeError(#[from] LeafNodeError),
    #[error(transparent)]
    SecureRngError(#[from] SecureRngError),
    #[error("commit already pending, please wait")]
    ExistingPendingCommit,
    #[error("pending commit not found")]
    PendingCommitNotFound,
    #[error("pending commit mismatch")]
    PendingCommitMismatch,
    #[error("signing identity not found for cipher suite {0:?}")]
    SigningIdentityNotFound(CipherSuite),
    #[error(transparent)]
    KeyPackageRepoError(Box<dyn std::error::Error + Send + Sync>),
    #[error("expected MLSMessage containing a Welcome")]
    ExpectedWelcomeMessage,
    #[error("expected protocol version {0:?}, found version {1:?}")]
    InvalidProtocol(ProtocolVersion, ProtocolVersion),
    #[error(transparent)]
    ProposalRejected(#[from] ProposalFilterError),
    #[error("Proposal {0:?} not found")]
    ProposalNotFound(ProposalRef),
}

impl From<GroupError> for SessionError {
    fn from(e: GroupError) -> Self {
        match e {
            GroupError::ProposalCacheError(ProposalCacheError::ProposalFilterError(e)) => {
                SessionError::ProposalRejected(e)
            }
            GroupError::ProposalCacheError(ProposalCacheError::ProposalNotFound(r)) => {
                SessionError::ProposalNotFound(r)
            }
            _ => SessionError::ProtocolError(e),
        }
    }
}

#[derive(Clone, Debug, TlsDeserialize, TlsSerialize, TlsSize)]
struct PendingCommit {
    #[tls_codec(with = "crate::tls::ByteVec")]
    packet_data: Vec<u8>,
    commit: CommitGeneration,
}

#[derive(Clone)]
pub struct CommitResult {
    pub commit_packet: Vec<u8>,
    pub welcome_packet: Option<Vec<u8>>,
}

impl Debug for CommitResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CommitResult")
            .field("packet_data", &hex::encode(&self.commit_packet))
            .field(
                "welcome_packet",
                &self.welcome_packet.as_ref().map(hex::encode),
            )
            .finish()
    }
}

#[derive(Debug)]
pub struct Session<C>
where
    C: ClientConfig + Clone,
{
    #[cfg(feature = "benchmark")]
    pub protocol: Group<C>,
    #[cfg(not(feature = "benchmark"))]
    protocol: Group<C>,
    pending_commit: Option<PendingCommit>,
}

#[derive(Clone, Debug)]
pub struct GroupStats {
    pub total_leaves: usize,
    pub current_index: u32,
    pub direct_path: Vec<HpkePublicKey>,
    pub epoch: u64,
}

pub struct Member {
    node: LeafNode,
    index: LeafIndex,
}

impl Member {
    pub fn index(&self) -> u32 {
        self.index.0
    }

    pub fn signing_identity(&self) -> &SigningIdentity {
        &self.node.signing_identity
    }

    pub fn capabilities(&self) -> &Capabilities {
        &self.node.capabilities
    }

    pub fn extensions(&self) -> &ExtensionList {
        &self.node.extensions
    }
}

impl From<(LeafIndex, &LeafNode)> for Member {
    fn from(item: (LeafIndex, &LeafNode)) -> Self {
        Member {
            node: item.1.clone(),
            index: item.0,
        }
    }
}

pub struct Roster<I>
where
    I: Iterator<Item = Member>,
{
    inner: I,
    total_members: u32,
}

impl<I> Roster<I>
where
    I: Iterator<Item = Member>,
{
    pub fn into_vec(self) -> Vec<Member> {
        self.collect()
    }

    pub fn member_count(&self) -> usize {
        self.total_members as usize
    }
}

impl<I> Iterator for Roster<I>
where
    I: Iterator<Item = Member>,
{
    type Item = I::Item;

    fn next(&mut self) -> Option<Self::Item> {
        self.inner.next()
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let total_members = self.total_members as usize;
        (total_members, Some(total_members))
    }
}

impl<C> Session<C>
where
    C: ClientConfig + Clone,
{
    pub(crate) fn create(
        group_id: Vec<u8>,
        cipher_suite: CipherSuite,
        protocol_version: ProtocolVersion,
        group_context_extensions: ExtensionList,
        config: C,
    ) -> Result<Self, SessionError> {
        let group = Group::new(
            config,
            group_id,
            cipher_suite,
            protocol_version,
            group_context_extensions,
        )?;

        Ok(Session {
            protocol: group,
            pending_commit: None,
        })
    }

    pub(crate) fn join(
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

        let ratchet_tree = ratchet_tree_data
            .map(|rt| Self::import_ratchet_tree(welcome_message.cipher_suite, rt))
            .transpose()?;

        let group = Group::join(protocol_version, welcome_message, ratchet_tree, config)?;

        Ok(Session {
            protocol: group,
            pending_commit: None,
        })
    }

    pub fn join_subgroup(
        &self,
        welcome: Welcome,
        ratchet_tree_data: Option<&[u8]>,
    ) -> Result<Self, SessionError> {
        let public_tree = ratchet_tree_data
            .map(|rt| Self::import_ratchet_tree(welcome.cipher_suite, rt))
            .transpose()?;

        Ok(Session {
            protocol: self.protocol.join_subgroup(welcome, public_tree)?,
            pending_commit: None,
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new_external(
        config: C,
        protocol_version: ProtocolVersion,
        group_info: GroupInfo,
        tree_data: Option<&[u8]>,
        to_remove: Option<u32>,
        external_psks: Vec<ExternalPskId>,
        authenticated_data: Vec<u8>,
    ) -> Result<(Self, Vec<u8>), SessionError> {
        let tree = tree_data
            .map(|t| Self::import_ratchet_tree(group_info.group_context.cipher_suite, t))
            .transpose()?;

        let (protocol, commit_message) = Group::new_external(
            config,
            protocol_version,
            group_info,
            tree,
            to_remove,
            external_psks,
            authenticated_data,
        )?;

        let session = Session {
            protocol,
            pending_commit: None,
        };

        let commit_message = session.serialize_control(commit_message)?;
        Ok((session, commit_message))
    }

    pub fn group_info_message(&self) -> Result<MLSMessage, SessionError> {
        Ok(MLSMessage {
            version: self.protocol.protocol_version(),
            payload: MLSMessagePayload::GroupInfo(self.protocol.external_commit_info()?),
        })
    }

    pub fn import_ratchet_tree(
        cipher_suite: CipherSuite,
        tree_data: &[u8],
    ) -> Result<TreeKemPublic, SessionError> {
        let nodes = Deserialize::tls_deserialize(&mut &*tree_data)?;
        TreeKemPublic::import_node_data(cipher_suite, nodes).map_err(Into::into)
    }

    pub fn roster(&self) -> Roster<impl Iterator<Item = Member> + '_> {
        let roster_iter = self
            .protocol
            .current_epoch_tree()
            .non_empty_leaves()
            .map(Member::from);

        Roster {
            inner: roster_iter,
            total_members: self.protocol.current_epoch_tree().occupied_leaf_count(),
        }
    }

    pub fn current_member_index(&self) -> u32 {
        self.protocol.current_user_index()
    }

    pub fn current_member(&self) -> Result<Member, GroupError> {
        Ok(Member::from((
            LeafIndex(self.protocol.current_user_index()),
            self.protocol.current_user_leaf_node()?,
        )))
    }

    #[inline]
    pub fn add_proposal(&mut self, key_package_data: &[u8]) -> Result<Proposal, SessionError> {
        let key_package = Deserialize::tls_deserialize(&mut &*key_package_data)?;
        self.protocol.add_proposal(key_package).map_err(Into::into)
    }

    #[inline(always)]
    pub fn update_proposal(&mut self) -> Result<Proposal, SessionError> {
        self.protocol.update_proposal().map_err(Into::into)
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
    pub fn propose_reinit(
        &mut self,
        version: ProtocolVersion,
        cipher_suite: CipherSuite,
        group_context_extensions: ExtensionList,
        authenticated_data: Vec<u8>,
    ) -> Result<Vec<u8>, SessionError> {
        let group_id = SecureRng::gen(cipher_suite.hash_function().digest_size())?;
        self.propose_reinit_with_group_id(
            version,
            cipher_suite,
            group_id,
            group_context_extensions,
            authenticated_data,
        )
    }

    #[inline(always)]
    pub fn propose_reinit_with_group_id(
        &mut self,
        version: ProtocolVersion,
        cipher_suite: CipherSuite,
        group_id: Vec<u8>,
        group_context_extensions: ExtensionList,
        authenticated_data: Vec<u8>,
    ) -> Result<Vec<u8>, SessionError> {
        let proposal =
            self.reinit_proposal(group_id, version, cipher_suite, group_context_extensions)?;
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
        let packet = self
            .protocol
            .create_proposal(proposal, authenticated_data)?;

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

        let (commit_data, welcome) =
            self.protocol
                .commit_proposals(proposals, None, authenticated_data)?;

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
                // TODO: For sender type `external` the `content_type` of the message MUST be `proposal`.
                let message = self.protocol.verify_incoming_plaintext(message)?;

                let credential = message
                    .plaintext
                    .credential(self.protocol.current_epoch_tree())?;
                let authenticated_data = message.content.authenticated_data.clone();
                (
                    self.process_incoming_plaintext(message)?,
                    credential,
                    authenticated_data,
                )
            }
            MLSMessagePayload::Cipher(message) => {
                let message = self.protocol.verify_incoming_ciphertext(message)?;
                let credential = message
                    .plaintext
                    .credential(self.protocol.current_epoch_tree())?;
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
        let res = self.protocol.process_incoming_message(message)?;

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
            .process_pending_commit(pending.commit)
            .map_err(Into::into)
    }

    pub fn clear_pending_commit(&mut self) {
        self.pending_commit = None
    }

    pub fn encrypt_application_data(
        &mut self,
        data: &[u8],
        authenticated_data: Vec<u8>,
    ) -> Result<Vec<u8>, SessionError> {
        let ciphertext = self
            .protocol
            .encrypt_application_message(data, authenticated_data)?;

        let msg = MLSMessage {
            version: self.protocol.protocol_version(),
            payload: MLSMessagePayload::Cipher(ciphertext),
        };
        Ok(msg.tls_serialize_detached()?)
    }

    pub fn export_tree(&self) -> Result<Vec<u8>, GroupError> {
        self.protocol
            .current_epoch_tree()
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
            total_leaves: self.roster().member_count(),
            current_index: self.protocol.current_user_index(),
            direct_path,
            epoch: self.protocol.current_epoch(),
        })
    }

    pub fn branch<F>(
        &self,
        sub_group_id: Vec<u8>,
        get_new_key_package: F,
    ) -> Result<(Self, Option<Welcome>), SessionError>
    where
        F: FnMut(&LeafNode) -> Option<KeyPackage>,
    {
        let (new_group, welcome) = self.protocol.branch(sub_group_id, get_new_key_package)?;

        let new_session = Session {
            protocol: new_group,
            pending_commit: None,
        };

        Ok((new_session, welcome))
    }

    pub fn finish_reinit_join(
        &self,
        welcome: Welcome,
        ratchet_tree_data: Option<&[u8]>,
    ) -> Result<Self, SessionError> {
        let public_tree = ratchet_tree_data
            .map(|rt| Self::import_ratchet_tree(welcome.cipher_suite, rt))
            .transpose()?;

        Ok(Session {
            protocol: self.protocol.finish_reinit_join(welcome, public_tree)?,
            pending_commit: None,
        })
    }

    pub fn finish_reinit_commit<F>(
        &self,
        get_new_key_package: F,
    ) -> Result<(Self, Option<Welcome>), SessionError>
    where
        F: FnMut(&LeafNode) -> Option<KeyPackage>,
    {
        let (new_group, welcome) = self.protocol.finish_reinit_commit(get_new_key_package)?;

        let new_session = Session {
            protocol: new_group,
            pending_commit: None,
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

    pub fn export(&self) -> Result<GroupState, SessionError> {
        self.protocol.export().map_err(Into::into)
    }

    pub(crate) fn import(config: C, state: GroupState) -> Result<Self, SessionError> {
        Ok(Self {
            protocol: Group::import(config, state)?,
            pending_commit: None,
        })
    }
}
