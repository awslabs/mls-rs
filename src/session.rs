use crate::cipher_suite::CipherSuite;
use crate::client_config::ClientConfig;
use crate::extension::ExtensionList;
use crate::group::{
    proposal::Proposal, CommitGeneration, Group, GroupInfo, GroupState, ProposalCacheError,
    ProposalFilterError, ProposalRef, Welcome,
};
use crate::group::{GroupStats, Member, Roster};
use crate::key_package::{KeyPackage, KeyPackageGenerationError};
use crate::message::{Event, ProcessedMessage};
pub use crate::psk::{ExternalPskId, JustPreSharedKeyID, Psk};
use crate::tree_kem::leaf_node::{LeafNode, LeafNodeError};
use crate::tree_kem::node::LeafIndex;
use crate::tree_kem::{RatchetTreeError, TreeKemPublic};
use crate::ProtocolVersion;
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
    #[error("signing identity not found for cipher suite {0:?}")]
    SigningIdentityNotFound(CipherSuite),
    #[error(transparent)]
    KeyPackageRepoError(Box<dyn std::error::Error + Send + Sync>),
    #[error("expected MLSMessage containing a Welcome")]
    ExpectedWelcomeMessage,
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

        Ok(Session { protocol: group })
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

        Ok(Session { protocol: group })
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

        let session = Session { protocol };

        let commit_message = session.serialize_message(&commit_message)?;
        Ok((session, commit_message))
    }

    pub fn group_info_message(&self) -> Result<MLSMessage, SessionError> {
        self.protocol.group_info_message().map_err(Into::into)
    }

    pub fn import_ratchet_tree(
        cipher_suite: CipherSuite,
        tree_data: &[u8],
    ) -> Result<TreeKemPublic, SessionError> {
        let nodes = Deserialize::tls_deserialize(&mut &*tree_data)?;
        TreeKemPublic::import_node_data(cipher_suite, nodes).map_err(Into::into)
    }

    pub fn roster(&self) -> Roster<impl Iterator<Item = Member> + '_> {
        self.protocol.roster()
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
    fn serialize_message(&self, message: &MLSMessage) -> Result<Vec<u8>, SessionError> {
        MLSMessage::tls_serialize_detached(message).map_err(Into::into)
    }

    fn send_proposal(
        &mut self,
        proposal: Proposal,
        authenticated_data: Vec<u8>,
    ) -> Result<Vec<u8>, SessionError> {
        let message = self
            .protocol
            .create_proposal(proposal, authenticated_data)?;

        self.serialize_message(&message)
    }

    pub fn commit(
        &mut self,
        proposals: Vec<Proposal>,
        authenticated_data: Vec<u8>,
    ) -> Result<CommitResult, SessionError> {
        let (commit_message, welcome) =
            self.protocol
                .commit_proposals(proposals, None, authenticated_data)?;

        let serialized_commit = self.serialize_message(&commit_message)?;

        Ok(CommitResult {
            commit_packet: serialized_commit,
            welcome_packet: welcome.map(|w| w.tls_serialize_detached()).transpose()?,
        })
    }

    pub fn process_incoming_bytes(
        &mut self,
        data: &[u8],
    ) -> Result<ProcessedMessage<Event>, SessionError> {
        self.process_incoming_message(MLSMessage::tls_deserialize(&mut &*data)?)
    }

    pub fn process_incoming_message(
        &mut self,
        message: MLSMessage,
    ) -> Result<ProcessedMessage<Event>, SessionError> {
        self.protocol
            .process_incoming_message(message)
            .map_err(Into::into)
    }

    pub fn apply_pending_commit(&mut self) -> Result<StateUpdate, SessionError> {
        self.protocol.process_pending_commit().map_err(Into::into)
    }

    pub fn clear_pending_commit(&mut self) {
        self.protocol.clear_pending_commit()
    }

    pub fn encrypt_application_data(
        &mut self,
        data: &[u8],
        authenticated_data: Vec<u8>,
    ) -> Result<Vec<u8>, SessionError> {
        let msg = self
            .protocol
            .encrypt_application_message(data, authenticated_data)?;

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
        self.protocol.group_stats().map_err(Into::into)
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
        })
    }
}
