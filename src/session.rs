use crate::group::framing::{MLSMessage, WireFormat};
use crate::group::{proposal::Proposal, CommitGeneration, Group, StateUpdate};
use crate::group::{OutboundPlaintext, Welcome};
use crate::key_package::{KeyPackage, KeyPackageGeneration, KeyPackageRef};
use crate::tree_kem::{RatchetTreeError, TreeKemPublic};
use ferriscrypt::asym::ec_key::{PublicKey, SecretKey};
use ferriscrypt::hpke::kem::HpkePublicKey;
use thiserror::Error;
use tls_codec::{Deserialize, Serialize};
use tls_codec_derive::{TlsDeserialize, TlsSerialize, TlsSize};

pub use crate::group::{GroupError, ProcessedMessage};

#[derive(Error, Debug)]
pub enum SessionError {
    #[error(transparent)]
    ProtocolError(#[from] GroupError),
    #[error(transparent)]
    Serialization(#[from] tls_codec::Error),
    #[error(transparent)]
    RatchetTreeError(#[from] RatchetTreeError),
    #[error("commit already pending, please wait")]
    ExistingPendingCommit,
    #[error("pending commit not found")]
    PendingCommitNotFound,
    #[error("pending commit mismatch")]
    PendingCommitMismatch,
}

#[derive(Clone, Debug, TlsDeserialize, TlsSerialize, TlsSize)]
pub struct SessionOpts {
    #[tls_codec(with = "crate::tls::Boolean")]
    pub encrypt_controls: bool,
    #[tls_codec(with = "crate::tls::Boolean")]
    pub ratchet_tree_extension: bool,
}

impl SessionOpts {
    pub fn new(encrypt_controls: bool, ratchet_tree_extension: bool) -> SessionOpts {
        SessionOpts {
            encrypt_controls,
            ratchet_tree_extension,
        }
    }

    pub fn wire_format(&self) -> WireFormat {
        if self.encrypt_controls {
            WireFormat::Cipher
        } else {
            WireFormat::Plain
        }
    }
}

#[derive(Clone, Debug, TlsDeserialize, TlsSerialize, TlsSize)]
struct PendingCommit {
    #[tls_codec(with = "crate::tls::ByteVec::<u32>")]
    packet_data: Vec<u8>,
    commit: CommitGeneration,
}

#[derive(Clone, Debug)]
pub struct CommitResult {
    pub commit_packet: Vec<u8>,
    pub welcome_packet: Option<Vec<u8>>,
}

#[derive(Clone, Debug, TlsDeserialize, TlsSerialize, TlsSize)]
pub struct Session {
    #[tls_codec(with = "crate::tls::SecretKeySer")]
    signing_key: SecretKey,
    protocol: Group,
    pending_commit: Option<PendingCommit>,
    pub opts: SessionOpts,
}

#[derive(Clone, Debug)]
pub struct TreeStats {
    pub total_leaves: u32,
    pub current_index: u32,
    pub direct_path: Vec<HpkePublicKey>,
}

impl Session {
    pub(crate) fn create(
        group_id: Vec<u8>,
        signing_key: SecretKey,
        key_package: KeyPackageGeneration,
        opts: SessionOpts,
    ) -> Result<Session, SessionError> {
        let group = Group::new(group_id, key_package)?;
        Ok(Session {
            signing_key,
            protocol: group,
            pending_commit: None,
            opts,
        })
    }

    pub(crate) fn join(
        signing_key: SecretKey,
        key_package: KeyPackageGeneration,
        ratchet_tree_data: Option<&[u8]>,
        welcome_message_data: &[u8],
        opts: SessionOpts,
    ) -> Result<Session, SessionError> {
        let welcome_message = Welcome::tls_deserialize(&mut &*welcome_message_data)?;

        let ratchet_tree = ratchet_tree_data
            .map(|rt| Session::import_ratchet_tree(&welcome_message, rt))
            .transpose()?;

        let group = Group::from_welcome_message(welcome_message, ratchet_tree, key_package)?;

        Ok(Session {
            signing_key,
            protocol: group,
            pending_commit: None,
            opts,
        })
    }

    fn import_ratchet_tree(
        welcome_message: &Welcome,
        tree_data: &[u8],
    ) -> Result<TreeKemPublic, SessionError> {
        let nodes = Deserialize::tls_deserialize(&mut &*tree_data)?;
        TreeKemPublic::import_node_data(welcome_message.cipher_suite, nodes).map_err(Into::into)
    }

    pub fn participant_count(&self) -> u32 {
        self.protocol
            .current_epoch_tree()
            .map_or(0, |t| t.leaf_count())
    }

    pub fn roster(&self) -> Vec<&KeyPackage> {
        self.protocol
            .current_epoch_tree()
            .map_or(vec![], |t| t.get_key_packages())
    }

    #[inline]
    pub fn add_proposal(&mut self, key_package_data: &[u8]) -> Result<Proposal, SessionError> {
        let key_package = Deserialize::tls_deserialize(&mut &*key_package_data)?;
        self.protocol
            .add_member_proposal(&key_package)
            .map_err(Into::into)
    }

    #[inline(always)]
    pub fn update_proposal(&mut self) -> Result<Proposal, SessionError> {
        self.protocol
            .update_proposal(&self.signing_key)
            .map_err(Into::into)
    }

    #[inline(always)]
    pub fn remove_proposal(
        &mut self,
        key_package_ref: &KeyPackageRef,
    ) -> Result<Proposal, SessionError> {
        self.protocol
            .remove_proposal(key_package_ref)
            .map_err(Into::into)
    }

    #[inline(always)]
    pub fn propose_add(&mut self, key_package_data: &[u8]) -> Result<Vec<u8>, SessionError> {
        let key_package = KeyPackage::tls_deserialize(&mut &*key_package_data)?;
        self.send_proposal(self.protocol.add_member_proposal(&key_package)?)
    }

    #[inline(always)]
    pub fn propose_update(&mut self) -> Result<Vec<u8>, SessionError> {
        let update = self.protocol.update_proposal(&self.signing_key)?;
        self.send_proposal(update)
    }

    #[inline(always)]
    pub fn propose_remove(
        &mut self,
        key_package_ref: &KeyPackageRef,
    ) -> Result<Vec<u8>, SessionError> {
        let remove = self.remove_proposal(key_package_ref)?;
        self.send_proposal(remove)
    }

    #[inline(always)]
    fn serialize_control(&mut self, plaintext: OutboundPlaintext) -> Result<Vec<u8>, SessionError> {
        Ok(plaintext.message().tls_serialize_detached()?)
    }

    fn send_proposal(&mut self, proposal: Proposal) -> Result<Vec<u8>, SessionError> {
        let packet =
            self.protocol
                .create_proposal(proposal, &self.signing_key, self.opts.wire_format())?;
        self.serialize_control(packet)
    }

    pub fn commit(&mut self, proposals: Vec<Proposal>) -> Result<CommitResult, SessionError> {
        if self.pending_commit.is_some() {
            return Err(SessionError::ExistingPendingCommit);
        }
        let (commit_data, welcome) = self.protocol.commit_proposals(
            &proposals,
            true,
            &self.signing_key,
            self.opts.wire_format(),
            self.opts.ratchet_tree_extension,
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
        self.process_incoming_bytes_with_external(data, |_| None)
    }

    pub fn process_incoming_bytes_with_external<F>(
        &mut self,
        data: &[u8],
        external_key_id_to_signing_key: F,
    ) -> Result<ProcessedMessage, SessionError>
    where
        F: FnMut(&[u8]) -> Option<PublicKey>,
    {
        self.process_incoming_message(
            MLSMessage::tls_deserialize(&mut &*data)?,
            external_key_id_to_signing_key,
        )
    }

    pub fn process_incoming_message<F>(
        &mut self,
        message: MLSMessage,
        external_key_id_to_signing_key: F,
    ) -> Result<ProcessedMessage, SessionError>
    where
        F: FnMut(&[u8]) -> Option<PublicKey>,
    {
        let res = self
            .protocol
            .process_incoming_message(message, external_key_id_to_signing_key)?;
        // This commit beat our current pending commit to the server, our commit is no longer
        // relevant
        if let ProcessedMessage::Commit(_) = res {
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

    pub fn encrypt_application_data(&mut self, data: &[u8]) -> Result<Vec<u8>, SessionError> {
        let ciphertext = self
            .protocol
            .encrypt_application_message(data, &self.signing_key)?;
        Ok(MLSMessage::Cipher(ciphertext).tls_serialize_detached()?)
    }

    pub fn export_tree(&self) -> Result<Vec<u8>, GroupError> {
        self.protocol
            .current_epoch_tree()?
            .export_node_data()
            .tls_serialize_detached()
            .map_err(Into::into)
    }

    pub fn has_equal_state(&self, other: &Session) -> bool {
        self.protocol == other.protocol
    }

    pub fn tree_stats(&self) -> Result<TreeStats, SessionError> {
        let direct_path = self
            .protocol
            .current_direct_path()?
            .iter()
            .map(|p| p.as_ref().unwrap_or(&vec![].into()).clone())
            .collect();

        Ok(TreeStats {
            total_leaves: self.participant_count(),
            current_index: self.protocol.current_user_index(),
            direct_path,
        })
    }
}
