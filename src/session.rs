use crate::credential::Credential;
use crate::framing::{Content, MLSCiphertext, MLSPlaintext};
use crate::group::{CommitGeneration, Group, GroupError, Proposal, StateUpdate, VerifiedPlaintext};
use crate::key_package::KeyPackageGeneration;
use crate::tree_kem::UpdatePathGeneration;
use ferriscrypt::asym::ec_key::SecretKey;
use serde::{Deserialize, Serialize};
use std::ops::Deref;
use std::option::Option::Some;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum SessionError {
    #[error(transparent)]
    ProtocolError(#[from] GroupError),
    #[error(transparent)]
    Serialization(#[from] bincode::Error),
    #[error("commit already pending, please wait")]
    ExistingPendingCommit,
    #[error("pending commit not found")]
    PendingCommitNotFound,
    #[error("pending commit mismatch")]
    PendingCommitMismatch,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SessionOpts {
    pub encrypt_controls: bool,
}

impl SessionOpts {
    pub fn new(encrypt_controls: bool) -> SessionOpts {
        SessionOpts { encrypt_controls }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct PendingCommit {
    packet_hash: Vec<u8>,
    commit: Option<UpdatePathGeneration>,
}

#[derive(Clone, Debug)]
pub struct CommitResult {
    pub commit_packet: Vec<u8>,
    pub welcome_packet: Option<Vec<u8>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Session {
    signing_key: SecretKey,
    protocol: Group,
    pending_commit: Option<CommitGeneration>,
    opts: SessionOpts,
}

#[derive(Clone, Debug)]
pub struct TreeStats {
    pub total_leaves: usize,
    pub current_index: usize,
    pub direct_path: Vec<Vec<u8>>,
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
        ratchet_tree_data: &[u8],
        welcome_message_data: &[u8],
        opts: SessionOpts,
    ) -> Result<Session, SessionError> {
        let welcome_message = bincode::deserialize(welcome_message_data)?;
        let ratchet_tree = bincode::deserialize(ratchet_tree_data)?;
        let group = Group::from_welcome_message(welcome_message, ratchet_tree, key_package)?;

        Ok(Session {
            signing_key,
            protocol: group,
            pending_commit: None,
            opts,
        })
    }

    pub fn export_tree(&self) -> Result<Vec<u8>, SessionError> {
        bincode::serialize(&self.protocol.public_tree).map_err(Into::into)
    }

    pub fn participant_count(&self) -> usize {
        self.protocol.public_tree.leaf_count()
    }

    pub fn roster(&self) -> Vec<Credential> {
        self.protocol.public_tree.get_credentials()
    }

    #[inline]
    pub fn add_proposal(&mut self, key_package_data: &[u8]) -> Result<Proposal, SessionError> {
        let key_package = bincode::deserialize(key_package_data)?;
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
    pub fn remove_proposal(&mut self, index: u32) -> Result<Proposal, SessionError> {
        self.protocol.remove_proposal(index).map_err(Into::into)
    }

    #[inline(always)]
    pub fn propose_add(&mut self, key_package_data: &[u8]) -> Result<Vec<u8>, SessionError> {
        let key_package = bincode::deserialize(key_package_data)?;
        self.send_proposal(self.protocol.add_member_proposal(&key_package)?)
    }

    #[inline(always)]
    pub fn propose_update(&mut self) -> Result<Vec<u8>, SessionError> {
        let update = self.protocol.update_proposal(&self.signing_key)?;
        self.send_proposal(update)
    }

    #[inline(always)]
    pub fn propose_remove(&mut self, index: u32) -> Result<Vec<u8>, SessionError> {
        let remove = self.remove_proposal(index)?;
        self.send_proposal(remove)
    }

    #[inline(always)]
    fn serialize_control(&mut self, plaintext: MLSPlaintext) -> Result<Vec<u8>, SessionError> {
        if !self.opts.encrypt_controls {
            bincode::serialize(&plaintext).map_err(Into::into)
        } else {
            let ciphertext = self.protocol.encrypt_plaintext(plaintext)?;
            bincode::serialize(&ciphertext).map_err(Into::into)
        }
    }

    fn send_proposal(&mut self, proposal: Proposal) -> Result<Vec<u8>, SessionError> {
        let packet = self.protocol.send_proposal(proposal, &self.signing_key)?;
        self.serialize_control(packet)
    }

    pub fn commit(&mut self, proposals: Vec<Proposal>) -> Result<CommitResult, SessionError> {
        if self.pending_commit.is_some() {
            return Err(SessionError::ExistingPendingCommit);
        }

        let (commit_data, welcome) =
            self.protocol
                .commit_proposals(&proposals, true, &self.signing_key)?;

        let serialized_commit = self.serialize_control(commit_data.plaintext.clone())?;

        self.pending_commit = Some(commit_data);

        Ok(CommitResult {
            commit_packet: serialized_commit,
            welcome_packet: welcome.map(|w| bincode::serialize(&w)).transpose()?,
        })
    }

    fn handle_commit(
        &mut self,
        plaintext: VerifiedPlaintext,
    ) -> Result<Option<StateUpdate>, SessionError> {
        // If the sender is the current user, then verify that the pending commit matches the
        // one received and apply the pending commit
        let res = if plaintext.sender.sender == self.protocol.current_user_index() {
            let pending = self
                .pending_commit
                .take()
                .ok_or(SessionError::PendingCommitNotFound)?;

            if &pending.plaintext != plaintext.deref() {
                return Err(SessionError::PendingCommitMismatch);
            }

            self.protocol.process_pending_commit(pending)
        } else {
            // This came from a different user, process as normal
            self.protocol
                .handle_handshake(plaintext)
                .map_err(Into::into)
        }?;

        self.pending_commit = None;

        Ok(res)
    }

    pub fn handle_handshake_data(
        &mut self,
        data: &[u8],
    ) -> Result<Option<StateUpdate>, SessionError> {
        let plaintext = match self.opts.encrypt_controls {
            true => {
                let ciphertext = bincode::deserialize(data)?;
                self.protocol.decrypt_ciphertext(ciphertext)
            }
            false => {
                let plaintext = bincode::deserialize(data)?;
                self.protocol.verify_plaintext(plaintext)
            }
        }?;

        if matches!(plaintext.content, Content::Commit(_)) {
            self.handle_commit(plaintext)
        } else {
            self.protocol
                .handle_handshake(plaintext)
                .map_err(Into::into)
        }
    }

    pub fn encrypt_application_data(&mut self, data: &[u8]) -> Result<Vec<u8>, SessionError> {
        let ciphertext = self
            .protocol
            .encrypt_application_message(data, &self.signing_key)?;
        bincode::serialize(&ciphertext).map_err(Into::into)
    }

    pub fn decrypt_application_data(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>, SessionError> {
        let ciphertext: MLSCiphertext = bincode::deserialize(ciphertext)?;
        self.protocol
            .decrypt_application_message(ciphertext)
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
            .map(|p| p.as_ref().unwrap_or(&vec![]).clone())
            .collect();
        Ok(TreeStats {
            total_leaves: self.protocol.public_tree.leaf_count(),
            current_index: self.protocol.current_user_index() as usize,
            direct_path,
        })
    }
}
