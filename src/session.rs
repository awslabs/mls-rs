use crate::credential::Credential;
use crate::group::framing::{Content, MLSCiphertext, MLSPlaintext};
use crate::group::{proposal::Proposal, CommitGeneration, Group, GroupError, StateUpdate};
use crate::key_package::{KeyPackage, KeyPackageGeneration};
use ferriscrypt::asym::ec_key::SecretKey;
use thiserror::Error;
use tls_codec::{Deserialize, Serialize};
use tls_codec_derive::{TlsDeserialize, TlsSerialize, TlsSize};

#[derive(Error, Debug)]
pub enum SessionError {
    #[error(transparent)]
    ProtocolError(#[from] GroupError),
    #[error(transparent)]
    Serialization(#[from] tls_codec::Error),
    #[error("commit already pending, please wait")]
    ExistingPendingCommit,
    #[error("pending commit not found")]
    PendingCommitNotFound,
    #[error("pending commit mismatch")]
    PendingCommitMismatch,
    #[error(
        "pending commit action denied, commit reflection must be disabled to use this feature"
    )]
    PendingCommitDenied,
}

#[derive(Clone, Debug, TlsDeserialize, TlsSerialize, TlsSize)]
pub struct SessionOpts {
    #[tls_codec(with = "crate::tls::Boolean")]
    pub encrypt_controls: bool,
    #[tls_codec(with = "crate::tls::Boolean")]
    pub commit_reflection: bool,
}

impl SessionOpts {
    pub fn new(encrypt_controls: bool, commit_reflection: bool) -> SessionOpts {
        SessionOpts {
            encrypt_controls,
            commit_reflection,
        }
    }
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
        let welcome_message = Deserialize::tls_deserialize(&mut &*welcome_message_data)?;
        let ratchet_tree = Deserialize::tls_deserialize(&mut &*ratchet_tree_data)?;
        let group = Group::from_welcome_message(welcome_message, ratchet_tree, key_package)?;

        Ok(Session {
            signing_key,
            protocol: group,
            pending_commit: None,
            opts,
        })
    }

    pub fn export_tree(&self) -> Result<Vec<u8>, SessionError> {
        Ok(self.protocol.public_tree.tls_serialize_detached()?)
    }

    pub fn participant_count(&self) -> u32 {
        self.protocol.public_tree.leaf_count()
    }

    pub fn roster(&self) -> Vec<Credential> {
        self.protocol.public_tree.get_credentials()
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
    pub fn remove_proposal(&mut self, index: u32) -> Result<Proposal, SessionError> {
        self.protocol.remove_proposal(index).map_err(Into::into)
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
    pub fn propose_remove(&mut self, index: u32) -> Result<Vec<u8>, SessionError> {
        let remove = self.remove_proposal(index)?;
        self.send_proposal(remove)
    }

    #[inline(always)]
    fn serialize_control(&mut self, plaintext: MLSPlaintext) -> Result<Vec<u8>, SessionError> {
        if !self.opts.encrypt_controls {
            Ok(plaintext.tls_serialize_detached()?)
        } else {
            let ciphertext = self.protocol.encrypt_plaintext(plaintext)?;
            Ok(ciphertext.tls_serialize_detached()?)
        }
    }

    fn send_proposal(&mut self, proposal: Proposal) -> Result<Vec<u8>, SessionError> {
        let packet =
            self.protocol
                .sign_proposal(proposal, &self.signing_key, self.opts.encrypt_controls)?;
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

        self.pending_commit = Some(PendingCommit {
            packet_data: serialized_commit.clone(),
            commit: commit_data,
        });

        Ok(CommitResult {
            commit_packet: serialized_commit,
            welcome_packet: welcome.map(|w| w.tls_serialize_detached()).transpose()?,
        })
    }

    pub fn handle_handshake_data(
        &mut self,
        mut data: &[u8],
    ) -> Result<Option<StateUpdate>, SessionError> {
        /*
            NOTE: This only matters if commit_reflection is on. If not commits have to be manually
            accepted or rejected based on server feedback.

            If there is a pending commit, check to see if the packet we received is that commit
            If it is, we will just process the pending commit and set pending_commit to None
        */
        if let Some(pending) = &self.pending_commit {
            if self.opts.commit_reflection && pending.packet_data == data {
                let pending = self.pending_commit.take().unwrap();
                return self
                    .protocol
                    .process_pending_commit(pending.commit)
                    .map_err(Into::into)
                    .map(Some);
            }
        }

        // This is not the pending commit to process as normal
        let plaintext = match self.opts.encrypt_controls {
            true => {
                let ciphertext = MLSCiphertext::tls_deserialize(&mut data)?;
                self.protocol.decrypt_ciphertext(ciphertext)
            }
            false => {
                let plaintext = MLSPlaintext::tls_deserialize(&mut data)?;
                self.protocol.verify_plaintext(plaintext)
            }
        }?;

        let is_commit = matches!(plaintext.content, Content::Commit(_));

        let res = self.protocol.handle_handshake(plaintext)?;

        // This commit beat our current pending commit to the server, our commit is no longer
        // relevant
        if is_commit {
            self.pending_commit = None;
        }

        Ok(res)
    }

    pub fn apply_pending_commit(&mut self) -> Result<StateUpdate, SessionError> {
        if self.opts.commit_reflection {
            return Err(SessionError::PendingCommitDenied);
        }

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
        Ok(ciphertext.tls_serialize_detached()?)
    }

    pub fn decrypt_application_data(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>, SessionError> {
        let ciphertext = MLSCiphertext::tls_deserialize(&mut &*ciphertext)?;
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
            current_index: self.protocol.current_user_index(),
            direct_path,
        })
    }
}
