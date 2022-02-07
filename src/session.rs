use crate::client_config::{ClientConfig, DefaultClientConfig, KeyPackageRepository};
use crate::credential::Credential;
use crate::extension::ExtensionList;
use crate::group::framing::{Content, MLSMessage, WireFormat};
use crate::group::{
    proposal::Proposal, CommitGeneration, Group, OutboundPlaintext, StateUpdate, Welcome,
};
use crate::key_package::{
    KeyPackage, KeyPackageGenerationError, KeyPackageGenerator, KeyPackageRef,
};
use crate::psk::ExternalPskId;
use crate::tree_kem::{RatchetTreeError, TreeKemPublic};
use ferriscrypt::asym::ec_key::SecretKey;
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
    #[error(transparent)]
    KeyPackageGenerationError(#[from] KeyPackageGenerationError),
    #[error("commit already pending, please wait")]
    ExistingPendingCommit,
    #[error("pending commit not found")]
    PendingCommitNotFound,
    #[error("pending commit mismatch")]
    PendingCommitMismatch,
    #[error("key package not found")]
    KeyPackageNotFound,
    #[error(transparent)]
    KeyPackageRepoError(Box<dyn std::error::Error + Send + Sync>),
    #[error(transparent)]
    ProposalRejected(Box<dyn std::error::Error + Send + Sync>),
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

#[derive(Clone, Debug)]
pub struct Session<C = DefaultClientConfig> {
    signing_key: SecretKey,
    credential: Credential,
    extensions: ExtensionList,
    protocol: Group,
    pending_commit: Option<PendingCommit>,
    config: C,
}

#[derive(Clone, Debug)]
pub struct GroupStats {
    pub total_leaves: u32,
    pub current_index: u32,
    pub direct_path: Vec<HpkePublicKey>,
    pub epoch: u64,
}

impl<C: ClientConfig> Session<C> {
    pub(crate) fn create(
        group_id: Vec<u8>,
        signing_key: SecretKey,
        key_package_generator: KeyPackageGenerator,
        group_context_extensions: ExtensionList,
        config: C,
    ) -> Result<Self, SessionError> {
        let credential = key_package_generator.credential.clone();
        let extensions = key_package_generator.extensions.clone();

        let group = Group::new(group_id, key_package_generator, group_context_extensions)?;

        Ok(Session {
            signing_key,
            protocol: group,
            pending_commit: None,
            config,
            credential,
            extensions,
        })
    }

    pub(crate) fn join(
        signing_key: SecretKey,
        key_package: Option<&KeyPackageRef>,
        ratchet_tree_data: Option<&[u8]>,
        welcome_message_data: &[u8],
        config: C,
    ) -> Result<Self, SessionError> {
        let welcome_message = Welcome::tls_deserialize(&mut &*welcome_message_data)?;

        let key_package_generation = match key_package {
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
        .ok_or(SessionError::KeyPackageNotFound)?;

        let ratchet_tree = ratchet_tree_data
            .map(|rt| Self::import_ratchet_tree(&welcome_message, rt))
            .transpose()?;

        let credential = key_package_generation.key_package.credential.clone();
        let extensions = key_package_generation.key_package.extensions.clone();

        let group = Group::from_welcome_message(
            welcome_message,
            ratchet_tree,
            key_package_generation,
            &config.secret_store(),
        )?;

        Ok(Session {
            signing_key,
            protocol: group,
            pending_commit: None,
            config,
            credential,
            extensions,
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
        self.protocol.add_proposal(key_package).map_err(Into::into)
    }

    #[inline(always)]
    pub fn update_proposal(&mut self) -> Result<Proposal, SessionError> {
        let generator = KeyPackageGenerator {
            cipher_suite: self.protocol.cipher_suite,
            signing_key: &self.signing_key,
            credential: &self.credential,
            extensions: &self.extensions,
        };

        self.protocol
            .update_proposal(&generator)
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
    pub fn psk_proposal(&mut self, psk: ExternalPskId) -> Result<Proposal, SessionError> {
        Ok(self.protocol.psk_proposal(psk)?)
    }

    #[inline(always)]
    pub fn propose_add(&mut self, key_package_data: &[u8]) -> Result<Vec<u8>, SessionError> {
        let key_package = KeyPackage::tls_deserialize(&mut &*key_package_data)?;
        self.send_proposal(self.protocol.add_proposal(key_package)?)
    }

    #[inline(always)]
    pub fn propose_update(&mut self) -> Result<Vec<u8>, SessionError> {
        let proposal = self.update_proposal()?;
        self.send_proposal(proposal)
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
    pub fn group_context_extension_proposal(&self, extension_list: ExtensionList) -> Proposal {
        self.protocol
            .group_context_extensions_proposal(extension_list)
    }

    #[inline(always)]
    pub fn propose_group_context_extension_update(
        &mut self,
        extension_list: ExtensionList,
    ) -> Result<Vec<u8>, SessionError> {
        let extension_update = self.group_context_extension_proposal(extension_list);
        self.send_proposal(extension_update)
    }

    #[inline(always)]
    pub fn propose_psk(&mut self, psk: ExternalPskId) -> Result<Vec<u8>, SessionError> {
        let proposal = self.protocol.psk_proposal(psk)?;
        self.send_proposal(proposal)
    }

    #[inline(always)]
    fn serialize_control(&mut self, plaintext: OutboundPlaintext) -> Result<Vec<u8>, SessionError> {
        Ok(plaintext.message().tls_serialize_detached()?)
    }

    fn send_proposal(&mut self, proposal: Proposal) -> Result<Vec<u8>, SessionError> {
        let packet = self.protocol.create_proposal(
            proposal,
            &self.signing_key,
            wire_format(&self.config),
        )?;
        self.serialize_control(packet)
    }

    // TODO: You should be able to skip sending a path update if this is an add only commit
    pub fn commit(&mut self, proposals: Vec<Proposal>) -> Result<CommitResult, SessionError> {
        if self.pending_commit.is_some() {
            return Err(SessionError::ExistingPendingCommit);
        }

        let key_package_generator = KeyPackageGenerator {
            cipher_suite: self.protocol.cipher_suite,
            credential: &self.credential,
            extensions: &self.extensions,
            signing_key: &self.signing_key,
        };

        let (commit_data, welcome) = self.protocol.commit_proposals(
            proposals,
            &key_package_generator,
            true,
            wire_format(&self.config),
            self.config.ratchet_tree_extension(),
            &self.config.secret_store(),
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
        let message = self
            .protocol
            .verify_incoming_message(message, |id| self.config.external_signing_key(id))?;
        match &message.content {
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
            .process_pending_commit(pending.commit, &self.config.secret_store())
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
}

fn wire_format<C: ClientConfig>(config: &C) -> WireFormat {
    if config.encrypt_controls() {
        WireFormat::Cipher
    } else {
        WireFormat::Plain
    }
}
