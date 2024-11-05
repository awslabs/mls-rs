// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// Copyright by contributors to this project.
// SPDX-License-Identifier: (Apache-2.0 OR MIT)

//! UniFFI-compatible wrapper around mls-rs.
//!
//! This is an opinionated UniFFI-compatible wrapper around mls-rs:
//!
//! - Opinionated: the wrapper removes some flexiblity from mls-rs and
//!   focuses on exposing the minimum functionality necessary for
//!   messaging apps.
//!
//! - UniFFI-compatible: the wrapper exposes types annotated to be
//!   used with [UniFFI]. This makes it possible to automatically
//!   generate a Kotlin, Swift, ... code which calls into the Rust
//!   code.
//!
//! [UniFFI]: https://mozilla.github.io/uniffi-rs/

mod config;

use std::sync::Arc;

pub use config::ClientConfig;
use config::UniFFIConfig;

#[cfg(not(mls_build_async))]
use std::sync::Mutex;
#[cfg(mls_build_async)]
use tokio::sync::Mutex;

use mls_rs::error::{IntoAnyError, MlsError};
use mls_rs::group;
use mls_rs::identity::basic;
use mls_rs::mls_rules;
use mls_rs::{CipherSuiteProvider, CryptoProvider};
use mls_rs_core::identity;
use mls_rs_core::identity::{BasicCredential, IdentityProvider};
use mls_rs_crypto_openssl::OpensslCryptoProvider;

uniffi::setup_scaffolding!();

/// Unwrap the `Arc` if there is a single strong reference, otherwise
/// clone the inner value.
fn arc_unwrap_or_clone<T: Clone>(arc: Arc<T>) -> T {
    // TODO(mgeisler): use Arc::unwrap_or_clone from Rust 1.76.
    match Arc::try_unwrap(arc) {
        Ok(t) => t,
        Err(arc) => (*arc).clone(),
    }
}

#[derive(Debug, thiserror::Error, uniffi::Error)]
#[uniffi(flat_error)]
#[non_exhaustive]
pub enum Error {
    #[error("A mls-rs error occurred: {inner}")]
    MlsError {
        #[from]
        inner: mls_rs::error::MlsError,
    },
    #[error("An unknown error occurred: {inner}")]
    AnyError {
        #[from]
        inner: mls_rs::error::AnyError,
    },
    #[error("A data encoding error occurred: {inner}")]
    MlsCodecError {
        #[from]
        inner: mls_rs_core::mls_rs_codec::Error,
    },
    #[error("Unexpected callback error in UniFFI: {inner}")]
    UnexpectedCallbackError {
        #[from]
        inner: uniffi::UnexpectedUniFFICallbackError,
    },
}

impl IntoAnyError for Error {}

/// A [`mls_rs::crypto::SignaturePublicKey`] wrapper.
#[derive(Clone, Debug, uniffi::Record)]
pub struct SignaturePublicKey {
    pub bytes: Vec<u8>,
}

impl From<mls_rs::crypto::SignaturePublicKey> for SignaturePublicKey {
    fn from(public_key: mls_rs::crypto::SignaturePublicKey) -> Self {
        Self {
            bytes: public_key.to_vec(),
        }
    }
}

impl From<SignaturePublicKey> for mls_rs::crypto::SignaturePublicKey {
    fn from(public_key: SignaturePublicKey) -> Self {
        Self::new(public_key.bytes)
    }
}

/// A [`mls_rs::crypto::SignatureSecretKey`] wrapper.
#[derive(Clone, Debug, uniffi::Record)]
pub struct SignatureSecretKey {
    pub bytes: Vec<u8>,
}

impl From<mls_rs::crypto::SignatureSecretKey> for SignatureSecretKey {
    fn from(secret_key: mls_rs::crypto::SignatureSecretKey) -> Self {
        Self {
            bytes: secret_key.as_bytes().to_vec(),
        }
    }
}

impl From<SignatureSecretKey> for mls_rs::crypto::SignatureSecretKey {
    fn from(secret_key: SignatureSecretKey) -> Self {
        Self::new(secret_key.bytes)
    }
}

/// A ([`SignaturePublicKey`], [`SignatureSecretKey`]) pair.
#[derive(uniffi::Record, Clone, Debug)]
pub struct SignatureKeypair {
    cipher_suite: CipherSuite,
    public_key: SignaturePublicKey,
    secret_key: SignatureSecretKey,
}

/// A [`mls_rs::ExtensionList`] wrapper.
#[derive(uniffi::Object, Debug, Clone)]
pub struct ExtensionList {
    _inner: mls_rs::ExtensionList,
}

impl From<mls_rs::ExtensionList> for ExtensionList {
    fn from(inner: mls_rs::ExtensionList) -> Self {
        Self { _inner: inner }
    }
}

/// A [`mls_rs::Extension`] wrapper.
#[derive(uniffi::Object, Debug, Clone)]
pub struct Extension {
    _inner: mls_rs::Extension,
}

impl From<mls_rs::Extension> for Extension {
    fn from(inner: mls_rs::Extension) -> Self {
        Self { _inner: inner }
    }
}

/// A [`mls_rs::Group`] and [`mls_rs::group::NewMemberInfo`] wrapper.
#[derive(uniffi::Record, Clone)]
pub struct JoinInfo {
    /// The group that was joined.
    pub group: Arc<Group>,
    /// Group info extensions found within the Welcome message used to join
    /// the group.
    pub group_info_extensions: Arc<ExtensionList>,
}

#[derive(Copy, Clone, Debug, uniffi::Enum)]
pub enum ProtocolVersion {
    /// MLS version 1.0.
    Mls10,
}

impl TryFrom<mls_rs::ProtocolVersion> for ProtocolVersion {
    type Error = Error;

    fn try_from(version: mls_rs::ProtocolVersion) -> Result<Self, Self::Error> {
        match version {
            mls_rs::ProtocolVersion::MLS_10 => Ok(ProtocolVersion::Mls10),
            _ => Err(MlsError::UnsupportedProtocolVersion(version))?,
        }
    }
}

/// A [`mls_rs::MlsMessage`] wrapper.
#[derive(Clone, Debug, uniffi::Object)]
pub struct Message {
    inner: mls_rs::MlsMessage,
}

impl From<mls_rs::MlsMessage> for Message {
    fn from(inner: mls_rs::MlsMessage) -> Self {
        Self { inner }
    }
}

#[derive(Clone, Debug, uniffi::Object)]
pub struct Proposal {
    // FIXME: This isn't very useful because we get no details about the
    // action this proposal performs
    _inner: mls_rs::group::proposal::Proposal,
}

impl From<mls_rs::group::proposal::Proposal> for Proposal {
    fn from(inner: mls_rs::group::proposal::Proposal) -> Self {
        Self { _inner: inner }
    }
}

#[derive(Debug, Clone, uniffi::Enum)]
pub enum CommitEffect {
    NewEpoch {
        applied_proposals: Vec<Arc<Proposal>>,
        unused_proposals: Vec<Arc<Proposal>>,
    },
    ReInit,
    Removed,
}

impl From<mls_rs::group::CommitEffect> for CommitEffect {
    fn from(value: mls_rs::group::CommitEffect) -> Self {
        match value {
            group::CommitEffect::NewEpoch(new_epoch) => CommitEffect::NewEpoch {
                applied_proposals: new_epoch
                    .applied_proposals
                    .into_iter()
                    .map(|p| Arc::new(p.proposal.into()))
                    .collect(),
                unused_proposals: new_epoch
                    .unused_proposals
                    .into_iter()
                    .map(|p| Arc::new(p.proposal.into()))
                    .collect(),
            },
            group::CommitEffect::Removed {
                new_epoch: _,
                remove_proposal: _,
            } => CommitEffect::Removed,
            group::CommitEffect::ReInit(_) => CommitEffect::ReInit,
        }
    }
}

/// A [`mls_rs::group::ReceivedMessage`] wrapper.
#[derive(Clone, Debug, uniffi::Enum)]
pub enum ReceivedMessage {
    /// A decrypted application message.
    ///
    /// The encoding of the data in the message is
    /// application-specific and is not determined by MLS.
    ApplicationMessage {
        sender: Arc<SigningIdentity>,
        data: Vec<u8>,
    },

    /// A new commit was processed creating a new group state.
    Commit {
        committer: Arc<SigningIdentity>,
        effect: CommitEffect,
    },

    // TODO(mgeisler): rename to `Proposal` when
    // https://github.com/awslabs/mls-rs/issues/98 is fixed.
    /// A proposal was received.
    ReceivedProposal {
        sender: Arc<SigningIdentity>,
        proposal: Arc<Proposal>,
    },
    /// Validated GroupInfo object.
    GroupInfo,
    /// Validated welcome message.
    Welcome,
    /// Validated key package.
    KeyPackage,
}

/// Supported cipher suites.
///
/// This is a subset of the cipher suites found in
/// [`mls_rs::CipherSuite`].
#[derive(Copy, Clone, Debug, uniffi::Enum)]
pub enum CipherSuite {
    // TODO(mgeisler): add more cipher suites.
    Curve25519Aes128,
}

impl From<CipherSuite> for mls_rs::CipherSuite {
    fn from(cipher_suite: CipherSuite) -> mls_rs::CipherSuite {
        match cipher_suite {
            CipherSuite::Curve25519Aes128 => mls_rs::CipherSuite::CURVE25519_AES128,
        }
    }
}

impl TryFrom<mls_rs::CipherSuite> for CipherSuite {
    type Error = Error;

    fn try_from(cipher_suite: mls_rs::CipherSuite) -> Result<Self, Self::Error> {
        match cipher_suite {
            mls_rs::CipherSuite::CURVE25519_AES128 => Ok(CipherSuite::Curve25519Aes128),
            _ => Err(MlsError::UnsupportedCipherSuite(cipher_suite))?,
        }
    }
}

/// Generate a MLS signature keypair.
///
/// This will use the default mls-lite crypto provider.
///
/// See [`mls_rs::CipherSuiteProvider::signature_key_generate`]
/// for details.
#[cfg_attr(not(mls_build_async), maybe_async::must_be_sync)]
#[cfg_attr(mls_build_async, maybe_async::must_be_async)]
#[uniffi::export]
pub async fn generate_signature_keypair(
    cipher_suite: CipherSuite,
) -> Result<SignatureKeypair, Error> {
    let crypto_provider = mls_rs_crypto_openssl::OpensslCryptoProvider::default();
    let cipher_suite_provider = crypto_provider
        .cipher_suite_provider(cipher_suite.into())
        .ok_or(MlsError::UnsupportedCipherSuite(cipher_suite.into()))?;

    let (secret_key, public_key) = cipher_suite_provider
        .signature_key_generate()
        .await
        .map_err(|err| MlsError::CryptoProviderError(err.into_any_error()))?;

    Ok(SignatureKeypair {
        cipher_suite,
        public_key: public_key.into(),
        secret_key: secret_key.into(),
    })
}

/// An MLS client used to create key packages and manage groups.
///
/// See [`mls_rs::Client`] for details.
#[derive(Clone, Debug, uniffi::Object)]
pub struct Client {
    inner: mls_rs::client::Client<UniFFIConfig>,
}

#[cfg_attr(not(mls_build_async), maybe_async::must_be_sync)]
#[cfg_attr(mls_build_async, maybe_async::must_be_async)]
#[uniffi::export]
impl Client {
    /// Create a new client.
    ///
    /// The user is identified by `id`, which will be used to create a
    /// basic credential together with the signature keypair.
    ///
    /// See [`mls_rs::Client::builder`] for details.
    #[uniffi::constructor]
    pub fn new(
        id: Vec<u8>,
        signature_keypair: SignatureKeypair,
        client_config: ClientConfig,
    ) -> Self {
        let cipher_suite = signature_keypair.cipher_suite;
        let public_key = signature_keypair.public_key;
        let secret_key = signature_keypair.secret_key;
        let crypto_provider = OpensslCryptoProvider::new();
        let basic_credential = BasicCredential::new(id);
        let signing_identity =
            identity::SigningIdentity::new(basic_credential.into_credential(), public_key.into());
        let commit_options = mls_rules::CommitOptions::default()
            .with_ratchet_tree_extension(client_config.use_ratchet_tree_extension)
            .with_single_welcome_message(true);
        let mls_rules = mls_rules::DefaultMlsRules::new().with_commit_options(commit_options);
        let client = mls_rs::Client::builder()
            .crypto_provider(crypto_provider)
            .identity_provider(basic::BasicIdentityProvider::new())
            .signing_identity(signing_identity, secret_key.into(), cipher_suite.into())
            .group_state_storage(client_config.group_state_storage.into())
            .mls_rules(mls_rules)
            .build();

        Client { inner: client }
    }

    /// Generate a new key package for this client.
    ///
    /// The key package is represented in is MLS message form. It is
    /// needed when joining a group and can be published to a server
    /// so other clients can look it up.
    ///
    /// See [`mls_rs::Client::generate_key_package_message`] for
    /// details.
    pub async fn generate_key_package_message(&self) -> Result<Message, Error> {
        let message = self
            .inner
            .generate_key_package_message(Default::default(), Default::default())
            .await?;
        Ok(message.into())
    }

    pub fn signing_identity(&self) -> Result<Arc<SigningIdentity>, Error> {
        let (signing_identity, _) = self.inner.signing_identity()?;
        Ok(Arc::new(signing_identity.clone().into()))
    }

    /// Create and immediately join a new group.
    ///
    /// If a group ID is not given, the underlying library will create
    /// a unique ID for you.
    ///
    /// See [`mls_rs::Client::create_group`] and
    /// [`mls_rs::Client::create_group_with_id`] for details.
    pub async fn create_group(&self, group_id: Option<Vec<u8>>) -> Result<Group, Error> {
        let extensions = mls_rs::ExtensionList::new();
        let inner = match group_id {
            Some(group_id) => {
                self.inner
                    .create_group_with_id(group_id, extensions, Default::default())
                    .await?
            }
            None => {
                self.inner
                    .create_group(extensions, Default::default())
                    .await?
            }
        };
        Ok(Group {
            inner: Arc::new(Mutex::new(inner)),
        })
    }

    /// Join an existing group.
    ///
    /// You must supply `ratchet_tree` if the client that created
    /// `welcome_message` did not set `use_ratchet_tree_extension`.
    ///
    /// See [`mls_rs::Client::join_group`] for details.
    pub async fn join_group(
        &self,
        ratchet_tree: Option<RatchetTree>,
        welcome_message: &Message,
    ) -> Result<JoinInfo, Error> {
        let ratchet_tree = ratchet_tree.map(TryInto::try_into).transpose()?;
        let (group, new_member_info) = self
            .inner
            .join_group(ratchet_tree, &welcome_message.inner)
            .await?;

        let group = Arc::new(Group {
            inner: Arc::new(Mutex::new(group)),
        });
        let group_info_extensions = Arc::new(new_member_info.group_info_extensions.into());
        Ok(JoinInfo {
            group,
            group_info_extensions,
        })
    }

    /// Load an existing group.
    ///
    /// See [`mls_rs::Client::load_group`] for details.
    pub async fn load_group(&self, group_id: Vec<u8>) -> Result<Group, Error> {
        self.inner
            .load_group(&group_id)
            .await
            .map(|g| Group {
                inner: Arc::new(Mutex::new(g)),
            })
            .map_err(Into::into)
    }
}

#[derive(Clone, Debug, PartialEq, uniffi::Record)]
pub struct RatchetTree {
    pub bytes: Vec<u8>,
}

impl TryFrom<mls_rs::group::ExportedTree<'_>> for RatchetTree {
    type Error = Error;

    fn try_from(exported_tree: mls_rs::group::ExportedTree<'_>) -> Result<Self, Error> {
        let bytes = exported_tree.to_bytes()?;
        Ok(Self { bytes })
    }
}

impl TryFrom<RatchetTree> for group::ExportedTree<'static> {
    type Error = Error;

    fn try_from(ratchet_tree: RatchetTree) -> Result<Self, Error> {
        group::ExportedTree::from_bytes(&ratchet_tree.bytes).map_err(Into::into)
    }
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct CommitOutput {
    /// Commit message to send to other group members.
    pub commit_message: Arc<Message>,

    /// Welcome message to send to new group members. This will be
    /// `None` if the commit did not add new members.
    pub welcome_message: Option<Arc<Message>>,

    /// Ratchet tree that can be sent out of band if the ratchet tree
    /// extension is not used.
    pub ratchet_tree: Option<RatchetTree>,

    /// A group info that can be provided to new members in order to
    /// enable external commit functionality.
    pub group_info: Option<Arc<Message>>,
    // TODO(mgeisler): decide if we should expose unused_proposals()
    // as well.
}

impl TryFrom<mls_rs::group::CommitOutput> for CommitOutput {
    type Error = Error;

    fn try_from(commit_output: mls_rs::group::CommitOutput) -> Result<Self, Error> {
        let commit_message = Arc::new(commit_output.commit_message.into());
        let welcome_message = commit_output
            .welcome_messages
            .into_iter()
            .next()
            .map(|welcome_message| Arc::new(welcome_message.into()));
        let ratchet_tree = commit_output
            .ratchet_tree
            .map(TryInto::try_into)
            .transpose()?;
        let group_info = commit_output
            .external_commit_group_info
            .map(|group_info| Arc::new(group_info.into()));

        Ok(Self {
            commit_message,
            welcome_message,
            ratchet_tree,
            group_info,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, uniffi::Object)]
#[uniffi::export(Eq)]
pub struct SigningIdentity {
    inner: identity::SigningIdentity,
}

impl From<identity::SigningIdentity> for SigningIdentity {
    fn from(inner: identity::SigningIdentity) -> Self {
        Self { inner }
    }
}

/// An MLS end-to-end encrypted group.
///
/// The group is used to send and process incoming messages and to
/// add/remove users.
///
/// See [`mls_rs::Group`] for details.
#[derive(Clone, uniffi::Object)]
pub struct Group {
    inner: Arc<Mutex<mls_rs::Group<UniFFIConfig>>>,
}

#[cfg_attr(not(mls_build_async), maybe_async::must_be_sync)]
#[cfg_attr(mls_build_async, maybe_async::must_be_async)]
impl Group {
    #[cfg(not(mls_build_async))]
    fn inner(&self) -> std::sync::MutexGuard<'_, mls_rs::Group<UniFFIConfig>> {
        self.inner.lock().unwrap()
    }

    #[cfg(mls_build_async)]
    async fn inner(&self) -> tokio::sync::MutexGuard<'_, mls_rs::Group<UniFFIConfig>> {
        self.inner.lock().await
    }
}

/// Find the identity for the member with a given index.
fn index_to_identity(
    group: &mls_rs::Group<UniFFIConfig>,
    index: u32,
) -> Result<identity::SigningIdentity, Error> {
    let member = group
        .member_at_index(index)
        .ok_or(MlsError::InvalidNodeIndex(index))?;
    Ok(member.signing_identity)
}

/// Extract the basic credential identifier from a  from a key package.
#[cfg_attr(not(mls_build_async), maybe_async::must_be_sync)]
#[cfg_attr(mls_build_async, maybe_async::must_be_async)]
async fn signing_identity_to_identifier(
    signing_identity: &identity::SigningIdentity,
) -> Result<Vec<u8>, Error> {
    let identifier = basic::BasicIdentityProvider::new()
        .identity(signing_identity, &mls_rs::ExtensionList::new())
        .await
        .map_err(|err| err.into_any_error())?;
    Ok(identifier)
}

#[cfg_attr(not(mls_build_async), maybe_async::must_be_sync)]
#[cfg_attr(mls_build_async, maybe_async::must_be_async)]
#[uniffi::export]
impl Group {
    /// Write the current state of the group to storage defined by
    /// [`ClientConfig::group_state_storage`]
    pub async fn write_to_storage(&self) -> Result<(), Error> {
        let mut group = self.inner().await;
        group.write_to_storage().await.map_err(Into::into)
    }

    /// Export the current epoch's ratchet tree in serialized format.
    ///
    /// This function is used to provide the current group tree to new
    /// members when `use_ratchet_tree_extension` is set to false in
    /// `ClientConfig`.
    pub async fn export_tree(&self) -> Result<RatchetTree, Error> {
        let group = self.inner().await;
        group.export_tree().try_into()
    }

    /// Perform a commit of received proposals (or an empty commit).
    ///
    /// TODO: ensure `path_required` is always set in
    /// [`MlsRules::commit_options`](`mls_rs::MlsRules::commit_options`).
    ///
    /// Returns the resulting commit message. See
    /// [`mls_rs::Group::commit`] for details.
    pub async fn commit(&self) -> Result<CommitOutput, Error> {
        let mut group = self.inner().await;
        let commit_output = group.commit(Vec::new()).await?;
        commit_output.try_into()
    }

    /// Commit the addition of one or more members.
    ///
    /// The members are representated by key packages. The result is
    /// the welcome messages to send to the new members.
    ///
    /// See [`mls_rs::group::CommitBuilder::add_member`] for details.
    pub async fn add_members(
        &self,
        key_packages: Vec<Arc<Message>>,
    ) -> Result<CommitOutput, Error> {
        let mut group = self.inner().await;
        let mut commit_builder = group.commit_builder();
        for key_package in key_packages {
            commit_builder = commit_builder.add_member(arc_unwrap_or_clone(key_package).inner)?;
        }
        let commit_output = commit_builder.build().await?;
        commit_output.try_into()
    }

    /// Propose to add one or more members to this group.
    ///
    /// The members are representated by key packages. The result is
    /// the proposal messages to send to the group.
    ///
    /// See [`mls_rs::Group::propose_add`] for details.
    pub async fn propose_add_members(
        &self,
        key_packages: Vec<Arc<Message>>,
    ) -> Result<Vec<Arc<Message>>, Error> {
        let mut group = self.inner().await;

        let mut messages = Vec::with_capacity(key_packages.len());
        for key_package in key_packages {
            let key_package = arc_unwrap_or_clone(key_package);
            let message = group.propose_add(key_package.inner, Vec::new()).await?;
            messages.push(Arc::new(message.into()));
        }

        Ok(messages)
    }

    /// Propose and commit the removal of one or more members.
    ///
    /// The members are representated by their signing identities.
    ///
    /// See [`mls_rs::group::CommitBuilder::remove_member`] for details.
    pub async fn remove_members(
        &self,
        signing_identities: &[Arc<SigningIdentity>],
    ) -> Result<CommitOutput, Error> {
        let mut group = self.inner().await;

        // Find member indices
        let mut member_indixes = Vec::with_capacity(signing_identities.len());
        for signing_identity in signing_identities {
            let identifier = signing_identity_to_identifier(&signing_identity.inner).await?;
            let member = group.member_with_identity(&identifier).await?;
            member_indixes.push(member.index);
        }

        let mut commit_builder = group.commit_builder();
        for index in member_indixes {
            commit_builder = commit_builder.remove_member(index)?;
        }
        let commit_output = commit_builder.build().await?;
        commit_output.try_into()
    }

    /// Propose to remove one or more members from this group.
    ///
    /// The members are representated by their signing identities. The
    /// result is the proposal messages to send to the group.
    ///
    /// See [`mls_rs::group::Group::propose_remove`] for details.
    pub async fn propose_remove_members(
        &self,
        signing_identities: &[Arc<SigningIdentity>],
    ) -> Result<Vec<Arc<Message>>, Error> {
        let mut group = self.inner().await;

        let mut messages = Vec::with_capacity(signing_identities.len());
        for signing_identity in signing_identities {
            let identifier = signing_identity_to_identifier(&signing_identity.inner).await?;
            let member = group.member_with_identity(&identifier).await?;
            let message = group.propose_remove(member.index, Vec::new()).await?;
            messages.push(Arc::new(message.into()));
        }

        Ok(messages)
    }

    /// Encrypt an application message using the current group state.
    ///
    /// An application message is an application-specific payload,
    /// e.g., an UTF-8 encoded text message in a chat app. The
    /// encoding is not determined by MLS and applications will have
    /// to implement their own mechanism for how to agree on the
    /// content encoding.
    ///
    /// The other group members will find the message in
    /// [`ReceivedMessage::ApplicationMessage`] after calling
    /// [`Group::process_incoming_message`].
    pub async fn encrypt_application_message(&self, message: &[u8]) -> Result<Message, Error> {
        let mut group = self.inner().await;
        let mls_message = group
            .encrypt_application_message(message, Vec::new())
            .await?;
        Ok(mls_message.into())
    }

    /// Process an inbound message for this group.
    pub async fn process_incoming_message(
        &self,
        message: Arc<Message>,
    ) -> Result<ReceivedMessage, Error> {
        let message = arc_unwrap_or_clone(message);
        let mut group = self.inner().await;
        match group.process_incoming_message(message.inner).await? {
            group::ReceivedMessage::ApplicationMessage(application_message) => {
                let sender =
                    Arc::new(index_to_identity(&group, application_message.sender_index)?.into());
                let data = application_message.data().to_vec();
                Ok(ReceivedMessage::ApplicationMessage { sender, data })
            }
            group::ReceivedMessage::Commit(commit_message) => {
                let committer =
                    Arc::new(index_to_identity(&group, commit_message.committer)?.into());

                Ok(ReceivedMessage::Commit {
                    committer,
                    effect: commit_message.effect.into(),
                })
            }
            group::ReceivedMessage::Proposal(proposal_message) => {
                let sender = match proposal_message.sender {
                    mls_rs::group::ProposalSender::Member(index) => {
                        Arc::new(index_to_identity(&group, index)?.into())
                    }
                    _ => todo!("External and NewMember proposal senders are not supported"),
                };
                let proposal = Arc::new(proposal_message.proposal.into());
                Ok(ReceivedMessage::ReceivedProposal { sender, proposal })
            }
            // TODO: group::ReceivedMessage::GroupInfo does not have any
            // public methods (unless the "ffi" Cargo feature is set).
            // So perhaps we don't need it?
            group::ReceivedMessage::GroupInfo(_) => Ok(ReceivedMessage::GroupInfo),
            group::ReceivedMessage::Welcome => Ok(ReceivedMessage::Welcome),
            group::ReceivedMessage::KeyPackage(_) => Ok(ReceivedMessage::KeyPackage),
        }
    }
}

#[cfg(test)]
mod tests {
    #[cfg(not(mls_build_async))]
    use super::*;
    #[cfg(not(mls_build_async))]
    use crate::config::group_state::{EpochRecord, GroupStateStorage};
    #[cfg(not(mls_build_async))]
    use std::collections::HashMap;

    #[test]
    #[cfg(not(mls_build_async))]
    fn test_simple_scenario() -> Result<(), Error> {
        #[derive(Debug, Default)]
        struct GroupStateData {
            state: Vec<u8>,
            epoch_data: Vec<EpochRecord>,
        }

        #[derive(Debug)]
        struct CustomGroupStateStorage {
            groups: Mutex<HashMap<Vec<u8>, GroupStateData>>,
        }

        impl CustomGroupStateStorage {
            fn new() -> Self {
                Self {
                    groups: Mutex::new(HashMap::new()),
                }
            }

            fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<Vec<u8>, GroupStateData>> {
                self.groups.lock().unwrap()
            }
        }

        impl GroupStateStorage for CustomGroupStateStorage {
            fn state(&self, group_id: Vec<u8>) -> Result<Option<Vec<u8>>, Error> {
                let groups = self.lock();
                Ok(groups.get(&group_id).map(|group| group.state.clone()))
            }

            fn epoch(&self, group_id: Vec<u8>, epoch_id: u64) -> Result<Option<Vec<u8>>, Error> {
                let groups = self.lock();
                match groups.get(&group_id) {
                    Some(group) => {
                        let epoch_record =
                            group.epoch_data.iter().find(|record| record.id == epoch_id);
                        let data = epoch_record.map(|record| record.data.clone());
                        Ok(data)
                    }
                    None => Ok(None),
                }
            }

            fn write(
                &self,
                group_id: Vec<u8>,
                group_state: Vec<u8>,
                epoch_inserts: Vec<EpochRecord>,
                epoch_updates: Vec<EpochRecord>,
            ) -> Result<(), Error> {
                let mut groups = self.lock();

                let group = groups.entry(group_id).or_default();
                group.state = group_state;
                for insert in epoch_inserts {
                    group.epoch_data.push(insert);
                }

                for update in epoch_updates {
                    for epoch in group.epoch_data.iter_mut() {
                        if epoch.id == update.id {
                            epoch.data = update.data;
                            break;
                        }
                    }
                }

                Ok(())
            }

            fn max_epoch_id(&self, group_id: Vec<u8>) -> Result<Option<u64>, Error> {
                let groups = self.lock();
                Ok(groups
                    .get(&group_id)
                    .and_then(|GroupStateData { epoch_data, .. }| epoch_data.last())
                    .map(|last| last.id))
            }
        }

        let alice_config = ClientConfig {
            group_state_storage: Arc::new(CustomGroupStateStorage::new()),
            ..Default::default()
        };
        let alice_keypair = generate_signature_keypair(CipherSuite::Curve25519Aes128)?;
        let alice = Client::new(b"alice".to_vec(), alice_keypair, alice_config);

        let bob_config = ClientConfig {
            group_state_storage: Arc::new(CustomGroupStateStorage::new()),
            ..Default::default()
        };
        let bob_keypair = generate_signature_keypair(CipherSuite::Curve25519Aes128)?;
        let bob = Client::new(b"bob".to_vec(), bob_keypair, bob_config);

        let alice_group = alice.create_group(None)?;
        let bob_key_package = bob.generate_key_package_message()?;
        let commit = alice_group.add_members(vec![Arc::new(bob_key_package)])?;
        alice_group.process_incoming_message(commit.commit_message)?;

        let bob_group = bob
            .join_group(None, &commit.welcome_message.unwrap())?
            .group;
        let message = alice_group.encrypt_application_message(b"hello, bob")?;
        let received_message = bob_group.process_incoming_message(Arc::new(message))?;

        alice_group.write_to_storage()?;

        let ReceivedMessage::ApplicationMessage { sender: _, data } = received_message else {
            panic!("Wrong message type: {received_message:?}");
        };
        assert_eq!(data, b"hello, bob");

        Ok(())
    }

    #[test]
    #[cfg(not(mls_build_async))]
    fn test_ratchet_tree_not_included() -> Result<(), Error> {
        let alice_config = ClientConfig {
            use_ratchet_tree_extension: true,
            ..ClientConfig::default()
        };

        let alice_keypair = generate_signature_keypair(CipherSuite::Curve25519Aes128)?;
        let alice = Client::new(b"alice".to_vec(), alice_keypair, alice_config);
        let group = alice.create_group(None)?;

        assert_eq!(group.commit()?.ratchet_tree, None);
        Ok(())
    }

    #[test]
    #[cfg(not(mls_build_async))]
    fn test_ratchet_tree_included() -> Result<(), Error> {
        let alice_config = ClientConfig {
            use_ratchet_tree_extension: false,
            ..ClientConfig::default()
        };

        let alice_keypair = generate_signature_keypair(CipherSuite::Curve25519Aes128)?;
        let alice = Client::new(b"alice".to_vec(), alice_keypair, alice_config);
        let group = alice.create_group(None)?;

        let ratchet_tree: group::ExportedTree =
            group.commit()?.ratchet_tree.unwrap().try_into().unwrap();
        group.inner().apply_pending_commit()?;

        assert_eq!(ratchet_tree, group.inner().export_tree());
        Ok(())
    }
}
