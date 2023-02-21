use async_trait::async_trait;
use aws_mls_core::extension::ExtensionList;
use aws_mls_core::identity::IdentityProvider;
use aws_mls_core::keychain::KeychainStorage;
use aws_mls_core::time::MlsTime;
use futures::{StreamExt, TryStreamExt};
use serde_with::serde_as;
use std::collections::HashMap;
use std::future::ready;
use std::ops::Deref;
use std::option::Option::Some;
use thiserror::Error;
use tls_codec::{Deserialize, Serialize};
use tls_codec_derive::{TlsDeserialize, TlsSerialize, TlsSize};

use crate::cipher_suite::CipherSuite;
use crate::client_config::{ClientConfig, MakeProposalFilter, ProposalFilterInit};
use crate::crypto::{HpkeCiphertext, HpkePublicKey, HpkeSecretKey, SignatureSecretKey};
use crate::extension::{ExternalPubExt, RatchetTreeExt};
use crate::identity::SigningIdentity;
use crate::key_package::{KeyPackage, KeyPackageRef, KeyPackageValidator};
use crate::protocol_version::ProtocolVersion;
use crate::psk::resolver::PskResolver;
use crate::psk::secret::{PskSecret, PskSecretInput};
use crate::psk::{
    ExternalPskId, JustPreSharedKeyID, PreSharedKey, PreSharedKeyID, PskGroupId, PskNonce,
    ResumptionPSKUsage, ResumptionPsk,
};
use crate::serde_utils::vec_u8_as_base64::VecAsBase64;
use crate::signer::Signable;
use crate::storage_provider::psk::PskStoreIdValidator;
use crate::tree_kem::hpke_encryption::HpkeEncryptable;
use crate::tree_kem::kem::TreeKem;
use crate::tree_kem::leaf_node::{ConfigProperties, LeafNode};
use crate::tree_kem::node::LeafIndex;
use crate::tree_kem::path_secret::PathSecret;
pub use crate::tree_kem::Capabilities;
use crate::tree_kem::{math as tree_math, ValidatedUpdatePath};
use crate::tree_kem::{TreeKemPrivate, TreeKemPublic};
use crate::{CipherSuiteProvider, CryptoProvider};

#[cfg(feature = "benchmark")]
use crate::client_builder::Preferences;

use ciphertext_processor::*;
use confirmation_tag::*;
use framing::*;
use key_schedule::*;
use membership_tag::*;
use message_signature::*;
use message_verifier::*;
use proposal::*;
use proposal_cache::*;
use secret_tree::*;
use state::*;
use transcript_hash::*;

#[cfg(test)]
pub(crate) use self::commit::test_utils::CommitModifiers;

#[cfg(test)]
pub use self::framing::PrivateMessage;

use self::epoch::{EpochSecrets, PriorEpoch, SenderDataSecret};
pub use self::message_processor::{Event, ProcessedMessage, StateUpdate};
use self::message_processor::{EventOrContent, MessageProcessor, ProvisionalState};
use self::padding::PaddingMode;
use self::state_repo::GroupStateRepository;
pub(crate) use group_info::GroupInfo;
pub(crate) use proposal_cache::ProposalCacheError;

use self::framing::MLSMessage;
pub use self::framing::Sender;
pub use commit::*;
pub(crate) use error::*;

pub use roster::*;

pub(crate) use transcript_hash::ConfirmedTranscriptHash;
pub(crate) use util::*;

#[cfg(feature = "benchmark")]
pub use context::*;

#[cfg(not(feature = "benchmark"))]
pub(crate) use context::*;

mod ciphertext_processor;
mod commit;
pub(crate) mod confirmation_tag;
mod context;
pub(crate) mod epoch;
pub(crate) mod error;
pub(crate) mod framing;
mod group_info;
pub(crate) mod key_schedule;
mod membership_tag;
pub(crate) mod message_processor;
pub(crate) mod message_signature;
pub(crate) mod message_verifier;
pub(crate) mod padding;
/// Proposals to evolve a MLS [`Group`]
pub mod proposal;
mod proposal_cache;
pub(crate) mod proposal_filter;
pub(crate) mod proposal_ref;
mod roster;
pub(crate) mod snapshot;
pub(crate) mod state;
pub(crate) mod state_repo;
pub(crate) mod transcript_hash;
mod util;

#[cfg(feature = "benchmark")]
#[doc(hidden)]
pub mod secret_tree;

#[cfg(not(feature = "benchmark"))]
pub(crate) mod secret_tree;

#[cfg(test)]
mod interop_test_vectors;

#[derive(Clone, Debug, PartialEq, TlsDeserialize, TlsSerialize, TlsSize)]
struct GroupSecrets {
    joiner_secret: JoinerSecret,
    path_secret: Option<PathSecret>,
    #[tls_codec(with = "crate::tls::DefVec")]
    psks: Vec<PreSharedKeyID>,
}

impl HpkeEncryptable for GroupSecrets {
    const ENCRYPT_LABEL: &'static str = "Welcome";

    type Error = tls_codec::Error;

    fn from_bytes(bytes: Vec<u8>) -> Result<Self, Self::Error> {
        Self::tls_deserialize(&mut &*bytes)
    }

    fn get_bytes(&self) -> Result<Vec<u8>, Self::Error> {
        self.tls_serialize_detached()
    }
}

#[derive(Clone, Debug, PartialEq, Eq, TlsDeserialize, TlsSerialize, TlsSize)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub(crate) struct EncryptedGroupSecrets {
    pub new_member: KeyPackageRef,
    pub encrypted_group_secrets: HpkeCiphertext,
}

#[derive(Clone, Debug, Eq, PartialEq, TlsDeserialize, TlsSerialize, TlsSize)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub(crate) struct Welcome {
    pub cipher_suite: CipherSuite,
    #[tls_codec(with = "crate::tls::DefVec")]
    pub secrets: Vec<EncryptedGroupSecrets>,
    #[tls_codec(with = "crate::tls::ByteVec")]
    pub encrypted_group_info: Vec<u8>,
}

#[derive(Clone, Debug)]
#[non_exhaustive]
/// Information provided to new members upon joining a group.
pub struct NewMemberInfo {
    /// Group info extensions found within the Welcome message used to join
    /// the group.
    pub(crate) group_info_extensions: ExtensionList,
}

impl NewMemberInfo {
    pub(crate) fn new(group_info_extensions: ExtensionList) -> Self {
        Self {
            group_info_extensions,
        }
    }

    /// Group info extensions found within the Welcome message used to join
    /// the group.
    pub fn group_info_extensions(&self) -> &ExtensionList {
        &self.group_info_extensions
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ControlEncryptionMode {
    Plaintext,
    Encrypted(PaddingMode),
}

pub(crate) mod internal {
    pub use super::*;
    /// An MLS end-to-end encrypted group.
    ///
    /// # Group Evolution
    ///
    /// MLS Groups are evolved via a propose-then-commit system. Each group state
    /// produced by a commit is called an epoch and can produce and consume
    /// application, proposal, and commit messages. A [commit](Group::commit) is used
    /// to advance to the next epoch by applying existing proposals sent in
    /// the current epoch by-reference along with an optional set of proposals
    /// that are included by-value using a [`CommitBuilder`].
    #[derive(Clone)]
    pub struct Group<C>
    where
        C: ClientConfig,
    {
        #[cfg(feature = "benchmark")]
        pub config: C,
        #[cfg(not(feature = "benchmark"))]
        pub(super) config: C,
        pub(super) cipher_suite_provider:
            <C::CryptoProvider as CryptoProvider>::CipherSuiteProvider,
        pub(super) state_repo: GroupStateRepository<C::GroupStateStorage, C::KeyPackageRepository>,
        pub(crate) state: GroupState,
        pub(super) epoch_secrets: EpochSecrets,
        pub(super) private_tree: TreeKemPrivate,
        pub(super) key_schedule: KeySchedule,
        pub(super) pending_updates: HashMap<HpkePublicKey, HpkeSecretKey>, // Hash of leaf node hpke public key to secret key
        pub(super) pending_commit: Option<CommitGeneration>,
        #[cfg(test)]
        pub(crate) commit_modifiers:
            CommitModifiers<<C::CryptoProvider as CryptoProvider>::CipherSuiteProvider>,
    }
}

pub(crate) use internal::*;

impl<C> Group<C>
where
    C: ClientConfig + Clone,
{
    pub(crate) async fn new(
        config: C,
        group_id: Option<Vec<u8>>,
        cipher_suite: CipherSuite,
        protocol_version: ProtocolVersion,
        signing_identity: SigningIdentity,
        group_context_extensions: ExtensionList,
    ) -> Result<Self, GroupError> {
        let cipher_suite_provider = cipher_suite_provider(config.crypto_provider(), cipher_suite)?;

        let signer = config
            .keychain()
            .signer(&signing_identity)
            .await
            .map_err(|e| GroupError::KeychainError(e.into()))?
            .ok_or(GroupError::SignerNotFound)?;

        let (leaf_node, leaf_node_secret) = LeafNode::generate(
            &cipher_suite_provider,
            config.leaf_properties(),
            signing_identity,
            &signer,
            config.lifetime(),
            &config.identity_provider(),
        )
        .await?;

        let (mut public_tree, private_tree) = TreeKemPublic::derive(
            leaf_node,
            leaf_node_secret,
            config.identity_provider(),
            &cipher_suite_provider,
        )
        .await?;

        let tree_hash = public_tree.tree_hash(&cipher_suite_provider)?;

        let group_id = group_id.unwrap_or(
            cipher_suite_provider
                .random_bytes_vec(cipher_suite_provider.kdf_extract_size())
                .map_err(|e| GroupError::CryptoProviderError(e.into()))?,
        );

        let context = GroupContext::new_group(
            protocol_version,
            cipher_suite,
            group_id,
            tree_hash,
            group_context_extensions,
        );

        let state_repo = GroupStateRepository::new(
            context.group_id.clone(),
            config.preferences().max_epoch_retention,
            config.group_state_storage(),
            config.key_package_repo(),
            None,
        )
        .await?;

        let key_schedule_result = KeySchedule::from_random_epoch_secret(
            &cipher_suite_provider,
            public_tree.total_leaf_count(),
        )?;

        let confirmation_tag = ConfirmationTag::create(
            &key_schedule_result.confirmation_key,
            &vec![].into(),
            &cipher_suite_provider,
        )?;

        let interim_hash = InterimTranscriptHash::create(
            &cipher_suite_provider,
            &vec![].into(),
            &confirmation_tag,
        )?;

        Ok(Self {
            config,
            state: GroupState::new(context, public_tree, interim_hash, confirmation_tag),
            private_tree,
            key_schedule: key_schedule_result.key_schedule,
            pending_updates: Default::default(),
            pending_commit: None,
            #[cfg(test)]
            commit_modifiers: Default::default(),
            epoch_secrets: key_schedule_result.epoch_secrets,
            state_repo,
            cipher_suite_provider,
        })
    }

    #[cfg(feature = "benchmark")]
    pub fn preferences(&self) -> Preferences {
        self.config.preferences()
    }

    pub(crate) async fn join(
        welcome: MLSMessage,
        tree_data: Option<&[u8]>,
        config: C,
    ) -> Result<(Self, NewMemberInfo), GroupError> {
        Self::from_welcome_message(None, welcome, tree_data, config).await
    }

    async fn from_welcome_message(
        parent_group: Option<&Group<C>>,
        welcome: MLSMessage,
        tree_data: Option<&[u8]>,
        config: C,
    ) -> Result<(Self, NewMemberInfo), GroupError> {
        let protocol_version = welcome.version;

        if !config.version_supported(protocol_version) {
            return Err(GroupError::UnsupportedProtocolVersion(protocol_version));
        }

        let wire_format = welcome.wire_format();

        let welcome = welcome.into_welcome().ok_or_else(|| {
            GroupError::UnexpectedMessageType(vec![WireFormat::Welcome], wire_format)
        })?;

        let cipher_suite_provider =
            cipher_suite_provider(config.crypto_provider(), welcome.cipher_suite)?;

        let (encrypted_group_secrets, key_package_generation) =
            find_key_package_generation(&config.key_package_repo(), &welcome.secrets).await?;

        let key_package_version = key_package_generation.key_package.version;

        if key_package_version != protocol_version {
            return Err(GroupError::ProtocolVersionMismatch {
                msg_version: protocol_version,
                wire_format: WireFormat::KeyPackage,
                version: key_package_version,
            });
        }

        // Decrypt the encrypted_group_secrets using HPKE with the algorithms indicated by the
        // cipher suite and the HPKE private key corresponding to the GroupSecrets. If a
        // PreSharedKeyID is part of the GroupSecrets and the client is not in possession of
        // the corresponding PSK, return an error
        let group_secrets = GroupSecrets::decrypt(
            &cipher_suite_provider,
            &key_package_generation.init_secret_key,
            &welcome.encrypted_group_info,
            &encrypted_group_secrets.encrypted_group_secrets,
        )?;

        let psk_store = config.secret_store();

        let psk_secret = if let Some(parent_group) = parent_group {
            PskResolver {
                group_context: parent_group.context(),
                current_epoch: &parent_group.epoch_secrets,
                prior_epochs: &parent_group.state_repo,
                psk_store: &psk_store,
            }
            .resolve_to_secret(&group_secrets.psks, &cipher_suite_provider)
            .await?
        } else {
            PskSecret::new(&cipher_suite_provider)
        };

        // From the joiner_secret in the decrypted GroupSecrets object and the PSKs specified in
        // the GroupSecrets, derive the welcome_secret and using that the welcome_key and
        // welcome_nonce.
        let welcome_secret = WelcomeSecret::from_joiner_secret(
            &cipher_suite_provider,
            &group_secrets.joiner_secret,
            &psk_secret,
        )?;

        // Use the key and nonce to decrypt the encrypted_group_info field.
        let decrypted_group_info = welcome_secret.decrypt(&welcome.encrypted_group_info)?;
        let group_info = GroupInfo::tls_deserialize(&mut &*decrypted_group_info)?;

        let join_context = validate_group_info(
            protocol_version,
            group_info,
            tree_data,
            &config.identity_provider(),
            &cipher_suite_provider,
        )
        .await?;

        // Identify a leaf in the tree array (any even-numbered node) whose leaf_node is identical
        // to the leaf_node field of the KeyPackage. If no such field exists, return an error. Let
        // index represent the index of this node among the leaves in the tree, namely the index of
        // the node in the tree array divided by two.
        let self_index = join_context
            .public_tree
            .find_leaf_node(&key_package_generation.key_package.leaf_node)
            .ok_or(GroupError::WelcomeKeyPackageNotFound)?;

        let used_key_package_ref = key_package_generation.reference;

        let mut private_tree =
            TreeKemPrivate::new_self_leaf(self_index, key_package_generation.leaf_node_secret_key);

        // If the path_secret value is set in the GroupSecrets object
        if let Some(path_secret) = group_secrets.path_secret {
            private_tree.update_secrets(
                &cipher_suite_provider,
                join_context.signer_index,
                path_secret,
                &join_context.public_tree,
            )?;
        }

        // Use the joiner_secret from the GroupSecrets object to generate the epoch secret and
        // other derived secrets for the current epoch.
        let key_schedule_result = KeySchedule::from_joiner(
            &cipher_suite_provider,
            &group_secrets.joiner_secret,
            &join_context.group_context,
            join_context.public_tree.total_leaf_count(),
            &psk_secret,
        )?;

        // Verify the confirmation tag in the GroupInfo using the derived confirmation key and the
        // confirmed_transcript_hash from the GroupInfo.
        if !join_context.confirmation_tag.matches(
            &key_schedule_result.confirmation_key,
            &join_context.group_context.confirmed_transcript_hash,
            &cipher_suite_provider,
        )? {
            return Err(GroupError::InvalidConfirmationTag);
        }

        Self::join_with(
            config,
            cipher_suite_provider,
            join_context,
            key_schedule_result.key_schedule,
            key_schedule_result.epoch_secrets,
            private_tree,
            Some(used_key_package_ref),
        )
        .await
    }

    async fn join_with(
        config: C,
        cipher_suite_provider: <C::CryptoProvider as CryptoProvider>::CipherSuiteProvider,
        join_context: JoinContext,
        key_schedule: KeySchedule,
        epoch_secrets: EpochSecrets,
        private_tree: TreeKemPrivate,
        used_key_package_ref: Option<KeyPackageRef>,
    ) -> Result<(Self, NewMemberInfo), GroupError> {
        // Use the confirmed transcript hash and confirmation tag to compute the interim transcript
        // hash in the new state.
        let interim_transcript_hash = InterimTranscriptHash::create(
            &cipher_suite_provider,
            &join_context.group_context.confirmed_transcript_hash,
            &join_context.confirmation_tag,
        )?;

        let state_repo = GroupStateRepository::new(
            join_context.group_context.group_id.clone(),
            config.preferences().max_epoch_retention,
            config.group_state_storage(),
            config.key_package_repo(),
            used_key_package_ref,
        )
        .await?;

        let group_info_extensions = join_context.group_info_extensions.clone();

        let group = Group {
            config,
            state: GroupState::new(
                join_context.group_context,
                join_context.public_tree,
                interim_transcript_hash,
                join_context.confirmation_tag,
            ),
            private_tree,
            key_schedule,
            pending_updates: Default::default(),
            pending_commit: None,
            #[cfg(test)]
            commit_modifiers: Default::default(),
            epoch_secrets,
            state_repo,
            cipher_suite_provider,
        };

        Ok((group, NewMemberInfo::new(group_info_extensions)))
    }

    /// Returns group and external commit message
    pub(crate) async fn new_external(
        config: C,
        group_info: MLSMessage,
        tree_data: Option<&[u8]>,
        signing_identity: SigningIdentity,
        to_remove: Option<u32>,
        external_psks: Vec<ExternalPskId>,
        authenticated_data: Vec<u8>,
    ) -> Result<(Self, MLSMessage), GroupError> {
        let protocol_version = group_info.version;

        if !config.version_supported(protocol_version) {
            return Err(GroupError::UnsupportedProtocolVersion(protocol_version));
        }

        let wire_format = group_info.wire_format();

        let group_info = group_info.into_group_info().ok_or_else(|| {
            GroupError::UnexpectedMessageType(vec![WireFormat::GroupInfo], wire_format)
        })?;

        let cipher_suite_provider = cipher_suite_provider(
            config.crypto_provider(),
            group_info.group_context.cipher_suite,
        )?;

        let external_pub_ext = group_info
            .extensions
            .get_as::<ExternalPubExt>()?
            .ok_or(GroupError::MissingExternalPubExtension)?;

        let join_context = validate_group_info(
            protocol_version,
            group_info,
            tree_data,
            &config.identity_provider(),
            &cipher_suite_provider,
        )
        .await?;

        let signer = config
            .keychain()
            .signer(&signing_identity)
            .await
            .map_err(|e| GroupError::KeychainError(e.into()))?
            .ok_or(GroupError::SignerNotFound)?;

        let (leaf_node, leaf_node_secret) = LeafNode::generate(
            &cipher_suite_provider,
            config.leaf_properties(),
            signing_identity,
            &signer,
            config.lifetime(),
            &config.identity_provider(),
        )
        .await?;

        let (init_secret, kem_output) = InitSecret::encode_for_external(
            &cipher_suite_provider,
            &external_pub_ext.external_pub,
        )?;

        let epoch_secrets = EpochSecrets {
            resumption_secret: PreSharedKey::from(vec![]),
            sender_data_secret: SenderDataSecret::from(vec![]),
            secret_tree: SecretTree::empty(),
        };

        let (mut group, _) = Self::join_with(
            config,
            cipher_suite_provider.clone(),
            join_context,
            KeySchedule::new(init_secret),
            epoch_secrets,
            TreeKemPrivate::new_self_leaf(LeafIndex(0), leaf_node_secret),
            None,
        )
        .await?;

        let psk_ids = external_psks
            .into_iter()
            .map(|psk_id| {
                Ok(PreSharedKeyID {
                    key_id: JustPreSharedKeyID::External(psk_id),
                    psk_nonce: PskNonce::random(&cipher_suite_provider)
                        .map_err(|e| GroupError::CryptoProviderError(e.into()))?,
                })
            })
            .collect::<Result<Vec<_>, GroupError>>()?;

        let proposals = psk_ids
            .into_iter()
            .map(|psk| Proposal::Psk(PreSharedKeyProposal { psk }))
            .chain([Proposal::ExternalInit(ExternalInit { kem_output })])
            .chain(to_remove.map(|r| {
                Proposal::Remove(RemoveProposal {
                    to_remove: LeafIndex(r),
                })
            }))
            .collect::<Vec<_>>();

        let commit_output = group
            .commit_internal(
                proposals,
                Some(&leaf_node),
                authenticated_data,
                Default::default(),
                None,
            )
            .await?;

        group.apply_pending_commit().await?;

        Ok((group, commit_output.commit_message))
    }

    #[inline(always)]
    pub(crate) fn current_epoch_tree(&self) -> &TreeKemPublic {
        &self.state.public_tree
    }

    /// The current epoch of the group. This value is incremented each
    /// time a [`Group::commit`] message is processed.
    #[inline(always)]
    pub fn current_epoch(&self) -> u64 {
        self.context().epoch
    }

    /// Index within the group's [`roster`](Group::roster) for the local
    /// group instance.
    #[inline(always)]
    pub fn current_member_index(&self) -> u32 {
        self.private_tree.self_index.0
    }

    fn current_user_leaf_node(&self) -> Result<&LeafNode, GroupError> {
        self.current_epoch_tree()
            .get_leaf_node(self.private_tree.self_index)
            .map_err(Into::into)
    }

    /// Signing identity currently in use by the local group instance.
    pub fn current_member_signing_identity(&self) -> Result<&SigningIdentity, GroupError> {
        self.current_user_leaf_node().map(|ln| &ln.signing_identity)
    }

    async fn proposal_message(
        &mut self,
        proposal: Proposal,
        authenticated_data: Vec<u8>,
    ) -> Result<MLSMessage, GroupError> {
        let signer = self.signer().await?;

        let auth_content = AuthenticatedContent::new_signed(
            &self.cipher_suite_provider,
            self.context(),
            Sender::Member(*self.private_tree.self_index),
            Content::Proposal(proposal.clone()),
            &signer,
            self.config.preferences().encryption_mode().into(),
            authenticated_data,
        )?;

        let proposal_ref = ProposalRef::from_content(&self.cipher_suite_provider, &auth_content)?;

        self.state
            .proposals
            .insert(proposal_ref, proposal, auth_content.content.sender.clone());

        self.format_for_wire(auth_content)
    }

    pub(crate) async fn signer(&self) -> Result<SignatureSecretKey, GroupError> {
        self.signer_for_identity(None).await
    }

    pub(crate) async fn signer_for_identity(
        &self,
        signing_identity: Option<&SigningIdentity>,
    ) -> Result<SignatureSecretKey, GroupError> {
        let signing_identity = signing_identity.unwrap_or(self.current_member_signing_identity()?);

        self.config
            .keychain()
            .signer(signing_identity)
            .await
            .map_err(|e| GroupError::KeychainError(e.into()))?
            .ok_or(GroupError::SignerNotFound)
    }

    /// Unique identifier for this group.
    #[inline(always)]
    pub fn group_id(&self) -> &[u8] {
        &self.context().group_id
    }

    fn provisional_private_tree(
        &self,
        provisional_state: &ProvisionalState,
    ) -> Result<TreeKemPrivate, GroupError> {
        // Update the private tree to create a provisional private tree
        let mut provisional_private_tree = self.private_tree.clone();
        let total_leaf_count = self.current_epoch_tree().total_leaf_count();

        // Apply updates to private tree
        for (_, leaf_node) in &provisional_state.updated_leaves {
            // Update the leaf in the private tree if this is our update
            if let Some(new_leaf_sk) = self.pending_updates.get(&leaf_node.public_key).cloned() {
                provisional_private_tree.update_leaf(total_leaf_count, new_leaf_sk)?;
            }
        }

        // Remove elements from the private tree
        provisional_state
            .removed_leaves
            .iter()
            .try_for_each(|(leaf_index, _)| {
                provisional_private_tree.remove_leaf(total_leaf_count, *leaf_index)?;
                Ok::<_, GroupError>(())
            })?;

        Ok(provisional_private_tree)
    }

    fn make_welcome_message(
        &self,
        new_members: Vec<(KeyPackage, LeafIndex)>,
        joiner_secret: &JoinerSecret,
        psk_secret: &PskSecret,
        path_secrets: Option<&Vec<Option<PathSecret>>>,
        psks: Vec<PreSharedKeyID>,
        group_info: &GroupInfo,
    ) -> Result<Option<MLSMessage>, GroupError> {
        // Encrypt the GroupInfo using the key and nonce derived from the joiner_secret for
        // the new epoch
        let welcome_secret = WelcomeSecret::from_joiner_secret(
            &self.cipher_suite_provider,
            joiner_secret,
            psk_secret,
        )?;

        let group_info_data = group_info.tls_serialize_detached()?;
        let encrypted_group_info = welcome_secret.encrypt(&group_info_data)?;

        let secrets = new_members
            .into_iter()
            .map(|(key_package, leaf_index)| {
                self.encrypt_group_secrets(
                    &key_package,
                    leaf_index,
                    joiner_secret,
                    path_secrets,
                    psks.clone(),
                    &encrypted_group_info,
                )
            })
            .collect::<Result<Vec<EncryptedGroupSecrets>, GroupError>>()?;

        Ok((!secrets.is_empty()).then_some(MLSMessage::new(
            self.context().protocol_version,
            MLSMessagePayload::Welcome(Welcome {
                cipher_suite: self.context().cipher_suite,
                secrets,
                encrypted_group_info,
            }),
        )))
    }

    async fn new_for_resumption(
        &self,
        new_context: &mut GroupContext,
        new_validated_leaf: LeafNode,
        new_leaf_secret: HpkeSecretKey,
        new_signer: &SignatureSecretKey,
        new_key_packages: Vec<MLSMessage>,
        resumption_psk_id: JustPreSharedKeyID,
    ) -> Result<(Self, Option<MLSMessage>), GroupError> {
        let required_capabilities = new_context.extensions.get_as()?;

        let cipher_suite_provider =
            cipher_suite_provider(self.config.crypto_provider(), new_context.cipher_suite)?;

        let key_package_validator = KeyPackageValidator::new(
            new_context.protocol_version,
            &cipher_suite_provider,
            required_capabilities.as_ref(),
            self.config.identity_provider(),
        );

        let id_provider = self.config.identity_provider();

        let mut new_key_packages = futures::stream::iter(new_key_packages)
            .then(|kp| async {
                let kp = kp.into_key_package().ok_or(GroupError::NotKeyPackage)?;

                id_provider
                    .identity(kp.signing_identity())
                    .await
                    .map_err(|e| GroupError::IdentityProviderError(e.into()))
                    .map(|id| (id, kp))
            })
            .try_collect::<HashMap<_, _>>()
            .await?;

        // Generate new leaves for all existing members
        let (new_members, new_key_pkgs) = {
            let current_tree = self.current_epoch_tree();
            let self_index = self.private_tree.self_index;

            futures::stream::iter(
                current_tree
                    .non_empty_leaves()
                    .filter(|&(index, _)| index != self_index),
            )
            .then(|(_, leaf_node)| async {
                id_provider
                    .identity(&leaf_node.signing_identity)
                    .await
                    .map_err(|e| GroupError::IdentityProviderError(e.into()))
            })
            .try_filter_map(|id| ready(Ok(new_key_packages.remove(&id))))
            .try_fold(
                (Vec::new(), Vec::new()),
                |(mut leaves, mut new_key_pkgs), new_key_pkg| async {
                    key_package_validator
                        .check_if_valid(&new_key_pkg, Default::default())
                        .await?;
                    let new_leaf = new_key_pkg.leaf_node.clone();
                    leaves.push(new_leaf);
                    new_key_pkgs.push(new_key_pkg);
                    Ok::<_, GroupError>((leaves, new_key_pkgs))
                },
            )
            .await?
        };

        let (mut new_pub_tree, new_priv_tree) = TreeKemPublic::derive(
            new_validated_leaf,
            new_leaf_secret,
            self.config.identity_provider(),
            &cipher_suite_provider,
        )
        .await?;

        // Add the generated leaves to new tree
        let added_member_indexes = new_pub_tree
            .add_leaves(
                new_members,
                self.config.identity_provider(),
                &cipher_suite_provider,
            )
            .await?;

        new_context.tree_hash = new_pub_tree.tree_hash(&cipher_suite_provider)?;

        let psks = vec![PreSharedKeyID {
            key_id: resumption_psk_id,
            psk_nonce: PskNonce::random(&cipher_suite_provider)
                .map_err(|e| GroupError::CryptoProviderError(e.into()))?,
        }];

        let psk_input = psks
            .iter()
            .map(|id| PskSecretInput {
                id: id.clone(),
                psk: self.epoch_secrets.resumption_secret.clone(),
            })
            .collect::<Vec<_>>();

        let psk_secret = PskSecret::calculate(&psk_input, &cipher_suite_provider)?;

        let key_schedule_result = KeySchedule::from_key_schedule(
            &KeySchedule::new(InitSecret::random(&cipher_suite_provider)?),
            &CommitSecret::empty(&cipher_suite_provider),
            new_context,
            new_pub_tree.total_leaf_count(),
            &psk_secret,
            &cipher_suite_provider,
        )?;

        let mut group_info = GroupInfo {
            group_context: new_context.clone(),
            extensions: ExtensionList::new(),
            confirmation_tag: ConfirmationTag::create(
                &key_schedule_result.confirmation_key,
                &new_context.confirmed_transcript_hash,
                &cipher_suite_provider,
            )?,
            signer: new_priv_tree.self_index,
            signature: Vec::new(),
        };

        group_info.sign(&cipher_suite_provider, new_signer, &())?;

        let interim_transcript_hash = InterimTranscriptHash::create(
            &cipher_suite_provider,
            &new_context.confirmed_transcript_hash,
            &group_info.confirmation_tag,
        )?;

        let state_repo = GroupStateRepository::new(
            new_context.group_id.clone(),
            self.config.preferences().max_epoch_retention,
            self.config.group_state_storage(),
            self.config.key_package_repo(),
            None,
        )
        .await?;

        let new_group = Group {
            config: self.config.clone(),
            state: GroupState::new(
                new_context.clone(),
                new_pub_tree,
                interim_transcript_hash,
                group_info.confirmation_tag.clone(),
            ),
            private_tree: new_priv_tree,
            key_schedule: key_schedule_result.key_schedule,
            pending_updates: Default::default(),
            pending_commit: None,
            #[cfg(test)]
            commit_modifiers: Default::default(),
            epoch_secrets: key_schedule_result.epoch_secrets,
            state_repo,
            cipher_suite_provider,
        };

        let welcome = new_group.make_welcome_message(
            new_key_pkgs.into_iter().zip(added_member_indexes).collect(),
            &key_schedule_result.joiner_secret,
            &psk_secret,
            None,
            psks,
            &group_info,
        )?;

        Ok((new_group, welcome))
    }

    /// Create a sub-group from a subset of the current group members.
    ///
    /// Membership within the resulting sub-group is indicated by providing a
    /// key package that produces the same
    /// [identity](crate::IdentityProvider::identity) value
    /// as an existing group member. The identity value of each key package
    /// is determined using the
    /// [`IdentityProvider`](crate::IdentityProvider)
    /// that is currently in use by this group instance.
    // TODO investigate if it's worth updating your own signing identity here
    pub async fn branch(
        &self,
        sub_group_id: Vec<u8>,
        new_key_packages: Vec<MLSMessage>,
    ) -> Result<(Group<C>, Option<MLSMessage>), GroupError> {
        let signer = self.signer().await?;

        let current_leaf_node = self.current_user_leaf_node()?;

        let leaf_properties = ConfigProperties {
            capabilities: current_leaf_node.capabilities.clone(),
            extensions: current_leaf_node.extensions.clone(),
        };

        let (new_leaf_node, new_leaf_secret) = LeafNode::generate(
            &self.cipher_suite_provider,
            leaf_properties,
            current_leaf_node.signing_identity.clone(),
            &signer,
            self.config.lifetime(),
            &self.config.identity_provider(),
        )
        .await?;

        let mut new_context = GroupContext {
            epoch: 1,
            ..GroupContext::new_group(
                self.state.protocol_version(),
                self.state.cipher_suite(),
                sub_group_id.clone(),
                vec![],
                self.context().extensions.clone(),
            )
        };

        let resumption_psk_id = JustPreSharedKeyID::Resumption(ResumptionPsk {
            usage: ResumptionPSKUsage::Branch,
            psk_group_id: PskGroupId(sub_group_id),
            psk_epoch: self.current_epoch(),
        });

        self.new_for_resumption(
            &mut new_context,
            new_leaf_node,
            new_leaf_secret,
            &signer,
            new_key_packages,
            resumption_psk_id,
        )
        .await
    }

    /// Join a subgroup that was created by [`Group::branch`].
    pub async fn join_subgroup(
        &self,
        welcome: MLSMessage,
        tree_data: Option<&[u8]>,
    ) -> Result<(Group<C>, NewMemberInfo), GroupError> {
        let (subgroup, new_member_info) =
            Self::from_welcome_message(Some(self), welcome, tree_data, self.config.clone()).await?;

        if subgroup.state.protocol_version() != self.state.protocol_version() {
            Err(GroupError::SubgroupWithDifferentProtocolVersion(
                subgroup.state.protocol_version(),
            ))
        } else if subgroup.state.cipher_suite() != self.state.cipher_suite() {
            Err(GroupError::SubgroupWithDifferentCipherSuite(
                subgroup.state.cipher_suite(),
            ))
        } else {
            Ok((subgroup, new_member_info))
        }
    }

    /// Create a new group that is based on properties defined by a previously
    /// sent [`ReInit`](proposal::ReInitProposal).
    ///
    /// For each member of the group, a key package that produces the same
    /// [identity](crate::IdentityProvider::identity) value
    /// as an existing group member. The identity value of each key package
    /// is determined using the
    /// [`IdentityProvider`](crate::IdentityProvider)
    /// that is currently in use by this group instance.
    ///
    /// The resulting commit message can be processed by other members using
    /// [`Group::finish_reinit_join`].
    ///
    /// # Warning
    ///
    /// This function will fail if the number of members in the reinitialized
    /// group is not the same as the prior group roster.
    pub async fn finish_reinit_commit(
        &self,
        new_key_packages: Vec<MLSMessage>,
        signing_identity: Option<SigningIdentity>,
    ) -> Result<(Group<C>, Option<MLSMessage>), GroupError> {
        let config = self.config.clone();

        let reinit = self
            .state
            .pending_reinit
            .as_ref()
            .ok_or(GroupError::PendingReInitNotFound)?;

        let signing_identity =
            signing_identity.unwrap_or(self.current_member_signing_identity()?.clone());

        let new_signer = self.signer_for_identity(Some(&signing_identity)).await?;

        let new_cipher_suite = self
            .config
            .crypto_provider()
            .cipher_suite_provider(reinit.cipher_suite)
            .ok_or_else(|| GroupError::UnsupportedCipherSuite(reinit.cipher_suite))?;

        let (new_leaf_node, new_leaf_secret) = LeafNode::generate(
            &new_cipher_suite,
            config.leaf_properties(),
            signing_identity,
            &new_signer,
            config.lifetime(),
            &config.identity_provider(),
        )
        .await?;

        let mut new_context = GroupContext {
            epoch: 1,
            ..GroupContext::new_group(
                reinit.version,
                reinit.cipher_suite,
                reinit.group_id.clone(),
                vec![],
                reinit.extensions.clone(),
            )
        };

        let resumption_psk_id = JustPreSharedKeyID::Resumption(ResumptionPsk {
            usage: ResumptionPSKUsage::Reinit,
            psk_group_id: PskGroupId(self.context().group_id.clone()),
            psk_epoch: self.current_epoch(),
        });

        let (group, welcome) = self
            .new_for_resumption(
                &mut new_context,
                new_leaf_node,
                new_leaf_secret,
                &new_signer,
                new_key_packages,
                resumption_psk_id,
            )
            .await?;

        if group.state.public_tree.occupied_leaf_count()
            != self.state.public_tree.occupied_leaf_count()
        {
            Err(GroupError::CommitRequired)
        } else {
            Ok((group, welcome))
        }
    }

    /// Join a reinitialized group that was created by
    /// [`Group::finish_reinit_commit`].
    pub async fn finish_reinit_join(
        &self,
        welcome: MLSMessage,
        tree_data: Option<&[u8]>,
    ) -> Result<(Group<C>, NewMemberInfo), GroupError> {
        let reinit = self
            .state
            .pending_reinit
            .as_ref()
            .ok_or(GroupError::PendingReInitNotFound)?;

        let (group, new_member_info) =
            Self::from_welcome_message(Some(self), welcome, tree_data, self.config.clone()).await?;

        if group.state.protocol_version() != reinit.version {
            Err(GroupError::ReInitVersionMismatch(
                group.state.protocol_version(),
                reinit.version,
            ))
        } else if group.state.cipher_suite() != reinit.cipher_suite {
            Err(GroupError::ReInitCiphersuiteMismatch(
                group.state.cipher_suite(),
                reinit.cipher_suite,
            ))
        } else if group.state.context.group_id != reinit.group_id {
            Err(GroupError::ReInitIdMismatch(
                group.state.context.group_id,
                reinit.group_id.clone(),
            ))
        } else if group.state.context.extensions != reinit.extensions {
            Err(GroupError::ReInitExtensionsMismatch(
                group.state.context.extensions,
                reinit.extensions.clone(),
            ))
        } else {
            Ok((group, new_member_info))
        }
    }

    fn encrypt_group_secrets(
        &self,
        key_package: &KeyPackage,
        leaf_index: LeafIndex,
        joiner_secret: &JoinerSecret,
        path_secrets: Option<&Vec<Option<PathSecret>>>,
        psks: Vec<PreSharedKeyID>,
        encrypted_group_info: &[u8],
    ) -> Result<EncryptedGroupSecrets, GroupError> {
        let path_secret = path_secrets
            .map(|secrets| {
                secrets
                    .get(
                        tree_math::leaf_lca_level(*self.private_tree.self_index, *leaf_index)
                            as usize
                            - 1,
                    )
                    .cloned()
                    .flatten()
                    .ok_or(GroupError::InvalidTreeKemPrivateKey)
            })
            .transpose()?;

        let group_secrets = GroupSecrets {
            joiner_secret: joiner_secret.clone(),
            path_secret,
            psks,
        };

        let encrypted_group_secrets = group_secrets.encrypt(
            &self.cipher_suite_provider,
            &key_package.hpke_init_key,
            encrypted_group_info,
        )?;

        Ok(EncryptedGroupSecrets {
            new_member: key_package.to_reference(&self.cipher_suite_provider)?,
            encrypted_group_secrets,
        })
    }

    /// Create a proposal message that adds a new member to the group.
    ///
    /// `authenticated_data` will be sent unencrypted along with the contents
    /// of the proposal message.
    pub async fn propose_add(
        &mut self,
        key_package: MLSMessage,
        authenticated_data: Vec<u8>,
    ) -> Result<MLSMessage, GroupError> {
        let proposal = self.add_proposal(key_package)?;
        self.proposal_message(proposal, authenticated_data).await
    }

    fn add_proposal(&self, key_package: MLSMessage) -> Result<Proposal, GroupError> {
        let wire_format = key_package.wire_format();

        Ok(Proposal::Add(AddProposal {
            key_package: key_package.into_key_package().ok_or_else(|| {
                GroupError::UnexpectedMessageType(vec![WireFormat::KeyPackage], wire_format)
            })?,
        }))
    }

    /// Create a proposal message that updates your own public keys.
    ///
    /// This proposal is useful for contributing additional forward secrecy
    /// and post-compromise security to the group without having to perform
    /// the necessary computation of a [`Group::commit`].
    ///
    /// `authenticated_data` will be sent unencrypted along with the contents
    /// of the proposal message.
    pub async fn propose_update(
        &mut self,
        authenticated_data: Vec<u8>,
    ) -> Result<MLSMessage, GroupError> {
        let proposal = self.update_proposal(None).await?;
        self.proposal_message(proposal, authenticated_data).await
    }

    /// Create a proposal message that updates your own public keys
    /// as well as your credential.
    ///
    /// This proposal is useful for contributing additional forward secrecy
    /// and post-compromise security to the group without having to perform
    /// the necessary computation of a [`Group::commit`].
    ///
    /// Identity updates are allowed by the group by default assuming that the
    /// new identity provided is considered
    /// [valid](crate::IdentityProvider::validate)
    /// by and matches the output of the
    /// [identity](crate::IdentityProvider)
    /// function of the current
    /// [`IdentityProvider`](crate::IdentityProvider).
    ///
    /// `authenticated_data` will be sent unencrypted along with the contents
    /// of the proposal message.
    pub async fn propose_update_with_identity(
        &mut self,
        signing_identity: SigningIdentity,
        authenticated_data: Vec<u8>,
    ) -> Result<MLSMessage, GroupError> {
        let proposal = self.update_proposal(Some(signing_identity)).await?;
        self.proposal_message(proposal, authenticated_data).await
    }

    async fn update_proposal(
        &mut self,
        signing_identity: Option<SigningIdentity>,
    ) -> Result<Proposal, GroupError> {
        // Grab a copy of the current node and update it to have new key material
        let signer = self.signer_for_identity(signing_identity.as_ref()).await?;
        let mut new_leaf_node = self.current_user_leaf_node()?.clone();

        let secret_key = new_leaf_node.update(
            &self.cipher_suite_provider,
            self.group_id(),
            self.current_member_index(),
            self.config.leaf_properties(),
            signing_identity,
            &signer,
        )?;

        // Store the secret key in the pending updates storage for later
        self.pending_updates
            .insert(new_leaf_node.public_key.clone(), secret_key);

        Ok(Proposal::Update(UpdateProposal {
            leaf_node: new_leaf_node,
        }))
    }

    /// Create a proposal message that removes an existing member from the
    /// group.
    ///
    /// `authenticated_data` will be sent unencrypted along with the contents
    /// of the proposal message.
    pub async fn propose_remove(
        &mut self,
        index: u32,
        authenticated_data: Vec<u8>,
    ) -> Result<MLSMessage, GroupError> {
        let proposal = self.remove_proposal(index)?;
        self.proposal_message(proposal, authenticated_data).await
    }

    fn remove_proposal(&self, index: u32) -> Result<Proposal, GroupError> {
        let leaf_index = LeafIndex(index);

        // Verify that this leaf is actually in the tree
        self.current_epoch_tree().get_leaf_node(leaf_index)?;

        Ok(Proposal::Remove(RemoveProposal {
            to_remove: leaf_index,
        }))
    }

    /// Create a proposal message that adds a pre shared key to the group.
    ///
    /// Each group member will need to have the PSK associated with
    /// [`ExternalPskId`](crate::storage_provider::ExternalPskId) installed within
    /// the [`PreSharedKeyStorage`](crate::PreSharedKeyStorage)
    /// in use by this group upon processing a [commit](Group::commit) that
    /// contains this proposal.
    ///
    /// `authenticated_data` will be sent unencrypted along with the contents
    /// of the proposal message.
    pub async fn propose_psk(
        &mut self,
        psk: ExternalPskId,
        authenticated_data: Vec<u8>,
    ) -> Result<MLSMessage, GroupError> {
        let proposal = self.psk_proposal(psk)?;
        self.proposal_message(proposal, authenticated_data).await
    }

    fn psk_proposal(&self, psk: ExternalPskId) -> Result<Proposal, GroupError> {
        Ok(Proposal::Psk(PreSharedKeyProposal {
            psk: PreSharedKeyID {
                key_id: JustPreSharedKeyID::External(psk),
                psk_nonce: PskNonce::random(&self.cipher_suite_provider)
                    .map_err(|e| GroupError::CryptoProviderError(e.into()))?,
            },
        }))
    }

    /// Create a proposal message that requests for this group to be
    /// reinitialized.
    ///
    /// Once a [`ReInitProposal`](proposal::ReInitProposal)
    /// has been sent, another group member can complete reinitialization of
    /// the group by calling [`Group::finish_reinit_commit`].
    ///
    /// `authenticated_data` will be sent unencrypted along with the contents
    /// of the proposal message.
    pub async fn propose_reinit(
        &mut self,
        group_id: Option<Vec<u8>>,
        version: ProtocolVersion,
        cipher_suite: CipherSuite,
        extensions: ExtensionList,
        authenticated_data: Vec<u8>,
    ) -> Result<MLSMessage, GroupError> {
        let proposal = self.reinit_proposal(group_id, version, cipher_suite, extensions)?;
        self.proposal_message(proposal, authenticated_data).await
    }

    fn reinit_proposal(
        &self,
        group_id: Option<Vec<u8>>,
        version: ProtocolVersion,
        cipher_suite: CipherSuite,
        extensions: ExtensionList,
    ) -> Result<Proposal, GroupError> {
        let group_id = group_id.unwrap_or(
            self.cipher_suite_provider
                .random_bytes_vec(self.cipher_suite_provider.kdf_extract_size())
                .map_err(|e| GroupError::CryptoProviderError(e.into()))?,
        );

        Ok(Proposal::ReInit(ReInitProposal {
            group_id,
            version,
            cipher_suite,
            extensions,
        }))
    }

    /// Create a proposal message that sets extensions stored in the group
    /// state.
    ///
    /// # Warning
    ///
    /// This function does not create a diff that will be applied to the
    /// current set of extension that are in use. In order for an existing
    /// extension to not be overwritten by this proposal, it must be included
    /// in the new set of extensions being proposed.
    ///
    ///
    /// `authenticated_data` will be sent unencrypted along with the contents
    /// of the proposal message.
    pub async fn propose_group_context_extensions(
        &mut self,
        extensions: ExtensionList,
        authenticated_data: Vec<u8>,
    ) -> Result<MLSMessage, GroupError> {
        let proposal = self.group_context_extensions_proposal(extensions);
        self.proposal_message(proposal, authenticated_data).await
    }

    fn group_context_extensions_proposal(&self, extensions: ExtensionList) -> Proposal {
        Proposal::GroupContextExtensions(extensions)
    }

    /// Create a custom proposal message.
    ///
    /// `authenticated_data` will be sent unencrypted along with the contents
    /// of the proposal message.
    pub async fn propose_custom(
        &mut self,
        proposal: CustomProposal,
        authenticated_data: Vec<u8>,
    ) -> Result<MLSMessage, GroupError> {
        self.proposal_message(Proposal::Custom(proposal), authenticated_data)
            .await
    }

    pub(crate) fn format_for_wire(
        &mut self,
        content: AuthenticatedContent,
    ) -> Result<MLSMessage, GroupError> {
        let payload = if content.wire_format == WireFormat::PrivateMessage {
            MLSMessagePayload::Cipher(self.create_ciphertext(content)?)
        } else {
            MLSMessagePayload::Plain(self.create_plaintext(content)?)
        };

        Ok(MLSMessage::new(self.protocol_version(), payload))
    }

    fn create_plaintext(
        &self,
        auth_content: AuthenticatedContent,
    ) -> Result<PublicMessage, GroupError> {
        let membership_tag = matches!(auth_content.content.sender, Sender::Member(_))
            .then(|| {
                self.key_schedule.get_membership_tag(
                    &auth_content,
                    self.context(),
                    &self.cipher_suite_provider,
                )
            })
            .transpose()?;

        Ok(PublicMessage {
            content: auth_content.content,
            auth: auth_content.auth,
            membership_tag,
        })
    }

    fn create_ciphertext(
        &mut self,
        auth_content: AuthenticatedContent,
    ) -> Result<PrivateMessage, GroupError> {
        let preferences = self.config.preferences();

        let mut encryptor = CiphertextProcessor::new(self, self.cipher_suite_provider.clone());

        encryptor
            .seal(auth_content, preferences.padding_mode)
            .map_err(Into::into)
    }

    /// Encrypt an application message using the current group state.
    ///
    /// `authenticated_data` will be sent unencrypted along with the contents
    /// of the proposal message.
    pub async fn encrypt_application_message(
        &mut self,
        message: &[u8],
        authenticated_data: Vec<u8>,
    ) -> Result<MLSMessage, GroupError> {
        let signer = self.signer().await?;

        // A group member that has observed one or more proposals within an epoch MUST send a Commit message
        // before sending application data
        if !self.state.proposals.is_empty() {
            return Err(GroupError::CommitRequired);
        }

        let auth_content = AuthenticatedContent::new_signed(
            &self.cipher_suite_provider,
            self.context(),
            Sender::Member(*self.private_tree.self_index),
            Content::Application(message.to_vec().into()),
            &signer,
            WireFormat::PrivateMessage,
            authenticated_data,
        )?;

        self.format_for_wire(auth_content)
    }

    async fn decrypt_incoming_ciphertext(
        &mut self,
        message: PrivateMessage,
    ) -> Result<AuthenticatedContent, GroupError> {
        let epoch_id = message.epoch;

        let auth_content = if epoch_id == self.context().epoch {
            let content =
                CiphertextProcessor::new(self, self.cipher_suite_provider.clone()).open(message)?;

            verify_auth_content_signature(
                &self.cipher_suite_provider,
                SignaturePublicKeysContainer::RatchetTree(&self.state.public_tree),
                self.context(),
                &content,
                &[],
            )?;

            Ok::<_, GroupError>(content)
        } else {
            let epoch = self
                .state_repo
                .get_epoch_mut(epoch_id)
                .await?
                .ok_or(GroupError::EpochNotFound(epoch_id))?;

            let content = CiphertextProcessor::new(epoch, self.cipher_suite_provider.clone())
                .open(message)?;

            verify_auth_content_signature(
                &self.cipher_suite_provider,
                SignaturePublicKeysContainer::List(&epoch.signature_public_keys),
                &epoch.context,
                &content,
                &[],
            )?;

            Ok(content)
        }?;

        Ok(auth_content)
    }

    /// Apply a pending commit that was created by [`Group::commit`] or
    /// [`CommitBuilder::build`].
    pub async fn apply_pending_commit(&mut self) -> Result<StateUpdate, GroupError> {
        let pending_commit = self
            .pending_commit
            .clone()
            .ok_or(GroupError::PendingCommitNotFound)?;

        self.process_commit(pending_commit.content, None).await
    }

    /// Clear the currently pending commit.
    ///
    /// This function will automatically be called in the event that a
    /// commit message is processed using [`Group::process_incoming_message`]
    /// before [`Group::apply_pending_commit`] is called.
    pub fn clear_pending_commit(&mut self) {
        self.pending_commit = None
    }

    /// Process an inbound message for this group.
    ///
    /// # Warning
    ///
    /// Changes to the group's state as a result of processing `message` will
    /// not be persisted by the
    /// [`GroupStateStorage`](crate::GroupStateStorage)
    /// in use by this group until [`Group::write_to_storage`] is called.
    pub async fn process_incoming_message(
        &mut self,
        message: MLSMessage,
    ) -> Result<ProcessedMessage<Event>, GroupError> {
        MessageProcessor::process_incoming_message(self, message, true).await
    }

    /// Process an inbound message for this group, providing additional context
    /// with a message timestamp.
    ///
    /// Providing a timestamp is useful when the
    /// [`IdentityProvider`](crate::IdentityProvider)
    /// in use by the group can determine validity based on a timestamp.
    /// For example, this allows for checking X.509 certificate expiration
    /// at the time when `message` was received by a server rather than when
    /// a specific client asynchronously received `message`
    ///
    /// # Warning
    ///
    /// Changes to the group's state as a result of processing `message` will
    /// not be persisted by the
    /// [`GroupStateStorage`](crate::GroupStateStorage)
    /// in use by this group until [`Group::write_to_storage`] is called.
    pub async fn process_incoming_message_with_time(
        &mut self,
        message: MLSMessage,
        time: MlsTime,
    ) -> Result<ProcessedMessage<Event>, GroupError> {
        MessageProcessor::process_incoming_message_with_time(self, message, true, Some(time)).await
    }

    /// Find a group member by
    /// [identity](crate::IdentityProvider::identity)
    ///
    /// This function determines identity by calling the
    /// [`IdentityProvider`](crate::IdentityProvider)
    /// currently in use by the group.
    pub fn get_member_with_identity(&self, identity: &[u8]) -> Result<Member, GroupError> {
        let index = self
            .state
            .public_tree
            .get_leaf_node_with_identity(identity)
            .ok_or(GroupError::MemberNotFound)?;

        let node = self.state.public_tree.get_leaf_node(index)?;

        Ok(member_from_leaf_node(node, index))
    }

    /// Create a group info message that can be used for external proposals and commits.
    ///
    /// The returned `GroupInfo` is suitable for one external commit for the current epoch.
    pub async fn group_info_message(
        &self,
        allow_external_commit: bool,
    ) -> Result<MLSMessage, GroupError> {
        let signer = self.signer().await?;

        let mut extensions = ExtensionList::new();

        let preferences = self.config.preferences();

        if preferences.ratchet_tree_extension {
            extensions.set_from(RatchetTreeExt {
                tree_data: self.state.public_tree.nodes.clone(),
            })?;
        }

        if allow_external_commit {
            extensions.set_from({
                let (_external_secret, external_pub) = self
                    .key_schedule
                    .get_external_key_pair(&self.cipher_suite_provider)?;

                ExternalPubExt { external_pub }
            })?;
        }

        let mut info = GroupInfo {
            group_context: self.context().clone(),
            extensions,
            confirmation_tag: self.state.confirmation_tag.clone(),
            signer: self.private_tree.self_index,
            signature: Vec::new(),
        };

        info.sign(&self.cipher_suite_provider, &signer, &())?;

        Ok(MLSMessage::new(
            self.protocol_version(),
            MLSMessagePayload::GroupInfo(info),
        ))
    }

    #[inline(always)]
    pub(crate) fn context(&self) -> &GroupContext {
        &self.state.context
    }

    /// Get the
    /// [epoch_authenticator](https://messaginglayersecurity.rocks/mls-protocol/draft-ietf-mls-protocol.html#name-key-schedule)
    /// of the current epoch.
    pub fn epoch_authenticator(&self) -> Result<Vec<u8>, GroupError> {
        Ok(self.key_schedule.authentication_secret.clone())
    }

    pub fn export_secret(
        &self,
        label: &str,
        context: &[u8],
        len: usize,
    ) -> Result<Vec<u8>, GroupError> {
        Ok(self
            .key_schedule
            .export_secret(label, context, len, &self.cipher_suite_provider)?)
    }

    /// Export the current epoch's ratchet tree in serialized format.
    ///
    /// This function is used to provide the current group tree to new members
    /// when the
    /// [ratchet_tree_extension preference](crate::client_builder::Preferences::ratchet_tree_extension)
    /// is not in use.
    pub fn export_tree(&self) -> Result<Vec<u8>, GroupError> {
        self.current_epoch_tree()
            .export_node_data()
            .tls_serialize_detached()
            .map_err(Into::into)
    }

    /// Current version of the MLS protocol in use by this group.
    pub fn protocol_version(&self) -> ProtocolVersion {
        self.context().protocol_version
    }

    /// Current cipher suite in use by this group.
    pub fn cipher_suite(&self) -> CipherSuite {
        self.context().cipher_suite
    }

    /// The current set of group members.
    pub fn roster(&self) -> Vec<Member> {
        self.group_state().roster()
    }

    /// Determines equality of two different groups internal states.
    /// Useful for testing.
    ///
    pub fn equal_group_state(a: &Group<C>, b: &Group<C>) -> bool {
        a.state == b.state && a.key_schedule == b.key_schedule && a.epoch_secrets == b.epoch_secrets
    }

    #[cfg(feature = "benchmark")]
    pub fn secret_tree(&self) -> &SecretTree {
        &self.epoch_secrets.secret_tree
    }
}

impl<C> GroupStateProvider for Group<C>
where
    C: ClientConfig + Clone,
{
    fn group_context(&self) -> &GroupContext {
        self.context()
    }

    fn self_index(&self) -> LeafIndex {
        self.private_tree.self_index
    }

    fn epoch_secrets_mut(&mut self) -> &mut EpochSecrets {
        &mut self.epoch_secrets
    }

    fn epoch_secrets(&self) -> &EpochSecrets {
        &self.epoch_secrets
    }
}

#[async_trait]
impl<C> MessageProcessor for Group<C>
where
    C: ClientConfig + Clone,
{
    type ProposalFilter = <C::MakeProposalFilter as MakeProposalFilter>::Filter;
    type IdentityProvider = C::IdentityProvider;
    type ExternalPskIdValidator = PskStoreIdValidator<C::PskStore>;
    type EventType = Event;
    type CipherSuiteProvider = <C::CryptoProvider as CryptoProvider>::CipherSuiteProvider;

    fn self_index(&self) -> Option<LeafIndex> {
        Some(self.private_tree.self_index)
    }

    async fn process_ciphertext(
        &mut self,
        cipher_text: PrivateMessage,
    ) -> Result<EventOrContent<Self::EventType>, GroupError> {
        self.decrypt_incoming_ciphertext(cipher_text)
            .await
            .map(EventOrContent::Content)
    }

    fn verify_plaintext_authentication(
        &self,
        message: PublicMessage,
    ) -> Result<EventOrContent<Self::EventType>, GroupError> {
        let auth_content = verify_plaintext_authentication(
            &self.cipher_suite_provider,
            message,
            Some(&self.key_schedule),
            Some(self.private_tree.self_index),
            &self.state,
        )?;

        Ok(EventOrContent::Content(auth_content))
    }

    async fn apply_update_path(
        &mut self,
        sender: LeafIndex,
        update_path: ValidatedUpdatePath,
        provisional_state: &mut ProvisionalState,
    ) -> Result<Option<(TreeKemPrivate, PathSecret)>, GroupError> {
        // Update the private tree to create a provisional private tree
        let mut provisional_private_tree = self.provisional_private_tree(provisional_state)?;

        let secrets = if let Some(pending) = self
            .pending_commit
            .as_ref()
            .and_then(|pc| pc.pending_secrets.as_ref())
        {
            provisional_state
                .public_tree
                .apply_update_path(
                    self.private_tree.self_index,
                    &update_path,
                    self.identity_provider(),
                    self.cipher_suite_provider(),
                )
                .await?;

            Ok(pending.clone())
        } else {
            TreeKem::new(
                &mut provisional_state.public_tree,
                &mut provisional_private_tree,
            )
            .decap(
                sender,
                &update_path,
                &provisional_state
                    .added_leaves
                    .iter()
                    .map(|(_, index)| *index)
                    .collect::<Vec<LeafIndex>>(),
                &mut provisional_state.group_context,
                self.config.identity_provider(),
                &self.cipher_suite_provider,
            )
            .await
            .map(|root_secret| (provisional_private_tree, root_secret))
        }?;

        Ok(Some(secrets))
    }

    async fn update_key_schedule(
        &mut self,
        secrets: Option<(TreeKemPrivate, PathSecret)>,
        interim_transcript_hash: InterimTranscriptHash,
        confirmation_tag: ConfirmationTag,
        provisional_state: ProvisionalState,
    ) -> Result<(), GroupError> {
        let commit_secret = CommitSecret::from_root_secret(
            &self.cipher_suite_provider,
            secrets.as_ref().map(|(_, root_secret)| root_secret),
        )?;

        let secret_store = self.config.secret_store();

        let psk_secret = PskResolver {
            group_context: self.context(),
            current_epoch: &self.epoch_secrets,
            prior_epochs: &self.state_repo,
            psk_store: &secret_store,
        }
        .resolve_to_secret(&provisional_state.psks, &self.cipher_suite_provider)
        .await?;

        // Use the commit_secret, the psk_secret, the provisional GroupContext, and the init secret
        // from the previous epoch (or from the external init) to compute the epoch secret and
        // derived secrets for the new epoch

        let key_schedule = match provisional_state.external_init {
            Some((_, ExternalInit { kem_output })) if self.pending_commit.is_none() => self
                .key_schedule
                .derive_for_external(&kem_output, &self.cipher_suite_provider)?,
            _ => self.key_schedule.clone(),
        };

        let key_schedule_result = KeySchedule::from_key_schedule(
            &key_schedule,
            &commit_secret,
            &provisional_state.group_context,
            provisional_state.public_tree.total_leaf_count(),
            &psk_secret,
            &self.cipher_suite_provider,
        )?;

        // Use the confirmation_key for the new epoch to compute the confirmation tag for
        // this message, as described below, and verify that it is the same as the
        // confirmation_tag field in the MLSPlaintext object.
        let new_confirmation_tag = ConfirmationTag::create(
            &key_schedule_result.confirmation_key,
            &provisional_state.group_context.confirmed_transcript_hash,
            &self.cipher_suite_provider,
        )?;

        if new_confirmation_tag != confirmation_tag {
            return Err(GroupError::InvalidConfirmationTag);
        }

        let signature_public_keys = self
            .state
            .public_tree
            .non_empty_leaves()
            .map(|(index, leaf)| (index, leaf.signing_identity.signature_key.clone()))
            .collect::<HashMap<_, _>>();

        let past_epoch = PriorEpoch {
            context: self.context().clone(),
            self_index: self.private_tree.self_index,
            secrets: self.epoch_secrets.clone(),
            signature_public_keys,
        };

        self.state_repo.insert(past_epoch).await?;

        self.epoch_secrets = key_schedule_result.epoch_secrets;

        // If the above checks are successful, consider the updated GroupContext object
        // as the current state of the group
        if let Some(private_tree) = secrets.map(|(private_key, _)| private_key) {
            self.private_tree = private_tree
        }

        self.state.context = provisional_state.group_context;

        self.state.interim_transcript_hash = interim_transcript_hash;

        self.key_schedule = key_schedule_result.key_schedule;

        self.state.public_tree = provisional_state.public_tree;
        self.state.confirmation_tag = new_confirmation_tag;

        // Clear the proposals list
        self.state.proposals.clear();

        // Clear the pending updates list
        self.pending_updates = Default::default();
        self.pending_commit = None;

        Ok(())
    }

    fn proposal_filter(&self, init: ProposalFilterInit) -> Self::ProposalFilter {
        self.config.proposal_filter(init)
    }

    fn identity_provider(&self) -> Self::IdentityProvider {
        self.config.identity_provider()
    }

    fn external_psk_id_validator(&self) -> Self::ExternalPskIdValidator {
        PskStoreIdValidator::from(self.config.secret_store())
    }

    fn group_state(&self) -> &GroupState {
        &self.state
    }

    fn group_state_mut(&mut self) -> &mut GroupState {
        &mut self.state
    }

    fn can_continue_processing(&self, provisional_state: &ProvisionalState) -> bool {
        !(provisional_state
            .removed_leaves
            .iter()
            .any(|(i, _)| *i == self.private_tree.self_index)
            && self.pending_commit.is_none())
    }

    fn min_epoch_available(&self) -> Option<u64> {
        None
    }

    fn cipher_suite_provider(&self) -> &Self::CipherSuiteProvider {
        &self.cipher_suite_provider
    }
}

#[cfg(test)]
pub(crate) mod test_utils;

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use crate::client::test_utils::{get_basic_client_builder, test_client_with_key_pkg};
    use crate::crypto::test_utils::{test_cipher_suite_provider, TestCryptoProvider};
    use crate::group::test_utils::random_bytes;
    use crate::identity::test_utils::get_test_basic_credential;
    use crate::key_package::test_utils::test_key_package_message;
    use crate::key_package::KeyPackageValidationError;
    use crate::time::MlsTime;
    use crate::tree_kem::leaf_node::test_utils::get_test_capabilities;
    use crate::{
        client::{
            test_utils::{TEST_CIPHER_SUITE, TEST_PROTOCOL_VERSION},
            Client,
        },
        client_builder::{test_utils::TestClientConfig, Preferences},
        extension::{test_utils::TestExtension, ExternalSendersExt, RequiredCapabilitiesExt},
        identity::test_utils::get_test_signing_identity,
        key_package::test_utils::test_key_package_custom,
        psk::PreSharedKey,
        tree_kem::{
            leaf_node::LeafNodeSource, leaf_node_validator::LeafNodeValidationError, Lifetime,
            RatchetTreeError, TreeIndexError, UpdatePathNode, UpdatePathValidationError,
        },
    };

    use super::test_utils::test_group_custom_config;
    use super::{
        test_utils::{
            get_test_25519_key, get_test_groups_with_features, group_extensions, process_commit,
            test_group, test_group_custom, test_member, test_n_member_group, TestGroup, TEST_GROUP,
        },
        *,
    };
    use assert_matches::assert_matches;

    use aws_mls_core::extension::{Extension, MlsExtension};
    use aws_mls_core::identity::{CertificateChain, Credential, CredentialType, CustomCredential};
    use futures::FutureExt;
    use internal::proposal_filter::ProposalFilterError;
    use tls_codec::Size;

    #[cfg(target_arch = "wasm32")]
    use wasm_bindgen_test::wasm_bindgen_test as test;

    #[futures_test::test]
    async fn test_create_group() {
        for (protocol_version, cipher_suite) in ProtocolVersion::all().flat_map(|p| {
            TestCryptoProvider::all_supported_cipher_suites()
                .into_iter()
                .map(move |cs| (p, cs))
        }) {
            let test_group = test_group(protocol_version, cipher_suite).await;
            let group = test_group.group;

            assert_eq!(group.state.cipher_suite(), cipher_suite);
            assert_eq!(group.state.context.epoch, 0);
            assert_eq!(group.state.context.group_id, TEST_GROUP.to_vec());
            assert_eq!(group.state.context.extensions, group_extensions());
            assert_eq!(
                group.state.context.confirmed_transcript_hash,
                ConfirmedTranscriptHash::from(vec![])
            );
            assert!(group.state.proposals.is_empty());
            assert!(group.pending_updates.is_empty());
            assert_eq!(
                group.private_tree.self_index.0,
                group.current_member_index()
            );

            assert_eq!(
                group.state.public_tree.get_leaf_nodes()[0].signing_identity,
                group.config.keychain().identities()[0].0
            );
        }
    }

    #[futures_test::test]
    async fn test_pending_proposals_application_data() {
        let mut test_group = test_group(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE).await;

        // Create a proposal
        let (bob_key_package, _) =
            test_member(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE, b"bob").await;

        let proposal = test_group
            .group
            .add_proposal(bob_key_package.key_package_message())
            .unwrap();

        test_group
            .group
            .proposal_message(proposal, vec![])
            .await
            .unwrap();

        // We should not be able to send application messages until a commit happens
        let res = test_group
            .group
            .encrypt_application_message(b"test", vec![])
            .await;

        assert_matches!(res, Err(GroupError::CommitRequired));

        // We should be able to send application messages after a commit
        test_group.group.commit(vec![]).await.unwrap();

        test_group.group.apply_pending_commit().await.unwrap();

        assert!(test_group
            .group
            .encrypt_application_message(b"test", vec![])
            .await
            .is_ok());
    }

    #[futures_test::test]
    async fn test_update_proposals() {
        let mut new_capabilities = get_test_capabilities();
        new_capabilities.extensions.push(42.into());

        let new_extension = TestExtension { foo: 10 };
        let mut extension_list = ExtensionList::default();
        extension_list.set_from(new_extension).unwrap();

        let mut test_group = test_group_custom(
            TEST_PROTOCOL_VERSION,
            TEST_CIPHER_SUITE,
            Some(new_capabilities.clone()),
            Some(extension_list.clone()),
            None,
        )
        .await;

        let existing_leaf = test_group.group.current_user_leaf_node().unwrap().clone();

        // Create an update proposal
        let proposal = test_group.update_proposal().await;

        let update = match proposal {
            Proposal::Update(update) => update,
            _ => panic!("non update proposal found"),
        };

        assert_ne!(update.leaf_node.public_key, existing_leaf.public_key);
        assert_eq!(
            update.leaf_node.signing_identity,
            existing_leaf.signing_identity
        );
        assert_eq!(update.leaf_node.extensions, extension_list);
        assert_eq!(update.leaf_node.capabilities, new_capabilities);
    }

    #[futures_test::test]
    async fn test_invalid_commit_self_update() {
        let mut test_group = test_group(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE).await;

        // Create an update proposal
        let proposal_msg = test_group.group.propose_update(vec![]).await.unwrap();

        let proposal = match proposal_msg.into_plaintext().unwrap().content.content {
            Content::Proposal(p) => p,
            _ => panic!("found non-proposal message"),
        };

        // The update should be filtered out because the committer commits an update for itself
        test_group.group.commit(vec![]).await.unwrap();
        let state_update = test_group.group.apply_pending_commit().await.unwrap();

        assert_matches!(
            &*state_update.rejected_proposals,
            [(_, p)] if *p == proposal
        );
    }

    #[futures_test::test]
    async fn update_proposal_with_bad_key_package_is_ignored_when_committing() {
        let (mut alice_group, mut bob_group) =
            test_two_member_group(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE, true).await;

        let mut proposal = alice_group.update_proposal().await;

        if let Proposal::Update(ref mut update) = proposal {
            update.leaf_node.signature = random_bytes(32);
        } else {
            panic!("Invalid update proposal")
        }

        let proposal_message = alice_group
            .group
            .proposal_message(proposal.clone(), vec![])
            .await
            .unwrap();

        let proposal_plaintext = match proposal_message.payload {
            MLSMessagePayload::Plain(p) => p,
            _ => panic!("Unexpected non-plaintext message"),
        };

        let proposal_ref = ProposalRef::from_content(
            &bob_group.group.cipher_suite_provider,
            &proposal_plaintext.clone().into(),
        )
        .unwrap();

        // Hack bob's receipt of the proposal
        bob_group.group.state.proposals.insert(
            proposal_ref,
            proposal,
            proposal_plaintext.content.sender,
        );

        let commit_output = bob_group.group.commit(vec![]).await.unwrap();

        assert_matches!(
            commit_output.commit_message,
            MLSMessage {
                payload: MLSMessagePayload::Plain(
                    PublicMessage {
                        content: FramedContent {
                            content: Content::Commit(Commit {
                                proposals,
                                ..
                            }),
                            ..
                        },
                        ..
                    }),
                ..
            } if proposals.is_empty()
        );
    }

    async fn test_two_member_group(
        protocol_version: ProtocolVersion,
        cipher_suite: CipherSuite,
        tree_ext: bool,
    ) -> (TestGroup, TestGroup) {
        let mut test_group = test_group_custom(
            protocol_version,
            cipher_suite,
            None,
            None,
            Some(Preferences::default().with_ratchet_tree_extension(tree_ext)),
        )
        .await;

        let (bob_test_group, _) = test_group.join("bob").await;

        assert!(Group::equal_group_state(
            &test_group.group,
            &bob_test_group.group
        ));

        (test_group, bob_test_group)
    }

    #[futures_test::test]
    async fn test_welcome_processing_exported_tree() {
        test_two_member_group(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE, false).await;
    }

    #[futures_test::test]
    async fn test_welcome_processing_tree_extension() {
        test_two_member_group(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE, true).await;
    }

    #[futures_test::test]
    async fn test_welcome_processing_missing_tree() {
        let mut test_group = test_group_custom(
            TEST_PROTOCOL_VERSION,
            TEST_CIPHER_SUITE,
            None,
            None,
            Some(Preferences::default().with_ratchet_tree_extension(false)),
        )
        .await;

        let (bob_client, bob_key_package) =
            test_client_with_key_pkg(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE, "bob").await;

        // Add bob to the group
        let commit_output = test_group
            .group
            .commit_builder()
            .add_member(bob_key_package)
            .unwrap()
            .build()
            .await
            .unwrap();

        // Group from Bob's perspective
        let bob_group = Group::join(
            commit_output.welcome_message.unwrap(),
            None,
            bob_client.config,
        )
        .await
        .map(|_| ());

        assert_matches!(bob_group, Err(GroupError::RatchetTreeNotFound));
    }

    #[futures_test::test]
    async fn test_group_context_ext_proposal_create() {
        let test_group = test_group(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE).await;

        let mut extension_list = ExtensionList::new();
        extension_list
            .set_from(RequiredCapabilitiesExt {
                extensions: vec![42.into()],
                proposals: vec![],
                credentials: vec![],
            })
            .unwrap();

        let proposal = test_group
            .group
            .group_context_extensions_proposal(extension_list.clone());

        assert_matches!(proposal, Proposal::GroupContextExtensions(ext) if ext == extension_list);
    }

    async fn group_context_extension_proposal_test(
        ext_list: ExtensionList,
    ) -> (TestGroup, Result<MLSMessage, GroupError>) {
        let protocol_version = TEST_PROTOCOL_VERSION;
        let cipher_suite = TEST_CIPHER_SUITE;

        let mut capabilities = get_test_capabilities();
        capabilities.extensions.push(42.into());

        let mut test_group = test_group_custom(
            protocol_version,
            cipher_suite,
            Some(capabilities),
            None,
            None,
        )
        .await;

        let commit = test_group
            .group
            .commit_builder()
            .set_group_context_ext(ext_list)
            .unwrap()
            .build()
            .await
            .map(|commit_output| commit_output.commit_message);

        (test_group, commit)
    }

    #[futures_test::test]
    async fn test_group_context_ext_proposal_commit() {
        let mut extension_list = ExtensionList::new();
        extension_list
            .set_from(RequiredCapabilitiesExt {
                extensions: vec![42.into()],
                proposals: vec![],
                credentials: vec![],
            })
            .unwrap();

        let (mut test_group, _) =
            group_context_extension_proposal_test(extension_list.clone()).await;
        let state_update = test_group.group.apply_pending_commit().await.unwrap();

        assert!(state_update.active);
        assert_eq!(test_group.group.state.context.extensions, extension_list)
    }

    #[futures_test::test]
    async fn test_group_context_ext_proposal_invalid() {
        let mut extension_list = ExtensionList::new();
        extension_list
            .set_from(RequiredCapabilitiesExt {
                extensions: vec![999.into()],
                proposals: vec![],
                credentials: vec![],
            })
            .unwrap();

        let (_, commit) = group_context_extension_proposal_test(extension_list.clone()).await;

        assert_matches!(
            commit,
            Err(GroupError::ProposalCacheError(
                ProposalCacheError::ProposalFilterError(
                    ProposalFilterError::LeafNodeValidationError(
                        LeafNodeValidationError::RequiredExtensionNotFound(a)
                    )
                )
            )) if a == 999.into()
        );
    }

    #[futures_test::test]
    async fn test_group_encrypt_plaintext_padding() {
        let protocol_version = TEST_PROTOCOL_VERSION;
        let cipher_suite = TEST_CIPHER_SUITE;

        let mut test_group = test_group_custom(
            protocol_version,
            cipher_suite,
            None,
            None,
            Some(Preferences::default().with_padding_mode(PaddingMode::None)),
        )
        .await;

        let without_padding = test_group
            .group
            .encrypt_application_message(&random_bytes(150), vec![])
            .await
            .unwrap();

        let mut test_group = test_group_custom(
            protocol_version,
            cipher_suite,
            None,
            None,
            Some(Preferences::default().with_padding_mode(PaddingMode::StepFunction)),
        )
        .await;

        let with_padding = test_group
            .group
            .encrypt_application_message(&random_bytes(150), vec![])
            .await
            .unwrap();

        assert!(with_padding.tls_serialized_len() > without_padding.tls_serialized_len());
    }

    #[futures_test::test]
    async fn external_commit_requires_external_pub_extension() {
        let protocol_version = TEST_PROTOCOL_VERSION;
        let cipher_suite = TEST_CIPHER_SUITE;
        let group = test_group(protocol_version, cipher_suite).await;

        let info = group
            .group
            .group_info_message(false)
            .await
            .unwrap()
            .into_group_info()
            .unwrap();

        let info_msg = MLSMessage::new(protocol_version, MLSMessagePayload::GroupInfo(info));

        let signing_identity = group
            .group
            .current_member_signing_identity()
            .unwrap()
            .clone();

        let res = Group::new_external(
            group.group.config,
            info_msg,
            None,
            signing_identity,
            None,
            vec![],
            vec![],
        )
        .await
        .map(|_| ());

        assert_matches!(res, Err(GroupError::MissingExternalPubExtension));
    }

    #[futures_test::test]
    async fn test_path_update_preference() {
        let protocol_version = TEST_PROTOCOL_VERSION;
        let cipher_suite = TEST_CIPHER_SUITE;

        let mut test_group = test_group_custom(
            protocol_version,
            cipher_suite,
            None,
            None,
            Some(Preferences::default().force_commit_path_update(false)),
        )
        .await;

        let test_key_package =
            test_key_package_message(protocol_version, cipher_suite, "alice").await;

        test_group
            .group
            .commit_builder()
            .add_member(test_key_package.clone())
            .unwrap()
            .build()
            .await
            .unwrap();

        assert!(test_group
            .group
            .pending_commit
            .unwrap()
            .pending_secrets
            .is_none());

        let mut test_group = test_group_custom(
            protocol_version,
            cipher_suite,
            None,
            None,
            Some(Preferences::default().force_commit_path_update(true)),
        )
        .await;

        test_group
            .group
            .commit_builder()
            .add_member(test_key_package)
            .unwrap()
            .build()
            .await
            .unwrap();

        assert!(test_group
            .group
            .pending_commit
            .unwrap()
            .pending_secrets
            .is_some());
    }

    #[futures_test::test]
    async fn test_path_update_preference_override() {
        let protocol_version = TEST_PROTOCOL_VERSION;
        let cipher_suite = TEST_CIPHER_SUITE;

        let mut test_group = test_group_custom(
            protocol_version,
            cipher_suite,
            None,
            None,
            Some(Preferences::default().force_commit_path_update(false)),
        )
        .await;

        test_group.group.commit(vec![]).await.unwrap();

        assert!(test_group
            .group
            .pending_commit
            .unwrap()
            .pending_secrets
            .is_some());
    }

    #[futures_test::test]
    async fn group_rejects_unencrypted_application_message() {
        let protocol_version = TEST_PROTOCOL_VERSION;
        let cipher_suite = TEST_CIPHER_SUITE;

        let mut alice = test_group(protocol_version, cipher_suite).await;
        let (mut bob, _) = alice.join("bob").await;

        let message = alice
            .make_plaintext(Content::Application(b"hello".to_vec().into()))
            .await;

        assert_matches!(
            bob.group.process_incoming_message(message).await,
            Err(GroupError::UnencryptedApplicationMessage)
        );
    }

    fn canonicalize_state_update(update: &mut StateUpdate) {
        update.roster_update.added.sort_by_key(|a| a.index());
        update.roster_update.updated.sort_by_key(|a| a.index());
        update.roster_update.removed.sort_by_key(|a| a.index());
    }

    #[futures_test::test]
    async fn test_state_update() {
        let protocol_version = TEST_PROTOCOL_VERSION;
        let cipher_suite = TEST_CIPHER_SUITE;

        // Create a group with 10 members
        let mut alice = test_group(protocol_version, cipher_suite).await;
        let (mut bob, _) = alice.join("bob").await;
        let mut leaves = vec![];

        for i in 0..8 {
            let (group, commit) = alice.join(&format!("charlie{i}")).await;
            leaves.push(group.group.current_user_leaf_node().unwrap().clone());
            bob.process_message(commit).await.unwrap();
        }

        // Create many proposals, make Alice commit them

        let update_message = bob.group.propose_update(vec![]).await.unwrap();

        alice.process_message(update_message).await.unwrap();

        let external_psk_ids: Vec<ExternalPskId> = (0..5)
            .map(|i| {
                let external_id = ExternalPskId::new(vec![i]);

                alice
                    .group
                    .config
                    .secret_store()
                    .insert(ExternalPskId::new(vec![i]), PreSharedKey::from(vec![i]));

                bob.group
                    .config
                    .secret_store()
                    .insert(ExternalPskId::new(vec![i]), PreSharedKey::from(vec![i]));

                external_id
            })
            .collect();

        let mut commit_builder = alice.group.commit_builder();

        for external_psk in external_psk_ids {
            commit_builder = commit_builder.add_psk(external_psk).unwrap();
        }

        for index in [2, 5, 6] {
            commit_builder = commit_builder.remove_member(index).unwrap();
        }

        for i in 0..5 {
            let (key_package, _) = test_member(
                protocol_version,
                cipher_suite,
                format!("dave{i}").as_bytes(),
            )
            .await;

            commit_builder = commit_builder
                .add_member(key_package.key_package_message())
                .unwrap()
        }

        let commit_output = commit_builder.build().await.unwrap();

        // Check that applying pending commit and processing commit yields correct update.
        let mut state_update_alice = alice.process_pending_commit().await.unwrap();
        canonicalize_state_update(&mut state_update_alice);

        assert_eq!(
            state_update_alice
                .roster_update
                .added
                .iter()
                .map(|m| m.index())
                .collect::<Vec<_>>(),
            vec![2, 5, 6, 10, 11]
        );

        assert_eq!(
            state_update_alice.roster_update.removed,
            vec![2, 5, 6]
                .into_iter()
                .map(|i| member_from_leaf_node(&leaves[i as usize - 2], LeafIndex(i)))
                .collect::<Vec<_>>()
        );

        assert_eq!(
            state_update_alice.roster_update.updated.as_slice(),
            &alice.group.roster()[0..2]
        );

        assert_eq!(
            state_update_alice.added_psks,
            (0..5)
                .map(|i| ExternalPskId::new(vec![i]))
                .collect::<Vec<_>>()
        );

        let payload = bob
            .process_message(commit_output.commit_message)
            .await
            .unwrap();
        assert_matches!(payload, Event::Commit(_));

        if let Event::Commit(mut state_update_bob) = payload {
            canonicalize_state_update(&mut state_update_bob);
            assert_eq!(
                state_update_alice.roster_update.added,
                state_update_bob.roster_update.added
            );
            assert_eq!(
                state_update_alice.roster_update.removed,
                state_update_bob.roster_update.removed
            );
            assert_eq!(
                state_update_alice.roster_update.updated,
                state_update_bob.roster_update.updated
            );
            assert_eq!(state_update_alice.added_psks, state_update_bob.added_psks);
        }
    }

    #[futures_test::test]
    async fn state_update_external_commit() {
        let mut alice_group = test_group(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE).await;

        let (bob, bob_identity) = get_basic_client_builder(TEST_CIPHER_SUITE, "bob");

        let (bob_group, commit) = bob
            .build()
            .commit_external(
                alice_group.group.group_info_message(true).await.unwrap(),
                Some(&alice_group.group.export_tree().unwrap()),
                bob_identity,
                None,
                vec![],
                vec![],
            )
            .await
            .unwrap();

        let event = alice_group.process_message(commit).await.unwrap();

        assert_matches!(event, Event::Commit(_));

        if let Event::Commit(update) = event {
            assert_eq!(
                update.roster_update.added.as_slice(),
                &bob_group.roster()[1..2]
            )
        }
    }

    #[futures_test::test]
    async fn can_join_new_group_externally() {
        let mut alice_group = test_group(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE).await;

        let (bob, bob_identity) = get_basic_client_builder(TEST_CIPHER_SUITE, "bob");

        let (_, commit) = bob
            .build()
            .commit_external(
                alice_group.group.group_info_message(true).await.unwrap(),
                Some(&alice_group.group.export_tree().unwrap()),
                bob_identity,
                None,
                vec![],
                vec![],
            )
            .await
            .unwrap();

        alice_group.process_message(commit).await.unwrap();
    }

    #[futures_test::test]
    async fn test_membership_tag_from_non_member() {
        let (mut alice_group, mut bob_group) =
            test_two_member_group(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE, true).await;

        let mut commit_output = alice_group.group.commit(vec![]).await.unwrap();

        let mut plaintext = match commit_output.commit_message.payload {
            MLSMessagePayload::Plain(ref mut plain) => plain,
            _ => panic!("Non plaintext message"),
        };

        plaintext.content.sender = Sender::External(0);

        assert_matches!(
            bob_group
                .process_message(commit_output.commit_message)
                .await,
            Err(GroupError::MembershipTagForNonMember)
        );
    }

    #[futures_test::test]
    async fn test_partial_commits() {
        let protocol_version = TEST_PROTOCOL_VERSION;
        let cipher_suite = TEST_CIPHER_SUITE;

        // Create a group with 3 members
        let mut alice = test_group(protocol_version, cipher_suite).await;
        let (mut bob, _) = alice.join("bob").await;

        let (mut charlie, commit) = alice
            .join_with_preferences(
                "charlie",
                Preferences::default()
                    .with_ratchet_tree_extension(true)
                    .force_commit_path_update(false),
            )
            .await;

        bob.process_message(commit).await.unwrap();

        let (_, commit) = charlie
            .join_with_preferences("dave", charlie.group.config.preferences())
            .await;

        alice.process_message(commit.clone()).await.unwrap();
        bob.process_message(commit).await.unwrap();
    }

    #[futures_test::test]
    async fn old_hpke_secrets_are_removed() {
        let mut alice = test_group(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE).await;
        alice.join("bob").await;
        alice.join("charlie").await;

        alice
            .group
            .commit_builder()
            .remove_member(1)
            .unwrap()
            .build()
            .await
            .unwrap();

        assert!(alice.group.private_tree.secret_keys.contains_key(&1));
        alice.process_pending_commit().await.unwrap();
        assert!(!alice.group.private_tree.secret_keys.contains_key(&1));
    }

    #[futures_test::test]
    async fn only_selected_members_of_the_original_group_can_join_subgroup() {
        let mut alice = test_group(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE).await;
        let (mut bob, _) = alice.join("bob").await;
        let (carol, commit) = alice.join("carol").await;

        // Apply the commit that adds carol
        bob.group.process_incoming_message(commit).await.unwrap();

        let bob_identity = bob.group.config.keychain().identities()[0].0.clone();

        let new_key_pkg = Client::new(bob.group.config.clone())
            .generate_key_package_message(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE, bob_identity)
            .await
            .unwrap();

        let (mut alice_sub_group, welcome) = alice
            .group
            .branch(b"subgroup".to_vec(), vec![new_key_pkg])
            .await
            .unwrap();

        let welcome = welcome.unwrap();

        let (mut bob_sub_group, _) = bob
            .group
            .join_subgroup(
                welcome.clone(),
                Some(&alice_sub_group.export_tree().unwrap()),
            )
            .await
            .unwrap();

        // Carol can't join
        assert_matches!(
            carol
                .group
                .join_subgroup(welcome, Some(&alice_sub_group.export_tree().unwrap()))
                .await
                .map(|_| ()),
            Err(_)
        );

        // Alice and Bob can still talk
        let commit_output = alice_sub_group.commit(vec![]).await.unwrap();

        bob_sub_group
            .process_incoming_message(commit_output.commit_message)
            .await
            .unwrap();
    }

    async fn joining_group_fails_if_unsupported<F>(
        f: F,
    ) -> Result<(TestGroup, MLSMessage), GroupError>
    where
        F: FnMut(&mut TestClientConfig),
    {
        let mut alice_group = test_group(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE).await;
        alice_group.join_with_custom_config("alice", false, f).await
    }

    #[futures_test::test]
    async fn joining_group_fails_if_protocol_version_is_not_supported() {
        let res = joining_group_fails_if_unsupported(|config| {
            config.0.settings.protocol_versions.clear();
        })
        .await
        .map(|_| ());

        assert_matches!(
            res,
            Err(GroupError::UnsupportedProtocolVersion(v)) if v ==
                TEST_PROTOCOL_VERSION
        );
    }

    #[futures_test::test]
    async fn joining_group_fails_if_cipher_suite_is_not_supported() {
        let res = joining_group_fails_if_unsupported(|config| {
            config
                .0
                .crypto_provider
                .enabled_cipher_suites
                .retain(|&x| x != TEST_CIPHER_SUITE);
        })
        .await
        .map(|_| ());

        assert_matches!(
            res,
            Err(GroupError::UnsupportedCipherSuite(TEST_CIPHER_SUITE))
        );
    }

    #[futures_test::test]
    async fn member_can_see_sender_creds() {
        let mut alice_group = test_group(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE).await;
        let (mut bob_group, _) = alice_group.join("bob").await;

        let bob_msg = b"I'm Bob";

        let msg = bob_group
            .group
            .encrypt_application_message(bob_msg, vec![])
            .await
            .unwrap();

        let received_by_alice = alice_group
            .group
            .process_incoming_message(msg)
            .await
            .unwrap();

        assert_eq!(
            Some(Sender::Member(bob_group.group.current_member_index())),
            received_by_alice.sender
        );
    }

    #[futures_test::test]
    async fn members_of_a_group_have_identical_authentication_secrets() {
        let mut alice_group = test_group(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE).await;
        let (bob_group, _) = alice_group.join("bob").await;

        assert_eq!(
            alice_group.group.epoch_authenticator().unwrap(),
            bob_group.group.epoch_authenticator().unwrap()
        );
    }

    #[futures_test::test]
    async fn member_cannot_decrypt_same_message_twice() {
        let mut alice_group = test_group(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE).await;
        let (mut bob_group, _) = alice_group.join("bob").await;

        let message = alice_group
            .group
            .encrypt_application_message(b"foobar", Vec::new())
            .await
            .unwrap();

        let received_message = bob_group
            .group
            .process_incoming_message(message.clone())
            .await
            .unwrap();

        assert_matches!(
            received_message.event,
            Event::ApplicationMessage(data) if data == b"foobar"
        );

        let res = bob_group.group.process_incoming_message(message).await;

        assert_matches!(
            res,
            Err(GroupError::CiphertextProcessorError(
                CiphertextProcessorError::SecretTreeError(SecretTreeError::KeyMissing(_))
            ))
        );
    }

    #[futures_test::test]
    async fn removing_requirements_allows_to_add() {
        let mut capabilities = get_test_capabilities();
        capabilities.extensions = vec![17.into()];

        let mut alice_group = test_group_custom(
            TEST_PROTOCOL_VERSION,
            TEST_CIPHER_SUITE,
            Some(capabilities),
            None,
            None,
        )
        .await;

        alice_group
            .group
            .commit_builder()
            .set_group_context_ext(
                vec![RequiredCapabilitiesExt {
                    extensions: vec![17.into()],
                    ..Default::default()
                }
                .into_extension()
                .unwrap()]
                .try_into()
                .unwrap(),
            )
            .unwrap()
            .build()
            .await
            .unwrap();

        alice_group.process_pending_commit().await.unwrap();

        let test_key_package = test_key_package_custom(
            &alice_group.group.cipher_suite_provider,
            TEST_PROTOCOL_VERSION,
            "bob",
            |gen| {
                async move {
                    gen.generate(
                        Lifetime::years(1).unwrap(),
                        get_test_capabilities(),
                        Default::default(),
                        Default::default(),
                    )
                    .await
                    .unwrap()
                }
                .boxed()
            },
        )
        .await;

        let test_key_package = MLSMessage::new(
            TEST_PROTOCOL_VERSION,
            MLSMessagePayload::KeyPackage(test_key_package),
        );

        alice_group
            .group
            .commit_builder()
            .add_member(test_key_package)
            .unwrap()
            .set_group_context_ext(Default::default())
            .unwrap()
            .build()
            .await
            .unwrap();

        let state_update = alice_group.process_pending_commit().await.unwrap();

        assert_eq!(
            state_update
                .roster_update
                .added
                .into_iter()
                .map(|m| m.index())
                .collect::<Vec<_>>(),
            vec![1]
        );

        assert_eq!(alice_group.group.roster().len(), 2);
    }

    #[futures_test::test]
    async fn commit_leaf_wrong_source() {
        // RFC, 13.4.2. "The leaf_node_source field MUST be set to commit."
        let mut groups = test_n_member_group(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE, 3).await;

        groups[0].group.commit_modifiers.modify_leaf = |leaf, sk, cp| {
            leaf.leaf_node_source = LeafNodeSource::Update;
            leaf.sign(cp, sk, &(TEST_GROUP, 0).into()).unwrap();
        };

        let commit_output = groups[0].group.commit(vec![]).await.unwrap();

        assert_matches!(
            groups[2]
                .process_message(commit_output.commit_message)
                .await,
            Err(GroupError::UpdatePathValidationError(
                UpdatePathValidationError::LeafNodeValidationError(
                    LeafNodeValidationError::InvalidLeafNodeSource
                )
            ))
        );
    }

    #[futures_test::test]
    async fn commit_leaf_same_hpke_key() {
        // RFC 13.4.2. "Verify that the encryption_key value in the LeafNode is different from the committer's current leaf node"

        let mut groups = test_n_member_group(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE, 3).await;

        // Group 0 starts using fixed key
        groups[0].group.commit_modifiers.modify_leaf = |leaf, sk, cp| {
            leaf.public_key = get_test_25519_key(1u8);
            leaf.sign(cp, sk, &(TEST_GROUP, 0).into()).unwrap();
        };

        let commit_output = groups[0].group.commit(vec![]).await.unwrap();
        groups[0].process_pending_commit().await.unwrap();
        groups[2]
            .process_message(commit_output.commit_message)
            .await
            .unwrap();

        // Group 0 tries to use the fixed key againd
        let commit_output = groups[0].group.commit(vec![]).await.unwrap();

        assert_matches!(
            groups[2]
                .process_message(commit_output.commit_message)
                .await,
            Err(GroupError::UpdatePathValidationError(
                UpdatePathValidationError::SameHpkeKey(LeafIndex(0))
            ))
        );
    }

    #[futures_test::test]
    async fn commit_leaf_duplicate_hpke_key() {
        // RFC 8.3 "Verify that the following fields are unique among the members of the group: `encryption_key`"

        let mut groups = test_n_member_group(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE, 10).await;

        // Group 1 uses the fixed key
        groups[1].group.commit_modifiers.modify_leaf = |leaf, sk, cp| {
            leaf.public_key = get_test_25519_key(1u8);
            leaf.sign(cp, sk, &(TEST_GROUP, 1).into()).unwrap();
        };

        let commit_output = groups
            .get_mut(1)
            .unwrap()
            .group
            .commit(vec![])
            .await
            .unwrap();

        process_commit(&mut groups, commit_output.commit_message, 1).await;

        // Group 0 tries to use the fixed key too
        groups[0].group.commit_modifiers.modify_leaf = |leaf, sk, cp| {
            leaf.public_key = get_test_25519_key(1u8);
            leaf.sign(cp, sk, &(TEST_GROUP, 0).into()).unwrap();
        };

        let commit_output = groups[0].group.commit(vec![]).await.unwrap();

        assert_matches!(
            groups[7]
                .process_message(commit_output.commit_message)
                .await,
            Err(GroupError::RatchetTreeError(
                RatchetTreeError::TreeIndexError(TreeIndexError::DuplicateHpkeKey(_))
            ))
        );
    }

    #[futures_test::test]
    async fn commit_leaf_duplicate_signature_key() {
        // RFC 8.3 "Verify that the following fields are unique among the members of the group: `signature_key`"

        let mut groups = test_n_member_group(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE, 10).await;

        // Group 1 uses the fixed key
        groups[1].group.commit_modifiers.modify_leaf = |leaf, _, cp| {
            let sk = SignatureSecretKey::from(vec![2u8; 32]);
            let pk = cp.signature_key_derive_public(&sk).unwrap();
            leaf.signing_identity.signature_key = pk;
            leaf.sign(cp, &sk, &(TEST_GROUP, 1).into()).unwrap();
        };

        let commit_output = groups
            .get_mut(1)
            .unwrap()
            .group
            .commit(vec![])
            .await
            .unwrap();

        process_commit(&mut groups, commit_output.commit_message, 1).await;

        // Group 0 tries to use the fixed key too
        groups[0].group.commit_modifiers.modify_leaf = |leaf, _, cp| {
            let sk = SignatureSecretKey::from(vec![2u8; 32]);
            let pk = cp.signature_key_derive_public(&sk).unwrap();
            leaf.signing_identity.signature_key = pk;
            leaf.sign(cp, &sk, &(TEST_GROUP, 0).into()).unwrap();
        };

        let commit_output = groups[0].group.commit(vec![]).await.unwrap();

        assert_matches!(
            groups[7]
                .process_message(commit_output.commit_message)
                .await,
            Err(GroupError::RatchetTreeError(
                RatchetTreeError::TreeIndexError(TreeIndexError::DuplicateSignatureKeys(_))
            ))
        );
    }

    #[futures_test::test]
    async fn commit_leaf_incorrect_signature() {
        let mut groups = test_n_member_group(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE, 3).await;

        groups[0].group.commit_modifiers.modify_leaf = |leaf, _, _| {
            leaf.signature[0] ^= 1;
        };

        let commit_output = groups[0].group.commit(vec![]).await.unwrap();

        assert_matches!(
            groups[2]
                .process_message(commit_output.commit_message)
                .await,
            Err(GroupError::UpdatePathValidationError(
                UpdatePathValidationError::LeafNodeValidationError(
                    LeafNodeValidationError::SignatureError(_)
                )
            ))
        );
    }

    #[futures_test::test]
    async fn commit_leaf_not_supporting_used_context_extension() {
        // The new leaf of the committer doesn't support an extension set in group context
        let extension = Extension::new(999.into(), vec![]);

        let mut groups =
            get_test_groups_with_features(3, vec![extension].into(), Default::default()).await;

        groups[0].commit_modifiers.modify_leaf = |leaf, sk, cp| {
            leaf.capabilities = get_test_capabilities();
            leaf.sign(cp, sk, &(TEST_GROUP, 0).into()).unwrap();
        };

        let commit_output = groups[0].commit(vec![]).await.unwrap();
        assert!(groups[1]
            .process_incoming_message(commit_output.commit_message)
            .await
            .is_err());
    }

    #[futures_test::test]
    async fn commit_leaf_not_supporting_used_leaf_extension() {
        // The new leaf of the committer doesn't support an extension set in another leaf
        let extension = Extension::new(999.into(), vec![]);

        let mut groups =
            get_test_groups_with_features(3, Default::default(), vec![extension].into()).await;

        groups[0].commit_modifiers.modify_leaf = |leaf, sk, cp| {
            leaf.capabilities = get_test_capabilities();
            leaf.extensions = ExtensionList::new();
            leaf.sign(cp, sk, &(TEST_GROUP, 0).into()).unwrap();
        };

        let commit_output = groups[0].commit(vec![]).await.unwrap();

        assert!(groups[1]
            .process_incoming_message(commit_output.commit_message)
            .await
            .is_err());
    }

    #[futures_test::test]
    async fn commit_leaf_uses_extension_unsupported_by_another_leaf() {
        // The new leaf of the committer uses an extension unsupported by another leaf
        let mut groups =
            get_test_groups_with_features(3, Default::default(), Default::default()).await;

        groups[0].commit_modifiers.modify_leaf = |leaf, sk, cp| {
            let extensions = [666, 999]
                .into_iter()
                .map(|extension_type| Extension::new(extension_type.into(), vec![]))
                .collect::<Vec<_>>()
                .into();

            leaf.extensions = extensions;
            leaf.capabilities.extensions = vec![666.into(), 999.into()];
            leaf.sign(cp, sk, &(TEST_GROUP, 0).into()).unwrap();
        };

        let commit_output = groups[0].commit(vec![]).await.unwrap();
        assert!(groups[1]
            .process_incoming_message(commit_output.commit_message)
            .await
            .is_err());
    }

    #[futures_test::test]
    async fn commit_leaf_not_supporting_required_extension() {
        // The new leaf of the committer doesn't support an extension required by group context

        let extension = RequiredCapabilitiesExt {
            extensions: vec![999.into()],
            proposals: vec![],
            credentials: vec![],
        };

        let extensions = vec![extension.into_extension().unwrap()];
        let mut groups =
            get_test_groups_with_features(3, extensions.into(), Default::default()).await;

        groups[0].commit_modifiers.modify_leaf = |leaf, sk, cp| {
            leaf.capabilities = Capabilities::default();
            leaf.sign(cp, sk, &(TEST_GROUP, 0).into()).unwrap();
        };

        let commit_output = groups[0].commit(vec![]).await.unwrap();
        assert!(groups[2]
            .process_incoming_message(commit_output.commit_message)
            .await
            .is_err());
    }

    #[futures_test::test]
    async fn commit_leaf_has_unsupported_credential() {
        // The new leaf of the committer has a credential unsupported by another leaf
        let mut groups =
            get_test_groups_with_features(3, Default::default(), Default::default()).await;

        for group in groups.iter_mut() {
            group.config.0.identity_provider.allow_any_custom = true;
        }

        groups[0].commit_modifiers.modify_leaf = |leaf, sk, cp| {
            leaf.signing_identity.credential = Credential::Custom(CustomCredential::new(
                CredentialType::new(43),
                leaf.signing_identity
                    .credential
                    .as_basic()
                    .unwrap()
                    .identifier()
                    .to_vec(),
            ));

            leaf.sign(cp, sk, &(b"TEST GROUP".as_slice(), 0).into())
                .unwrap();
        };

        let commit_output = groups[0].commit(vec![]).await.unwrap();

        assert_matches!(
            groups[2]
                .process_incoming_message(commit_output.commit_message)
                .await,
            Err(GroupError::RatchetTreeError(
                RatchetTreeError::TreeIndexError(
                    TreeIndexError::CredentialTypeOfNewLeafIsUnsupported(_)
                )
            ))
        );
    }

    #[futures_test::test]
    async fn commit_leaf_not_supporting_credential_used_in_another_leaf() {
        // The new leaf of the committer doesn't support another leaf's credential

        let mut groups =
            get_test_groups_with_features(3, Default::default(), Default::default()).await;

        groups[0].commit_modifiers.modify_leaf = |leaf, sk, cp| {
            leaf.capabilities.credentials = vec![2.into()];
            leaf.sign(cp, sk, &(b"TEST GROUP".as_slice(), 0).into())
                .unwrap();
        };

        let commit_output = groups[0].commit(vec![]).await.unwrap();

        assert_matches!(
            groups[2]
                .process_incoming_message(commit_output.commit_message)
                .await,
            Err(GroupError::RatchetTreeError(
                RatchetTreeError::TreeIndexError(
                    TreeIndexError::InUseCredentialTypeUnsupportedByNewLeaf(..)
                )
            ))
        );
    }

    #[futures_test::test]
    async fn commit_leaf_not_supporting_required_credential() {
        // The new leaf of the committer doesn't support a credentia required by group context

        let extension = RequiredCapabilitiesExt {
            extensions: vec![],
            proposals: vec![],
            credentials: vec![1.into()],
        };

        let extensions = vec![extension.into_extension().unwrap()];
        let mut groups =
            get_test_groups_with_features(3, extensions.into(), Default::default()).await;

        groups[0].commit_modifiers.modify_leaf = |leaf, sk, cp| {
            leaf.capabilities.credentials = vec![2.into()];
            leaf.sign(cp, sk, &(b"TEST GROUP".as_slice(), 0).into())
                .unwrap();
        };

        let commit_output = groups[0].commit(vec![]).await.unwrap();

        assert_matches!(
            groups[2]
                .process_incoming_message(commit_output.commit_message)
                .await,
            Err(GroupError::UpdatePathValidationError(
                UpdatePathValidationError::LeafNodeValidationError(
                    LeafNodeValidationError::RequiredCredentialNotFound(_)
                )
            ))
        );
    }

    #[futures_test::test]
    async fn commit_leaf_not_supporting_credential_used_by_external_sender() {
        // The new leaf of the committer doesn't support credential used by an external sender
        let (_, ext_sender_pk) = test_cipher_suite_provider(TEST_CIPHER_SUITE)
            .signature_key_generate()
            .unwrap();

        let ext_sender_id = SigningIdentity {
            signature_key: ext_sender_pk,
            credential: Credential::X509(CertificateChain::from(vec![random_bytes(32)])),
        };

        let ext_senders = ExternalSendersExt::new(vec![ext_sender_id])
            .into_extension()
            .unwrap();

        let mut groups =
            get_test_groups_with_features(3, vec![ext_senders].into(), Default::default()).await;

        // New leaf for group 0 supports only basic credentials (used by the group) but not X509 used by external sender
        groups[0].commit_modifiers.modify_leaf = |leaf, sk, cp| {
            leaf.capabilities.credentials = vec![1.into()];
            leaf.sign(cp, sk, &(TEST_GROUP, 0).into()).unwrap();
        };

        let commit_output = groups[0].commit(vec![]).await.unwrap();

        assert!(groups[2]
            .process_incoming_message(commit_output.commit_message)
            .await
            .is_err());
    }

    /*
     * Edge case paths
     */

    #[futures_test::test]
    async fn committing_degenerate_path_succeeds() {
        let mut groups = test_n_member_group(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE, 10).await;

        groups[0].group.commit_modifiers.modify_tree = |tree: &mut TreeKemPublic| {
            tree.update_node(get_test_25519_key(1u8), 1).unwrap();
            tree.update_node(get_test_25519_key(1u8), 3).unwrap();
        };

        groups[0].group.commit_modifiers.modify_leaf = |leaf, sk, cp| {
            leaf.public_key = get_test_25519_key(1u8);
            leaf.sign(cp, sk, &(TEST_GROUP, 0).into()).unwrap();
        };

        let commit_output = groups[0].group.commit(vec![]).await.unwrap();

        assert!(groups[7]
            .process_message(commit_output.commit_message)
            .await
            .is_ok());
    }

    #[futures_test::test]
    async fn inserting_key_in_filtered_node_fails() {
        let mut groups = test_n_member_group(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE, 10).await;

        let commit_output = groups[0]
            .group
            .commit_builder()
            .remove_member(1)
            .unwrap()
            .build()
            .await
            .unwrap();

        groups[0].process_pending_commit().await.unwrap();

        for group in groups.iter_mut().skip(2) {
            group
                .process_message(commit_output.commit_message.clone())
                .await
                .unwrap();
        }

        groups[0].group.commit_modifiers.modify_tree = |tree: &mut TreeKemPublic| {
            tree.update_node(get_test_25519_key(1u8), 1).unwrap();
        };

        groups[0].group.commit_modifiers.modify_path = |path: Vec<UpdatePathNode>| {
            let mut path = path;
            let mut node = path[0].clone();
            node.public_key = get_test_25519_key(1u8);
            path.insert(0, node);
            path
        };

        let commit_output = groups[0].group.commit(vec![]).await.unwrap();

        // We should get a path validation error, since the path is too long
        assert_matches!(
            groups[7]
                .process_message(commit_output.commit_message)
                .await,
            Err(GroupError::UpdatePathValidationError(_))
        );
    }

    #[futures_test::test]
    async fn commit_with_too_short_path_fails() {
        let mut groups = test_n_member_group(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE, 10).await;

        let commit_output = groups[0]
            .group
            .commit_builder()
            .remove_member(1)
            .unwrap()
            .build()
            .await
            .unwrap();

        groups[0].process_pending_commit().await.unwrap();

        for group in groups.iter_mut().skip(2) {
            group
                .process_message(commit_output.commit_message.clone())
                .await
                .unwrap();
        }

        groups[0].group.commit_modifiers.modify_path = |path: Vec<UpdatePathNode>| {
            let mut path = path;
            path.pop();
            path
        };

        let commit_output = groups[0].group.commit(vec![]).await.unwrap();

        assert!(groups[7]
            .process_message(commit_output.commit_message)
            .await
            .is_err());
    }

    #[futures_test::test]
    async fn update_proposal_can_change_credential() {
        let mut groups = test_n_member_group(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE, 3).await;
        let (identity, secret_key) =
            get_test_signing_identity(TEST_CIPHER_SUITE, b"member".to_vec());

        // Add new identity
        groups[0]
            .group
            .config
            .0
            .keychain
            .insert(identity.clone(), secret_key, TEST_CIPHER_SUITE);

        let update = groups[0]
            .group
            .propose_update_with_identity(identity.clone(), vec![])
            .await
            .unwrap();

        groups[1].process_message(update).await.unwrap();
        let commit_output = groups[1].group.commit(vec![]).await.unwrap();

        // Check that the credential was updated by in the committer's state.
        groups[1].process_pending_commit().await.unwrap();
        let new_member = groups[1].group.roster().first().cloned().unwrap();

        assert_eq!(
            new_member.signing_identity().credential,
            get_test_basic_credential(b"member".to_vec())
        );

        assert_eq!(
            new_member.signing_identity().signature_key,
            identity.signature_key
        );

        // Check that the credential was updated in the updater's state.
        groups[0]
            .process_message(commit_output.commit_message)
            .await
            .unwrap();
        let new_member = groups[0].group.roster().first().cloned().unwrap();

        assert_eq!(
            new_member.signing_identity().credential,
            get_test_basic_credential(b"member".to_vec())
        );

        assert_eq!(
            new_member.signing_identity().signature_key,
            identity.signature_key
        );
    }

    #[futures_test::test]
    async fn receiving_commit_with_old_adds_fails() {
        let mut groups = test_n_member_group(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE, 2).await;

        let key_package =
            test_key_package_message(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE, "foobar").await;

        let proposal = groups[0]
            .group
            .propose_add(key_package, vec![])
            .await
            .unwrap();

        let commit = groups[0].group.commit(vec![]).await.unwrap().commit_message;

        // 10 years from now
        let future_time = MlsTime::now().seconds_since_epoch().unwrap() + 10 * 365 * 24 * 3600;
        let future_time =
            MlsTime::from_duration_since_epoch(Duration::from_secs(future_time)).unwrap();

        groups[1]
            .group
            .process_incoming_message(proposal)
            .await
            .unwrap();
        let res = groups[1]
            .group
            .process_incoming_message_with_time(commit, future_time)
            .await;

        assert_matches!(
            res,
            Err(GroupError::ProposalCacheError(
                ProposalCacheError::ProposalFilterError(
                    ProposalFilterError::KeyPackageValidationError(
                        KeyPackageValidationError::LeafNodeValidationError(
                            LeafNodeValidationError::InvalidLifetime(_, _)
                        )
                    )
                )
            ))
        );
    }

    async fn custom_proposal_setup() -> (TestGroup, TestGroup) {
        let mut alice = test_group_custom_config(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE, |b| {
            b.custom_proposal_type(ProposalType::new(42))
        })
        .await;

        let (bob, _) = alice
            .join_with_custom_config("bob", true, |c| {
                c.0.settings
                    .custom_proposal_types
                    .push(ProposalType::new(42))
            })
            .await
            .unwrap();

        (alice, bob)
    }

    #[futures_test::test]
    async fn custom_proposal_by_value() {
        let (mut alice, mut bob) = custom_proposal_setup().await;

        let custom_proposal = CustomProposal::new(ProposalType::new(42), vec![0, 1, 2]);

        let commit = alice
            .group
            .commit_builder()
            .custom_proposal(custom_proposal.clone())
            .build()
            .await
            .unwrap()
            .commit_message;

        let res = bob.group.process_incoming_message(commit).await.unwrap();

        assert_matches!(res.event, Event::Commit(commit) if commit.custom_proposals == vec![custom_proposal])
    }

    #[futures_test::test]
    async fn custom_proposal_by_reference() {
        let (mut alice, mut bob) = custom_proposal_setup().await;

        let custom_proposal = CustomProposal::new(ProposalType::new(42), vec![0, 1, 2]);

        let proposal = alice
            .group
            .propose_custom(custom_proposal.clone(), vec![])
            .await
            .unwrap();

        let recv_prop = bob.group.process_incoming_message(proposal).await.unwrap();

        assert_matches!(recv_prop.event, Event::Proposal((Proposal::Custom(c), _)) if c == custom_proposal);

        let commit = bob.group.commit(vec![]).await.unwrap().commit_message;
        let res = alice.group.process_incoming_message(commit).await.unwrap();

        assert_matches!(res.event, Event::Commit(commit) if commit.custom_proposals == vec![custom_proposal])
    }
}
