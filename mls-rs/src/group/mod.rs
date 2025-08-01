// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// Copyright by contributors to this project.
// SPDX-License-Identifier: (Apache-2.0 OR MIT)

use alloc::vec;
use alloc::vec::Vec;
use core::fmt::{self, Debug};
use mls_rs_codec::{MlsDecode, MlsEncode, MlsSize};
use mls_rs_core::error::IntoAnyError;
#[cfg(feature = "last_resort_key_package_ext")]
use mls_rs_core::extension::MlsExtension;
use mls_rs_core::identity::MemberValidationContext;
use mls_rs_core::secret::Secret;
use mls_rs_core::time::MlsTime;
use snapshot::PendingCommitSnapshot;

use crate::cipher_suite::CipherSuite;
use crate::client::MlsError;
use crate::client_config::ClientConfig;
use crate::crypto::{HpkeCiphertext, SignatureSecretKey};
#[cfg(feature = "last_resort_key_package_ext")]
use crate::extension::LastResortKeyPackageExt;
use crate::extension::RatchetTreeExt;
use crate::identity::SigningIdentity;
use crate::key_package::{KeyPackage, KeyPackageGeneration, KeyPackageRef};
use crate::protocol_version::ProtocolVersion;
use crate::psk::secret::PskSecret;
use crate::psk::PreSharedKeyID;
use crate::signer::Signable;
use crate::tree_kem::hpke_encryption::HpkeEncryptable;
use crate::tree_kem::kem::TreeKem;
use crate::tree_kem::leaf_node::LeafNode;
use crate::tree_kem::leaf_node_validator::{LeafNodeValidator, ValidationContext};
use crate::tree_kem::node::LeafIndex;
use crate::tree_kem::path_secret::PathSecret;
pub use crate::tree_kem::Capabilities;
use crate::tree_kem::{math as tree_math, ValidatedUpdatePath};
use crate::tree_kem::{TreeKemPrivate, TreeKemPublic};
use crate::{CipherSuiteProvider, CryptoProvider};
pub use state::GroupState;

#[cfg(feature = "by_ref_proposal")]
use crate::crypto::{HpkePublicKey, HpkeSecretKey};

use crate::extension::ExternalPubExt;

use self::message_hash::MessageHash;
#[cfg(feature = "private_message")]
use self::mls_rules::{EncryptionOptions, MlsRules};

#[cfg(feature = "psk")]
pub use self::resumption::ReinitClient;

#[cfg(feature = "psk")]
use crate::psk::{
    resolver::PskResolver, secret::PskSecretInput, ExternalPskId, JustPreSharedKeyID, PskGroupId,
    ResumptionPSKUsage, ResumptionPsk,
};

#[cfg(feature = "private_message")]
use ciphertext_processor::*;

use component_operation::{ComponentID, ComponentOperationLabel};
use confirmation_tag::*;
use framing::*;
use key_schedule::*;
use membership_tag::*;
use message_signature::*;
use message_verifier::*;
use proposal::*;
#[cfg(feature = "by_ref_proposal")]
use proposal_cache::*;
use transcript_hash::*;

#[cfg(test)]
pub(crate) use self::commit::test_utils::CommitModifiers;

#[cfg(all(test, feature = "private_message"))]
pub use self::framing::PrivateMessage;

use self::proposal_filter::ProposalInfo;

#[cfg(any(feature = "secret_tree_access", feature = "private_message"))]
use secret_tree::*;

#[cfg(feature = "prior_epoch")]
use self::epoch::PriorEpoch;

use self::epoch::EpochSecrets;
pub use self::message_processor::{
    ApplicationMessageDescription, CommitEffect, CommitMessageDescription, NewEpoch,
    ProposalMessageDescription, ProposalSender, ReceivedMessage,
};
use self::message_processor::{EventOrContent, MessageProcessor, ProvisionalState};
#[cfg(feature = "by_ref_proposal")]
use self::proposal_ref::ProposalRef;
use self::state_repo::GroupStateRepository;
pub use group_info::GroupInfo;

pub use self::framing::{ContentType, Sender};
pub use commit::*;
pub use mls_rs_core::group::GroupContext;
pub use roster::*;

pub(crate) use mls_rs_core::group::ConfirmedTranscriptHash;
pub(crate) use util::*;

#[cfg(all(feature = "by_ref_proposal", feature = "external_client"))]
pub use self::message_processor::CachedProposal;

#[cfg(feature = "private_message")]
mod ciphertext_processor;

mod commit;
pub mod component_operation;
pub(crate) mod confirmation_tag;
pub(crate) mod epoch;
pub(crate) mod framing;
mod group_info;
pub(crate) mod key_schedule;
mod membership_tag;
pub(crate) mod message_hash;
pub(crate) mod message_processor;
pub(crate) mod message_signature;
pub(crate) mod message_verifier;
pub mod mls_rules;
#[cfg(feature = "private_message")]
pub(crate) mod padding;
/// Proposals to evolve a MLS [`Group`]
pub mod proposal;
mod proposal_cache;
pub(crate) mod proposal_filter;
#[cfg(feature = "by_ref_proposal")]
pub(crate) mod proposal_ref;
#[cfg(feature = "psk")]
mod resumption;
mod roster;
pub(crate) mod snapshot;
pub(crate) mod state;

#[cfg(feature = "prior_epoch")]
pub(crate) mod state_repo;
#[cfg(not(feature = "prior_epoch"))]
pub(crate) mod state_repo_light;
#[cfg(not(feature = "prior_epoch"))]
pub(crate) use state_repo_light as state_repo;

pub(crate) mod transcript_hash;
mod util;

/// External commit building.
pub mod external_commit;

#[cfg(any(feature = "secret_tree_access", feature = "private_message"))]
pub(crate) mod secret_tree;

#[cfg(any(feature = "secret_tree_access", feature = "private_message"))]
pub use secret_tree::MessageKeyData as MessageKey;

#[cfg(all(test, feature = "rfc_compliant"))]
mod interop_test_vectors;

mod exported_tree;

pub use exported_tree::ExportedTree;

#[derive(Clone, Debug, PartialEq, MlsSize, MlsEncode, MlsDecode)]
struct GroupSecrets {
    joiner_secret: JoinerSecret,
    path_secret: Option<PathSecret>,
    psks: Vec<PreSharedKeyID>,
}

impl HpkeEncryptable for GroupSecrets {
    const ENCRYPT_LABEL: &'static str = "Welcome";

    fn from_bytes(bytes: Vec<u8>) -> Result<Self, MlsError> {
        Self::mls_decode(&mut bytes.as_slice()).map_err(Into::into)
    }

    fn get_bytes(&self) -> Result<Vec<u8>, MlsError> {
        self.mls_encode_to_vec().map_err(Into::into)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, MlsSize, MlsEncode, MlsDecode)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub(crate) struct EncryptedGroupSecrets {
    pub new_member: KeyPackageRef,
    pub encrypted_group_secrets: HpkeCiphertext,
}

#[derive(Clone, Eq, PartialEq, MlsSize, MlsEncode, MlsDecode)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub(crate) struct Welcome {
    pub cipher_suite: CipherSuite,
    pub secrets: Vec<EncryptedGroupSecrets>,
    #[mls_codec(with = "mls_rs_codec::byte_vec")]
    pub encrypted_group_info: Vec<u8>,
}

impl Debug for Welcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Welcome")
            .field("cipher_suite", &self.cipher_suite)
            .field("secrets", &self.secrets)
            .field(
                "encrypted_group_info",
                &mls_rs_core::debug::pretty_bytes(&self.encrypted_group_info),
            )
            .finish()
    }
}

#[derive(Clone, Debug)]
#[cfg_attr(
    all(feature = "ffi", not(test)),
    safer_ffi_gen::ffi_type(clone, opaque)
)]
#[non_exhaustive]
/// Information provided to new members upon joining a group.
pub struct NewMemberInfo {
    /// Group info extensions found within the Welcome message used to join
    /// the group.
    pub group_info_extensions: ExtensionList,
    /// The group member who generated the Commit adding the joiner to the
    /// group. This may not be the party who generated the corresponding
    /// add proposal
    pub sender: u32,
}

#[cfg_attr(all(feature = "ffi", not(test)), safer_ffi_gen::safer_ffi_gen)]
impl NewMemberInfo {
    pub(crate) fn new(group_info_extensions: ExtensionList, sender: u32) -> Self {
        let mut new_member_info = Self {
            group_info_extensions,
            sender,
        };

        new_member_info.ungrease();

        new_member_info
    }

    /// Group info extensions found within the Welcome message used to join
    /// the group.
    #[cfg(feature = "ffi")]
    pub fn group_info_extensions(&self) -> &ExtensionList {
        &self.group_info_extensions
    }
}

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
#[cfg_attr(all(feature = "ffi", not(test)), safer_ffi_gen::ffi_type(opaque))]
#[derive(Clone)]
pub struct Group<C>
where
    C: ClientConfig,
{
    config: C,
    cipher_suite_provider: <C::CryptoProvider as CryptoProvider>::CipherSuiteProvider,
    state_repo: GroupStateRepository<C::GroupStateStorage, C::KeyPackageRepository>,
    pub(crate) state: GroupState,
    epoch_secrets: EpochSecrets,
    private_tree: TreeKemPrivate,
    key_schedule: KeySchedule,
    #[cfg(feature = "by_ref_proposal")]
    pending_updates:
        crate::map::SmallMap<HpkePublicKey, (HpkeSecretKey, Option<SignatureSecretKey>)>,
    pending_commit: PendingCommitSnapshot,
    #[cfg(feature = "psk")]
    previous_psk: Option<PskSecretInput>,
    #[cfg(test)]
    pub(crate) commit_modifiers: CommitModifiers,
    pub(crate) signer: SignatureSecretKey,
}

#[cfg_attr(all(feature = "ffi", not(test)), safer_ffi_gen::safer_ffi_gen)]
impl<C> Group<C>
where
    C: ClientConfig + Clone,
{
    #[allow(clippy::too_many_arguments)]
    #[cfg_attr(not(mls_build_async), maybe_async::must_be_sync)]
    pub(crate) async fn new(
        config: C,
        group_id: Option<Vec<u8>>,
        cipher_suite: CipherSuite,
        protocol_version: ProtocolVersion,
        signing_identity: SigningIdentity,
        group_context_extensions: ExtensionList,
        leaf_node_extensions: ExtensionList,
        signer: SignatureSecretKey,
        maybe_now_time: Option<MlsTime>,
    ) -> Result<Self, MlsError> {
        let cipher_suite_provider = cipher_suite_provider(config.crypto_provider(), cipher_suite)?;

        let (leaf_node, leaf_node_secret) = LeafNode::generate(
            &cipher_suite_provider,
            config.leaf_properties(leaf_node_extensions),
            signing_identity,
            &signer,
            config.lifetime(maybe_now_time),
        )
        .await?;

        let (mut public_tree, private_tree) = TreeKemPublic::derive(
            leaf_node,
            leaf_node_secret,
            &config.identity_provider(),
            &group_context_extensions,
        )
        .await?;

        let tree_hash = public_tree.tree_hash(&cipher_suite_provider).await?;

        let group_id = group_id.map(Ok).unwrap_or_else(|| {
            cipher_suite_provider
                .random_bytes_vec(cipher_suite_provider.kdf_extract_size())
                .map_err(|e| MlsError::CryptoProviderError(e.into_any_error()))
        })?;

        let context = GroupContext::new(
            protocol_version,
            cipher_suite,
            group_id,
            tree_hash,
            group_context_extensions,
        );

        let identity_provider = config.identity_provider();

        let member_validation_context = MemberValidationContext::ForNewGroup {
            current_context: &context,
        };

        let leaf_node_validator = LeafNodeValidator::new(
            &cipher_suite_provider,
            &identity_provider,
            member_validation_context,
        );

        leaf_node_validator
            .check_if_valid(
                public_tree.get_leaf_node(LeafIndex::unchecked(0))?,
                ValidationContext::Add(maybe_now_time),
            )
            .await?;

        let state_repo = GroupStateRepository::new(
            #[cfg(feature = "prior_epoch")]
            context.group_id.clone(),
            config.group_state_storage(),
            config.key_package_repo(),
            None,
        )?;

        let key_schedule_result = KeySchedule::from_random_epoch_secret(
            &cipher_suite_provider,
            #[cfg(any(feature = "secret_tree_access", feature = "private_message"))]
            public_tree.total_leaf_count(),
        )
        .await?;

        let confirmation_tag = ConfirmationTag::create(
            &key_schedule_result.confirmation_key,
            &vec![].into(),
            &cipher_suite_provider,
        )
        .await?;

        let interim_hash = InterimTranscriptHash::create(
            &cipher_suite_provider,
            &vec![].into(),
            &confirmation_tag,
        )
        .await?;

        Ok(Self {
            config,
            state: GroupState::new(context, public_tree, interim_hash, confirmation_tag),
            private_tree,
            key_schedule: key_schedule_result.key_schedule,
            #[cfg(feature = "by_ref_proposal")]
            pending_updates: Default::default(),
            pending_commit: Default::default(),
            #[cfg(test)]
            commit_modifiers: Default::default(),
            epoch_secrets: key_schedule_result.epoch_secrets,
            state_repo,
            cipher_suite_provider,
            #[cfg(feature = "psk")]
            previous_psk: None,
            signer,
        })
    }

    #[cfg_attr(not(mls_build_async), maybe_async::must_be_sync)]
    pub(crate) async fn join(
        welcome: &MlsMessage,
        tree_data: Option<ExportedTree<'_>>,
        config: C,
        signer: SignatureSecretKey,
        maybe_time: Option<MlsTime>,
    ) -> Result<(Self, NewMemberInfo), MlsError> {
        Self::from_welcome_message(
            welcome,
            tree_data,
            config,
            signer,
            #[cfg(feature = "psk")]
            None,
            maybe_time,
        )
        .await
    }

    #[cfg_attr(not(mls_build_async), maybe_async::must_be_sync)]
    async fn from_welcome_message(
        welcome: &MlsMessage,
        tree_data: Option<ExportedTree<'_>>,
        config: C,
        signer: SignatureSecretKey,
        #[cfg(feature = "psk")] additional_psk: Option<PskSecretInput>,
        maybe_time: Option<MlsTime>,
    ) -> Result<(Self, NewMemberInfo), MlsError> {
        let (group_info, key_package_generation, group_secrets, psk_secret) =
            Self::decrypt_group_info_internal(
                welcome,
                &config,
                #[cfg(feature = "psk")]
                additional_psk,
            )
            .await?;

        let cipher_suite_provider = cipher_suite_provider(
            config.crypto_provider(),
            group_info.group_context.cipher_suite,
        )?;

        let id_provider = config.identity_provider();

        let public_tree = validate_tree_and_info_joiner(
            welcome.version,
            &group_info,
            tree_data,
            &id_provider,
            &cipher_suite_provider,
            maybe_time,
        )
        .await?;

        let key_package = key_package_generation.key_package;

        // Identify a leaf in the tree array (any even-numbered node) whose leaf_node is identical
        // to the leaf_node field of the KeyPackage. If no such field exists, return an error. Let
        // index represent the index of this node among the leaves in the tree, namely the index of
        // the node in the tree array divided by two.
        let self_index = public_tree
            .find_leaf_node(&key_package.leaf_node)
            .ok_or(MlsError::WelcomeKeyPackageNotFound)?;

        #[cfg(not(feature = "last_resort_key_package_ext"))]
        let is_last_resort = false;
        #[cfg(feature = "last_resort_key_package_ext")]
        let is_last_resort = key_package
            .extensions
            .has_extension(LastResortKeyPackageExt::extension_type());
        // Delete the key just used if this is not a last-resort key package.
        let used_key_package_ref = (!is_last_resort).then_some(key_package_generation.reference);

        let mut private_tree =
            TreeKemPrivate::new_self_leaf(self_index, key_package_generation.leaf_node_secret_key);

        // If the path_secret value is set in the GroupSecrets object
        if let Some(path_secret) = group_secrets.path_secret {
            private_tree
                .update_secrets(
                    &cipher_suite_provider,
                    group_info.signer,
                    path_secret,
                    &public_tree,
                )
                .await?;
        }

        // Use the joiner_secret from the GroupSecrets object to generate the epoch secret and
        // other derived secrets for the current epoch.
        let key_schedule_result = KeySchedule::from_joiner(
            &cipher_suite_provider,
            &group_secrets.joiner_secret,
            &group_info.group_context,
            #[cfg(any(feature = "secret_tree_access", feature = "private_message"))]
            public_tree.total_leaf_count(),
            &psk_secret,
        )
        .await?;

        // Verify the confirmation tag in the GroupInfo using the derived confirmation key and the
        // confirmed_transcript_hash from the GroupInfo.
        if !group_info
            .confirmation_tag
            .matches(
                &key_schedule_result.confirmation_key,
                &group_info.group_context.confirmed_transcript_hash,
                &cipher_suite_provider,
            )
            .await?
        {
            return Err(MlsError::InvalidConfirmationTag);
        }

        Self::join_with(
            config,
            group_info,
            public_tree,
            key_schedule_result.key_schedule,
            key_schedule_result.epoch_secrets,
            private_tree,
            used_key_package_ref,
            signer,
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    #[cfg_attr(not(mls_build_async), maybe_async::must_be_sync)]
    async fn join_with(
        config: C,
        group_info: GroupInfo,
        public_tree: TreeKemPublic,
        key_schedule: KeySchedule,
        epoch_secrets: EpochSecrets,
        private_tree: TreeKemPrivate,
        used_key_package_ref: Option<KeyPackageRef>,
        signer: SignatureSecretKey,
    ) -> Result<(Self, NewMemberInfo), MlsError> {
        let cs = group_info.group_context.cipher_suite;

        let cs = config
            .crypto_provider()
            .cipher_suite_provider(cs)
            .ok_or(MlsError::UnsupportedCipherSuite(cs))?;

        // Use the confirmed transcript hash and confirmation tag to compute the interim transcript
        // hash in the new state.
        let interim_transcript_hash = InterimTranscriptHash::create(
            &cs,
            &group_info.group_context.confirmed_transcript_hash,
            &group_info.confirmation_tag,
        )
        .await?;

        let state_repo = GroupStateRepository::new(
            #[cfg(feature = "prior_epoch")]
            group_info.group_context.group_id.clone(),
            config.group_state_storage(),
            config.key_package_repo(),
            used_key_package_ref,
        )?;

        let group = Group {
            config,
            state: GroupState::new(
                group_info.group_context,
                public_tree,
                interim_transcript_hash,
                group_info.confirmation_tag,
            ),
            private_tree,
            key_schedule,
            #[cfg(feature = "by_ref_proposal")]
            pending_updates: Default::default(),
            pending_commit: Default::default(),
            #[cfg(test)]
            commit_modifiers: Default::default(),
            epoch_secrets,
            state_repo,
            cipher_suite_provider: cs,
            #[cfg(feature = "psk")]
            previous_psk: None,
            signer,
        };

        Ok((
            group,
            NewMemberInfo::new(group_info.extensions, *group_info.signer),
        ))
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

    #[cfg_attr(not(mls_build_async), maybe_async::must_be_sync)]
    async fn hpke_encrypt_to_recipient_with_generic_context(
        &self,
        recipient_index: u32,
        context_info: &[u8],
        associated_data: Option<&[u8]>,
        plaintext: &[u8],
    ) -> Result<HpkeCiphertext, MlsError> {
        let member_leaf_node = self
            .group_state()
            .public_tree
            .get_leaf_node(LeafIndex::try_from(recipient_index)?)?;
        let member_public_key = &member_leaf_node.public_key;
        let hpke_ciphertext = self
            .cipher_suite_provider
            .hpke_seal(member_public_key, context_info, associated_data, plaintext)
            .await
            .map_err(|e| MlsError::CryptoProviderError(e.into_any_error()))?;
        Ok(hpke_ciphertext)
    }

    /// HPKE encrypts a message to the member at the specified `recipient_index` in the group.
    ///
    /// Takes `context_info`, `associated_data`, and `plaintext`.
    /// Returns `ciphertext` and `kem_output` inside `HpkeCiphertext`.
    ///
    /// WARNING: The message sender is not authenticated.
    #[cfg(feature = "non_domain_separated_hpke_encrypt_decrypt")]
    #[cfg_attr(not(mls_build_async), maybe_async::must_be_sync)]
    #[cfg_attr(feature = "ffi", safer_ffi_gen::safer_ffi_gen_ignore)]
    pub async fn hpke_encrypt_to_recipient(
        &self,
        recipient_index: u32,
        context_info: &[u8],
        associated_data: Option<&[u8]>,
        plaintext: &[u8],
    ) -> Result<HpkeCiphertext, MlsError> {
        self.hpke_encrypt_to_recipient_with_generic_context(
            recipient_index,
            context_info,
            associated_data,
            plaintext,
        )
        .await
    }

    /// HPKE encrypts a message to the member at the specified `recipient_index` in the group.
    ///
    /// Takes a `component_id` and `context` to construct a `ComponentOperationLabel`, to be used as
    /// the HPKE seal context, to ensure domain separation.
    /// Also takes an `associated_data` and `plaintext`.
    /// Returns `ciphertext` and `kem_output` inside `HpkeCiphertext`.
    #[cfg_attr(not(mls_build_async), maybe_async::must_be_sync)]
    pub async fn safe_encrypt_with_context_to_recipient(
        &self,
        recipient_index: u32,
        component_id: ComponentID,
        context: &[u8],
        associated_data: Option<&[u8]>,
        plaintext: &[u8],
    ) -> Result<HpkeCiphertext, MlsError> {
        let component_operation_label = ComponentOperationLabel::new(component_id, context);
        self.hpke_encrypt_to_recipient_with_generic_context(
            recipient_index,
            &component_operation_label.get_bytes()?,
            associated_data,
            plaintext,
        )
        .await
    }

    #[cfg_attr(not(mls_build_async), maybe_async::must_be_sync)]
    async fn hpke_decrypt_for_current_member_with_generic_context(
        &self,
        context_info: &[u8],
        associated_data: Option<&[u8]>,
        hpke_ciphertext: HpkeCiphertext,
    ) -> Result<Vec<u8>, MlsError> {
        let self_private_key = &self.private_tree.secret_keys[0]
            .as_ref()
            .ok_or(MlsError::InvalidTreeKemPrivateKey)?;
        let self_public_key = &self.current_user_leaf_node()?.public_key;
        let plaintext = self
            .cipher_suite_provider
            .hpke_open(
                &hpke_ciphertext,
                self_private_key,
                self_public_key,
                context_info,
                associated_data,
            )
            .await
            .map_err(|e| MlsError::CryptoProviderError(e.into_any_error()))?;
        Ok(plaintext)
    }

    /// HPKE decrypts a message sent to the current member.
    ///
    /// Takes `HpkeCiphertext` generated by `hpke_encrypt_to_recipient` intended for the
    /// current member.
    ///
    /// WARNING: The message sender is not authenticated.
    #[cfg(feature = "non_domain_separated_hpke_encrypt_decrypt")]
    #[cfg_attr(not(mls_build_async), maybe_async::must_be_sync)]
    #[cfg_attr(feature = "ffi", safer_ffi_gen::safer_ffi_gen_ignore)]
    pub async fn hpke_decrypt_for_current_member(
        &self,
        context_info: &[u8],
        associated_data: Option<&[u8]>,
        hpke_ciphertext: HpkeCiphertext,
    ) -> Result<Vec<u8>, MlsError> {
        self.hpke_decrypt_for_current_member_with_generic_context(
            context_info,
            associated_data,
            hpke_ciphertext,
        )
        .await
    }

    /// HPKE decrypts a message sent to the current member.
    ///
    /// Takes `HpkeCiphertext` generated by `hpke_encrypt_to_recipient` intended for the
    /// current member.
    #[cfg_attr(not(mls_build_async), maybe_async::must_be_sync)]
    pub async fn safe_decrypt_with_context_for_current_member(
        &self,
        component_id: ComponentID,
        context: &[u8],
        associated_data: Option<&[u8]>,
        hpke_ciphertext: HpkeCiphertext,
    ) -> Result<Vec<u8>, MlsError> {
        let component_operation_label = ComponentOperationLabel::new(component_id, context);
        self.hpke_decrypt_for_current_member_with_generic_context(
            &component_operation_label.get_bytes()?,
            associated_data,
            hpke_ciphertext,
        )
        .await
    }

    /// Index within the group's state for the local group instance.
    ///
    /// This index corresponds to indexes in content descriptions within
    /// [`ReceivedMessage`].
    #[inline(always)]
    pub fn current_member_index(&self) -> u32 {
        *self.current_member_leaf_index()
    }

    #[inline(always)]
    fn current_member_leaf_index(&self) -> LeafIndex {
        self.private_tree.self_index
    }

    fn current_user_leaf_node(&self) -> Result<&LeafNode, MlsError> {
        self.current_epoch_tree()
            .get_leaf_node(self.private_tree.self_index)
    }

    /// Signing identity currently in use by the local group instance.
    #[cfg_attr(all(feature = "ffi", not(test)), safer_ffi_gen::safer_ffi_gen_ignore)]
    pub fn current_member_signing_identity(&self) -> Result<&SigningIdentity, MlsError> {
        self.current_user_leaf_node().map(|ln| &ln.signing_identity)
    }

    /// Member at a specific index in the group state.
    ///
    /// These indexes correspond to indexes in content descriptions within
    /// [`ReceivedMessage`].
    pub fn member_at_index(&self, index: u32) -> Option<Member> {
        self.group_state().member_at_index(index)
    }

    #[cfg(feature = "by_ref_proposal")]
    #[cfg_attr(not(mls_build_async), maybe_async::must_be_sync)]
    async fn proposal_message(
        &mut self,
        proposal: Proposal,
        authenticated_data: Vec<u8>,
    ) -> Result<MlsMessage, MlsError> {
        let sender = Sender::Member(*self.private_tree.self_index);

        let auth_content = AuthenticatedContent::new_signed(
            &self.cipher_suite_provider,
            self.context(),
            sender,
            Content::Proposal(alloc::boxed::Box::new(proposal.clone())),
            &self.signer,
            #[cfg(feature = "private_message")]
            self.encryption_options()?.control_wire_format(sender),
            #[cfg(not(feature = "private_message"))]
            WireFormat::PublicMessage,
            authenticated_data,
        )
        .await?;

        let sender = auth_content.content.sender;

        let proposal_desc =
            ProposalMessageDescription::new(&self.cipher_suite_provider, &auth_content, proposal)
                .await?;

        let message = self.format_for_wire(auth_content).await?;

        self.state
            .proposals
            .insert_own(proposal_desc, &message, sender, &self.cipher_suite_provider)
            .await?;

        Ok(message)
    }

    /// Unique identifier for this group.
    pub fn group_id(&self) -> &[u8] {
        &self.context().group_id
    }

    fn provisional_private_tree(
        &self,
        provisional_state: &ProvisionalState,
    ) -> Result<(TreeKemPrivate, Option<SignatureSecretKey>), MlsError> {
        let mut provisional_private_tree = self.private_tree.clone();
        let self_index = provisional_private_tree.self_index;

        // Remove secret keys for blanked nodes
        let path = provisional_state
            .public_tree
            .nodes
            .direct_copath(self_index);

        provisional_private_tree
            .secret_keys
            .resize(path.len() + 1, None);

        for (i, n) in path.iter().enumerate() {
            if provisional_state.public_tree.nodes.is_blank(n.path)? {
                provisional_private_tree.secret_keys[i + 1] = None;
            }
        }

        // Apply own update
        let new_signer = None;

        #[cfg(feature = "by_ref_proposal")]
        let mut new_signer = new_signer;

        #[cfg(feature = "by_ref_proposal")]
        for p in &provisional_state.applied_proposals.updates {
            if p.sender == Sender::Member(*self_index) {
                let leaf_pk = &p.proposal.leaf_node.public_key;

                // Update the leaf in the private tree if this is our update
                #[cfg(feature = "std")]
                let new_leaf_sk_and_signer = self.pending_updates.get(leaf_pk);

                #[cfg(not(feature = "std"))]
                let new_leaf_sk_and_signer = self
                    .pending_updates
                    .iter()
                    .find_map(|(pk, sk)| (pk == leaf_pk).then_some(sk));

                let new_leaf_sk = new_leaf_sk_and_signer.map(|(sk, _)| sk.clone());
                new_signer = new_leaf_sk_and_signer.and_then(|(_, sk)| sk.clone());

                provisional_private_tree
                    .update_leaf(new_leaf_sk.ok_or(MlsError::UpdateErrorNoSecretKey)?);

                break;
            }
        }

        Ok((provisional_private_tree, new_signer))
    }

    #[cfg_attr(not(mls_build_async), maybe_async::must_be_sync)]
    async fn encrypt_group_secrets(
        &self,
        key_package: &KeyPackage,
        leaf_index: LeafIndex,
        joiner_secret: &JoinerSecret,
        path_secrets: Option<&Vec<Option<PathSecret>>>,
        #[cfg(feature = "psk")] psks: Vec<PreSharedKeyID>,
        encrypted_group_info: &[u8],
    ) -> Result<EncryptedGroupSecrets, MlsError> {
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
                    .ok_or(MlsError::InvalidTreeKemPrivateKey)
            })
            .transpose()?;

        #[cfg(not(feature = "psk"))]
        let psks = Vec::new();

        let group_secrets = GroupSecrets {
            joiner_secret: joiner_secret.clone(),
            path_secret,
            psks,
        };

        let encrypted_group_secrets = group_secrets
            .encrypt(
                &self.cipher_suite_provider,
                &key_package.hpke_init_key,
                encrypted_group_info,
            )
            .await?;

        Ok(EncryptedGroupSecrets {
            new_member: key_package
                .to_reference(&self.cipher_suite_provider)
                .await?,
            encrypted_group_secrets,
        })
    }

    /// Create a proposal message that adds a new member to the group.
    ///
    /// `authenticated_data` will be sent unencrypted along with the contents
    /// of the proposal message.
    #[cfg(feature = "by_ref_proposal")]
    #[cfg_attr(not(mls_build_async), maybe_async::must_be_sync)]
    pub async fn propose_add(
        &mut self,
        key_package: MlsMessage,
        authenticated_data: Vec<u8>,
    ) -> Result<MlsMessage, MlsError> {
        let proposal = self.add_proposal(key_package)?;
        self.proposal_message(proposal, authenticated_data).await
    }

    fn add_proposal(&self, key_package: MlsMessage) -> Result<Proposal, MlsError> {
        Ok(Proposal::Add(alloc::boxed::Box::new(AddProposal {
            key_package: key_package
                .into_key_package()
                .ok_or(MlsError::UnexpectedMessageType)?,
        })))
    }

    /// Create a proposal message that updates your own public keys.
    ///
    /// This proposal is useful for contributing additional forward secrecy
    /// and post-compromise security to the group without having to perform
    /// the necessary computation of a [`Group::commit`].
    ///
    /// `authenticated_data` will be sent unencrypted along with the contents
    /// of the proposal message.
    #[cfg(feature = "by_ref_proposal")]
    #[cfg_attr(not(mls_build_async), maybe_async::must_be_sync)]
    pub async fn propose_update(
        &mut self,
        authenticated_data: Vec<u8>,
    ) -> Result<MlsMessage, MlsError> {
        let proposal = self.update_proposal(None, None, None).await?;
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
    /// [valid](crate::IdentityProvider::validate_member)
    /// by and matches the output of the
    /// [identity](crate::IdentityProvider)
    /// function of the current
    /// [`IdentityProvider`](crate::IdentityProvider).
    ///
    /// `authenticated_data` will be sent unencrypted along with the contents
    /// of the proposal message.
    #[cfg(feature = "by_ref_proposal")]
    #[cfg_attr(not(mls_build_async), maybe_async::must_be_sync)]
    pub async fn propose_update_with_identity(
        &mut self,
        signer: SignatureSecretKey,
        signing_identity: SigningIdentity,
        authenticated_data: Vec<u8>,
    ) -> Result<MlsMessage, MlsError> {
        let proposal = self
            .update_proposal(Some(signer), Some(signing_identity), None)
            .await?;

        self.proposal_message(proposal, authenticated_data).await
    }

    #[cfg(feature = "by_ref_proposal")]
    #[cfg_attr(not(mls_build_async), maybe_async::must_be_sync)]
    async fn update_proposal(
        &mut self,
        signer: Option<SignatureSecretKey>,
        signing_identity: Option<SigningIdentity>,
        leaf_node_extensions: Option<ExtensionList>,
    ) -> Result<Proposal, MlsError> {
        // Grab a copy of the current node and update it to have new key material
        let mut new_leaf_node: LeafNode = self.current_user_leaf_node()?.clone();

        let new_leaf_node_extensions =
            leaf_node_extensions.unwrap_or(new_leaf_node.ungreased_extensions());
        let secret_key = new_leaf_node
            .update(
                &self.cipher_suite_provider,
                self.group_id(),
                self.current_member_index(),
                Some(self.config.leaf_properties(new_leaf_node_extensions)),
                signing_identity,
                signer.as_ref().unwrap_or(&self.signer),
            )
            .await?;

        // Store the secret key in the pending updates storage for later
        #[cfg(feature = "std")]
        self.pending_updates
            .insert(new_leaf_node.public_key.clone(), (secret_key, signer));

        #[cfg(not(feature = "std"))]
        self.pending_updates
            .push((new_leaf_node.public_key.clone(), (secret_key, signer)));

        Ok(Proposal::Update(UpdateProposal {
            leaf_node: new_leaf_node,
        }))
    }

    /// Create a proposal message that removes an existing member from the
    /// group.
    ///
    /// `authenticated_data` will be sent unencrypted along with the contents
    /// of the proposal message.
    #[cfg(feature = "by_ref_proposal")]
    #[cfg_attr(not(mls_build_async), maybe_async::must_be_sync)]
    pub async fn propose_remove(
        &mut self,
        index: u32,
        authenticated_data: Vec<u8>,
    ) -> Result<MlsMessage, MlsError> {
        let proposal = self.remove_proposal(index)?;
        self.proposal_message(proposal, authenticated_data).await
    }

    fn remove_proposal(&self, index: u32) -> Result<Proposal, MlsError> {
        let leaf_index = LeafIndex::try_from(index)?;

        // Verify that this leaf is actually in the tree
        self.current_epoch_tree().get_leaf_node(leaf_index)?;

        Ok(Proposal::Remove(RemoveProposal {
            to_remove: leaf_index,
        }))
    }

    #[cfg(all(
        feature = "by_ref_proposal",
        feature = "custom_proposal",
        feature = "self_remove_proposal"
    ))]
    #[cfg_attr(feature = "ffi", safer_ffi_gen::safer_ffi_gen_ignore)]
    #[cfg_attr(not(mls_build_async), maybe_async::must_be_sync)]
    pub async fn propose_self_remove(
        &mut self,
        authenticated_data: Vec<u8>,
    ) -> Result<MlsMessage, MlsError> {
        if self.state.proposals.has_own_self_remove() {
            return Err(MlsError::SelfRemoveAlreadyProposed);
        }
        let proposal = Proposal::SelfRemove(SelfRemoveProposal {});
        self.proposal_message(proposal, authenticated_data).await
    }

    /// Create a proposal message that adds an external pre shared key to the group.
    ///
    /// Each group member will need to have the PSK associated with
    /// [`ExternalPskId`](mls_rs_core::psk::ExternalPskId) installed within
    /// the [`PreSharedKeyStorage`](mls_rs_core::psk::PreSharedKeyStorage)
    /// in use by this group upon processing a [commit](Group::commit) that
    /// contains this proposal.
    ///
    /// `authenticated_data` will be sent unencrypted along with the contents
    /// of the proposal message.
    #[cfg(all(feature = "by_ref_proposal", feature = "psk"))]
    #[cfg_attr(not(mls_build_async), maybe_async::must_be_sync)]
    pub async fn propose_external_psk(
        &mut self,
        psk: ExternalPskId,
        authenticated_data: Vec<u8>,
    ) -> Result<MlsMessage, MlsError> {
        let proposal = self.psk_proposal(JustPreSharedKeyID::External(psk))?;
        self.proposal_message(proposal, authenticated_data).await
    }

    #[cfg(feature = "psk")]
    fn psk_proposal(&self, key_id: JustPreSharedKeyID) -> Result<Proposal, MlsError> {
        Ok(Proposal::Psk(PreSharedKeyProposal {
            psk: PreSharedKeyID::new(key_id, &self.cipher_suite_provider)?,
        }))
    }

    /// Create a proposal message that adds a pre shared key from a previous
    /// epoch to the current group state.
    ///
    /// Each group member will need to have the secret state from `psk_epoch`.
    /// In particular, the members who joined between `psk_epoch` and the
    /// current epoch cannot process a commit containing this proposal.
    ///
    /// `authenticated_data` will be sent unencrypted along with the contents
    /// of the proposal message.
    #[cfg(all(feature = "by_ref_proposal", feature = "psk"))]
    #[cfg_attr(not(mls_build_async), maybe_async::must_be_sync)]
    pub async fn propose_resumption_psk(
        &mut self,
        psk_epoch: u64,
        authenticated_data: Vec<u8>,
    ) -> Result<MlsMessage, MlsError> {
        let key_id = ResumptionPsk {
            psk_epoch,
            usage: ResumptionPSKUsage::Application,
            psk_group_id: PskGroupId(self.group_id().to_vec()),
        };

        let proposal = self.psk_proposal(JustPreSharedKeyID::Resumption(key_id))?;
        self.proposal_message(proposal, authenticated_data).await
    }

    /// Create a proposal message that requests for this group to be
    /// reinitialized.
    ///
    /// Once a [`ReInitProposal`](proposal::ReInitProposal)
    /// has been sent, another group member can complete reinitialization of
    /// the group by calling [`Group::get_reinit_client`].
    ///
    /// `authenticated_data` will be sent unencrypted along with the contents
    /// of the proposal message.
    #[cfg(feature = "by_ref_proposal")]
    #[cfg_attr(not(mls_build_async), maybe_async::must_be_sync)]
    pub async fn propose_reinit(
        &mut self,
        group_id: Option<Vec<u8>>,
        version: ProtocolVersion,
        cipher_suite: CipherSuite,
        extensions: ExtensionList,
        authenticated_data: Vec<u8>,
    ) -> Result<MlsMessage, MlsError> {
        let proposal = self.reinit_proposal(group_id, version, cipher_suite, extensions)?;
        self.proposal_message(proposal, authenticated_data).await
    }

    fn reinit_proposal(
        &self,
        group_id: Option<Vec<u8>>,
        version: ProtocolVersion,
        cipher_suite: CipherSuite,
        extensions: ExtensionList,
    ) -> Result<Proposal, MlsError> {
        let group_id = group_id.map(Ok).unwrap_or_else(|| {
            self.cipher_suite_provider
                .random_bytes_vec(self.cipher_suite_provider.kdf_extract_size())
                .map_err(|e| MlsError::CryptoProviderError(e.into_any_error()))
        })?;

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
    #[cfg(feature = "by_ref_proposal")]
    #[cfg_attr(not(mls_build_async), maybe_async::must_be_sync)]
    pub async fn propose_group_context_extensions(
        &mut self,
        extensions: ExtensionList,
        authenticated_data: Vec<u8>,
    ) -> Result<MlsMessage, MlsError> {
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
    #[cfg(all(feature = "custom_proposal", feature = "by_ref_proposal"))]
    #[cfg_attr(not(mls_build_async), maybe_async::must_be_sync)]
    pub async fn propose_custom(
        &mut self,
        proposal: CustomProposal,
        authenticated_data: Vec<u8>,
    ) -> Result<MlsMessage, MlsError> {
        self.proposal_message(Proposal::Custom(proposal), authenticated_data)
            .await
    }

    /// Validate a custom proposal message, verifying its signature and membership
    /// tag. Can be a proposal from the current or a prior epoch.
    /// Can also pass in a ProposalType to check the custom proposal against.
    /// Returns the `authenticated_data` and sender of the custom proposal, or an error if
    /// it fails to validate or if the message is not a custom proposal.
    ///
    /// WARNING: This API is not recommend for general purpose usage as it reduces the guarantees of RFC9420.
    /// Since prior epochs' membership keys are stored, an attacker that compromises a client's signature key
    /// and membership key is able to send valid MLS PublicMessages appearing to originate from the compromised
    /// client from prior epochs.
    /// This API is used by the GSMA's Rich Communication Suite for certain types of messages. See section 7.6
    /// for specifics https://www.gsma.com/solutions-and-impact/technologies/networks/wp-content/uploads/2025/03/RCC.16-v1.0.pdf.
    #[cfg(all(
        feature = "custom_proposal",
        feature = "by_ref_proposal",
        feature = "prior_epoch_membership_key"
    ))]
    #[cfg_attr(feature = "ffi", safer_ffi_gen::safer_ffi_gen_ignore)]
    #[cfg_attr(not(mls_build_async), maybe_async::must_be_sync)]
    pub async fn validate_custom_proposal(
        &mut self,
        msg: &MlsMessage,
        proposal_type: Option<ProposalType>,
    ) -> Result<(Vec<u8>, Sender), MlsError> {
        let auth_content = self.validate_public_message(msg).await?;
        let proposal = match auth_content.content.content {
            Content::Proposal(p) => match *p {
                Proposal::Custom(c) => c,
                _ => return Err(MlsError::UnexpectedMessageType),
            },
            _ => return Err(MlsError::UnexpectedMessageType),
        };
        if proposal_type.is_some() && Some(proposal.proposal_type()) != proposal_type {
            return Err(MlsError::UnsupportedCustomProposal(
                proposal.proposal_type(),
            ));
        }
        Ok((
            auth_content.content.authenticated_data,
            auth_content.content.sender,
        ))
    }

    // Only used for custom proposals right now; consider removing this feature flag
    // if there are future use cases.
    #[cfg(all(feature = "custom_proposal", feature = "prior_epoch_membership_key"))]
    #[cfg_attr(feature = "ffi", safer_ffi_gen::safer_ffi_gen_ignore)]
    #[cfg_attr(not(mls_build_async), maybe_async::must_be_sync)]
    async fn validate_public_message(
        &mut self,
        msg: &MlsMessage,
    ) -> Result<AuthenticatedContent, MlsError> {
        let plaintext = match msg.payload {
            MlsMessagePayload::Plain(ref plaintext) => plaintext.clone(),
            _ => return Err(MlsError::UnexpectedMessageType),
        };
        let epoch_id = msg.epoch().ok_or(MlsError::EpochNotFound)?;
        let auth_content = if epoch_id == self.context().epoch {
            let auth_content = verify_plaintext_authentication(
                &self.cipher_suite_provider,
                plaintext,
                Some(&self.key_schedule.membership_key),
                &self.state.context,
                SignaturePublicKeysContainer::RatchetTree(&self.state.public_tree),
            )
            .await?;

            Ok::<_, MlsError>(auth_content)
        } else {
            #[cfg(feature = "prior_epoch")]
            {
                let epoch = self
                    .state_repo
                    .get_epoch_mut(epoch_id)
                    .await?
                    .ok_or(MlsError::EpochNotFound)?;

                let auth_content = verify_plaintext_authentication(
                    &self.cipher_suite_provider,
                    plaintext,
                    Some(&epoch.membership_key),
                    &epoch.context,
                    SignaturePublicKeysContainer::List(&epoch.signature_public_keys),
                )
                .await?;

                Ok(auth_content)
            }

            #[cfg(not(feature = "prior_epoch"))]
            Err(MlsError::EpochNotFound)
        }?;

        Ok(auth_content)
    }

    /// Delete all sent and received proposals cached for commit.
    #[cfg(feature = "by_ref_proposal")]
    pub fn clear_proposal_cache(&mut self) {
        self.state.proposals.clear()
    }

    #[cfg_attr(not(mls_build_async), maybe_async::must_be_sync)]
    pub(crate) async fn format_for_wire(
        &mut self,
        content: AuthenticatedContent,
    ) -> Result<MlsMessage, MlsError> {
        #[cfg(feature = "private_message")]
        let payload = if content.wire_format == WireFormat::PrivateMessage {
            MlsMessagePayload::Cipher(self.create_ciphertext(content).await?)
        } else {
            MlsMessagePayload::Plain(self.create_plaintext(content).await?)
        };
        #[cfg(not(feature = "private_message"))]
        let payload = MlsMessagePayload::Plain(self.create_plaintext(content).await?);

        Ok(MlsMessage::new(self.protocol_version(), payload))
    }

    #[cfg_attr(not(mls_build_async), maybe_async::must_be_sync)]
    async fn create_plaintext(
        &self,
        auth_content: AuthenticatedContent,
    ) -> Result<PublicMessage, MlsError> {
        let membership_tag = if matches!(auth_content.content.sender, Sender::Member(_)) {
            let tag = self
                .key_schedule
                .get_membership_tag(&auth_content, self.context(), &self.cipher_suite_provider)
                .await?;

            Some(tag)
        } else {
            None
        };

        Ok(PublicMessage {
            content: auth_content.content,
            auth: auth_content.auth,
            membership_tag,
        })
    }

    #[cfg(feature = "private_message")]
    #[cfg_attr(not(mls_build_async), maybe_async::must_be_sync)]
    async fn create_ciphertext(
        &mut self,
        auth_content: AuthenticatedContent,
    ) -> Result<PrivateMessage, MlsError> {
        let padding_mode = self.encryption_options()?.padding_mode;

        let mut encryptor = CiphertextProcessor::new(self, self.cipher_suite_provider.clone());

        encryptor.seal(auth_content, padding_mode).await
    }

    /// Encrypt an application message using the current group state.
    ///
    /// `authenticated_data` will be sent unencrypted along with the contents
    /// of the proposal message.
    #[cfg(feature = "private_message")]
    #[cfg_attr(not(mls_build_async), maybe_async::must_be_sync)]
    pub async fn encrypt_application_message(
        &mut self,
        message: &[u8],
        authenticated_data: Vec<u8>,
    ) -> Result<MlsMessage, MlsError> {
        // A group member that has observed one or more proposals within an epoch MUST send a Commit message
        // before sending application data
        #[cfg(feature = "by_ref_proposal")]
        if !self.state.proposals.is_empty() {
            return Err(MlsError::CommitRequired);
        }

        let auth_content = AuthenticatedContent::new_signed(
            &self.cipher_suite_provider,
            self.context(),
            Sender::Member(*self.private_tree.self_index),
            Content::Application(message.to_vec().into()),
            &self.signer,
            WireFormat::PrivateMessage,
            authenticated_data,
        )
        .await?;

        self.format_for_wire(auth_content).await
    }

    #[cfg(feature = "private_message")]
    #[cfg_attr(not(mls_build_async), maybe_async::must_be_sync)]
    async fn decrypt_incoming_ciphertext(
        &mut self,
        message: &PrivateMessage,
    ) -> Result<AuthenticatedContent, MlsError> {
        let epoch_id = message.epoch;

        let auth_content = if epoch_id == self.context().epoch {
            let content = CiphertextProcessor::new(self, self.cipher_suite_provider.clone())
                .open(message)
                .await?;

            verify_auth_content_signature(
                &self.cipher_suite_provider,
                SignaturePublicKeysContainer::RatchetTree(&self.state.public_tree),
                self.context(),
                &content,
                #[cfg(feature = "by_ref_proposal")]
                &[],
            )
            .await?;

            Ok::<_, MlsError>(content)
        } else {
            #[cfg(feature = "prior_epoch")]
            {
                let epoch = self
                    .state_repo
                    .get_epoch_mut(epoch_id)
                    .await?
                    .ok_or(MlsError::EpochNotFound)?;

                let content = CiphertextProcessor::new(epoch, self.cipher_suite_provider.clone())
                    .open(message)
                    .await?;

                verify_auth_content_signature(
                    &self.cipher_suite_provider,
                    SignaturePublicKeysContainer::List(&epoch.signature_public_keys),
                    &epoch.context,
                    &content,
                    #[cfg(feature = "by_ref_proposal")]
                    &[],
                )
                .await?;

                Ok(content)
            }

            #[cfg(not(feature = "prior_epoch"))]
            Err(MlsError::EpochNotFound)
        }?;

        Ok(auth_content)
    }

    /// Apply a pending commit that was created by [`Group::commit`] or
    /// [`CommitBuilder::build`].
    #[cfg_attr(not(mls_build_async), maybe_async::must_be_sync)]
    pub async fn apply_pending_commit(&mut self) -> Result<CommitMessageDescription, MlsError> {
        let pending = core::mem::take(&mut self.pending_commit);
        self.apply_detached_commit(CommitSecrets(pending)).await
    }

    #[cfg_attr(not(mls_build_async), maybe_async::must_be_sync)]
    pub async fn apply_pending_commit_backwards_compatible(
        &mut self,
    ) -> Result<CommitMessageDescription, MlsError> {
        let pending = core::mem::take(&mut self.pending_commit);
        self.apply_detached_commit_backwards_compatible(CommitSecrets(pending))
            .await
    }

    /// Apply a detached commit that was created by [`Group::commit_detached`] or
    /// [`CommitBuilder::build_detached`].
    #[cfg_attr(not(mls_build_async), maybe_async::must_be_sync)]
    pub async fn apply_detached_commit(
        &mut self,
        commit_secrets: CommitSecrets,
    ) -> Result<CommitMessageDescription, MlsError> {
        let pending = match commit_secrets.0 {
            PendingCommitSnapshot::PendingCommit(bytes) => PendingCommit::mls_decode(&mut &*bytes)?,
            _ => return Err(MlsError::PendingCommitNotFound),
        };

        self.insert_past_epoch().await?;

        self.state = pending.state;
        self.epoch_secrets = pending.epoch_secrets;
        self.private_tree = pending.private_tree;
        self.key_schedule = pending.key_schedule;
        self.signer = pending.signer;

        Ok(pending.output)
    }

    #[cfg_attr(not(mls_build_async), maybe_async::must_be_sync)]
    pub async fn apply_detached_commit_backwards_compatible(
        &mut self,
        commit_secrets: CommitSecrets,
    ) -> Result<CommitMessageDescription, MlsError> {
        match commit_secrets.0 {
            PendingCommitSnapshot::None | PendingCommitSnapshot::PendingCommit(_) => {
                self.apply_detached_commit(commit_secrets).await
            }
            PendingCommitSnapshot::LegacyPendingCommit(legacy_pending) => {
                let content = legacy_pending.content.clone();
                self.pending_commit = PendingCommitSnapshot::LegacyPendingCommit(legacy_pending);
                self.process_commit(content, None).await
            }
        }
    }

    /// Returns true if a commit has been created but not yet applied
    /// with [`Group::apply_pending_commit`] or cleared with [`Group::clear_pending_commit`]
    pub fn has_pending_commit(&self) -> bool {
        !self.pending_commit.is_none()
    }

    /// Clear the currently pending commit.
    ///
    /// This function will automatically be called in the event that a
    /// commit message is processed using [`Group::process_incoming_message`]
    /// before [`Group::apply_pending_commit`] is called.
    pub fn clear_pending_commit(&mut self) {
        self.pending_commit = Default::default()
    }

    /// Returns true if the client has received or issued a proposal
    /// that needs to be committed to with [`Group::commit`] before encrypting an
    /// application message.
    #[cfg(feature = "by_ref_proposal")]
    pub fn commit_required(&self) -> bool {
        !self.state.proposals.is_empty()
    }

    /// Process an inbound message for this group.
    ///
    /// # Warning
    ///
    /// Changes to the group's state as a result of processing `message` will
    /// not be persisted by the
    /// [`GroupStateStorage`](crate::GroupStateStorage)
    /// in use by this group until [`Group::write_to_storage`] is called.
    #[cfg_attr(not(mls_build_async), maybe_async::must_be_sync)]
    #[inline(never)]
    pub async fn process_incoming_message(
        &mut self,
        message: MlsMessage,
    ) -> Result<ReceivedMessage, MlsError> {
        if let Some(pending) = self.pending_commit.commit_hash()? {
            let message_hash = MessageHash::compute(&self.cipher_suite_provider, &message).await?;

            if message_hash == pending {
                let message_description = self.apply_pending_commit().await?;

                return Ok(ReceivedMessage::Commit(message_description));
            }
        }

        #[cfg(feature = "by_ref_proposal")]
        if message.wire_format() == WireFormat::PrivateMessage {
            let cached_own_proposal = self
                .state
                .proposals
                .get_own(&self.cipher_suite_provider, &message)
                .await?;

            if let Some(cached) = cached_own_proposal {
                return Ok(ReceivedMessage::Proposal(cached));
            }
        }

        MessageProcessor::process_incoming_message(
            self,
            message,
            #[cfg(feature = "by_ref_proposal")]
            true,
        )
        .await
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
    #[cfg_attr(not(mls_build_async), maybe_async::must_be_sync)]
    pub async fn process_incoming_message_with_time(
        &mut self,
        message: MlsMessage,
        time: MlsTime,
    ) -> Result<ReceivedMessage, MlsError> {
        if let Some(pending) = self.pending_commit.commit_hash()? {
            let message_hash = MessageHash::compute(&self.cipher_suite_provider, &message).await?;

            if message_hash == pending {
                let message_description = self.apply_pending_commit().await?;

                return Ok(ReceivedMessage::Commit(message_description));
            }
        }

        #[cfg(feature = "by_ref_proposal")]
        if message.wire_format() == WireFormat::PrivateMessage {
            let cached_own_proposal = self
                .state
                .proposals
                .get_own(&self.cipher_suite_provider, &message)
                .await?;

            if let Some(cached) = cached_own_proposal {
                return Ok(ReceivedMessage::Proposal(cached));
            }
        }

        MessageProcessor::process_incoming_message_with_time(
            self,
            message,
            #[cfg(feature = "by_ref_proposal")]
            true,
            Some(time),
        )
        .await
    }

    /// Find a group member by
    /// [identity](crate::IdentityProvider::identity)
    ///
    /// This function determines identity by calling the
    /// [`IdentityProvider`](crate::IdentityProvider)
    /// currently in use by the group.
    #[cfg_attr(not(mls_build_async), maybe_async::must_be_sync)]
    pub async fn member_with_identity(&self, identity: &[u8]) -> Result<Member, MlsError> {
        let tree = &self.state.public_tree;

        #[cfg(feature = "tree_index")]
        let index = tree.get_leaf_node_with_identity(identity);

        #[cfg(not(feature = "tree_index"))]
        let index = tree
            .get_leaf_node_with_identity(
                identity,
                &self.identity_provider(),
                &self.state.context.extensions,
            )
            .await?;

        let index = index.ok_or(MlsError::MemberNotFound)?;
        let node = self.state.public_tree.get_leaf_node(index)?;

        Ok(member_from_leaf_node(node, index))
    }

    /// Create a group info message that can be used for external proposals and commits.
    ///
    /// The returned `GroupInfo` is suitable for one external commit for the current epoch.
    /// If `with_tree_in_extension` is set to true, the returned `GroupInfo` contains the
    /// ratchet tree and therefore contains all information needed to join the group. Otherwise,
    /// the ratchet tree must be obtained separately, e.g. via
    /// (ExternalClient::export_tree)[crate::external_client::ExternalGroup::export_tree].
    #[cfg_attr(not(mls_build_async), maybe_async::must_be_sync)]
    pub async fn group_info_message_allowing_ext_commit(
        &self,
        with_tree_in_extension: bool,
    ) -> Result<MlsMessage, MlsError> {
        let mut extensions = ExtensionList::new();

        extensions.set_from({
            self.key_schedule
                .get_external_key_pair_ext(&self.cipher_suite_provider)
                .await?
        })?;

        self.group_info_message_internal(extensions, with_tree_in_extension)
            .await
    }

    /// Create a group info message that can be used for external proposals.
    #[cfg_attr(not(mls_build_async), maybe_async::must_be_sync)]
    pub async fn group_info_message(
        &self,
        with_tree_in_extension: bool,
    ) -> Result<MlsMessage, MlsError> {
        self.group_info_message_internal(ExtensionList::new(), with_tree_in_extension)
            .await
    }

    #[cfg_attr(not(mls_build_async), maybe_async::must_be_sync)]
    pub async fn group_info_message_internal(
        &self,
        mut initial_extensions: ExtensionList,
        with_tree_in_extension: bool,
    ) -> Result<MlsMessage, MlsError> {
        if with_tree_in_extension {
            initial_extensions.set_from(RatchetTreeExt {
                tree_data: ExportedTree::new(self.state.public_tree.nodes.clone()),
            })?;
        }

        let mut info = GroupInfo {
            group_context: self.context().clone(),
            extensions: initial_extensions,
            confirmation_tag: self.state.confirmation_tag.clone(),
            signer: self.private_tree.self_index,
            signature: Vec::new(),
        };

        info.grease(self.cipher_suite_provider())?;

        info.sign(&self.cipher_suite_provider, &self.signer, &())
            .await?;

        Ok(MlsMessage::new(
            self.protocol_version(),
            MlsMessagePayload::GroupInfo(info),
        ))
    }

    /// Get the current group context summarizing various information about the group.
    #[inline(always)]
    pub fn context(&self) -> &GroupContext {
        &self.group_state().context
    }

    /// Get the
    /// [epoch_authenticator](https://messaginglayersecurity.rocks/mls-protocol/draft-ietf-mls-protocol.html#name-key-schedule)
    /// of the current epoch.
    pub fn epoch_authenticator(&self) -> Result<Secret, MlsError> {
        Ok(self.key_schedule.authentication_secret.clone().into())
    }

    /// Export a secret for use outside of MLS. Each epoch, label, context
    /// combination has a unique and independent secret. Secrets for all
    /// epochs, labels and contexts can be derived until either the epoch
    /// changes, i.e. a commit is received (or own commit is applied), or
    /// [Group::delete_exporter] is called.
    #[cfg_attr(not(mls_build_async), maybe_async::must_be_sync)]
    pub async fn export_secret(
        &self,
        label: &[u8],
        context: &[u8],
        len: usize,
    ) -> Result<Secret, MlsError> {
        self.key_schedule
            .export_secret(label, context, len, &self.cipher_suite_provider)
            .await
            .map(Into::into)
    }

    /// Delete the exporter secret. Afterwards the state contains no information
    /// about any secrets outputted by [Group::export_secret] (for the current or
    /// past epochs). This means that after calling this function, [Group::export_secret]
    /// can no longer be used and we get forward secrecy for all secrets derived using
    /// [Group::export_secret].
    pub fn delete_exporter(&mut self) {
        self.key_schedule.delete_exporter();
    }

    /// Export the current epoch's ratchet tree in serialized format.
    ///
    /// This function is used to provide the current group tree to new members
    /// when the `ratchet_tree_extension` is not used according to [`MlsRules::commit_options`].
    pub fn export_tree(&self) -> ExportedTree<'_> {
        ExportedTree::new_borrowed(&self.current_epoch_tree().nodes)
    }

    /// Current version of the MLS protocol in use by this group.
    pub fn protocol_version(&self) -> ProtocolVersion {
        self.context().protocol_version
    }

    /// Current cipher suite in use by this group.
    pub fn cipher_suite(&self) -> CipherSuite {
        self.context().cipher_suite
    }

    /// Current roster
    pub fn roster(&self) -> Roster<'_> {
        self.group_state().public_tree.roster()
    }

    /// Determines equality of two different groups internal states.
    /// Useful for testing.
    ///
    pub fn equal_group_state(a: &Group<C>, b: &Group<C>) -> bool {
        a.state == b.state && a.key_schedule == b.key_schedule && a.epoch_secrets == b.epoch_secrets
    }

    #[cfg(feature = "psk")]
    #[cfg_attr(not(mls_build_async), maybe_async::must_be_sync)]
    async fn get_psk(
        &self,
        psks: &[ProposalInfo<PreSharedKeyProposal>],
    ) -> Result<(PskSecret, Vec<PreSharedKeyID>), MlsError> {
        if let Some(psk) = self.previous_psk.clone() {
            // TODO consider throwing error if psks not empty
            let psk_id = vec![psk.id.clone()];
            let psk = PskSecret::calculate(&[psk], self.cipher_suite_provider()).await?;

            Ok((psk, psk_id))
        } else {
            let psks = psks
                .iter()
                .map(|psk| psk.proposal.psk.clone())
                .collect::<Vec<_>>();

            let psk = PskResolver {
                group_context: Some(self.context()),
                current_epoch: Some(&self.epoch_secrets),
                prior_epochs: Some(&self.state_repo),
                psk_store: &self.config.secret_store(),
            }
            .resolve_to_secret(&psks, self.cipher_suite_provider())
            .await?;

            Ok((psk, psks))
        }
    }

    #[cfg(feature = "private_message")]
    pub(crate) fn encryption_options(&self) -> Result<EncryptionOptions, MlsError> {
        self.config
            .mls_rules()
            .encryption_options(&self.roster(), self.group_context())
            .map_err(|e| MlsError::MlsRulesError(e.into_any_error()))
    }

    #[cfg(not(feature = "psk"))]
    fn get_psk(&self) -> PskSecret {
        PskSecret::new(self.cipher_suite_provider())
    }

    #[cfg(feature = "secret_tree_access")]
    #[cfg_attr(not(mls_build_async), maybe_async::must_be_sync)]
    #[inline(never)]
    pub async fn next_encryption_key(&mut self) -> Result<MessageKey, MlsError> {
        self.epoch_secrets
            .secret_tree
            .next_message_key(
                &self.cipher_suite_provider,
                crate::tree_kem::node::NodeIndex::from(self.private_tree.self_index),
                KeyType::Application,
            )
            .await
    }

    #[cfg(feature = "secret_tree_access")]
    #[cfg_attr(not(mls_build_async), maybe_async::must_be_sync)]
    pub async fn derive_decryption_key(
        &mut self,
        sender: u32,
        generation: u32,
    ) -> Result<MessageKey, MlsError> {
        self.epoch_secrets
            .secret_tree
            .message_key_generation(
                &self.cipher_suite_provider,
                crate::tree_kem::node::NodeIndex::from(sender),
                KeyType::Application,
                generation,
            )
            .await
    }
}

impl<C: ClientConfig> Group<C> {
    #[cfg(feature = "psk")]
    #[cfg_attr(not(mls_build_async), maybe_async::must_be_sync)]
    async fn psk_secret<CS: CipherSuiteProvider>(
        config: &C,
        cipher_suite_provider: &CS,
        psks: &[PreSharedKeyID],
        additional_psk: Option<PskSecretInput>,
    ) -> Result<PskSecret, MlsError> {
        if let Some(psk) = additional_psk {
            let psk_id = psks.first().ok_or(MlsError::UnexpectedPskId)?;

            match &psk_id.key_id {
                JustPreSharedKeyID::Resumption(r) if r.usage != ResumptionPSKUsage::Application => {
                    Ok(())
                }
                _ => Err(MlsError::UnexpectedPskId),
            }?;

            let mut psk = psk;
            psk.id.psk_nonce = psk_id.psk_nonce.clone();
            PskSecret::calculate(&[psk], cipher_suite_provider).await
        } else {
            PskResolver::<
                <C as ClientConfig>::GroupStateStorage,
                <C as ClientConfig>::KeyPackageRepository,
                <C as ClientConfig>::PskStore,
            > {
                group_context: None,
                current_epoch: None,
                prior_epochs: None,
                psk_store: &config.secret_store(),
            }
            .resolve_to_secret(psks, cipher_suite_provider)
            .await
        }
    }

    #[cfg(not(feature = "psk"))]
    #[cfg_attr(not(mls_build_async), maybe_async::must_be_sync)]
    async fn psk_secret<CS: CipherSuiteProvider>(
        _config: &C,
        cipher_suite_provider: &CS,
        _psks: &[PreSharedKeyID],
    ) -> Result<PskSecret, MlsError> {
        Ok(PskSecret::new(cipher_suite_provider))
    }

    #[cfg_attr(not(mls_build_async), maybe_async::must_be_sync)]
    pub(crate) async fn decrypt_group_info(
        welcome: &MlsMessage,
        config: &C,
    ) -> Result<GroupInfo, MlsError> {
        Self::decrypt_group_info_internal(
            welcome,
            config,
            #[cfg(feature = "psk")]
            None,
        )
        .await
        .map(|info| info.0)
    }

    #[cfg_attr(not(mls_build_async), maybe_async::must_be_sync)]
    async fn decrypt_group_info_internal(
        welcome: &MlsMessage,
        config: &C,
        #[cfg(feature = "psk")] additional_psk: Option<PskSecretInput>,
    ) -> Result<(GroupInfo, KeyPackageGeneration, GroupSecrets, PskSecret), MlsError> {
        let protocol_version = welcome.version;

        if !config.version_supported(protocol_version) {
            return Err(MlsError::UnsupportedProtocolVersion(protocol_version));
        }

        let MlsMessagePayload::Welcome(welcome) = &welcome.payload else {
            return Err(MlsError::UnexpectedMessageType);
        };

        let cipher_suite_provider =
            cipher_suite_provider(config.crypto_provider(), welcome.cipher_suite)?;

        let (encrypted_group_secrets, key_package_generation) =
            find_key_package_generation(&config.key_package_repo(), &welcome.secrets).await?;

        let key_package_version = key_package_generation.key_package.version;

        if key_package_version != protocol_version {
            return Err(MlsError::ProtocolVersionMismatch);
        }

        // Decrypt the encrypted_group_secrets using HPKE with the algorithms indicated by the
        // cipher suite and the HPKE private key corresponding to the GroupSecrets. If a
        // PreSharedKeyID is part of the GroupSecrets and the client is not in possession of
        // the corresponding PSK, return an error
        let group_secrets = GroupSecrets::decrypt(
            &cipher_suite_provider,
            &key_package_generation.init_secret_key,
            &key_package_generation.key_package.hpke_init_key,
            &welcome.encrypted_group_info,
            &encrypted_group_secrets.encrypted_group_secrets,
        )
        .await?;

        let psk_secret = Self::psk_secret(
            config,
            &cipher_suite_provider,
            &group_secrets.psks,
            #[cfg(feature = "psk")]
            additional_psk,
        )
        .await?;

        // From the joiner_secret in the decrypted GroupSecrets object and the PSKs specified in
        // the GroupSecrets, derive the welcome_secret and using that the welcome_key and
        // welcome_nonce.
        let welcome_secret = WelcomeSecret::from_joiner_secret(
            &cipher_suite_provider,
            &group_secrets.joiner_secret,
            &psk_secret,
        )
        .await?;

        // Use the key and nonce to decrypt the encrypted_group_info field.
        let decrypted_group_info = welcome_secret
            .decrypt(&welcome.encrypted_group_info)
            .await?;

        let group_info = GroupInfo::mls_decode(&mut &**decrypted_group_info)?;

        Ok((
            group_info,
            key_package_generation,
            group_secrets,
            psk_secret,
        ))
    }

    #[cfg_attr(not(mls_build_async), maybe_async::must_be_sync)]
    #[cfg(feature = "prior_epoch")]
    pub(crate) async fn insert_past_epoch(&mut self) -> Result<(), MlsError> {
        let signature_public_keys = self
            .state
            .public_tree
            .leaves()
            .map(|l| l.map(|n| n.signing_identity.signature_key.clone()))
            .collect();

        let past_epoch = PriorEpoch {
            context: self.context().clone(),
            self_index: self.private_tree.self_index,
            secrets: self.epoch_secrets.clone(),
            signature_public_keys,
            #[cfg(feature = "prior_epoch_membership_key")]
            membership_key: self.key_schedule.membership_key.to_vec(),
        };

        self.state_repo.insert(past_epoch).await?;

        Ok(())
    }

    #[cfg_attr(not(mls_build_async), maybe_async::must_be_sync)]
    #[cfg(not(feature = "prior_epoch"))]
    pub(crate) async fn insert_past_epoch(&mut self) -> Result<(), MlsError> {
        Ok(())
    }
}

#[cfg(feature = "private_message")]
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

#[cfg_attr(not(mls_build_async), maybe_async::must_be_sync)]
#[cfg_attr(all(target_arch = "wasm32", mls_build_async), maybe_async::must_be_async(?Send))]
#[cfg_attr(
    all(not(target_arch = "wasm32"), mls_build_async),
    maybe_async::must_be_async
)]
impl<C> MessageProcessor for Group<C>
where
    C: ClientConfig + Clone,
{
    type MlsRules = C::MlsRules;
    type IdentityProvider = C::IdentityProvider;
    type PreSharedKeyStorage = C::PskStore;
    type OutputType = ReceivedMessage;
    type CipherSuiteProvider = <C::CryptoProvider as CryptoProvider>::CipherSuiteProvider;

    #[cfg(feature = "private_message")]
    async fn process_ciphertext(
        &mut self,
        cipher_text: &PrivateMessage,
    ) -> Result<EventOrContent<Self::OutputType>, MlsError> {
        self.decrypt_incoming_ciphertext(cipher_text)
            .await
            .map(EventOrContent::Content)
    }

    async fn verify_plaintext_authentication(
        &self,
        message: PublicMessage,
    ) -> Result<EventOrContent<Self::OutputType>, MlsError> {
        let auth_content = verify_plaintext_authentication(
            &self.cipher_suite_provider,
            message,
            Some(&self.key_schedule.membership_key),
            &self.state.context,
            SignaturePublicKeysContainer::RatchetTree(&self.state.public_tree),
        )
        .await?;

        Ok(EventOrContent::Content(auth_content))
    }

    async fn apply_update_path(
        &mut self,
        sender: LeafIndex,
        update_path: &ValidatedUpdatePath,
        provisional_state: &mut ProvisionalState,
    ) -> Result<Option<(TreeKemPrivate, PathSecret)>, MlsError> {
        // Update the private tree to create a provisional private tree
        let (mut provisional_private_tree, new_signer) =
            self.provisional_private_tree(provisional_state)?;

        if let Some(signer) = new_signer {
            self.signer = signer;
        }

        provisional_state
            .public_tree
            .apply_update_path(
                sender,
                update_path,
                &provisional_state.group_context.extensions,
                self.identity_provider(),
                self.cipher_suite_provider(),
            )
            .await?;

        if sender == self.private_tree.self_index {
            let PendingCommitSnapshot::LegacyPendingCommit(legacy_pending) = &self.pending_commit
            else {
                return Err(MlsError::CantProcessMessageFromSelf);
            };

            return Ok(Some((
                legacy_pending.private_tree.clone(),
                legacy_pending.commit_secret.clone(),
            )));
        }

        // Update the tree hash to get context for decryption
        provisional_state.group_context.tree_hash = provisional_state
            .public_tree
            .tree_hash(&self.cipher_suite_provider)
            .await?;

        let context_bytes = provisional_state.group_context.mls_encode_to_vec()?;

        TreeKem::new(
            &mut provisional_state.public_tree,
            &mut provisional_private_tree,
        )
        .decap(
            sender,
            update_path,
            &provisional_state.indexes_of_added_kpkgs,
            &context_bytes,
            &self.cipher_suite_provider,
        )
        .await
        .map(|root_secret| Some((provisional_private_tree, root_secret)))
    }

    async fn update_key_schedule(
        &mut self,
        secrets: Option<(TreeKemPrivate, PathSecret)>,
        interim_transcript_hash: InterimTranscriptHash,
        confirmation_tag: &ConfirmationTag,
        provisional_state: ProvisionalState,
    ) -> Result<(), MlsError> {
        let commit_secret = if let Some(secrets) = secrets {
            self.private_tree = secrets.0;
            secrets.1
        } else {
            PathSecret::empty(&self.cipher_suite_provider)
        };

        // Use the commit_secret, the psk_secret, the provisional GroupContext, and the init secret
        // from the previous epoch (or from the external init) to compute the epoch secret and
        // derived secrets for the new epoch

        let key_schedule = match provisional_state
            .applied_proposals
            .external_initializations
            .first()
            .cloned()
        {
            Some(ext_init) if self.pending_commit.is_none() => {
                self.key_schedule
                    .derive_for_external(&ext_init.proposal.kem_output, &self.cipher_suite_provider)
                    .await?
            }
            _ => self.key_schedule.clone(),
        };

        #[cfg(feature = "psk")]
        let (psk, _) = self
            .get_psk(&provisional_state.applied_proposals.psks)
            .await?;

        #[cfg(not(feature = "psk"))]
        let psk = self.get_psk();

        let key_schedule_result = KeySchedule::from_key_schedule(
            &key_schedule,
            &commit_secret,
            &provisional_state.group_context,
            #[cfg(any(feature = "secret_tree_access", feature = "private_message"))]
            provisional_state.public_tree.total_leaf_count(),
            &psk,
            &self.cipher_suite_provider,
        )
        .await?;

        // Use the confirmation_key for the new epoch to compute the confirmation tag for
        // this message, as described below, and verify that it is the same as the
        // confirmation_tag field in the MlsPlaintext object.
        let new_confirmation_tag = ConfirmationTag::create(
            &key_schedule_result.confirmation_key,
            &provisional_state.group_context.confirmed_transcript_hash,
            &self.cipher_suite_provider,
        )
        .await?;

        if &new_confirmation_tag != confirmation_tag {
            return Err(MlsError::InvalidConfirmationTag);
        }

        self.insert_past_epoch().await?;

        self.epoch_secrets = key_schedule_result.epoch_secrets;
        self.state.context = provisional_state.group_context;
        self.state.interim_transcript_hash = interim_transcript_hash;
        self.key_schedule = key_schedule_result.key_schedule;
        self.state.public_tree = provisional_state.public_tree;
        self.state.confirmation_tag = new_confirmation_tag;

        // Clear the proposals list
        #[cfg(feature = "by_ref_proposal")]
        self.state.proposals.clear();

        // Clear the pending updates list
        #[cfg(feature = "by_ref_proposal")]
        {
            self.pending_updates = Default::default();
        }

        self.pending_commit = Default::default();

        Ok(())
    }

    fn mls_rules(&self) -> Self::MlsRules {
        self.config.mls_rules()
    }

    fn identity_provider(&self) -> Self::IdentityProvider {
        self.config.identity_provider()
    }

    fn psk_storage(&self) -> Self::PreSharedKeyStorage {
        self.config.secret_store()
    }

    fn group_state(&self) -> &GroupState {
        &self.state
    }

    fn group_state_mut(&mut self) -> &mut GroupState {
        &mut self.state
    }

    fn removal_proposal(
        &self,
        provisional_state: &ProvisionalState,
    ) -> Option<ProposalInfo<RemoveProposal>> {
        provisional_state
            .applied_proposals
            .removals
            .iter()
            .find(|p| p.proposal.to_remove == self.private_tree.self_index)
            .cloned()
    }

    #[cfg(all(
        feature = "by_ref_proposal",
        feature = "custom_proposal",
        feature = "self_remove_proposal"
    ))]
    #[cfg_attr(feature = "ffi", safer_ffi_gen::safer_ffi_gen_ignore)]
    fn self_removal_proposal(
        &self,
        provisional_state: &ProvisionalState,
    ) -> Option<ProposalInfo<SelfRemoveProposal>> {
        provisional_state
            .applied_proposals
            .self_removes
            .iter()
            .find(|p| p.sender == Sender::Member(*self.private_tree.self_index))
            .cloned()
    }

    #[cfg(feature = "private_message")]
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
    use crate::{
        client::test_utils::{
            test_client_with_key_pkg, TestClientBuilder, TEST_CIPHER_SUITE, TEST_PROTOCOL_VERSION,
        },
        client_builder::test_utils::TestClientConfig,
        crypto::test_utils::TestCryptoProvider,
        group::proposal_filter::ProposalInfo,
        identity::test_utils::get_test_signing_identity,
        key_package::test_utils::test_key_package_message,
        mls_rules::CommitOptions,
        tree_kem::{
            leaf_node::{test_utils::get_test_capabilities, LeafNodeSource},
            UpdatePathNode,
        },
    };

    #[cfg(feature = "by_ref_proposal")]
    use crate::{
        client::test_utils::{test_client_with_key_pkg_custom, TEST_CUSTOM_PROPOSAL_TYPE},
        client_builder::{ClientBuilder, MlsConfig},
        group::{
            component_operation::ComponentID,
            mls_rules::{CommitDirection, CommitSource},
            proposal_filter::ProposalBundle,
        },
        identity::basic::BasicIdentityProvider,
        identity::test_utils::BasicWithCustomProvider,
    };

    #[cfg(any(feature = "private_message", feature = "custom_proposal"))]
    use crate::group::mls_rules::DefaultMlsRules;

    #[cfg(feature = "prior_epoch")]
    use crate::group::padding::PaddingMode;

    use crate::{extension::RequiredCapabilitiesExt, key_package::test_utils::test_key_package};

    #[cfg(all(feature = "by_ref_proposal", feature = "custom_proposal"))]
    use super::test_utils::test_group_custom_config;

    #[cfg(any(feature = "psk", feature = "std"))]
    use crate::client::Client;

    #[cfg(feature = "psk")]
    use crate::psk::PreSharedKey;

    #[cfg(any(feature = "by_ref_proposal", feature = "private_message"))]
    use crate::group::test_utils::random_bytes;

    #[cfg(feature = "by_ref_proposal")]
    use crate::{
        extension::test_utils::TestExtension, identity::test_utils::get_test_basic_credential,
        time::MlsTime,
    };

    use super::{
        test_utils::{
            get_test_25519_key, get_test_groups_with_features, group_extensions, process_commit,
            test_group, test_group_custom, test_n_member_group, TestGroup, TEST_GROUP,
        },
        *,
    };

    use assert_matches::assert_matches;

    use message_processor::CommitEffect;
    use mls_rs_core::extension::{Extension, ExtensionType};
    use mls_rs_core::identity::{Credential, CredentialType, CustomCredential};

    #[cfg(feature = "by_ref_proposal")]
    use mls_rs_core::identity::CertificateChain;

    #[cfg(feature = "by_ref_proposal")]
    use crate::{crypto::test_utils::test_cipher_suite_provider, extension::ExternalSendersExt};

    #[cfg(feature = "private_message")]
    use super::test_utils::test_member;

    use mls_rs_core::extension::MlsExtension;

    #[maybe_async::test(not(mls_build_async), async(mls_build_async, crate::futures_test))]
    async fn test_create_group() {
        for (protocol_version, cipher_suite) in ProtocolVersion::all().flat_map(|p| {
            TestCryptoProvider::all_supported_cipher_suites()
                .into_iter()
                .map(move |cs| (p, cs))
        }) {
            let group = test_group(protocol_version, cipher_suite).await;

            assert_eq!(group.cipher_suite(), cipher_suite);
            assert_eq!(group.state.context.epoch, 0);
            assert_eq!(group.state.context.group_id, TEST_GROUP.to_vec());
            assert_eq!(group.state.context.extensions, group_extensions());

            assert_eq!(
                group.state.context.confirmed_transcript_hash,
                ConfirmedTranscriptHash::from(vec![])
            );

            #[cfg(feature = "private_message")]
            assert!(group.state.proposals.is_empty());

            #[cfg(feature = "by_ref_proposal")]
            assert!(group.pending_updates.is_empty());

            assert!(!group.has_pending_commit());

            assert_eq!(*group.private_tree.self_index, group.current_member_index());
        }
    }

    #[cfg(feature = "private_message")]
    #[maybe_async::test(not(mls_build_async), async(mls_build_async, crate::futures_test))]
    async fn test_pending_proposals_application_data() {
        let mut test_group = test_group(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE).await;

        // Create a proposal
        let (bob_key_package, _) =
            test_member(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE, b"bob").await;

        let proposal = test_group
            .add_proposal(bob_key_package.key_package_message())
            .unwrap();

        test_group.proposal_message(proposal, vec![]).await.unwrap();

        // We should not be able to send application messages until a commit happens
        let res = test_group
            .encrypt_application_message(b"test", vec![])
            .await;

        assert_matches!(res, Err(MlsError::CommitRequired));

        // We should be able to send application messages after a commit
        test_group.commit(vec![]).await.unwrap();

        assert!(test_group.has_pending_commit());

        test_group.apply_pending_commit().await.unwrap();

        let res = test_group
            .encrypt_application_message(b"test", vec![])
            .await;

        assert!(res.is_ok());
    }

    #[cfg(feature = "by_ref_proposal")]
    #[maybe_async::test(not(mls_build_async), async(mls_build_async, crate::futures_test))]
    async fn test_update_proposals() {
        let new_extension = TestExtension { foo: 10 };
        let mut extension_list = ExtensionList::default();
        extension_list.set_from(new_extension).unwrap();

        let mut test_group = test_group_custom(
            TEST_PROTOCOL_VERSION,
            TEST_CIPHER_SUITE,
            vec![42.into()],
            Some(extension_list.clone()),
            None,
        )
        .await;

        let existing_leaf = test_group.current_user_leaf_node().unwrap().clone();

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

        assert_eq!(update.leaf_node.ungreased_extensions(), extension_list);
        assert_eq!(
            update.leaf_node.ungreased_capabilities().sorted(),
            Capabilities {
                extensions: vec![42.into()],
                ..get_test_capabilities()
            }
            .sorted()
        );
    }

    #[cfg(feature = "by_ref_proposal")]
    #[maybe_async::test(not(mls_build_async), async(mls_build_async, crate::futures_test))]
    async fn test_invalid_commit_self_update() {
        let mut test_group = test_group(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE).await;

        // Create an update proposal
        let proposal_msg = test_group.propose_update(vec![]).await.unwrap();

        let proposal = match proposal_msg.into_plaintext().unwrap().content.content {
            Content::Proposal(p) => p,
            _ => panic!("found non-proposal message"),
        };

        let update_leaf = match *proposal {
            Proposal::Update(u) => u.leaf_node,
            _ => panic!("found proposal message that isn't an update"),
        };

        test_group.commit(vec![]).await.unwrap();
        test_group.apply_pending_commit().await.unwrap();

        // The leaf node should not be the one from the update, because the committer rejects it
        assert_ne!(&update_leaf, test_group.current_user_leaf_node().unwrap());
    }

    #[cfg(feature = "by_ref_proposal")]
    #[maybe_async::test(not(mls_build_async), async(mls_build_async, crate::futures_test))]
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
            .proposal_message(proposal.clone(), vec![])
            .await
            .unwrap();

        let proposal_plaintext = match proposal_message.payload {
            MlsMessagePayload::Plain(p) => p,
            _ => panic!("Unexpected non-plaintext message"),
        };

        let proposal_ref = ProposalRef::from_content(
            &bob_group.cipher_suite_provider,
            &proposal_plaintext.clone().into(),
        )
        .await
        .unwrap();

        // Hack bob's receipt of the proposal
        bob_group
            .state
            .proposals
            .insert(proposal_ref, proposal, proposal_plaintext.content.sender);

        let commit_output = bob_group.commit(vec![]).await.unwrap();

        assert_matches!(
            commit_output.commit_message,
            MlsMessage {
                payload: MlsMessagePayload::Plain(
                    PublicMessage {
                        content: FramedContent {
                            content: Content::Commit(c),
                            ..
                        },
                        ..
                    }),
                ..
            } if c.proposals.is_empty()
        );
    }

    #[cfg(feature = "non_domain_separated_hpke_encrypt_decrypt")]
    #[maybe_async::test(not(mls_build_async), async(mls_build_async, crate::futures_test))]
    async fn test_hpke_encrypt_decrypt() {
        let (alice_group, bob_group) =
            test_two_member_group(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE, true).await;
        let receiver_index = alice_group.current_member_index();
        let sender_index = bob_group.current_member_index();

        let context_info: Vec<u8> = vec![
            receiver_index.try_into().unwrap(),
            sender_index.try_into().unwrap(),
        ];
        let plaintext = b"message";

        let hpke_ciphertext = bob_group
            .hpke_encrypt_to_recipient(receiver_index, &context_info, None, plaintext)
            .await
            .unwrap();
        let hpke_decrypted = alice_group
            .hpke_decrypt_for_current_member(&context_info, None, hpke_ciphertext)
            .await
            .unwrap();

        assert_eq!(plaintext.to_vec(), hpke_decrypted);
    }

    #[maybe_async::test(not(mls_build_async), async(mls_build_async, crate::futures_test))]
    async fn safe_context_test_hpke_encrypt_decrypt() {
        let component_id: ComponentID = 1;
        let (alice_group, bob_group) =
            test_two_member_group(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE, true).await;
        let receiver_index = alice_group.current_member_index();
        let sender_index = bob_group.current_member_index();

        let context_info: Vec<u8> = vec![
            receiver_index.try_into().unwrap(),
            sender_index.try_into().unwrap(),
        ];
        let plaintext = b"message";

        let hpke_ciphertext = bob_group
            .safe_encrypt_with_context_to_recipient(
                receiver_index,
                component_id,
                &context_info,
                None,
                plaintext,
            )
            .await
            .unwrap();
        let hpke_decrypted = alice_group
            .safe_decrypt_with_context_for_current_member(
                component_id,
                &context_info,
                None,
                hpke_ciphertext,
            )
            .await
            .unwrap();

        assert_eq!(plaintext.to_vec(), hpke_decrypted);
    }

    #[cfg(feature = "non_domain_separated_hpke_encrypt_decrypt")]
    #[maybe_async::test(not(mls_build_async), async(mls_build_async, crate::futures_test))]
    async fn test_hpke_non_recipient_cant_decrypt() {
        let mut alice = test_group(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE).await;
        let (mut bob, _) = alice.join("bob").await;
        let (carol, commit) = alice.join("carol").await;

        // Apply the commit that adds carol
        bob.process_incoming_message(commit).await.unwrap();

        let receiver_index = alice.current_member_index();
        let sender_index = bob.current_member_index();

        let context_info: Vec<u8> = vec![
            receiver_index.try_into().unwrap(),
            sender_index.try_into().unwrap(),
        ];
        let plaintext = b"message";

        let hpke_ciphertext = bob
            .hpke_encrypt_to_recipient(receiver_index, &context_info, None, plaintext)
            .await
            .unwrap();

        // different recipient tries to decrypt
        let hpke_decrypted = carol
            .hpke_decrypt_for_current_member(&context_info, None, hpke_ciphertext)
            .await;

        // should fail because carol can't decrypt the message encrypted for alice
        assert_matches!(hpke_decrypted, Err(MlsError::CryptoProviderError(_)));
    }

    #[maybe_async::test(not(mls_build_async), async(mls_build_async, crate::futures_test))]
    async fn safe_context_test_hpke_non_recipient_cant_decrypt() {
        let component_id: ComponentID = 345;
        let mut alice = test_group(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE).await;
        let (mut bob, _) = alice.join("bob").await;
        let (carol, commit) = alice.join("carol").await;

        // Apply the commit that adds carol
        bob.process_incoming_message(commit).await.unwrap();

        let receiver_index = alice.current_member_index();
        let sender_index = bob.current_member_index();

        let context_info: Vec<u8> = vec![
            receiver_index.try_into().unwrap(),
            sender_index.try_into().unwrap(),
        ];
        let plaintext = b"message";

        let hpke_ciphertext = bob
            .safe_encrypt_with_context_to_recipient(
                receiver_index,
                component_id,
                &context_info,
                None,
                plaintext,
            )
            .await
            .unwrap();

        // different recipient tries to decrypt
        let hpke_decrypted = carol
            .safe_decrypt_with_context_for_current_member(
                component_id,
                &context_info,
                None,
                hpke_ciphertext,
            )
            .await;

        // should fail because carol can't decrypt the message encrypted for alice
        assert_matches!(hpke_decrypted, Err(MlsError::CryptoProviderError(_)));
    }

    #[cfg(feature = "non_domain_separated_hpke_encrypt_decrypt")]
    #[maybe_async::test(not(mls_build_async), async(mls_build_async, crate::futures_test))]
    async fn test_hpke_can_decrypt_after_group_changes() {
        let mut alice = test_group(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE).await;
        let (mut bob, _) = alice.join("bob").await;

        let receiver_index = alice.current_member_index();
        let sender_index = bob.current_member_index();
        let context_info: Vec<u8> = vec![
            receiver_index.try_into().unwrap(),
            sender_index.try_into().unwrap(),
        ];
        let associated_data: Vec<u8> = vec![1, 2, 3, 4];
        let plaintext = b"message";

        // encrypt the message to alice
        let hpke_ciphertext = bob
            .hpke_encrypt_to_recipient(
                receiver_index,
                &context_info,
                Some(&associated_data),
                plaintext,
            )
            .await
            .unwrap();

        // add carol to the group
        let (_carol, commit) = alice.join("carol").await;
        bob.process_incoming_message(commit).await.unwrap();

        // make sure alice can still decrypt
        let hpke_decrypted = alice
            .hpke_decrypt_for_current_member(&context_info, Some(&associated_data), hpke_ciphertext)
            .await
            .unwrap();
        assert_eq!(plaintext.to_vec(), hpke_decrypted);
    }

    #[maybe_async::test(not(mls_build_async), async(mls_build_async, crate::futures_test))]
    async fn safe_context_test_hpke_can_decrypt_after_group_changes() {
        let component_id: ComponentID = 2;
        let mut alice = test_group(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE).await;
        let (mut bob, _) = alice.join("bob").await;

        let receiver_index = alice.current_member_index();
        let sender_index = bob.current_member_index();
        let context_info: Vec<u8> = vec![
            receiver_index.try_into().unwrap(),
            sender_index.try_into().unwrap(),
        ];
        let associated_data: Vec<u8> = vec![1, 2, 3, 4];
        let plaintext = b"message";

        // encrypt the message to alice
        let hpke_ciphertext = bob
            .safe_encrypt_with_context_to_recipient(
                receiver_index,
                component_id,
                &context_info,
                Some(&associated_data),
                plaintext,
            )
            .await
            .unwrap();

        // add carol to the group
        let (_carol, commit) = alice.join("carol").await;
        bob.process_incoming_message(commit).await.unwrap();

        // make sure alice can still decrypt
        let hpke_decrypted = alice
            .safe_decrypt_with_context_for_current_member(
                component_id,
                &context_info,
                Some(&associated_data),
                hpke_ciphertext,
            )
            .await
            .unwrap();
        assert_eq!(plaintext.to_vec(), hpke_decrypted);
    }

    #[cfg(all(
        feature = "prior_epoch",
        feature = "custom_proposal",
        feature = "by_ref_proposal",
        feature = "prior_epoch_membership_key"
    ))]
    #[maybe_async::test(not(mls_build_async), async(mls_build_async, crate::futures_test))]
    async fn test_can_validate_and_get_data_custom_proposal_from_past_epoch() {
        let mut alice = test_group(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE).await;
        let (mut bob, _) = alice.join("bob").await;

        let data = vec![1, 2, 3];
        let custom_proposal = CustomProposal::new(TEST_CUSTOM_PROPOSAL_TYPE, vec![4, 5, 6]);
        let proposal = alice
            .propose_custom(custom_proposal.clone(), data.clone())
            .await
            .unwrap();

        // add carol to the group
        let (_carol, commit) = alice.join("carol").await;
        bob.process_incoming_message(commit).await.unwrap();
        let (validated_data, sender) = bob
            .validate_custom_proposal(&proposal, Some(TEST_CUSTOM_PROPOSAL_TYPE))
            .await
            .unwrap();
        assert_eq!(data, validated_data);
        assert_eq!(sender, Sender::Member(0));
    }

    #[cfg(all(
        feature = "prior_epoch",
        feature = "custom_proposal",
        feature = "by_ref_proposal",
        feature = "prior_epoch_membership_key"
    ))]
    #[maybe_async::test(not(mls_build_async), async(mls_build_async, crate::futures_test))]
    async fn test_can_validate_and_get_data_custom_proposal_from_current_epoch() {
        let mut alice = test_group(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE).await;
        let (mut bob, _) = alice.join("bob").await;

        let data = vec![1, 2, 3];
        let custom_proposal = CustomProposal::new(TEST_CUSTOM_PROPOSAL_TYPE, vec![3, 4, 5]);
        let proposal = alice
            .propose_custom(custom_proposal.clone(), data.clone())
            .await
            .unwrap();

        let (validated_data, sender) = bob.validate_custom_proposal(&proposal, None).await.unwrap();
        assert_eq!(data, validated_data);
        assert_eq!(sender, Sender::Member(0));
    }

    #[cfg(all(feature = "prior_epoch", feature = "prior_epoch_membership_key"))]
    #[maybe_async::test(not(mls_build_async), async(mls_build_async, crate::futures_test))]
    async fn test_can_validate_non_custom_proposal_from_past_epoch() {
        let mut alice = test_group(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE).await;
        let (mut bob, _) = alice.join("bob").await;

        let proposal = alice.propose_update(Vec::new()).await.unwrap();

        // add carol to the group
        let (_carol, commit) = alice.join("carol").await;
        bob.process_incoming_message(commit).await.unwrap();

        bob.validate_public_message(&proposal).await.unwrap();
    }

    #[cfg(all(
        feature = "prior_epoch",
        feature = "by_ref_proposal",
        feature = "prior_epoch_membership_key"
    ))]
    #[maybe_async::test(not(mls_build_async), async(mls_build_async, crate::futures_test))]
    async fn test_cannot_validate_custom_proposal_for_non_custom_proposal() {
        let mut alice = test_group(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE).await;
        let (mut bob, _) = alice.join("bob").await;

        let proposal = alice.propose_update(Vec::new()).await.unwrap();

        // add carol to the group
        let (_carol, commit) = alice.join("carol").await;
        bob.process_incoming_message(commit).await.unwrap();

        let data_err = bob.validate_custom_proposal(&proposal, None).await;
        assert_matches!(data_err, Err(MlsError::UnexpectedMessageType));
    }

    #[cfg(all(feature = "prior_epoch", feature = "prior_epoch_membership_key"))]
    #[maybe_async::test(not(mls_build_async), async(mls_build_async, crate::futures_test))]
    async fn test_can_validate_commit_from_past_epoch() {
        let mut alice = test_group(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE).await;
        let (mut bob, _) = alice.join("bob").await;

        let old_commit_output = bob
            .commit_builder()
            .remove_member(0)
            .unwrap()
            .build()
            .await
            .unwrap();

        // add carol to the group
        let (_carol, commit) = alice.join("carol").await;
        bob.process_incoming_message(commit).await.unwrap();

        bob.validate_public_message(&old_commit_output.commit_message)
            .await
            .unwrap();
    }

    #[cfg(all(
        feature = "prior_epoch",
        feature = "custom_proposal",
        feature = "prior_epoch_membership_key"
    ))]
    #[maybe_async::test(not(mls_build_async), async(mls_build_async, crate::futures_test))]
    async fn test_can_validate_custom_proposal_from_current_epoch() {
        let mut alice = test_group(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE).await;
        let (mut bob, _) = alice.join("bob").await;

        let custom_proposal = CustomProposal::new(TEST_CUSTOM_PROPOSAL_TYPE, vec![0, 1, 2]);
        let proposal = alice
            .propose_custom(custom_proposal.clone(), vec![])
            .await
            .unwrap();

        bob.validate_public_message(&proposal).await.unwrap();
    }

    #[cfg(all(feature = "prior_epoch", feature = "prior_epoch_membership_key"))]
    #[maybe_async::test(not(mls_build_async), async(mls_build_async, crate::futures_test))]
    async fn test_cannot_validate_non_public_message() {
        let mut alice = test_group(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE).await;
        let (mut bob, _) = alice.join("bob").await;

        let res = alice
            .encrypt_application_message(b"test", vec![])
            .await
            .unwrap();

        let auth_content = bob.validate_public_message(&res).await;
        assert_matches!(auth_content, Err(MlsError::UnexpectedMessageType));
    }

    #[cfg_attr(not(mls_build_async), maybe_async::must_be_sync)]
    async fn test_two_member_group(
        protocol_version: ProtocolVersion,
        cipher_suite: CipherSuite,
        tree_ext: bool,
    ) -> (TestGroup, TestGroup) {
        let mut test_group = test_group_custom(
            protocol_version,
            cipher_suite,
            Default::default(),
            None,
            Some(CommitOptions::new().with_ratchet_tree_extension(tree_ext)),
        )
        .await;

        let (bob_test_group, _) = test_group.join("bob").await;

        assert!(Group::equal_group_state(&test_group, &bob_test_group));

        (test_group, bob_test_group)
    }

    #[maybe_async::test(not(mls_build_async), async(mls_build_async, crate::futures_test))]
    async fn test_welcome_processing_exported_tree() {
        test_two_member_group(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE, false).await;
    }

    #[maybe_async::test(not(mls_build_async), async(mls_build_async, crate::futures_test))]
    async fn test_welcome_processing_tree_extension() {
        test_two_member_group(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE, true).await;
    }

    #[maybe_async::test(not(mls_build_async), async(mls_build_async, crate::futures_test))]
    async fn test_welcome_processing_missing_tree() {
        let mut test_group = test_group_custom(
            TEST_PROTOCOL_VERSION,
            TEST_CIPHER_SUITE,
            Default::default(),
            None,
            Some(CommitOptions::new().with_ratchet_tree_extension(false)),
        )
        .await;

        let (bob_client, bob_key_package) =
            test_client_with_key_pkg(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE, "bob").await;

        // Add bob to the group
        let commit_output = test_group
            .commit_builder()
            .add_member(bob_key_package)
            .unwrap()
            .build()
            .await
            .unwrap();

        // Group from Bob's perspective
        let bob_group = Group::join(
            &commit_output.welcome_messages[0],
            None,
            bob_client.config,
            bob_client.signer.unwrap(),
            None,
        )
        .await
        .map(|_| ());

        assert_matches!(bob_group, Err(MlsError::RatchetTreeNotFound));
    }

    #[maybe_async::test(not(mls_build_async), async(mls_build_async, crate::futures_test))]
    async fn test_reused_key_package() {
        let mut alice_group = test_group(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE).await;
        let (bob_client, bob_key_package) =
            test_client_with_key_pkg(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE, "bob").await;
        let mut carla_group = test_group(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE).await;

        // Alice adds Bob to her group.
        let commit_output = alice_group
            .group
            .commit_builder()
            .add_member(bob_key_package.clone())
            .unwrap()
            .build()
            .await
            .unwrap();

        // Bob joins group.
        let (mut bob_group, _) = bob_client
            .join_group(None, &commit_output.welcome_messages[0], None)
            .await
            .unwrap();
        // This deletes the key package used to join the group.
        bob_group.write_to_storage().await.unwrap();

        // Carla adds Bob, reusing the same key package.
        let commit_output = carla_group
            .group
            .commit_builder()
            .add_member(bob_key_package.clone())
            .unwrap()
            .build()
            .await
            .unwrap();

        // Bob cannot join Carla's group.
        let bob_group = bob_client
            .join_group(None, &commit_output.welcome_messages[0], None)
            .await
            .map(|_| ());
        assert_matches!(bob_group, Err(MlsError::WelcomeKeyPackageNotFound));
    }

    #[cfg(feature = "last_resort_key_package_ext")]
    #[maybe_async::test(not(mls_build_async), async(mls_build_async, crate::futures_test))]
    async fn test_last_resort_key_package() -> Result<(), MlsError> {
        let mut alice_group = test_group(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE).await;
        let (bob_client, bob_key_package) = test_client_with_key_pkg_custom(
            TEST_PROTOCOL_VERSION,
            TEST_CIPHER_SUITE,
            "bob",
            vec![LastResortKeyPackageExt.into_extension().unwrap()].into(),
            Default::default(),
            |_| {},
        )
        .await;
        let mut carla_group = test_group(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE).await;

        // Alice adds Bob to her group.
        let commit_output = alice_group
            .group
            .commit_builder()
            .add_member(bob_key_package.clone())?
            .build()
            .await?;

        // Bob joins group.
        let (mut bob_group, _) = bob_client
            .join_group(None, &commit_output.welcome_messages[0], None)
            .await?;
        // This no longer deletes the key package
        bob_group.write_to_storage()?;

        // Carla adds Bob, reusing the same key package.
        let commit_output = carla_group
            .group
            .commit_builder()
            .add_member(bob_key_package.clone())?
            .build()
            .await?;

        // Bob can join Carla's group.
        bob_client
            .join_group(None, &commit_output.welcome_messages[0], None)
            .await?;

        Ok(())
    }

    #[maybe_async::test(not(mls_build_async), async(mls_build_async, crate::futures_test))]
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

        let proposal = test_group.group_context_extensions_proposal(extension_list.clone());

        assert_matches!(proposal, Proposal::GroupContextExtensions(ext) if ext == extension_list);
    }

    #[cfg_attr(not(mls_build_async), maybe_async::must_be_sync)]
    async fn group_context_extension_proposal_test(
        ext_list: ExtensionList,
    ) -> (TestGroup, Result<MlsMessage, MlsError>) {
        let protocol_version = TEST_PROTOCOL_VERSION;
        let cipher_suite = TEST_CIPHER_SUITE;

        let mut test_group =
            test_group_custom(protocol_version, cipher_suite, vec![42.into()], None, None).await;

        let commit = test_group
            .commit_builder()
            .set_group_context_ext(ext_list)
            .unwrap()
            .build()
            .await
            .map(|commit_output| commit_output.commit_message);

        (test_group, commit)
    }

    #[maybe_async::test(not(mls_build_async), async(mls_build_async, crate::futures_test))]
    async fn test_group_context_ext_proposal_commit() {
        use message_processor::CommitEffect;

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

        let update = test_group.apply_pending_commit().await.unwrap();

        // FIXME: Test Reporting
        assert_matches!(update.effect, CommitEffect::NewEpoch(_));

        assert_eq!(test_group.state.context.extensions, extension_list)
    }

    #[maybe_async::test(not(mls_build_async), async(mls_build_async, crate::futures_test))]
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
            Err(MlsError::RequiredExtensionNotFound(a)) if a == 999.into()
        );
    }

    #[cfg_attr(not(mls_build_async), maybe_async::must_be_sync)]
    async fn make_group_with_required_capabilities(
        required_caps: RequiredCapabilitiesExt,
    ) -> Result<Group<TestClientConfig>, MlsError> {
        test_client_with_key_pkg(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE, "alice")
            .await
            .0
            .create_group(
                core::iter::once(required_caps.into_extension().unwrap()).collect(),
                Default::default(),
                None,
            )
            .await
    }

    #[maybe_async::test(not(mls_build_async), async(mls_build_async, crate::futures_test))]
    async fn creating_group_with_member_not_supporting_required_credential_type_fails() {
        let group_creation = make_group_with_required_capabilities(RequiredCapabilitiesExt {
            credentials: vec![CredentialType::BASIC, CredentialType::X509],
            ..Default::default()
        })
        .await
        .map(|_| ());

        assert_matches!(
            group_creation,
            Err(MlsError::RequiredCredentialNotFound(CredentialType::X509))
        );
    }

    #[maybe_async::test(not(mls_build_async), async(mls_build_async, crate::futures_test))]
    async fn creating_group_with_member_not_supporting_required_extension_type_fails() {
        const EXTENSION_TYPE: ExtensionType = ExtensionType::new(33);

        let group_creation = make_group_with_required_capabilities(RequiredCapabilitiesExt {
            extensions: vec![EXTENSION_TYPE],
            ..Default::default()
        })
        .await
        .map(|_| ());

        assert_matches!(
            group_creation,
            Err(MlsError::RequiredExtensionNotFound(EXTENSION_TYPE))
        );
    }

    #[maybe_async::test(not(mls_build_async), async(mls_build_async, crate::futures_test))]
    async fn creating_group_with_member_not_supporting_required_proposal_type_fails() {
        const PROPOSAL_TYPE: ProposalType = ProposalType::new(33);

        let group_creation = make_group_with_required_capabilities(RequiredCapabilitiesExt {
            proposals: vec![PROPOSAL_TYPE],
            ..Default::default()
        })
        .await
        .map(|_| ());

        assert_matches!(
            group_creation,
            Err(MlsError::RequiredProposalNotFound(PROPOSAL_TYPE))
        );
    }

    #[cfg(feature = "by_ref_proposal")]
    #[cfg(not(target_arch = "wasm32"))]
    #[maybe_async::test(not(mls_build_async), async(mls_build_async, crate::futures_test))]
    async fn creating_group_with_member_not_supporting_external_sender_credential_fails() {
        let ext_senders = make_x509_external_senders_ext()
            .await
            .into_extension()
            .unwrap();

        let group_creation =
            test_client_with_key_pkg(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE, "alice")
                .await
                .0
                .create_group(
                    core::iter::once(ext_senders).collect(),
                    Default::default(),
                    None,
                )
                .await
                .map(|_| ());

        assert_matches!(
            group_creation,
            Err(MlsError::RequiredCredentialNotFound(CredentialType::X509))
        );
    }

    #[cfg(all(not(target_arch = "wasm32"), feature = "private_message"))]
    #[maybe_async::test(not(mls_build_async), async(mls_build_async, crate::futures_test))]
    async fn test_group_encrypt_plaintext_padding() {
        let protocol_version = TEST_PROTOCOL_VERSION;
        // This test requires a cipher suite whose signatures are not variable in length.
        let cipher_suite = CipherSuite::CURVE25519_AES128;

        let mut test_group = test_group_custom_config(protocol_version, cipher_suite, |b| {
            b.mls_rules(
                DefaultMlsRules::default()
                    .with_encryption_options(EncryptionOptions::new(true, PaddingMode::None)),
            )
        })
        .await;

        let without_padding = test_group
            .encrypt_application_message(&random_bytes(150), vec![])
            .await
            .unwrap();

        let mut test_group =
            test_group_custom_config(protocol_version, cipher_suite, |b| {
                b.mls_rules(DefaultMlsRules::default().with_encryption_options(
                    EncryptionOptions::new(true, PaddingMode::StepFunction),
                ))
            })
            .await;

        let with_step_function_padding = test_group
            .encrypt_application_message(&random_bytes(150), vec![])
            .await
            .unwrap();

        assert!(with_step_function_padding.mls_encoded_len() > without_padding.mls_encoded_len());

        let mut test_group = test_group_custom_config(protocol_version, cipher_suite, |b| {
            b.mls_rules(
                DefaultMlsRules::default()
                    .with_encryption_options(EncryptionOptions::new(true, PaddingMode::Padme)),
            )
        })
        .await;

        let with_padme_padding = test_group
            .encrypt_application_message(&random_bytes(150), vec![])
            .await
            .unwrap();

        assert!(with_padme_padding.mls_encoded_len() > without_padding.mls_encoded_len());
    }

    #[maybe_async::test(not(mls_build_async), async(mls_build_async, crate::futures_test))]
    async fn external_commit_requires_external_pub_extension() {
        let protocol_version = TEST_PROTOCOL_VERSION;
        let cipher_suite = TEST_CIPHER_SUITE;
        let group = test_group(protocol_version, cipher_suite).await;

        let info = group
            .group_info_message(false)
            .await
            .unwrap()
            .into_group_info()
            .unwrap();

        let info_msg = MlsMessage::new(protocol_version, MlsMessagePayload::GroupInfo(info));

        let signing_identity = group.current_member_signing_identity().unwrap().clone();

        let res = external_commit::ExternalCommitBuilder::new(
            group.group.signer,
            signing_identity,
            group.group.config,
        )
        .build(info_msg)
        .await
        .map(|_| {});

        assert_matches!(res, Err(MlsError::MissingExternalPubExtension));
    }

    #[maybe_async::test(not(mls_build_async), async(mls_build_async, crate::futures_test))]
    async fn external_commit_via_commit_options_round_trip() {
        let mut group = test_group_custom(
            TEST_PROTOCOL_VERSION,
            TEST_CIPHER_SUITE,
            vec![],
            None,
            CommitOptions::default()
                .with_allow_external_commit(true)
                .into(),
        )
        .await;

        let commit_output = group.commit(vec![]).await.unwrap();

        let (test_client, _) =
            test_client_with_key_pkg(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE, "bob").await;

        test_client
            .external_commit_builder()
            .unwrap()
            .build(commit_output.external_commit_group_info.unwrap())
            .await
            .unwrap();
    }

    #[maybe_async::test(not(mls_build_async), async(mls_build_async, crate::futures_test))]
    async fn test_path_update_preference() {
        let protocol_version = TEST_PROTOCOL_VERSION;
        let cipher_suite = TEST_CIPHER_SUITE;

        let mut test_group = test_group_custom(
            protocol_version,
            cipher_suite,
            Default::default(),
            None,
            Some(CommitOptions::new()),
        )
        .await;

        let test_key_package =
            test_key_package_message(protocol_version, cipher_suite, "alice").await;

        let has_path = test_group
            .commit_builder()
            .add_member(test_key_package.clone())
            .unwrap()
            .build()
            .await
            .unwrap()
            .contains_update_path;

        assert!(!has_path);

        let mut test_group = test_group_custom(
            protocol_version,
            cipher_suite,
            Default::default(),
            None,
            Some(CommitOptions::new().with_path_required(true)),
        )
        .await;

        let has_path = test_group
            .commit_builder()
            .add_member(test_key_package)
            .unwrap()
            .build()
            .await
            .unwrap()
            .contains_update_path;

        assert!(has_path)
    }

    #[maybe_async::test(not(mls_build_async), async(mls_build_async, crate::futures_test))]
    async fn test_path_update_preference_override() {
        let protocol_version = TEST_PROTOCOL_VERSION;
        let cipher_suite = TEST_CIPHER_SUITE;

        let mut test_group = test_group_custom(
            protocol_version,
            cipher_suite,
            Default::default(),
            None,
            Some(CommitOptions::new()),
        )
        .await;

        let has_path = test_group
            .commit(vec![])
            .await
            .unwrap()
            .contains_update_path;

        assert!(has_path);
    }

    #[cfg(feature = "private_message")]
    #[maybe_async::test(not(mls_build_async), async(mls_build_async, crate::futures_test))]
    async fn group_rejects_unencrypted_application_message() {
        let protocol_version = TEST_PROTOCOL_VERSION;
        let cipher_suite = TEST_CIPHER_SUITE;

        let mut alice = test_group(protocol_version, cipher_suite).await;
        let (mut bob, _) = alice.join("bob").await;

        let message = alice
            .make_plaintext(Content::Application(b"hello".to_vec().into()))
            .await;

        let res = bob.process_incoming_message(message).await;

        assert_matches!(res, Err(MlsError::UnencryptedApplicationMessage));
    }

    #[maybe_async::test(not(mls_build_async), async(mls_build_async, crate::futures_test))]
    async fn commit_description_external_commit() {
        let mut alice_group = test_group(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE).await;

        let (bob_identity, secret_key) = get_test_signing_identity(TEST_CIPHER_SUITE, b"bob").await;

        let bob = TestClientBuilder::new_for_test()
            .signing_identity(bob_identity, secret_key, TEST_CIPHER_SUITE)
            .build();

        let (bob_group, commit) = bob
            .external_commit_builder()
            .unwrap()
            .build(
                alice_group
                    .group_info_message_allowing_ext_commit(true)
                    .await
                    .unwrap(),
            )
            .await
            .unwrap();

        let event = alice_group.process_message(commit).await.unwrap();

        let ReceivedMessage::Commit(commit_description) = event else {
            panic!("expected commit");
        };

        assert!(commit_description.is_external);
        assert_eq!(commit_description.committer, 1);

        let new_epoch = match commit_description.effect {
            CommitEffect::NewEpoch(new_epoch) => new_epoch,
            _ => panic!("unexpected commit effect"),
        };

        assert_eq!(new_epoch.applied_proposals.len(), 1);

        itertools::assert_equal(
            bob_group.roster().members_iter(),
            alice_group.roster().members_iter(),
        );
    }

    #[maybe_async::test(not(mls_build_async), async(mls_build_async, crate::futures_test))]
    async fn can_join_new_group_externally() {
        use crate::client::test_utils::TestClientBuilder;

        let mut alice_group = test_group(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE).await;

        let (bob_identity, secret_key) = get_test_signing_identity(TEST_CIPHER_SUITE, b"bob").await;

        let bob = TestClientBuilder::new_for_test()
            .signing_identity(bob_identity, secret_key, TEST_CIPHER_SUITE)
            .build();

        let (_, commit) = bob
            .external_commit_builder()
            .unwrap()
            .with_tree_data(alice_group.export_tree().into_owned())
            .build(
                alice_group
                    .group_info_message_allowing_ext_commit(false)
                    .await
                    .unwrap(),
            )
            .await
            .unwrap();

        alice_group.process_message(commit).await.unwrap();
    }

    #[maybe_async::test(not(mls_build_async), async(mls_build_async, crate::futures_test))]
    async fn test_membership_tag_from_non_member() {
        let (mut alice_group, mut bob_group) =
            test_two_member_group(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE, true).await;

        let mut commit_output = alice_group.commit(vec![]).await.unwrap();

        let plaintext = match commit_output.commit_message.payload {
            MlsMessagePayload::Plain(ref mut plain) => plain,
            _ => panic!("Non plaintext message"),
        };

        plaintext.content.sender = Sender::NewMemberCommit;

        let res = bob_group
            .process_message(commit_output.commit_message)
            .await;

        assert_matches!(res, Err(MlsError::MembershipTagForNonMember));
    }

    #[maybe_async::test(not(mls_build_async), async(mls_build_async, crate::futures_test))]
    async fn test_partial_commits() {
        let protocol_version = TEST_PROTOCOL_VERSION;
        let cipher_suite = TEST_CIPHER_SUITE;

        let mut alice = test_group(protocol_version, cipher_suite).await;
        let (mut bob, _) = alice.join("bob").await;
        let (mut charlie, commit) = alice.join("charlie").await;
        bob.process_message(commit).await.unwrap();

        let (_, commit) = charlie.join("dave").await;

        alice.process_message(commit.clone()).await.unwrap();
        bob.process_message(commit.clone()).await.unwrap();

        let Content::Commit(commit) = commit.into_plaintext().unwrap().content.content else {
            panic!("Expected commit")
        };

        assert!(commit.path.is_none());
    }

    #[cfg_attr(not(mls_build_async), maybe_async::must_be_sync)]
    async fn group_with_path_required() -> TestGroup {
        let mut alice = test_group(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE).await;

        alice.config.0.mls_rules.commit_options.path_required = true;

        alice
    }

    #[maybe_async::test(not(mls_build_async), async(mls_build_async, crate::futures_test))]
    async fn old_hpke_secrets_are_removed() {
        let mut alice = group_with_path_required().await;
        alice.join("bob").await;
        alice.join("charlie").await;

        alice
            .commit_builder()
            .remove_member(1)
            .unwrap()
            .build()
            .await
            .unwrap();

        assert!(alice.private_tree.secret_keys[1].is_some());
        alice.process_pending_commit().await.unwrap();
        assert!(alice.private_tree.secret_keys[1].is_none());
    }

    #[maybe_async::test(not(mls_build_async), async(mls_build_async, crate::futures_test))]
    async fn old_hpke_secrets_of_removed_are_removed() {
        let mut alice = group_with_path_required().await;
        alice.join("bob").await;
        let (mut charlie, _) = alice.join("charlie").await;

        let commit = charlie
            .commit_builder()
            .remove_member(1)
            .unwrap()
            .build()
            .await
            .unwrap();

        assert!(alice.private_tree.secret_keys[1].is_some());
        alice.process_message(commit.commit_message).await.unwrap();
        assert!(alice.private_tree.secret_keys[1].is_none());
    }

    #[cfg(feature = "by_ref_proposal")]
    #[maybe_async::test(not(mls_build_async), async(mls_build_async, crate::futures_test))]
    async fn old_hpke_secrets_of_updated_are_removed() {
        let mut alice = group_with_path_required().await;
        let (mut bob, _) = alice.join("bob").await;
        let (mut charlie, commit) = alice.join("charlie").await;
        bob.process_message(commit).await.unwrap();

        let update = bob.propose_update(vec![]).await.unwrap();
        charlie.process_message(update.clone()).await.unwrap();
        alice.process_message(update).await.unwrap();

        let commit = charlie.commit(vec![]).await.unwrap();

        assert!(alice.private_tree.secret_keys[1].is_some());
        alice.process_message(commit.commit_message).await.unwrap();
        assert!(alice.private_tree.secret_keys[1].is_none());
    }

    #[cfg(feature = "psk")]
    #[maybe_async::test(not(mls_build_async), async(mls_build_async, crate::futures_test))]
    async fn only_selected_members_of_the_original_group_can_join_subgroup() {
        let mut alice = test_group(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE).await;
        let (mut bob, _) = alice.join("bob").await;
        let (carol, commit) = alice.join("carol").await;

        // Apply the commit that adds carol
        bob.process_incoming_message(commit).await.unwrap();

        let bob_identity = bob.current_member_signing_identity().unwrap().clone();
        let signer = bob.signer.clone();

        let new_key_pkg = Client::new(
            bob.config.clone(),
            Some(signer),
            Some((bob_identity, TEST_CIPHER_SUITE)),
            TEST_PROTOCOL_VERSION,
        )
        .generate_key_package_message(Default::default(), Default::default(), None)
        .await
        .unwrap();

        let (mut alice_sub_group, welcome) = alice
            .branch(b"subgroup".to_vec(), vec![new_key_pkg], None)
            .await
            .unwrap();

        let welcome = &welcome[0];

        let (mut bob_sub_group, _) = bob.join_subgroup(welcome, None, None).await.unwrap();

        // Carol can't join
        let res = carol.join_subgroup(welcome, None, None).await.map(|_| ());
        assert_matches!(res, Err(_));

        // Alice and Bob can still talk
        let commit_output = alice_sub_group.commit(vec![]).await.unwrap();

        bob_sub_group
            .process_incoming_message(commit_output.commit_message)
            .await
            .unwrap();
    }

    #[cfg_attr(not(mls_build_async), maybe_async::must_be_sync)]
    async fn joining_group_fails_if_unsupported<F>(
        f: F,
    ) -> Result<(TestGroup, MlsMessage), MlsError>
    where
        F: FnMut(&mut TestClientConfig),
    {
        let mut alice_group = test_group(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE).await;
        alice_group.join_with_custom_config("alice", false, f).await
    }

    #[maybe_async::test(not(mls_build_async), async(mls_build_async, crate::futures_test))]
    async fn joining_group_fails_if_protocol_version_is_not_supported() {
        let res = joining_group_fails_if_unsupported(|config| {
            config.0.settings.protocol_versions.clear();
        })
        .await
        .map(|_| ());

        assert_matches!(
            res,
            Err(MlsError::UnsupportedProtocolVersion(v)) if v ==
                TEST_PROTOCOL_VERSION
        );
    }

    // WebCrypto does not support disabling ciphersuites
    #[cfg(not(target_arch = "wasm32"))]
    #[maybe_async::test(not(mls_build_async), async(mls_build_async, crate::futures_test))]
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
            Err(MlsError::UnsupportedCipherSuite(TEST_CIPHER_SUITE))
        );
    }

    #[cfg(feature = "private_message")]
    #[maybe_async::test(not(mls_build_async), async(mls_build_async, crate::futures_test))]
    async fn member_can_see_sender_creds() {
        let mut alice_group = test_group(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE).await;
        let (mut bob_group, _) = alice_group.join("bob").await;

        let bob_msg = b"I'm Bob";

        let msg = bob_group
            .encrypt_application_message(bob_msg, vec![])
            .await
            .unwrap();

        let received_by_alice = alice_group.process_incoming_message(msg).await.unwrap();

        assert_matches!(
            received_by_alice,
            ReceivedMessage::ApplicationMessage(ApplicationMessageDescription { sender_index, .. })
                if sender_index == bob_group.current_member_index()
        );
    }

    #[maybe_async::test(not(mls_build_async), async(mls_build_async, crate::futures_test))]
    async fn members_of_a_group_have_identical_authentication_secrets() {
        let mut alice_group = test_group(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE).await;
        let (bob_group, _) = alice_group.join("bob").await;

        assert_eq!(
            alice_group.epoch_authenticator().unwrap(),
            bob_group.epoch_authenticator().unwrap()
        );
    }

    #[cfg(feature = "private_message")]
    #[maybe_async::test(not(mls_build_async), async(mls_build_async, crate::futures_test))]
    async fn member_cannot_decrypt_same_message_twice() {
        let mut alice_group = test_group(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE).await;
        let (mut bob_group, _) = alice_group.join("bob").await;

        let message = alice_group
            .encrypt_application_message(b"foobar", Vec::new())
            .await
            .unwrap();

        let received_message = bob_group
            .process_incoming_message(message.clone())
            .await
            .unwrap();

        assert_matches!(
            received_message,
            ReceivedMessage::ApplicationMessage(m) if m.data() == b"foobar"
        );

        let res = bob_group.process_incoming_message(message).await;

        assert_matches!(res, Err(MlsError::KeyMissing(0)));
    }

    #[maybe_async::test(not(mls_build_async), async(mls_build_async, crate::futures_test))]
    async fn removing_requirements_allows_to_add() {
        let mut alice_group = test_group_custom(
            TEST_PROTOCOL_VERSION,
            TEST_CIPHER_SUITE,
            vec![17.into()],
            None,
            None,
        )
        .await;

        alice_group
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

        let test_key_package =
            test_key_package(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE, "bob").await;

        let test_key_package = MlsMessage::new(
            TEST_PROTOCOL_VERSION,
            MlsMessagePayload::KeyPackage(test_key_package),
        );

        alice_group
            .commit_builder()
            .add_member(test_key_package.clone())
            .unwrap()
            .set_group_context_ext(Default::default())
            .unwrap()
            .build()
            .await
            .unwrap();

        let CommitEffect::NewEpoch(new_epoch) =
            alice_group.process_pending_commit().await.unwrap().effect
        else {
            panic!("unexpected commit effect")
        };

        assert_eq!(new_epoch.applied_proposals.len(), 2);

        assert_matches!(
            new_epoch.applied_proposals[0],
            ProposalInfo { proposal: Proposal::Add(ref add), .. }
                if add.key_package == test_key_package.into_key_package().unwrap()
        );

        assert_eq!(alice_group.roster().members_iter().count(), 2);
    }

    #[maybe_async::test(not(mls_build_async), async(mls_build_async, crate::futures_test))]
    async fn commit_leaf_wrong_source() {
        // RFC, 13.4.2. "The leaf_node_source field MUST be set to commit."
        let mut groups = test_n_member_group(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE, 3).await;

        groups[0].commit_modifiers.modify_leaf = |leaf, sk| {
            leaf.leaf_node_source = LeafNodeSource::Update;
            Some(sk.clone())
        };

        let commit_output = groups[0].commit(vec![]).await.unwrap();

        let res = groups[2]
            .process_message(commit_output.commit_message)
            .await;

        assert_matches!(res, Err(MlsError::InvalidLeafNodeSource));
    }

    #[maybe_async::test(not(mls_build_async), async(mls_build_async, crate::futures_test))]
    async fn commit_leaf_same_hpke_key() {
        // RFC 13.4.2. "Verify that the encryption_key value in the LeafNode is different from the committer's current leaf node"

        let mut groups = test_n_member_group(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE, 3).await;

        // Group 0 starts using fixed key
        groups[0].commit_modifiers.modify_leaf = |leaf, sk| {
            leaf.public_key = get_test_25519_key(1u8);
            Some(sk.clone())
        };

        let commit_output = groups[0].commit(vec![]).await.unwrap();
        groups[0].process_pending_commit().await.unwrap();
        groups[2]
            .process_message(commit_output.commit_message)
            .await
            .unwrap();

        // Group 0 tries to use the fixed key againd
        let commit_output = groups[0].commit(vec![]).await.unwrap();

        let res = groups[2]
            .process_message(commit_output.commit_message)
            .await;

        assert_matches!(res, Err(MlsError::SameHpkeKey(0)));
    }

    #[maybe_async::test(not(mls_build_async), async(mls_build_async, crate::futures_test))]
    async fn commit_leaf_duplicate_hpke_key() {
        // RFC 8.3 "Verify that the following fields are unique among the members of the group: `encryption_key`"

        if TEST_CIPHER_SUITE != CipherSuite::CURVE25519_AES128
            && TEST_CIPHER_SUITE != CipherSuite::CURVE25519_CHACHA
        {
            return;
        }

        let mut groups = test_n_member_group(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE, 10).await;

        // Group 1 uses the fixed key
        groups[1].commit_modifiers.modify_leaf = |leaf, sk| {
            leaf.public_key = get_test_25519_key(1u8);
            Some(sk.clone())
        };

        let commit_output = groups.get_mut(1).unwrap().commit(vec![]).await.unwrap();

        process_commit(&mut groups, commit_output.commit_message, 1).await;

        // Group 0 tries to use the fixed key too
        groups[0].commit_modifiers.modify_leaf = |leaf, sk| {
            leaf.public_key = get_test_25519_key(1u8);
            Some(sk.clone())
        };

        let commit_output = groups[0].commit(vec![]).await.unwrap();

        let res = groups[7]
            .process_message(commit_output.commit_message)
            .await;

        assert_matches!(res, Err(MlsError::DuplicateLeafData(_)));
    }

    #[maybe_async::test(not(mls_build_async), async(mls_build_async, crate::futures_test))]
    async fn commit_leaf_duplicate_signature_key() {
        // RFC 8.3 "Verify that the following fields are unique among the members of the group: `signature_key`"

        if TEST_CIPHER_SUITE != CipherSuite::CURVE25519_AES128
            && TEST_CIPHER_SUITE != CipherSuite::CURVE25519_CHACHA
        {
            return;
        }

        let mut groups = test_n_member_group(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE, 10).await;

        // Group 1 uses the fixed key
        groups[1].commit_modifiers.modify_leaf = |leaf, _| {
            let sk = hex!(
                "3468b4c890255c983e3d5cbf5cb64c1ef7f6433a518f2f3151d6672f839a06ebcad4fc381fe61822af45135c82921a348e6f46643d66ddefc70483565433714b"
            )
            .into();

            leaf.signing_identity.signature_key =
                hex!("cad4fc381fe61822af45135c82921a348e6f46643d66ddefc70483565433714b").into();

            Some(sk)
        };

        let commit_output = groups.get_mut(1).unwrap().commit(vec![]).await.unwrap();

        process_commit(&mut groups, commit_output.commit_message, 1).await;

        // Group 0 tries to use the fixed key too
        groups[0].commit_modifiers.modify_leaf = |leaf, _| {
            let sk = hex!(
                "3468b4c890255c983e3d5cbf5cb64c1ef7f6433a518f2f3151d6672f839a06ebcad4fc381fe61822af45135c82921a348e6f46643d66ddefc70483565433714b"
            )
            .into();

            leaf.signing_identity.signature_key =
                hex!("cad4fc381fe61822af45135c82921a348e6f46643d66ddefc70483565433714b").into();

            Some(sk)
        };

        let commit_output = groups[0].commit(vec![]).await.unwrap();

        let res = groups[7]
            .process_message(commit_output.commit_message)
            .await;

        assert_matches!(res, Err(MlsError::DuplicateLeafData(_)));
    }

    #[maybe_async::test(not(mls_build_async), async(mls_build_async, crate::futures_test))]
    async fn commit_leaf_incorrect_signature() {
        let mut groups = test_n_member_group(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE, 3).await;

        groups[0].commit_modifiers.modify_leaf = |leaf, _| {
            leaf.signature[0] ^= 1;
            None
        };

        let commit_output = groups[0].commit(vec![]).await.unwrap();

        let res = groups[2]
            .process_message(commit_output.commit_message)
            .await;

        assert_matches!(res, Err(MlsError::InvalidSignature));
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[maybe_async::test(not(mls_build_async), async(mls_build_async, crate::futures_test))]
    async fn commit_leaf_not_supporting_used_context_extension() {
        const EXT_TYPE: ExtensionType = ExtensionType::new(999);

        // The new leaf of the committer doesn't support an extension set in group context
        let extension = Extension::new(EXT_TYPE, vec![]);

        let mut groups =
            get_test_groups_with_features(3, vec![extension].into(), Default::default()).await;

        groups[0].commit_modifiers.modify_leaf = |leaf, sk| {
            leaf.capabilities = get_test_capabilities();
            Some(sk.clone())
        };

        let commit_output = groups[0].commit(vec![]).await.unwrap();

        let res = groups[1]
            .process_incoming_message(commit_output.commit_message)
            .await;

        assert_matches!(res, Err(MlsError::UnsupportedGroupExtension(EXT_TYPE)));
    }

    #[maybe_async::test(not(mls_build_async), async(mls_build_async, crate::futures_test))]
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

        groups[0].commit_modifiers.modify_leaf = |leaf, sk| {
            leaf.capabilities = Capabilities::default();
            Some(sk.clone())
        };

        let commit_output = groups[0].commit(vec![]).await.unwrap();

        let res = groups[2]
            .process_incoming_message(commit_output.commit_message)
            .await;

        assert!(res.is_err());
    }

    #[maybe_async::test(not(mls_build_async), async(mls_build_async, crate::futures_test))]
    async fn commit_leaf_has_unsupported_credential() {
        // The new leaf of the committer has a credential unsupported by another leaf
        let mut groups =
            get_test_groups_with_features(3, Default::default(), Default::default()).await;

        for group in groups.iter_mut() {
            group.config.0.identity_provider.allow_any_custom = true;
        }

        groups[0].commit_modifiers.modify_leaf = |leaf, sk| {
            leaf.signing_identity.credential = Credential::Custom(CustomCredential::new(
                CredentialType::new(43),
                leaf.signing_identity
                    .credential
                    .as_basic()
                    .unwrap()
                    .identifier
                    .to_vec(),
            ));

            Some(sk.clone())
        };

        let commit_output = groups[0].commit(vec![]).await.unwrap();

        let res = groups[2]
            .process_incoming_message(commit_output.commit_message)
            .await;

        assert_matches!(res, Err(MlsError::CredentialTypeOfNewLeafIsUnsupported));
    }

    #[maybe_async::test(not(mls_build_async), async(mls_build_async, crate::futures_test))]
    async fn commit_leaf_not_supporting_credential_used_in_another_leaf() {
        // The new leaf of the committer doesn't support another leaf's credential

        let mut groups =
            get_test_groups_with_features(3, Default::default(), Default::default()).await;

        groups[0].commit_modifiers.modify_leaf = |leaf, sk| {
            leaf.capabilities.credentials = vec![2.into()];
            Some(sk.clone())
        };

        let commit_output = groups[0].commit(vec![]).await.unwrap();

        let res = groups[2]
            .process_incoming_message(commit_output.commit_message)
            .await;

        assert_matches!(res, Err(MlsError::InUseCredentialTypeUnsupportedByNewLeaf));
    }

    #[maybe_async::test(not(mls_build_async), async(mls_build_async, crate::futures_test))]
    async fn commit_leaf_not_supporting_required_credential() {
        // The new leaf of the committer doesn't support a credential required by group context

        let extension = RequiredCapabilitiesExt {
            extensions: vec![],
            proposals: vec![],
            credentials: vec![1.into()],
        };

        let extensions = vec![extension.into_extension().unwrap()];
        let mut groups =
            get_test_groups_with_features(3, extensions.into(), Default::default()).await;

        groups[0].commit_modifiers.modify_leaf = |leaf, sk| {
            leaf.capabilities.credentials = vec![2.into()];
            Some(sk.clone())
        };

        let commit_output = groups[0].commit(vec![]).await.unwrap();

        let res = groups[2]
            .process_incoming_message(commit_output.commit_message)
            .await;

        assert_matches!(res, Err(MlsError::RequiredCredentialNotFound(_)));
    }

    #[cfg(feature = "by_ref_proposal")]
    #[cfg(not(target_arch = "wasm32"))]
    #[cfg_attr(not(mls_build_async), maybe_async::must_be_sync)]
    async fn make_x509_external_senders_ext() -> ExternalSendersExt {
        let (_, ext_sender_pk) = test_cipher_suite_provider(TEST_CIPHER_SUITE)
            .signature_key_generate()
            .await
            .unwrap();

        let ext_sender_id = SigningIdentity {
            signature_key: ext_sender_pk,
            credential: Credential::X509(CertificateChain::from(vec![random_bytes(32)])),
        };

        ExternalSendersExt::new(vec![ext_sender_id])
    }

    #[cfg(feature = "by_ref_proposal")]
    #[cfg(not(target_arch = "wasm32"))]
    #[maybe_async::test(not(mls_build_async), async(mls_build_async, crate::futures_test))]
    async fn commit_leaf_not_supporting_external_sender_credential_leads_to_rejected_commit() {
        let ext_senders = make_x509_external_senders_ext()
            .await
            .into_extension()
            .unwrap();

        let mut alice = ClientBuilder::new()
            .crypto_provider(TestCryptoProvider::new())
            .identity_provider(
                BasicWithCustomProvider::default().with_credential_type(CredentialType::X509),
            )
            .with_random_signing_identity("alice", TEST_CIPHER_SUITE)
            .await
            .build()
            .create_group(vec![ext_senders].into(), Default::default(), None)
            .await
            .unwrap();

        let bob = ClientBuilder::new()
            .crypto_provider(TestCryptoProvider::new())
            .identity_provider(
                BasicWithCustomProvider::default().with_credential_type(CredentialType::X509),
            )
            .with_random_signing_identity("bob", TEST_CIPHER_SUITE)
            .await
            .build();

        let kp = bob
            .generate_key_package_message(Default::default(), Default::default(), None)
            .await
            .unwrap();

        let commit = alice
            .commit_builder()
            .add_member(kp)
            .unwrap()
            .build()
            .await
            .unwrap();

        let (mut bob, _) = bob
            .join_group(None, &commit.welcome_messages[0], None)
            .await
            .unwrap();

        alice.apply_pending_commit().await.unwrap();

        // New leaf supports only basic credentials (used by the group) but not X509 used by external sender
        alice.commit_modifiers.modify_leaf = |leaf, sk| {
            leaf.capabilities.credentials = vec![CredentialType::BASIC];
            Some(sk.clone())
        };

        let commit = alice.commit(vec![]).await.unwrap();
        let res = bob.process_incoming_message(commit.commit_message).await;

        assert_matches!(
            res,
            Err(MlsError::RequiredCredentialNotFound(CredentialType::X509))
        );
    }

    #[cfg(feature = "by_ref_proposal")]
    #[cfg(not(target_arch = "wasm32"))]
    #[maybe_async::test(not(mls_build_async), async(mls_build_async, crate::futures_test))]
    async fn node_not_supporting_external_sender_credential_cannot_join_group() {
        let ext_senders = make_x509_external_senders_ext()
            .await
            .into_extension()
            .unwrap();

        let mut alice = ClientBuilder::new()
            .crypto_provider(TestCryptoProvider::new())
            .identity_provider(
                BasicWithCustomProvider::default().with_credential_type(CredentialType::X509),
            )
            .with_random_signing_identity("alice", TEST_CIPHER_SUITE)
            .await
            .build()
            .create_group(
                core::iter::once(ext_senders).collect(),
                Default::default(),
                None,
            )
            .await
            .unwrap();

        let (_, bob_key_pkg) =
            test_client_with_key_pkg(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE, "bob").await;

        let commit = alice
            .commit_builder()
            .add_member(bob_key_pkg)
            .unwrap()
            .build()
            .await;

        assert_matches!(
            commit,
            Err(MlsError::RequiredCredentialNotFound(CredentialType::X509))
        );
    }

    #[cfg(feature = "by_ref_proposal")]
    #[cfg(not(target_arch = "wasm32"))]
    #[maybe_async::test(not(mls_build_async), async(mls_build_async, crate::futures_test))]
    async fn external_senders_extension_is_rejected_if_member_does_not_support_credential_type() {
        let mut alice = ClientBuilder::new()
            .crypto_provider(TestCryptoProvider::new())
            .identity_provider(
                BasicWithCustomProvider::default().with_credential_type(CredentialType::X509),
            )
            .with_random_signing_identity("alice", TEST_CIPHER_SUITE)
            .await
            .build()
            .create_group(Default::default(), Default::default(), None)
            .await
            .unwrap();

        let (_, bob_key_pkg) =
            test_client_with_key_pkg(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE, "bob").await;

        alice
            .commit_builder()
            .add_member(bob_key_pkg)
            .unwrap()
            .build()
            .await
            .unwrap();

        alice.apply_pending_commit().await.unwrap();
        assert_eq!(alice.roster().members_iter().count(), 2);

        let ext_senders = make_x509_external_senders_ext()
            .await
            .into_extension()
            .unwrap();

        let res = alice
            .commit_builder()
            .set_group_context_ext(core::iter::once(ext_senders).collect())
            .unwrap()
            .build()
            .await;

        assert_matches!(
            res,
            Err(MlsError::RequiredCredentialNotFound(CredentialType::X509))
        );
    }

    /*
     * Edge case paths
     */

    #[maybe_async::test(not(mls_build_async), async(mls_build_async, crate::futures_test))]
    async fn committing_degenerate_path_succeeds() {
        let mut groups = test_n_member_group(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE, 10).await;

        groups[0].commit_modifiers.modify_tree = |tree: &mut TreeKemPublic| {
            tree.update_node(get_test_25519_key(1u8), 1).unwrap();
            tree.update_node(get_test_25519_key(1u8), 3).unwrap();
        };

        groups[0].commit_modifiers.modify_leaf = |leaf, sk| {
            leaf.public_key = get_test_25519_key(1u8);
            Some(sk.clone())
        };

        let commit_output = groups[0].commit(vec![]).await.unwrap();

        let res = groups[7]
            .process_message(commit_output.commit_message)
            .await;

        assert!(res.is_ok());
    }

    #[maybe_async::test(not(mls_build_async), async(mls_build_async, crate::futures_test))]
    async fn inserting_key_in_filtered_node_fails() {
        let mut groups = test_n_member_group(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE, 10).await;

        let commit_output = groups[0]
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

        groups[0].commit_modifiers.modify_tree = |tree: &mut TreeKemPublic| {
            tree.update_node(get_test_25519_key(1u8), 1).unwrap();
        };

        groups[0].commit_modifiers.modify_path = |path: Vec<UpdatePathNode>| {
            let mut path = path;
            let mut node = path[0].clone();
            node.public_key = get_test_25519_key(1u8);
            path.insert(0, node);
            path
        };

        let commit_output = groups[0].commit(vec![]).await.unwrap();

        let res = groups[7]
            .process_message(commit_output.commit_message)
            .await;

        // We should get a path validation error, since the path is too long
        assert_matches!(res, Err(MlsError::WrongPathLen));
    }

    #[maybe_async::test(not(mls_build_async), async(mls_build_async, crate::futures_test))]
    async fn commit_with_too_short_path_fails() {
        let mut groups = test_n_member_group(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE, 10).await;

        let commit_output = groups[0]
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

        groups[0].commit_modifiers.modify_path = |path: Vec<UpdatePathNode>| {
            let mut path = path;
            path.pop();
            path
        };

        let commit_output = groups[0].commit(vec![]).await.unwrap();

        let res = groups[7]
            .process_message(commit_output.commit_message)
            .await;

        assert!(res.is_err());
    }

    #[cfg(feature = "by_ref_proposal")]
    #[maybe_async::test(not(mls_build_async), async(mls_build_async, crate::futures_test))]
    async fn update_proposal_can_change_credential() {
        let mut groups = test_n_member_group(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE, 3).await;
        let (identity, secret_key) = get_test_signing_identity(TEST_CIPHER_SUITE, b"member").await;

        let update = groups[0]
            .propose_update_with_identity(secret_key, identity.clone(), vec![])
            .await
            .unwrap();

        groups[1].process_message(update).await.unwrap();
        let commit_output = groups[1].commit(vec![]).await.unwrap();

        // Check that the credential was updated by in the committer's state.
        groups[1].process_pending_commit().await.unwrap();
        let new_member = groups[1].roster().member_with_index(0).unwrap();

        assert_eq!(
            new_member.signing_identity.credential,
            get_test_basic_credential(b"member".to_vec())
        );

        assert_eq!(
            new_member.signing_identity.signature_key,
            identity.signature_key
        );

        // Check that the credential was updated in the updater's state.
        groups[0]
            .process_message(commit_output.commit_message)
            .await
            .unwrap();
        let new_member = groups[0].roster().member_with_index(0).unwrap();

        assert_eq!(
            new_member.signing_identity.credential,
            get_test_basic_credential(b"member".to_vec())
        );

        assert_eq!(
            new_member.signing_identity.signature_key,
            identity.signature_key
        );
    }

    #[cfg(feature = "by_ref_proposal")]
    #[maybe_async::test(not(mls_build_async), async(mls_build_async, crate::futures_test))]
    async fn receiving_commit_with_old_adds_fails() {
        let mut groups = test_n_member_group(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE, 2).await;

        let key_package =
            test_key_package_message(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE, "foobar").await;

        let proposal = groups[0].propose_add(key_package, vec![]).await.unwrap();

        let commit = groups[0].commit(vec![]).await.unwrap().commit_message;

        // 10 years from now
        let future_time = MlsTime::now().seconds_since_epoch() + 10 * 365 * 24 * 3600;

        let future_time =
            MlsTime::from_duration_since_epoch(core::time::Duration::from_secs(future_time));

        groups[1].process_incoming_message(proposal).await.unwrap();
        let res = groups[1]
            .process_incoming_message_with_time(commit, future_time)
            .await;

        assert_matches!(
            res,
            Err(MlsError::InvalidLifetime { timestamp, .. })
                if timestamp == future_time
        );
    }

    #[maybe_async::test(not(mls_build_async), async(mls_build_async, crate::futures_test))]
    async fn can_process_commit_from_self_with_time() {
        let mut alice = test_group(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE).await;

        let commit = alice.commit(Vec::new()).await.unwrap();
        assert!(alice.has_pending_commit());

        alice
            .process_incoming_message_with_time(commit.commit_message, MlsTime::now())
            .await
            .unwrap();
    }

    #[cfg(feature = "custom_proposal")]
    #[cfg_attr(not(mls_build_async), maybe_async::must_be_sync)]
    async fn custom_proposal_setup() -> (TestGroup, TestGroup) {
        let mut alice = test_group_custom_config(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE, |b| {
            b.custom_proposal_type(TEST_CUSTOM_PROPOSAL_TYPE)
        })
        .await;

        let (bob, _) = alice
            .join_with_custom_config("bob", true, |c| {
                c.0.settings
                    .custom_proposal_types
                    .push(TEST_CUSTOM_PROPOSAL_TYPE)
            })
            .await
            .unwrap();

        (alice, bob)
    }

    #[cfg(all(
        feature = "by_ref_proposal",
        feature = "custom_proposal",
        feature = "self_remove_proposal"
    ))]
    #[cfg_attr(not(mls_build_async), maybe_async::must_be_sync)]
    async fn self_remove_group_setup() -> (TestGroup, TestGroup) {
        let mut alice = test_group_custom_config(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE, |b| {
            b.custom_proposal_type(ProposalType::SELF_REMOVE)
        })
        .await;

        let (bob, _) = alice
            .join_with_custom_config("bob", true, |c| {
                c.0.settings
                    .custom_proposal_types
                    .push(ProposalType::SELF_REMOVE)
            })
            .await
            .unwrap();

        (alice, bob)
    }

    #[cfg(feature = "custom_proposal")]
    #[maybe_async::test(not(mls_build_async), async(mls_build_async, crate::futures_test))]
    async fn custom_proposal_by_value() {
        let (mut alice, mut bob) = custom_proposal_setup().await;

        let custom_proposal = CustomProposal::new(TEST_CUSTOM_PROPOSAL_TYPE, vec![0, 1, 2]);

        let commit = alice
            .commit_builder()
            .custom_proposal(custom_proposal.clone())
            .build()
            .await
            .unwrap()
            .commit_message;

        let ReceivedMessage::Commit(CommitMessageDescription {
            effect: CommitEffect::NewEpoch(new_epoch),
            ..
        }) = bob.process_incoming_message(commit).await.unwrap()
        else {
            panic!("unexpected commit effect");
        };

        assert_eq!(new_epoch.applied_proposals.len(), 1);

        assert_eq!(
            new_epoch.applied_proposals[0].proposal,
            Proposal::Custom(custom_proposal)
        );
    }

    #[cfg(feature = "custom_proposal")]
    #[maybe_async::test(not(mls_build_async), async(mls_build_async, crate::futures_test))]
    async fn custom_proposal_by_reference() {
        let (mut alice, mut bob) = custom_proposal_setup().await;

        let custom_proposal = CustomProposal::new(TEST_CUSTOM_PROPOSAL_TYPE, vec![0, 1, 2]);

        let proposal = alice
            .propose_custom(custom_proposal.clone(), vec![])
            .await
            .unwrap();

        let recv_prop = bob.process_incoming_message(proposal).await.unwrap();

        assert_matches!(recv_prop, ReceivedMessage::Proposal(ProposalMessageDescription { proposal: Proposal::Custom(c), ..})
            if c == custom_proposal);

        let commit = bob.commit(vec![]).await.unwrap().commit_message;

        let ReceivedMessage::Commit(CommitMessageDescription {
            effect: CommitEffect::NewEpoch(new_epoch),
            ..
        }) = bob.process_incoming_message(commit).await.unwrap()
        else {
            panic!("unexpected commit effect");
        };

        assert_eq!(new_epoch.applied_proposals.len(), 1);

        assert_eq!(
            new_epoch.applied_proposals[0].proposal,
            Proposal::Custom(custom_proposal)
        );
    }

    #[cfg(feature = "psk")]
    #[maybe_async::test(not(mls_build_async), async(mls_build_async, crate::futures_test))]
    async fn can_join_with_psk() {
        let mut alice = test_group(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE).await;

        let (bob, key_pkg) =
            test_client_with_key_pkg(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE, "bob").await;

        let psk_id = ExternalPskId::new(vec![0]);
        let psk = PreSharedKey::from(vec![0]);

        alice
            .config
            .secret_store()
            .insert(psk_id.clone(), psk.clone());

        bob.config.secret_store().insert(psk_id.clone(), psk);

        let commit = alice
            .commit_builder()
            .add_member(key_pkg)
            .unwrap()
            .add_external_psk(psk_id)
            .unwrap()
            .build()
            .await
            .unwrap();

        bob.join_group(None, &commit.welcome_messages[0], None)
            .await
            .unwrap();
    }

    #[cfg(feature = "by_ref_proposal")]
    #[maybe_async::test(not(mls_build_async), async(mls_build_async, crate::futures_test))]
    async fn invalid_update_does_not_prevent_other_updates() {
        const EXTENSION_TYPE: ExtensionType = ExtensionType::new(33);

        let group_extensions = ExtensionList::from(vec![RequiredCapabilitiesExt {
            extensions: vec![EXTENSION_TYPE],
            ..Default::default()
        }
        .into_extension()
        .unwrap()]);

        // Alice creates a group requiring support for an extension
        let mut alice = TestClientBuilder::new_for_test()
            .with_random_signing_identity("alice", TEST_CIPHER_SUITE)
            .await
            .extension_type(EXTENSION_TYPE)
            .build()
            .create_group(group_extensions.clone(), Default::default(), None)
            .await
            .unwrap();

        let (bob_signing_identity, bob_secret_key) =
            get_test_signing_identity(TEST_CIPHER_SUITE, b"bob").await;

        let bob_client = TestClientBuilder::new_for_test()
            .signing_identity(
                bob_signing_identity.clone(),
                bob_secret_key.clone(),
                TEST_CIPHER_SUITE,
            )
            .extension_type(EXTENSION_TYPE)
            .build();

        let carol_client = TestClientBuilder::new_for_test()
            .with_random_signing_identity("carol", TEST_CIPHER_SUITE)
            .await
            .extension_type(EXTENSION_TYPE)
            .build();

        let dave_client = TestClientBuilder::new_for_test()
            .with_random_signing_identity("dave", TEST_CIPHER_SUITE)
            .await
            .extension_type(EXTENSION_TYPE)
            .build();

        // Alice adds Bob, Carol and Dave to the group. They all support the mandatory extension.
        let commit = alice
            .commit_builder()
            .add_member(
                bob_client
                    .generate_key_package_message(Default::default(), Default::default(), None)
                    .await
                    .unwrap(),
            )
            .unwrap()
            .add_member(
                carol_client
                    .generate_key_package_message(Default::default(), Default::default(), None)
                    .await
                    .unwrap(),
            )
            .unwrap()
            .add_member(
                dave_client
                    .generate_key_package_message(Default::default(), Default::default(), None)
                    .await
                    .unwrap(),
            )
            .unwrap()
            .build()
            .await
            .unwrap();

        alice.apply_pending_commit().await.unwrap();

        let mut bob = bob_client
            .join_group(None, &commit.welcome_messages[0], None)
            .await
            .unwrap()
            .0;

        bob.write_to_storage().await.unwrap();

        // Bob reloads his group data, but with parameters that will cause his generated leaves to
        // not support the mandatory extension.
        let mut bob = TestClientBuilder::new_for_test()
            .signing_identity(bob_signing_identity, bob_secret_key, TEST_CIPHER_SUITE)
            .key_package_repo(bob.config.key_package_repo())
            .group_state_storage(bob.config.group_state_storage())
            .build()
            .load_group(alice.group_id())
            .await
            .unwrap();

        let mut carol = carol_client
            .join_group(None, &commit.welcome_messages[0], None)
            .await
            .unwrap()
            .0;

        let mut dave = dave_client
            .join_group(None, &commit.welcome_messages[0], None)
            .await
            .unwrap()
            .0;

        // Bob's updated leaf does not support the mandatory extension.
        let bob_update = bob.propose_update(Vec::new()).await.unwrap();
        let carol_update = carol.propose_update(Vec::new()).await.unwrap();
        let dave_update = dave.propose_update(Vec::new()).await.unwrap();

        // Alice receives the update proposals to be committed.
        alice.process_incoming_message(bob_update).await.unwrap();
        alice.process_incoming_message(carol_update).await.unwrap();
        alice.process_incoming_message(dave_update).await.unwrap();

        // Alice commits the update proposals.
        alice.commit(Vec::new()).await.unwrap();

        let CommitEffect::NewEpoch(new_epoch) = alice.apply_pending_commit().await.unwrap().effect
        else {
            panic!("unexpected commit effect");
        };

        let find_update_for = |id: &str| {
            new_epoch
                .applied_proposals
                .iter()
                .filter_map(|p| match p.proposal {
                    Proposal::Update(ref u) => u.signing_identity().credential.as_basic(),
                    _ => None,
                })
                .any(|c| c.identifier == id.as_bytes())
        };

        // Carol's and Dave's updates should be part of the commit.
        assert!(find_update_for("carol"));
        assert!(find_update_for("dave"));

        // Bob's update should be rejected.
        assert!(!find_update_for("bob"));

        // Check that all members are still in the group.
        let all_members_are_in = alice
            .roster()
            .members_iter()
            .zip(["alice", "bob", "carol", "dave"])
            .all(|(member, id)| {
                member
                    .signing_identity
                    .credential
                    .as_basic()
                    .unwrap()
                    .identifier
                    == id.as_bytes()
            });

        assert!(all_members_are_in);
    }

    #[cfg(all(
        feature = "by_ref_proposal",
        feature = "custom_proposal",
        feature = "self_remove_proposal"
    ))]
    #[maybe_async::test(not(mls_build_async), async(mls_build_async, crate::futures_test))]
    async fn client_cannot_propose_self_remove_twice() {
        let mut alice = TestClientBuilder::new_for_test()
            .with_random_signing_identity("alice", TEST_CIPHER_SUITE)
            .await
            .custom_proposal_type(ProposalType::SELF_REMOVE)
            .build()
            .create_group(ExtensionList::new(), Default::default(), None)
            .await
            .unwrap();

        alice.propose_self_remove(Vec::new()).await.unwrap();
        let again = alice.propose_self_remove(Vec::new()).await;
        assert_matches!(again, Err(MlsError::SelfRemoveAlreadyProposed));
    }

    #[cfg(all(
        feature = "by_ref_proposal",
        feature = "custom_proposal",
        feature = "self_remove_proposal"
    ))]
    #[maybe_async::test(not(mls_build_async), async(mls_build_async, crate::futures_test))]
    async fn client_can_self_remove_and_another_client_can_commit() {
        let (mut alice, mut bob) = self_remove_group_setup().await;

        let carol_client = TestClientBuilder::new_for_test()
            .with_random_signing_identity("carol", TEST_CIPHER_SUITE)
            .await
            .custom_proposal_type(ProposalType::SELF_REMOVE)
            .build();

        // Alice adds Carol to the group.
        let commit = alice
            .commit_builder()
            .add_member(
                carol_client
                    .generate_key_package_message(Default::default(), Default::default(), None)
                    .await
                    .unwrap(),
            )
            .unwrap()
            .build()
            .await
            .unwrap();

        alice.apply_pending_commit().await.unwrap();
        bob.process_incoming_message(commit.commit_message)
            .await
            .unwrap();

        let mut carol = carol_client
            .join_group(None, &commit.welcome_messages[0], None)
            .await
            .unwrap()
            .0;

        // Bob proposes self-remove.
        let bob_self_remove = bob.propose_self_remove(Vec::new()).await.unwrap();

        // Alice receives the self-remove proposal to be committed.
        // Carol also receives the self-remove proposal. Carol will need this in order
        // to process the commit including the proposal, because self-remove proposals
        // are included by reference.
        alice
            .process_incoming_message(bob_self_remove.clone())
            .await
            .unwrap();
        carol
            .process_incoming_message(bob_self_remove)
            .await
            .unwrap();

        // Alice commits Bob's self-remove.
        let commit = alice.commit(Vec::new()).await.unwrap();
        alice.apply_pending_commit().await.unwrap();

        // Assert that after applying the commit removing Bob, that Bob is no longer in the group.
        let expected_members = vec![
            alice.member_at_index(alice.current_member_index()).unwrap(),
            carol.member_at_index(carol.current_member_index()).unwrap(),
        ];
        itertools::assert_equal(alice.roster().members_iter(), expected_members.clone());

        // Assert that Carol can also process the commit and it removes Bob from the group.
        carol
            .process_incoming_message(commit.commit_message.clone())
            .await
            .unwrap();
        itertools::assert_equal(carol.roster().members_iter(), expected_members.clone());
        // Assert that Bob can process the commit.
        bob.process_incoming_message(commit.commit_message)
            .await
            .unwrap();
    }

    #[cfg(all(
        feature = "by_ref_proposal",
        feature = "custom_proposal",
        feature = "self_remove_proposal"
    ))]
    #[maybe_async::test(not(mls_build_async), async(mls_build_async, crate::futures_test))]
    async fn commit_with_both_remove_and_self_remove_for_same_client_leaves_remove_unused() {
        let (mut alice, mut bob) = self_remove_group_setup().await;

        // Bob proposes self-remove.
        let bob_self_remove = bob.propose_self_remove(Vec::new()).await.unwrap();

        // Alice receives the self-remove proposal to be committed.
        alice
            .process_incoming_message(bob_self_remove.clone())
            .await
            .unwrap();

        // Alice also removes Bob with a regular remove proposal.
        alice.propose_remove(1, Vec::new()).await.unwrap();

        // Alice commits Bob's self-remove and Alice's removal of Bob. This filters out the remove proposal.
        let commit = alice.commit(Vec::new()).await.unwrap();
        let unused = &commit.unused_proposals[0];

        let expected_index = LeafIndex::unchecked(1);

        assert_matches!(
            unused,
            ProposalInfo {
                proposal: Proposal::Remove(RemoveProposal {
                    to_remove: i,
                }),
                sender: Sender::Member(0),
                ..
            }
        if *i == expected_index);
    }

    #[cfg(all(
        feature = "by_ref_proposal",
        feature = "custom_proposal",
        feature = "self_remove_proposal"
    ))]
    #[maybe_async::test(not(mls_build_async), async(mls_build_async, crate::futures_test))]
    async fn client_processing_commit_with_self_remove_without_processing_proposal_first_errors() {
        let (mut alice, mut bob) = self_remove_group_setup().await;

        let carol_client = TestClientBuilder::new_for_test()
            .with_random_signing_identity("carol", TEST_CIPHER_SUITE)
            .await
            .custom_proposal_type(ProposalType::SELF_REMOVE)
            .build();

        // Alice adds Carol.
        let commit = alice
            .commit_builder()
            .add_member(
                carol_client
                    .generate_key_package_message(Default::default(), Default::default(), None)
                    .await
                    .unwrap(),
            )
            .unwrap()
            .build()
            .await
            .unwrap();
        let mut carol = carol_client
            .join_group(None, &commit.welcome_messages[0], None)
            .await
            .unwrap()
            .0;
        alice
            .process_incoming_message(commit.commit_message.clone())
            .await
            .unwrap();
        bob.process_incoming_message(commit.commit_message)
            .await
            .unwrap();

        // Bob proposes self-remove.
        let bob_self_remove = bob.propose_self_remove(Vec::new()).await.unwrap();

        // Alice receives the self-remove proposal to be committed.
        alice
            .process_incoming_message(bob_self_remove.clone())
            .await
            .unwrap();

        let remove_bob_commit = alice.commit(Vec::new()).await.unwrap();

        // Carol has not processed Bob's self-remove proposal,
        // and so the by-ref proposal is not found.
        let carol_attempts_commit_processing = carol
            .process_incoming_message(remove_bob_commit.commit_message)
            .await;
        assert_matches!(
            carol_attempts_commit_processing,
            Err(MlsError::ProposalNotFound)
        );
    }

    #[cfg(all(
        feature = "by_ref_proposal",
        feature = "custom_proposal",
        feature = "self_remove_proposal"
    ))]
    #[maybe_async::test(not(mls_build_async), async(mls_build_async, crate::futures_test))]
    async fn external_commit_can_have_self_remove() {
        let (mut alice, mut bob) = self_remove_group_setup().await;

        let carol_client = TestClientBuilder::new_for_test()
            .with_random_signing_identity("carol", TEST_CIPHER_SUITE)
            .await
            .custom_proposal_type(ProposalType::SELF_REMOVE)
            .build();

        // Alice adds Carol.
        let commit = alice
            .commit_builder()
            .add_member(
                carol_client
                    .generate_key_package_message(Default::default(), Default::default(), None)
                    .await
                    .unwrap(),
            )
            .unwrap()
            .build()
            .await
            .unwrap();
        let mut carol = carol_client
            .join_group(None, &commit.welcome_messages[0], None)
            .await
            .unwrap()
            .0;
        alice
            .process_incoming_message(commit.commit_message.clone())
            .await
            .unwrap();
        bob.process_incoming_message(commit.commit_message)
            .await
            .unwrap();

        let bob_self_remove = bob.propose_self_remove(Vec::new()).await.unwrap();

        let group_info = alice
            .group_info_message_allowing_ext_commit(true)
            .await
            .unwrap();
        carol
            .process_incoming_message(bob_self_remove.clone())
            .await
            .unwrap();
        alice
            .process_incoming_message(bob_self_remove.clone())
            .await
            .unwrap();

        let (mut carol_new_group, commit) = carol_client
            .external_commit_builder()
            .unwrap()
            .with_removal(carol.current_member_index())
            .with_received_custom_proposal(bob_self_remove)
            .build(group_info)
            .await
            .unwrap();
        bob.process_incoming_message(commit.clone()).await.unwrap();
        alice
            .process_incoming_message(commit.clone())
            .await
            .unwrap();

        // Check that carol can decrypt a message in this new group
        let encrypted_message = alice
            .encrypt_application_message(b"test", vec![])
            .await
            .unwrap();
        carol_new_group
            .process_incoming_message(encrypted_message)
            .await
            .unwrap();

        // Assert that after applying the commit removing Bob, that Bob is no longer in the group.
        let alice_identity = alice.current_member_signing_identity().unwrap();
        let carol_identity = carol_new_group.current_member_signing_identity().unwrap();
        let expected_member_identities = vec![alice_identity.clone(), carol_identity.clone()];
        itertools::assert_equal(
            alice.roster().members_iter().map(|m| m.signing_identity),
            expected_member_identities.clone(),
        );
        itertools::assert_equal(
            carol_new_group
                .roster()
                .members_iter()
                .map(|m| m.signing_identity),
            expected_member_identities.clone(),
        );

        // Check that carol's signing identity has not changed.
        let carol_old_identity = carol_new_group.current_member_signing_identity().unwrap();
        assert!(carol_identity == carol_old_identity);
    }

    #[cfg(all(
        feature = "by_ref_proposal",
        feature = "custom_proposal",
        feature = "self_remove_proposal"
    ))]
    #[maybe_async::test(not(mls_build_async), async(mls_build_async, crate::futures_test))]
    async fn can_build_external_commit_from_group_with_self_remove() {
        let (mut alice, mut bob) = self_remove_group_setup().await;

        let carol_client = TestClientBuilder::new_for_test()
            .with_random_signing_identity("carol", TEST_CIPHER_SUITE)
            .await
            .custom_proposal_type(ProposalType::SELF_REMOVE)
            .build();

        // Alice adds Carol.
        let commit = alice
            .commit_builder()
            .add_member(
                carol_client
                    .generate_key_package_message(Default::default(), Default::default(), None)
                    .await
                    .unwrap(),
            )
            .unwrap()
            .build()
            .await
            .unwrap();
        let carol = carol_client
            .join_group(None, &commit.welcome_messages[0], None)
            .await
            .unwrap()
            .0;
        alice
            .process_incoming_message(commit.commit_message.clone())
            .await
            .unwrap();
        bob.process_incoming_message(commit.commit_message)
            .await
            .unwrap();

        let bob_self_remove = bob.propose_self_remove(Vec::new()).await.unwrap();
        alice
            .process_incoming_message(bob_self_remove.clone())
            .await
            .unwrap();

        // Alice commits Bob's self-remove proposal
        let remove_bob_commit = alice.commit(Vec::new()).await.unwrap();

        alice
            .process_incoming_message(remove_bob_commit.commit_message.clone())
            .await
            .unwrap();

        let group_info = alice
            .group_info_message_allowing_ext_commit(true)
            .await
            .unwrap();

        // Carol builds an external commit with Alice's group state, that includes Bob's self-remove committed.
        let (_, commit) = carol_client
            .external_commit_builder()
            .unwrap()
            .with_removal(carol.current_member_index())
            .build(group_info)
            .await
            .unwrap();
        alice
            .process_incoming_message(commit.clone())
            .await
            .unwrap();
    }

    #[cfg(all(
        feature = "by_ref_proposal",
        feature = "custom_proposal",
        feature = "self_remove_proposal"
    ))]
    #[maybe_async::test(not(mls_build_async), async(mls_build_async, crate::futures_test))]
    async fn external_commit_can_have_multiple_self_removes() {
        let (mut alice, mut bob) = self_remove_group_setup().await;

        let carol_client = TestClientBuilder::new_for_test()
            .with_random_signing_identity("carol", TEST_CIPHER_SUITE)
            .await
            .custom_proposal_type(ProposalType::SELF_REMOVE)
            .build();

        // Alice adds Carol.
        let commit = alice
            .commit_builder()
            .add_member(
                carol_client
                    .generate_key_package_message(Default::default(), Default::default(), None)
                    .await
                    .unwrap(),
            )
            .unwrap()
            .build()
            .await
            .unwrap();
        let mut carol = carol_client
            .join_group(None, &commit.welcome_messages[0], None)
            .await
            .unwrap()
            .0;
        alice
            .process_incoming_message(commit.commit_message.clone())
            .await
            .unwrap();
        bob.process_incoming_message(commit.commit_message)
            .await
            .unwrap();

        let bob_self_remove = bob.propose_self_remove(Vec::new()).await.unwrap();
        let alice_self_remove = alice.propose_self_remove(Vec::new()).await.unwrap();

        let group_info = alice
            .group_info_message_allowing_ext_commit(true)
            .await
            .unwrap();
        carol
            .process_incoming_message(bob_self_remove.clone())
            .await
            .unwrap();
        alice
            .process_incoming_message(bob_self_remove.clone())
            .await
            .unwrap();
        bob.process_incoming_message(alice_self_remove.clone())
            .await
            .unwrap();
        carol
            .process_incoming_message(alice_self_remove.clone())
            .await
            .unwrap();

        let (carol_new_group, commit) = carol_client
            .external_commit_builder()
            .unwrap()
            .with_removal(carol.current_member_index())
            .with_received_custom_proposal(bob_self_remove)
            .with_received_custom_proposal(alice_self_remove)
            .build(group_info)
            .await
            .unwrap();

        carol
            .process_incoming_message(commit.clone())
            .await
            .unwrap();
        bob.process_incoming_message(commit.clone()).await.unwrap();
        alice.process_incoming_message(commit).await.unwrap();

        // Assert that after applying the commit removing Bob, that Bob and Alice are no longer in the group.
        let carol_identity = carol_new_group.current_member_signing_identity().unwrap();
        let expected_member_identities = vec![carol_identity.clone()];
        itertools::assert_equal(
            carol_new_group
                .roster()
                .members_iter()
                .map(|m| m.signing_identity),
            expected_member_identities.clone(),
        );
    }

    #[cfg(feature = "std")]
    #[maybe_async::test(not(mls_build_async), async(mls_build_async, crate::futures_test))]
    async fn commit_processes_with_custom_time() {
        // Corresponds to Wednesday, February 19, 2025 9:20:00 PM GMT
        let mut current_time: u64 = 1740000000;

        let (bob_identity, secret_key) = get_test_signing_identity(TEST_CIPHER_SUITE, b"bob").await;
        let bob = TestClientBuilder::new_for_test()
            .signing_identity(bob_identity, secret_key, TEST_CIPHER_SUITE)
            .build();

        current_time += 10;

        let (alice_identity, secret_key) =
            get_test_signing_identity(TEST_CIPHER_SUITE, b"alice").await;
        let alice = TestClientBuilder::new_for_test()
            .signing_identity(alice_identity, secret_key, TEST_CIPHER_SUITE)
            .build();

        current_time += 10;

        let mut alice_group = alice
            .create_group(
                Default::default(),
                Default::default(),
                Some(current_time.into()),
            )
            .await
            .unwrap();

        current_time += 10;

        let bob_key_package = bob
            .generate_key_package_message(
                Default::default(),
                Default::default(),
                Some(current_time.into()),
            )
            .await
            .unwrap();

        current_time += 10;

        let commit_output = alice_group
            .commit_builder()
            .add_member(bob_key_package)
            .unwrap()
            .commit_time(current_time.into())
            .build()
            .await
            .unwrap();

        current_time += 10;

        alice_group
            .process_incoming_message_with_time(commit_output.commit_message, current_time.into())
            .await
            .unwrap();
    }

    #[cfg(feature = "custom_proposal")]
    #[maybe_async::test(not(mls_build_async), async(mls_build_async, crate::futures_test))]
    async fn custom_proposal_may_enforce_path() {
        test_custom_proposal_mls_rules(true).await;
    }

    #[cfg(feature = "custom_proposal")]
    #[maybe_async::test(not(mls_build_async), async(mls_build_async, crate::futures_test))]
    async fn custom_proposal_need_not_enforce_path() {
        test_custom_proposal_mls_rules(false).await;
    }

    #[cfg(feature = "custom_proposal")]
    #[cfg_attr(not(mls_build_async), maybe_async::must_be_sync)]
    async fn test_custom_proposal_mls_rules(path_required_for_custom: bool) {
        let mls_rules = CustomMlsRules {
            path_required_for_custom,
            external_joiner_can_send_custom: true,
        };

        let mut alice = client_with_custom_rules(b"alice", mls_rules.clone())
            .await
            .create_group(Default::default(), Default::default(), None)
            .await
            .unwrap();

        let alice_pub_before = alice.current_user_leaf_node().unwrap().public_key.clone();

        let kp = client_with_custom_rules(b"bob", mls_rules)
            .await
            .generate_key_package_message(Default::default(), Default::default(), None)
            .await
            .unwrap();

        alice
            .commit_builder()
            .custom_proposal(CustomProposal::new(TEST_CUSTOM_PROPOSAL_TYPE, vec![]))
            .add_member(kp)
            .unwrap()
            .build()
            .await
            .unwrap();

        alice.apply_pending_commit().await.unwrap();

        let alice_pub_after = &alice.current_user_leaf_node().unwrap().public_key;

        if path_required_for_custom {
            assert_ne!(alice_pub_after, &alice_pub_before);
        } else {
            assert_eq!(alice_pub_after, &alice_pub_before);
        }
    }

    #[cfg(feature = "custom_proposal")]
    #[maybe_async::test(not(mls_build_async), async(mls_build_async, crate::futures_test))]
    async fn custom_proposal_by_value_in_external_join_may_be_allowed() {
        test_custom_proposal_by_value_in_external_join(true).await
    }

    #[cfg(feature = "custom_proposal")]
    #[maybe_async::test(not(mls_build_async), async(mls_build_async, crate::futures_test))]
    async fn custom_proposal_by_value_in_external_join_may_not_be_allowed() {
        test_custom_proposal_by_value_in_external_join(false).await
    }

    #[cfg(feature = "custom_proposal")]
    #[cfg_attr(not(mls_build_async), maybe_async::must_be_sync)]
    async fn test_custom_proposal_by_value_in_external_join(external_joiner_can_send_custom: bool) {
        let mls_rules = CustomMlsRules {
            path_required_for_custom: true,
            external_joiner_can_send_custom,
        };

        let mut alice = client_with_custom_rules(b"alice", mls_rules.clone())
            .await
            .create_group(Default::default(), Default::default(), None)
            .await
            .unwrap();

        let group_info = alice
            .group_info_message_allowing_ext_commit(true)
            .await
            .unwrap();

        let commit = client_with_custom_rules(b"bob", mls_rules)
            .await
            .external_commit_builder()
            .unwrap()
            .with_custom_proposal(CustomProposal::new(TEST_CUSTOM_PROPOSAL_TYPE, vec![]))
            .build(group_info)
            .await;

        if external_joiner_can_send_custom {
            let commit = commit.unwrap().1;
            alice.process_incoming_message(commit).await.unwrap();
        } else {
            assert_matches!(commit.map(|_| ()), Err(MlsError::MlsRulesError(_)));
        }
    }

    #[cfg(feature = "custom_proposal")]
    #[maybe_async::test(not(mls_build_async), async(mls_build_async, crate::futures_test))]
    async fn custom_proposal_by_ref_in_external_join() {
        let mls_rules = CustomMlsRules {
            path_required_for_custom: true,
            external_joiner_can_send_custom: true,
        };

        let mut alice = client_with_custom_rules(b"alice", mls_rules.clone())
            .await
            .create_group(Default::default(), Default::default(), None)
            .await
            .unwrap();

        let by_ref = CustomProposal::new(TEST_CUSTOM_PROPOSAL_TYPE, vec![]);
        let by_ref = alice.propose_custom(by_ref, vec![]).await.unwrap();

        let group_info = alice
            .group_info_message_allowing_ext_commit(true)
            .await
            .unwrap();

        let (_, commit) = client_with_custom_rules(b"bob", mls_rules)
            .await
            .external_commit_builder()
            .unwrap()
            .with_received_custom_proposal(by_ref)
            .build(group_info)
            .await
            .unwrap();

        alice.process_incoming_message(commit).await.unwrap();
    }

    #[cfg(feature = "custom_proposal")]
    #[cfg_attr(not(mls_build_async), maybe_async::must_be_sync)]
    async fn client_with_custom_rules(
        name: &[u8],
        mls_rules: CustomMlsRules,
    ) -> Client<impl MlsConfig> {
        let (signing_identity, signer) = get_test_signing_identity(TEST_CIPHER_SUITE, name).await;

        ClientBuilder::new()
            .crypto_provider(TestCryptoProvider::new())
            .identity_provider(BasicWithCustomProvider::new(BasicIdentityProvider::new()))
            .signing_identity(signing_identity, signer, TEST_CIPHER_SUITE)
            .custom_proposal_type(TEST_CUSTOM_PROPOSAL_TYPE)
            .mls_rules(mls_rules)
            .build()
    }

    #[derive(Debug, Clone)]
    struct CustomMlsRules {
        path_required_for_custom: bool,
        external_joiner_can_send_custom: bool,
    }

    #[cfg(feature = "custom_proposal")]
    impl ProposalBundle {
        fn has_test_custom_proposal(&self) -> bool {
            self.custom_proposal_types()
                .any(|t| t == TEST_CUSTOM_PROPOSAL_TYPE)
        }
    }

    #[cfg(feature = "custom_proposal")]
    #[cfg_attr(not(mls_build_async), maybe_async::must_be_sync)]
    #[cfg_attr(mls_build_async, maybe_async::must_be_async)]
    impl crate::MlsRules for CustomMlsRules {
        type Error = MlsError;

        fn commit_options(
            &self,
            _: &Roster,
            _: &GroupContext,
            proposals: &ProposalBundle,
        ) -> Result<CommitOptions, MlsError> {
            Ok(CommitOptions::default().with_path_required(
                !proposals.has_test_custom_proposal() || self.path_required_for_custom,
            ))
        }

        fn encryption_options(
            &self,
            _: &Roster,
            _: &GroupContext,
        ) -> Result<crate::mls_rules::EncryptionOptions, MlsError> {
            Ok(Default::default())
        }

        async fn filter_proposals(
            &self,
            _: CommitDirection,
            sender: CommitSource,
            _: &Roster,
            _: &GroupContext,
            proposals: ProposalBundle,
        ) -> Result<ProposalBundle, MlsError> {
            let is_external = matches!(sender, CommitSource::NewMember(_));
            let has_custom = proposals.has_test_custom_proposal();
            let allowed = !has_custom || !is_external || self.external_joiner_can_send_custom;

            allowed.then_some(proposals).ok_or(MlsError::InvalidSender)
        }
    }

    #[maybe_async::test(not(mls_build_async), async(mls_build_async, crate::futures_test))]
    async fn group_can_receive_commit_from_self() {
        let mut group = test_group(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE).await;

        let commit = group.commit(vec![]).await.unwrap();

        let update = group
            .process_incoming_message(commit.commit_message)
            .await
            .unwrap();

        let ReceivedMessage::Commit(update) = update else {
            panic!("expected commit message")
        };

        assert_eq!(update.committer, *group.private_tree.self_index);
    }

    #[maybe_async::test(not(mls_build_async), async(mls_build_async, crate::futures_test))]
    async fn can_process_commit_when_pending_commit() {
        let mut groups = test_n_member_group(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE, 2).await;

        let commit = groups[0].commit(vec![]).await.unwrap().commit_message;
        groups[1].commit(vec![]).await.unwrap();

        groups[1].process_incoming_message(commit).await.unwrap();

        let res = groups[1].apply_pending_commit().await;
        assert_matches!(res, Err(MlsError::PendingCommitNotFound));
    }

    #[cfg(feature = "by_ref_proposal")]
    #[maybe_async::test(not(mls_build_async), async(mls_build_async, crate::futures_test))]
    async fn can_process_own_plaintext_proposal() {
        can_process_own_proposal(false).await;
    }

    #[cfg(feature = "by_ref_proposal")]
    #[maybe_async::test(not(mls_build_async), async(mls_build_async, crate::futures_test))]
    async fn can_process_own_ciphertext_proposal() {
        can_process_own_proposal(true).await;
    }

    #[cfg(feature = "by_ref_proposal")]
    #[cfg_attr(not(mls_build_async), maybe_async::must_be_sync)]
    async fn can_process_own_proposal(encrypt_proposal: bool) {
        let (alice, _) = test_client_with_key_pkg_custom(
            TEST_PROTOCOL_VERSION,
            TEST_CIPHER_SUITE,
            "alice",
            Default::default(),
            Default::default(),
            |c| c.0.mls_rules.encryption_options.encrypt_control_messages = encrypt_proposal,
        )
        .await;

        let mut alice = TestGroup {
            group: alice
                .create_group(Default::default(), Default::default(), None)
                .await
                .unwrap(),
        };

        let mut bob = alice.join("bob").await.0;
        let mut alice = alice;

        let upd = alice.propose_update(vec![]).await.unwrap();
        alice.process_incoming_message(upd.clone()).await.unwrap();

        bob.process_incoming_message(upd).await.unwrap();
        let commit = bob.commit(vec![]).await.unwrap().commit_message;
        let update = alice.process_incoming_message(commit).await.unwrap();

        let ReceivedMessage::Commit(CommitMessageDescription {
            effect: CommitEffect::NewEpoch(new_epoch),
            ..
        }) = update
        else {
            panic!("unexpected commit effect")
        };

        assert_eq!(new_epoch.applied_proposals.len(), 1);
        assert_eq!(new_epoch.applied_proposals[0].sender, Sender::Member(0));
    }

    #[cfg(feature = "by_ref_proposal")]
    #[maybe_async::test(not(mls_build_async), async(mls_build_async, crate::futures_test))]
    async fn commit_clears_proposals() {
        let mut groups = test_n_member_group(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE, 2).await;

        groups[0].propose_update(vec![]).await.unwrap();

        assert_eq!(groups[0].state.proposals.proposals.len(), 1);
        assert_eq!(groups[0].state.proposals.own_proposals.len(), 1);

        let commit = groups[1].commit(vec![]).await.unwrap().commit_message;
        groups[0].process_message(commit).await.unwrap();

        assert!(groups[0].state.proposals.proposals.is_empty());
        assert!(groups[0].state.proposals.own_proposals.is_empty());
    }

    #[cfg(feature = "by_ref_proposal")]
    #[maybe_async::test(not(mls_build_async), async(mls_build_async, crate::futures_test))]
    async fn commit_required_is_true_when_proposals_pending() {
        let mut group = test_group(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE).await;

        assert!(!group.commit_required());

        group
            .propose_group_context_extensions(ExtensionList::new(), vec![])
            .await
            .unwrap();

        assert!(group.commit_required());

        let res = group.encrypt_application_message(&[0u8; 32], vec![]).await;

        assert_matches!(res, Err(MlsError::CommitRequired));

        group.commit(vec![]).await.unwrap();
        group.apply_pending_commit().await.unwrap();

        assert!(!group.commit_required());
    }

    // Testing with std is sufficient. Non-std creates incompatible storage and a lot of special cases.
    #[cfg(feature = "std")]
    #[maybe_async::test(not(mls_build_async), async(mls_build_async, crate::futures_test))]
    async fn can_be_stored_without_tree() {
        let mut group = test_group(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE).await;
        let storage = group.config.group_state_storage().inner;

        group.write_to_storage().await.unwrap();
        let snapshot_with_tree = storage.lock().unwrap().drain().next().unwrap().1;

        group.write_to_storage_without_ratchet_tree().await.unwrap();
        let snapshot_without_tree = storage.lock().unwrap().iter().next().unwrap().1.clone();

        let tree = group.state.public_tree.nodes.mls_encode_to_vec().unwrap();
        let empty_tree = Vec::<u8>::new().mls_encode_to_vec().unwrap();

        assert_eq!(
            snapshot_with_tree.state_data.len() - snapshot_without_tree.state_data.len(),
            tree.len() - empty_tree.len()
        );

        let exported_tree = group.export_tree();

        let restored = Client::new(group.config.clone(), None, None, TEST_PROTOCOL_VERSION)
            .load_group_with_ratchet_tree(group.group_id(), exported_tree)
            .await
            .unwrap();

        assert_eq!(restored.group_state(), group.group_state());
    }

    #[maybe_async::test(not(mls_build_async), async(mls_build_async, crate::futures_test))]
    async fn delete_exporter() {
        let mut group = test_group(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE).await;

        group.export_secret(b"123", b"", 15).await.unwrap();

        group.delete_exporter();
        let res = group.export_secret(b"123", b"", 15).await;
        assert_matches!(res, Err(MlsError::ExporterDeleted));

        group.commit(vec![]).await.unwrap();
        group.apply_pending_commit().await.unwrap();
        group.export_secret(b"123", b"", 15).await.unwrap();
    }
}
