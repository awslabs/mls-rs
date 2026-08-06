// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// Copyright by contributors to this project.
// SPDX-License-Identifier: (Apache-2.0 OR MIT)

use alloc::{vec, vec::Vec};

use mls_rs_core::{
    crypto::{CipherSuite, CipherSuiteProvider, SignatureSecretKey},
    error::IntoAnyError,
    extension::{Extension, ExtensionList},
    group::GroupContext,
    identity::{MemberValidationContext, SigningIdentity},
    protocol_version::ProtocolVersion,
    time::MlsTime,
};

use crate::{
    client_config::ClientConfig,
    error::MlsError,
    group::{
        cipher_suite_provider, confirmation_tag::ConfirmationTag, key_schedule::KeySchedule,
        state_repo::GroupStateRepository, transcript_hash::InterimTranscriptHash, GroupState,
        LeafIndex, LeafNode,
    },
    tree_kem::{
        leaf_node_validator::{LeafNodeValidator, ValidationContext},
        TreeKemPublic,
    },
    Group,
};

/// Builder for creating a new MLS [`Group`] with customizable parameters.
///
/// A `GroupBuilder` is typically obtained via [`Client::group_builder`](crate::Client::group_builder),
/// which pre-fills the cipher suite, signing identity, and signer from the client configuration.
/// Optional parameters such as group ID, extensions, and protocol version can then be set
/// using the `with_*` methods before calling [`build`](GroupBuilder::build) to finalize the group.
///
/// If no group ID is provided, a random one is generated. The protocol version defaults
/// to MLS 1.0.
pub struct GroupBuilder<C> {
    pub(crate) group_id: Option<Vec<u8>>,
    pub(crate) protocol_version: ProtocolVersion,
    pub(crate) group_context_extensions: ExtensionList,
    pub(crate) leaf_node_extensions: ExtensionList,
    pub(crate) now_time: Option<MlsTime>,
    #[cfg(feature = "custom_start_epoch")]
    pub(crate) start_epoch: u64,
    pub(crate) config: C,
    pub(crate) cipher_suite: CipherSuite,
    pub(crate) signing_identity: SigningIdentity,
    pub(crate) signer: SignatureSecretKey,
}

impl<C> GroupBuilder<C> {
    /// Create a new `GroupBuilder` with the required parameters.
    ///
    /// Most callers should use [`Client::group_builder`](crate::Client::group_builder) instead,
    /// which fills these from the client's configuration.
    pub(crate) fn new(
        config: C,
        cipher_suite: CipherSuite,
        signing_identity: SigningIdentity,
        signer: SignatureSecretKey,
    ) -> Self {
        Self {
            group_id: None,
            protocol_version: ProtocolVersion::MLS_10,
            group_context_extensions: Default::default(),
            leaf_node_extensions: Default::default(),
            now_time: None,
            #[cfg(feature = "custom_start_epoch")]
            start_epoch: 0,
            config,
            cipher_suite,
            signing_identity,
            signer,
        }
    }

    /// Set a specific group ID. If not called, a random group ID is generated
    /// during [`build`](GroupBuilder::build).
    pub fn with_group_id(mut self, group_id: Vec<u8>) -> Self {
        self.group_id = Some(group_id);
        self
    }

    /// Set the MLS protocol version. Defaults to [`ProtocolVersion::MLS_10`].
    pub fn with_protocol_version(mut self, protocol_version: ProtocolVersion) -> Self {
        self.protocol_version = protocol_version;
        self
    }

    /// Set extensions to include in the group context.
    pub fn with_group_context_extensions(mut self, extensions: ExtensionList) -> Self {
        self.group_context_extensions = extensions;
        self
    }

    /// Add extension to include in the group context.
    pub fn with_group_context_extension(mut self, extension: Extension) -> Self {
        self.group_context_extensions.set(extension);
        self
    }

    /// Set extensions to include in the creator's leaf node.
    pub fn with_leaf_node_extensions(mut self, extensions: ExtensionList) -> Self {
        self.leaf_node_extensions = extensions;
        self
    }

    /// Add extension to include in the creator's leaf node.
    pub fn with_leaf_node_extension(mut self, extension: Extension) -> Self {
        self.leaf_node_extensions.set(extension);
        self
    }

    /// Set the current time used for leaf node lifetime validation.
    pub fn with_now_time(mut self, now_time: MlsTime) -> Self {
        self.now_time = Some(now_time);
        self
    }

    /// Set the epoch the newly created group starts from.
    ///
    /// By default a group starts at epoch 0, as mandated by RFC 9420. Setting a
    /// non-zero value here makes the group start at the given epoch instead, which
    /// allows an application to keep epoch numbers non-overlapping across group
    /// resets (see mls-rs issue #327).
    ///
    /// This is **not** RFC 9420 compliant and only affects the group created
    /// locally by this builder; it does not apply to groups joined via a Welcome,
    /// external commit, or to branch/re-init subgroups (whose Welcome epoch must
    /// be 1).
    #[cfg(feature = "custom_start_epoch")]
    pub fn with_start_epoch(mut self, start_epoch: u64) -> Self {
        self.start_epoch = start_epoch;
        self
    }
}

impl<C: ClientConfig + Clone> GroupBuilder<C> {
    /// Consume the builder and create the new [`Group`].
    ///
    /// This generates the initial ratchet tree, key schedule, and group context
    /// for the starting epoch of the group.
    #[cfg_attr(not(mls_build_async), maybe_async::must_be_sync)]
    pub async fn build(self) -> Result<Group<C>, MlsError> {
        let cipher_suite_provider =
            cipher_suite_provider(self.config.crypto_provider(), self.cipher_suite)?;

        let (leaf_node, leaf_node_secret) = LeafNode::generate(
            &cipher_suite_provider,
            self.config.leaf_properties(self.leaf_node_extensions),
            self.signing_identity,
            &self.signer,
            self.config.lifetime(self.now_time),
        )
        .await?;

        let (mut public_tree, private_tree) = TreeKemPublic::derive(
            leaf_node,
            leaf_node_secret,
            &self.config.identity_provider(),
            &self.group_context_extensions,
        )
        .await?;

        let tree_hash = public_tree.tree_hash(&cipher_suite_provider).await?;

        let group_id = self.group_id.map(Ok).unwrap_or_else(|| {
            cipher_suite_provider
                .random_bytes_vec(cipher_suite_provider.kdf_extract_size())
                .map_err(|e| MlsError::CryptoProviderError(e.into_any_error()))
        })?;

        let context = GroupContext::new(
            self.protocol_version,
            self.cipher_suite,
            group_id,
            tree_hash,
            self.group_context_extensions,
        );

        #[cfg(feature = "custom_start_epoch")]
        let context = GroupContext {
            epoch: self.start_epoch,
            ..context
        };

        let identity_provider = self.config.identity_provider();

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
                ValidationContext::Add(self.now_time),
            )
            .await?;

        let state_repo = GroupStateRepository::new(
            #[cfg(feature = "prior_epoch")]
            context.group_id.clone(),
            self.config.group_state_storage(),
            self.config.key_package_repo(),
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

        Ok(Group {
            config: self.config,
            state: GroupState::new(context, public_tree, interim_hash, confirmation_tag),
            private_tree,
            key_schedule: key_schedule_result.key_schedule,
            #[cfg(feature = "by_ref_proposal")]
            pending_updates: Default::default(),
            pending_commit: Default::default(),
            epoch_secrets: key_schedule_result.epoch_secrets,
            state_repo,
            cipher_suite_provider,
            #[cfg(feature = "psk")]
            previous_psk: None,
            signer: self.signer,
            #[cfg(test)]
            commit_modifiers: Default::default(),
        })
    }
}
