// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// Copyright by contributors to this project.
// SPDX-License-Identifier: (Apache-2.0 OR MIT)

use mls_rs_core::{
    crypto::SignatureSecretKey, extension::ExtensionList, identity::SigningIdentity,
    protocol_version::ProtocolVersion,
};

use crate::{
    client_config::ClientConfig,
    group::{
        cipher_suite_provider,
        epoch::SenderDataSecret,
        key_schedule::{InitSecret, KeySchedule},
        proposal::{ExternalInit, Proposal, RemoveProposal},
        EpochSecrets, ExternalPubExt, LeafIndex, LeafNode, MlsError, TreeKemPrivate,
    },
    mls_rules::{ProposalBundle, ProposalSource},
    Group, MlsMessage,
};

#[cfg(any(feature = "secret_tree_access", feature = "private_message"))]
use crate::group::secret_tree::SecretTree;

#[cfg(feature = "custom_proposal")]
use crate::group::{
    framing::MlsMessagePayload, message_verifier::verify_plaintext_authentication, CustomProposal,
};

use alloc::vec;
use alloc::vec::Vec;

#[cfg(feature = "psk")]
use mls_rs_core::psk::{ExternalPskId, PreSharedKey};

#[cfg(feature = "psk")]
use crate::group::{
    PreSharedKeyProposal, {JustPreSharedKeyID, PreSharedKeyID},
};

use super::{validate_tree_and_info_joiner, ExportedTree, PskSecretInput, GroupInfo, Sender};

/// A builder that aids with the construction of an external commit.
#[cfg_attr(all(feature = "ffi", not(test)), safer_ffi_gen::ffi_type(opaque))]
pub struct ExternalCommitBuilder<C: ClientConfig> {
    signer: SignatureSecretKey,
    signing_identity: SigningIdentity,
    leaf_node_extensions: ExtensionList,
    config: C,
    tree_data: Option<ExportedTree<'static>>,
    external_psks: Vec<(ExternalPskId, PreSharedKey)>,
    #[cfg(feature = "psk")]
    authenticated_data: Vec<u8>,
    #[cfg(feature = "custom_proposal")]
    received_custom_proposals: Vec<PublicMessage>,
    proposals: ProposalBundle,
    group_info: GroupInfo,
    protocol_version: ProtocolVersion,
    init_secret: InitSecret,
}

impl<C: ClientConfig> ExternalCommitBuilder<C> {
    #[cfg_attr(not(mls_build_async), maybe_async::must_be_sync)]
    pub(crate) async fn new(
        signer: SignatureSecretKey,
        signing_identity: SigningIdentity,
        config: C,
        group_info: MlsMessage,
    ) -> Result<Self, MlsError> {
        let protocol_version = group_info.version;

        if !config.version_supported(protocol_version) {
            return Err(MlsError::UnsupportedProtocolVersion(protocol_version));
        }

        let group_info = group_info
            .into_group_info()
            .ok_or(MlsError::UnexpectedMessageType)?;

        let cipher_suite = cipher_suite_provider(
            config.crypto_provider(),
            group_info.group_context.cipher_suite,
        )?;

        let external_pub_ext = group_info
            .extensions
            .get_as::<ExternalPubExt>()?
            .ok_or(MlsError::MissingExternalPubExtension)?;

        let (init_secret, kem_output) =
            InitSecret::encode_for_external(&cipher_suite, &external_pub_ext.external_pub).await?;

        let builder = Self {
            tree_data: None,
            authenticated_data: Vec::new(),
            signer,
            signing_identity,
            leaf_node_extensions: Default::default(),
            config,
            #[cfg(feature = "custom_proposal")]
            received_custom_proposals: Vec::new(),
            proposals: Default::default(),
            group_info,
            protocol_version,
            init_secret,
        };

        Ok(builder.with_proposal(Proposal::ExternalInit(ExternalInit { kem_output })))
    }

    #[must_use]
    /// Use external tree data if the GroupInfo message does not contain a
    /// [`RatchetTreeExt`](crate::extension::built_in::RatchetTreeExt)
    pub fn with_tree_data(self, tree_data: ExportedTree<'static>) -> Self {
        Self {
            tree_data: Some(tree_data),
            ..self
        }
    }

    #[must_use]
    /// Propose the removal of an old version of the client as part of the external commit.
    /// Only one such proposal is allowed.
    pub fn with_removal(self, to_remove: u32) -> Self {
        self.with_proposal(Proposal::Remove(RemoveProposal {
            to_remove: LeafIndex(to_remove),
        }))
    }

    #[must_use]
    /// Add plaintext authenticated data to the resulting commit message.
    pub fn with_authenticated_data(self, data: Vec<u8>) -> Self {
        Self {
            authenticated_data: data,
            ..self
        }
    }

    #[cfg(feature = "psk")]
    /// Add an external psk to the group as part of the external commit.
    pub fn with_external_psk(mut self, id: ExternalPskId, psk: PreSharedKey) -> Self {
        self.external_psks.push((id, psk));
        self
    }

    #[cfg(feature = "custom_proposal")]
    #[must_use]
    /// Insert a [`CustomProposal`] into the current commit that is being built.
    pub fn with_custom_proposal(self, proposal: CustomProposal) -> Self {
        self.with_proposal(Proposal::Custom(proposal))
    }

    #[cfg(all(feature = "custom_proposal", feature = "by_ref_proposal"))]
    /// Insert a [`CustomProposal`] received from a current group member into the current
    /// commit that is being built.
    ///
    /// # Warning
    ///
    /// The authenticity of the proposal is NOT fully verified. It is only verified the
    /// same way as by [`ExternalGroup`](`crate::external_client::ExternalGroup`).
    /// The proposal MUST be an MlsPlaintext, else the [`Self::build`] function will fail.
    pub fn with_received_custom_proposal(mut self, proposal: MlsMessage) -> Result<Self, MlsError> {
        let MlsMessagePayload::Plain(plaintext) = proposal.payload else {
            return Err(MlsError::UnexpectedMessageType);
        };

        let super::Content::Proposal(proposal) = plaintext.content.content.clone() else {
            return Err(MlsError::UnexpectedMessageType);
        };

        // We store proposal to verify authenticity later. At this point this may not be possible if we
        // don't have the tree.
        self.received_custom_proposals.push(plaintext);

        Ok(self.with_proposal(*proposal))
    }

    /// Change the committer's leaf node extensions as part of making this commit.
    pub fn with_leaf_node_extensions(self, leaf_node_extensions: ExtensionList) -> Self {
        Self {
            leaf_node_extensions,
            ..self
        }
    }

    fn with_proposal(mut self, proposal: Proposal) -> Self {
        self.proposals
            .add(proposal, Sender::NewMemberCommit, ProposalSource::ByValue);

        self
    }

    /// Build the external commit using a GroupInfo message provided by an existing group member.
    #[cfg_attr(not(mls_build_async), maybe_async::must_be_sync)]
    pub async fn build(self) -> Result<(Group<C>, MlsMessage), MlsError> {
        let group_info = self.group_info;

        let cipher_suite = cipher_suite_provider(
            self.config.crypto_provider(),
            group_info.group_context.cipher_suite,
        )?;

        let public_tree = validate_tree_and_info_joiner(
            self.protocol_version,
            &group_info,
            self.tree_data,
            &self.config.identity_provider(),
            &cipher_suite,
        )
        .await?;

        let (leaf_node, _) = LeafNode::generate(
            &cipher_suite,
            self.config.leaf_properties(self.leaf_node_extensions),
            self.signing_identity,
            &self.signer,
            self.config.lifetime(),
        )
        .await?;

        let epoch_secrets = EpochSecrets {
            #[cfg(feature = "psk")]
            resumption_secret: PreSharedKey::new(vec![]),
            sender_data_secret: SenderDataSecret::from(vec![]),
            #[cfg(any(feature = "secret_tree_access", feature = "private_message"))]
            secret_tree: SecretTree::empty(),
        };

        let (mut group, _) = Group::join_with(
            self.config,
            group_info,
            public_tree,
            KeySchedule::new(self.init_secret),
            epoch_secrets,
            TreeKemPrivate::new_for_external(),
            self.signer,
        )
        .await?;

        let mut proposals = vec![Proposal::ExternalInit(ExternalInit { kem_output })];

        #[cfg(feature = "psk")]
        let psks = self
            .external_psks
            .into_iter()
            .map(|(psk_id, psk_secret)| {
                let key_id =
                    PreSharedKeyID::new(JustPreSharedKeyID::External(psk_id), &cipher_suite)?;

                proposals.push(Proposal::Psk(PreSharedKeyProposal {
                    psk: key_id.clone(),
                }));

                Ok(PskSecretInput {
                    id: key_id,
                    psk: psk_secret,
                })
            })
            .collect::<Result<Vec<_>, MlsError>>()?;

        #[cfg(feature = "custom_proposal")]
        {
            let mut custom_proposals = self.custom_proposals;
            proposals.append(&mut custom_proposals);
        }

        #[cfg(all(feature = "custom_proposal", feature = "by_ref_proposal"))]
        for message in self.received_custom_proposals {
            verify_plaintext_authentication(&cipher_suite, message, None, &group.state).await?;
        }

        let (commit_output, pending_commit) = group
            .commit_internal(
                self.proposals,
                Some(&leaf_node),
                self.authenticated_data,
                Default::default(),
                None,
                None,
                None,
                #[cfg(feature = "psk")]
                psks,
            )
            .await?;

        group.pending_commit = pending_commit.try_into()?;
        group.apply_pending_commit().await?;

        Ok((group, commit_output.commit_message))
    }
}
