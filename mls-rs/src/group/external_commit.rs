// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// Copyright by contributors to this project.
// SPDX-License-Identifier: (Apache-2.0 OR MIT)

use mls_rs_core::{
    crypto::SignatureSecretKey, extension::ExtensionList, identity::SigningIdentity,
};

use crate::{
    client_config::ClientConfig,
    group::{
        cipher_suite_provider,
        epoch::SenderDataSecret,
        key_schedule::{InitSecret, KeySchedule},
        proposal::{ExternalInit, Proposal},
        EpochSecrets, ExternalPubExt, LeafNode, MlsError, TreeKemPrivate,
    },
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
use crate::psk::{secret::PskSecretInput, ExternalPskId, PreSharedKey};

#[cfg(feature = "psk")]
use crate::group::{
    PreSharedKeyProposal, {JustPreSharedKeyID, PreSharedKeyID},
};

use super::{
    proposal_filter::{ProposalBundle, ProposalSource},
    validate_tree_and_info_joiner, CommitOptions, ExportedTree, Sender,
};

/// A builder that aids with the construction of an external commit.
#[cfg_attr(all(feature = "ffi", not(test)), safer_ffi_gen::ffi_type(opaque))]
pub struct ExternalCommitBuilder<C: ClientConfig> {
    signer: SignatureSecretKey,
    signing_identity: SigningIdentity,
    leaf_node_extensions: ExtensionList,
    config: C,
    tree_data: Option<ExportedTree<'static>>,
    to_remove: Option<u32>,
    #[cfg(feature = "psk")]
    external_psks: Vec<(ExternalPskId, PreSharedKey)>,
    #[cfg(feature = "custom_proposal")]
    custom_proposals: Vec<Proposal>,
    #[cfg(feature = "custom_proposal")]
    received_custom_proposals: Vec<MlsMessage>,
    group_info: MlsMessage,
    options: CommitOptions,
}

impl<C: ClientConfig> ExternalCommitBuilder<C> {
    pub(crate) fn new(
        signer: SignatureSecretKey,
        signing_identity: SigningIdentity,
        config: C,
        group_info: MlsMessage,
    ) -> Self {
        Self {
            signer,
            signing_identity,
            config,
            group_info,
            tree_data: None,
            options: CommitOptions {
                sender: Sender::NewMemberCommit,
                path_required: false,
                ratchet_tree_extension: true,
                single_welcome_message: true,
                allow_external_commit: false,
                authenticated_data: Default::default(),
                encryption_mode: Default::default(),
            },
            leaf_node_extensions: Default::default(),
            to_remove: Default::default(),
            #[cfg(feature = "custom_proposal")]
            custom_proposals: Vec::new(),
            #[cfg(feature = "custom_proposal")]
            received_custom_proposals: Vec::new(),
            #[cfg(feature = "psk")]
            external_psks: Default::default(),
        }
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
        Self {
            to_remove: Some(to_remove),
            ..self
        }
    }

    #[must_use]
    /// Add plaintext authenticated data to the resulting commit message.
    pub fn with_authenticated_data(mut self, data: Vec<u8>) -> Self {
        self.options.authenticated_data = data;
        self
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
    pub fn with_custom_proposal(mut self, proposal: CustomProposal) -> Self {
        self.custom_proposals.push(Proposal::Custom(proposal));
        self
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
    pub fn with_received_custom_proposal(mut self, proposal: MlsMessage) -> Self {
        self.received_custom_proposals.push(proposal);
        self
    }

    /// Change the committer's leaf node extensions as part of making this commit.
    pub fn with_leaf_node_extensions(self, leaf_node_extensions: ExtensionList) -> Self {
        Self {
            leaf_node_extensions,
            ..self
        }
    }

    pub fn allow_external_commit(mut self, allow_external_commit: bool) -> Self {
        self.options.allow_external_commit = allow_external_commit;
        self
    }

    /// Build the external commit using a GroupInfo message provided by an existing group member.
    #[cfg_attr(not(mls_build_async), maybe_async::must_be_sync)]
    pub async fn build(self) -> Result<(Group<C>, MlsMessage), MlsError> {
        let protocol_version = self.group_info.version;

        if !self.config.version_supported(protocol_version) {
            return Err(MlsError::UnsupportedProtocolVersion(protocol_version));
        }

        let group_info = self
            .group_info
            .into_group_info()
            .ok_or(MlsError::UnexpectedMessageType)?;

        let cipher_suite = cipher_suite_provider(
            self.config.crypto_provider(),
            group_info.group_context.cipher_suite,
        )?;

        let public_tree = validate_tree_and_info_joiner(
            protocol_version,
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

        let external_pub_ext = group_info
            .extensions
            .get_as::<ExternalPubExt>()?
            .ok_or(MlsError::MissingExternalPubExtension)?;

        let (init_secret, kem_output) =
            InitSecret::encode_for_external(&cipher_suite, &external_pub_ext.external_pub).await?;

        let (mut group, _) = Group::join_with(
            self.config,
            group_info,
            public_tree,
            KeySchedule::new(init_secret),
            epoch_secrets,
            TreeKemPrivate::new_for_external(),
            self.signer,
        )
        .await?;

        let mut proposals = vec![Proposal::ExternalInit(ExternalInit { kem_output })];

        if let Some(to_remove) = self.to_remove {
            proposals.push(Proposal::Remove(to_remove.into()));
        }

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
            let MlsMessagePayload::Plain(plaintext) = message.payload else {
                return Err(MlsError::UnexpectedMessageType);
            };

            let super::Content::Proposal(proposal) = plaintext.content.content.clone() else {
                return Err(MlsError::UnexpectedMessageType);
            };

            verify_plaintext_authentication(&cipher_suite, plaintext, None, &group.state).await?;

            proposals.push(*proposal);
        }

        let proposal_bundle =
            proposals
                .into_iter()
                .fold(ProposalBundle::default(), |mut bundle, proposal| {
                    bundle.add(proposal, Sender::NewMemberCommit, ProposalSource::ByValue);
                    bundle
                });

        let (commit_output, pending_commit) = group
            .commit_internal(
                proposal_bundle,
                Some(&leaf_node),
                Default::default(),
                None,
                None,
                None,
                self.options,
                #[cfg(feature = "psk")]
                psks,
            )
            .await?;

        group.pending_commit = pending_commit.try_into()?;
        group.apply_pending_commit().await?;

        Ok((group, commit_output.commit_message))
    }
}
