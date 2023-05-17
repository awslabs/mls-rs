use aws_mls_core::{
    error::IntoAnyError,
    identity::SigningIdentity,
    keychain::KeychainStorage,
    psk::{ExternalPskId, PreSharedKey},
};

use crate::{
    client_config::ClientConfig,
    group::{
        cipher_suite_provider,
        internal::{EpochSecrets, ExternalPubExt, LeafIndex, LeafNode, TreeKemPrivate},
        key_schedule::{InitSecret, KeySchedule},
        proposal::{ExternalInit, PreSharedKeyProposal, Proposal, RemoveProposal},
        validate_group_info,
    },
    Group, MLSMessage, WireFormat,
};

use super::{
    epoch::SenderDataSecret,
    internal::{JustPreSharedKeyID, PreSharedKeyID, PskNonce},
    secret_tree::SecretTree,
    MlsError,
};

use alloc::vec;
use alloc::vec::Vec;

/// A builder that aids with the construction of an external commit.
pub struct ExternalCommitBuilder<C: ClientConfig> {
    signing_identity: SigningIdentity,
    config: C,
    tree_data: Option<Vec<u8>>,
    to_remove: Option<u32>,
    external_psks: Vec<ExternalPskId>,
    authenticated_data: Vec<u8>,
}

impl<C: ClientConfig> ExternalCommitBuilder<C> {
    pub(crate) fn new(signing_identity: SigningIdentity, config: C) -> Self {
        Self {
            tree_data: None,
            to_remove: None,
            authenticated_data: Vec::new(),
            signing_identity,
            config,
            external_psks: Vec::new(),
        }
    }

    #[must_use]
    /// Use external tree data if the GroupInfo message does not contain a
    /// [`RatchetTreeExt`](crate::extension::built_in::RatchetTreeExt)
    pub fn with_tree_data(self, tree_data: Vec<u8>) -> Self {
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
    pub fn with_authenticated_data(self, data: Vec<u8>) -> Self {
        Self {
            authenticated_data: data,
            ..self
        }
    }

    #[must_use]
    /// Add an external psk to the group as part of the external commit.
    pub fn with_external_psk(mut self, psk: ExternalPskId) -> Self {
        self.external_psks.push(psk);
        self
    }

    /// Build the external commit using a GroupInfo message provided by an existing group member.
    #[maybe_async::maybe_async]
    pub async fn build(self, group_info: MLSMessage) -> Result<(Group<C>, MLSMessage), MlsError> {
        let protocol_version = group_info.version;

        if !self.config.version_supported(protocol_version) {
            return Err(MlsError::UnsupportedProtocolVersion(protocol_version));
        }

        let wire_format = group_info.wire_format();

        let group_info = group_info.into_group_info().ok_or_else(|| {
            MlsError::UnexpectedMessageType(vec![WireFormat::GroupInfo], wire_format)
        })?;

        let cipher_suite_provider = cipher_suite_provider(
            self.config.crypto_provider(),
            group_info.group_context.cipher_suite,
        )?;

        let external_pub_ext = group_info
            .extensions
            .get_as::<ExternalPubExt>()?
            .ok_or(MlsError::MissingExternalPubExtension)?;

        let join_context = validate_group_info(
            protocol_version,
            group_info,
            self.tree_data.as_deref(),
            &self.config.identity_provider(),
            &cipher_suite_provider,
        )
        .await?;

        let signer = self
            .config
            .keychain()
            .signer(&self.signing_identity)
            .await
            .map_err(|e| MlsError::KeychainError(e.into_any_error()))?
            .ok_or(MlsError::SignerNotFound)?;

        let (leaf_node, _) = LeafNode::generate(
            &cipher_suite_provider,
            self.config.leaf_properties(),
            self.signing_identity,
            &signer,
            self.config.lifetime(),
        )
        .await?;

        let (init_secret, kem_output) = InitSecret::encode_for_external(
            &cipher_suite_provider,
            &external_pub_ext.external_pub,
        )?;

        let epoch_secrets = EpochSecrets {
            resumption_secret: PreSharedKey::new(vec![]),
            sender_data_secret: SenderDataSecret::from(vec![]),
            secret_tree: SecretTree::empty(),
        };

        let (mut group, _) = Group::join_with(
            self.config,
            cipher_suite_provider.clone(),
            join_context,
            KeySchedule::new(init_secret),
            epoch_secrets,
            TreeKemPrivate::new_for_external(),
            None,
        )
        .await?;

        let psk_ids = self
            .external_psks
            .into_iter()
            .map(|psk_id| {
                Ok(PreSharedKeyID {
                    key_id: JustPreSharedKeyID::External(psk_id),
                    psk_nonce: PskNonce::random(&cipher_suite_provider)
                        .map_err(|e| MlsError::CryptoProviderError(e.into_any_error()))?,
                })
            })
            .collect::<Result<Vec<_>, MlsError>>()?;

        let proposals = psk_ids
            .into_iter()
            .map(|psk| Proposal::Psk(PreSharedKeyProposal { psk }))
            .chain([Proposal::ExternalInit(ExternalInit { kem_output })])
            .chain(self.to_remove.map(|r| {
                Proposal::Remove(RemoveProposal {
                    to_remove: LeafIndex(r),
                })
            }))
            .collect::<Vec<_>>();

        let commit_output = group
            .commit_internal(
                proposals,
                Some(&leaf_node),
                self.authenticated_data,
                Default::default(),
                None,
                None,
            )
            .await?;

        group.apply_pending_commit().await?;

        Ok((group, commit_output.commit_message))
    }
}
