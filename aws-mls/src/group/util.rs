use aws_mls_core::identity::IdentityProvider;
use tls_codec::Deserialize;

use crate::{
    cipher_suite::{CipherSuite, MaybeCipherSuite},
    client_config::ClientConfig,
    extension::{
        ExtensionList, ExternalSendersExt, GroupContextExtension, GroupInfoExtension,
        RatchetTreeExt,
    },
    key_package::KeyPackageGeneration,
    protocol_version::{MaybeProtocolVersion, ProtocolVersion},
    provider::{
        crypto::{CipherSuiteProvider, CryptoProvider},
        key_package::KeyPackageRepository,
    },
    psk::ExternalPskIdValidator,
    signer::Signable,
    time::MlsTime,
    tree_kem::{
        node::{LeafIndex, NodeVec},
        tree_validator::TreeValidator,
        TreeKemPublic,
    },
};

use super::{
    confirmation_tag::ConfirmationTag,
    framing::{Sender, WireFormat},
    message_processor::ProvisionalState,
    message_signature::MLSAuthenticatedContent,
    proposal_cache::{ProposalCache, ProposalSetEffects},
    proposal_filter::ProposalFilter,
    transcript_hash::InterimTranscriptHash,
    Commit, ConfirmedTranscriptHash, EncryptedGroupSecrets, GroupContext, GroupError, GroupInfo,
    ProposalCacheError, Welcome,
};

#[derive(Clone, Debug)]
#[non_exhaustive]
pub(crate) struct JoinContext {
    pub group_info_extensions: ExtensionList<GroupInfoExtension>,
    pub group_context: GroupContext,
    pub confirmation_tag: ConfirmationTag,
    pub public_tree: TreeKemPublic,
    pub signer_index: LeafIndex,
}

pub(crate) async fn process_group_info<I, C>(
    msg_protocol_version: ProtocolVersion,
    group_info: GroupInfo,
    tree_data: Option<&[u8]>,
    identity_provider: &I,
    cipher_suite_provider: &C,
) -> Result<JoinContext, GroupError>
where
    I: IdentityProvider,
    C: CipherSuiteProvider,
{
    let group_protocol_version = group_info.group_context.protocol_version;

    if msg_protocol_version as u16 != group_protocol_version.raw_value() {
        return Err(GroupError::ProtocolVersionMismatch {
            msg_version: msg_protocol_version,
            wire_format: WireFormat::GroupInfo,
            version: group_protocol_version,
        });
    }

    let cipher_suite = cipher_suite_provider.cipher_suite();

    if group_info.group_context.cipher_suite.raw_value() != cipher_suite as u16 {
        return Err(GroupError::CipherSuiteMismatch);
    }

    let ratchet_tree_ext = group_info.extensions.get_extension::<RatchetTreeExt>()?;

    let public_tree = find_tree(tree_data, ratchet_tree_ext, identity_provider).await?;

    let sender_key_package = public_tree.get_leaf_node(group_info.signer)?;

    group_info.verify(
        cipher_suite_provider,
        &sender_key_package.signing_identity.signature_key,
        &(),
    )?;

    let confirmation_tag = group_info.confirmation_tag;
    let signer_index = group_info.signer;

    let group_context = GroupContext {
        protocol_version: msg_protocol_version,
        cipher_suite,
        group_id: group_info.group_context.group_id,
        epoch: group_info.group_context.epoch,
        tree_hash: group_info.group_context.tree_hash,
        confirmed_transcript_hash: group_info.group_context.confirmed_transcript_hash,
        extensions: group_info.group_context.extensions,
    };

    Ok(JoinContext {
        group_info_extensions: group_info.extensions,
        group_context,
        confirmation_tag,
        public_tree,
        signer_index,
    })
}

pub(super) async fn validate_group_info<I: IdentityProvider, C: CipherSuiteProvider>(
    msg_protocol_version: ProtocolVersion,
    group_info: GroupInfo,
    tree_data: Option<&[u8]>,
    identity_provider: &I,
    cipher_suite_provider: &C,
) -> Result<JoinContext, GroupError> {
    let mut join_context = process_group_info(
        msg_protocol_version,
        group_info,
        tree_data,
        identity_provider,
        cipher_suite_provider,
    )
    .await?;

    let required_capabilities = join_context.group_context.extensions.get_extension()?;

    // Verify the integrity of the ratchet tree
    let tree_validator = TreeValidator::new(
        cipher_suite_provider,
        &join_context.group_context.group_id,
        &join_context.group_context.tree_hash,
        required_capabilities.as_ref(),
        identity_provider,
    );

    tree_validator
        .validate(&mut join_context.public_tree)
        .await?;

    if let Some(ext_senders) = join_context
        .group_context
        .extensions
        .get_extension::<ExternalSendersExt>()?
    {
        // TODO do joiners verify group against current time??
        ext_senders
            .verify_all(&identity_provider, None)
            .await
            .map_err(|e| GroupError::IdentityProviderError(e.into()))?;
    }

    Ok(join_context)
}

pub(super) async fn find_tree<C>(
    tree_data: Option<&[u8]>,
    extension: Option<RatchetTreeExt>,
    identity_provider: &C,
) -> Result<TreeKemPublic, GroupError>
where
    C: IdentityProvider,
{
    match tree_data {
        Some(tree_data) => Ok(TreeKemPublic::import_node_data(
            NodeVec::tls_deserialize(&mut &*tree_data)?,
            identity_provider,
        )
        .await?),
        None => {
            let tree_extension = extension.ok_or(GroupError::RatchetTreeNotFound)?;

            Ok(
                TreeKemPublic::import_node_data(tree_extension.tree_data, identity_provider)
                    .await?,
            )
        }
    }
}

pub(super) fn commit_sender(
    sender: &Sender,
    provisional_state: &ProvisionalState,
) -> Result<LeafIndex, GroupError> {
    match sender {
        Sender::Member(index) => Ok(LeafIndex(*index)),
        Sender::External(_) => Err(GroupError::ExternalSenderCannotCommit),
        Sender::NewMemberProposal => Err(GroupError::ExpectedAddProposalForNewMemberProposal),
        Sender::NewMemberCommit => provisional_state
            .external_init
            .as_ref()
            .map(|(index, _)| *index)
            .ok_or(GroupError::ExternalCommitMissingExternalInit),
    }
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn proposal_effects<C, F, P, CSP>(
    commit_receiver: Option<LeafIndex>,
    proposals: &ProposalCache,
    commit: &Commit,
    sender: &Sender,
    group_extensions: &ExtensionList<GroupContextExtension>,
    identity_provider: C,
    cipher_suite_provider: &CSP,
    public_tree: &TreeKemPublic,
    external_psk_id_validator: P,
    user_filter: F,
    commit_time: Option<MlsTime>,
) -> Result<ProposalSetEffects, ProposalCacheError>
where
    C: IdentityProvider,
    F: ProposalFilter,
    P: ExternalPskIdValidator,
    CSP: CipherSuiteProvider,
{
    proposals
        .resolve_for_commit(
            sender.clone(),
            commit_receiver,
            commit.proposals.clone(),
            commit.path.as_ref().map(|path| &path.leaf_node),
            group_extensions,
            identity_provider,
            cipher_suite_provider,
            public_tree,
            external_psk_id_validator,
            user_filter,
            commit_time,
        )
        .await
}

pub(super) fn transcript_hashes<P: CipherSuiteProvider>(
    cipher_suite_provider: &P,
    prev_interim_transcript_hash: &InterimTranscriptHash,
    content: &MLSAuthenticatedContent,
) -> Result<(InterimTranscriptHash, ConfirmedTranscriptHash), GroupError> {
    let confirmed_transcript_hash = ConfirmedTranscriptHash::create(
        cipher_suite_provider,
        prev_interim_transcript_hash,
        content,
    )?;

    let confirmation_tag = content
        .auth
        .confirmation_tag
        .as_ref()
        .ok_or(GroupError::InvalidConfirmationTag)?;

    let interim_transcript_hash = InterimTranscriptHash::create(
        cipher_suite_provider,
        &confirmed_transcript_hash,
        confirmation_tag,
    )?;

    Ok((interim_transcript_hash, confirmed_transcript_hash))
}

pub(super) fn check_protocol_version(
    allowed: &[ProtocolVersion],
    version: MaybeProtocolVersion,
) -> Result<ProtocolVersion, GroupError> {
    version
        .into_enum()
        .filter(|v| allowed.contains(v))
        .ok_or(GroupError::UnsupportedProtocolVersion(version))
}

pub(super) fn find_key_package_generation<'a, C>(
    config: &C,
    welcome_message: &'a Welcome,
) -> Result<(&'a EncryptedGroupSecrets, KeyPackageGeneration), GroupError>
where
    C: ClientConfig,
{
    welcome_message
        .secrets
        .iter()
        .find_map(|secrets| {
            config
                .key_package_repo()
                .get(&secrets.new_member)
                .transpose()
                .map(|res| res.map(|key_package_gen| (secrets, key_package_gen)))
        })
        .transpose()
        .map_err(|e| GroupError::KeyPackageRepositoryError(e.into()))?
        .ok_or(GroupError::KeyPackageNotFound)
}

pub(super) fn cipher_suite_provider<P>(
    crypto: P,
    cipher_suite: CipherSuite,
) -> Result<P::CipherSuiteProvider, GroupError>
where
    P: CryptoProvider,
{
    crypto
        .cipher_suite_provider(cipher_suite)
        .ok_or(GroupError::UnsupportedCipherSuite(cipher_suite.into()))
}

pub(super) fn maybe_cipher_suite_provider<P>(
    crypto: P,
    cipher_suite: MaybeCipherSuite,
) -> Result<P::CipherSuiteProvider, GroupError>
where
    P: CryptoProvider,
{
    cipher_suite
        .into_enum()
        .and_then(|cs| crypto.cipher_suite_provider(cs))
        .ok_or_else(|| GroupError::UnsupportedCipherSuite(cipher_suite))
}
