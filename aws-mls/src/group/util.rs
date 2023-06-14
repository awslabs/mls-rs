use aws_mls_codec::MlsDecode;
use aws_mls_core::{
    error::IntoAnyError, identity::IdentityProvider, key_package::KeyPackageStorage,
};

use crate::{
    cipher_suite::CipherSuite,
    client::MlsError,
    extension::RatchetTreeExt,
    key_package::KeyPackageGeneration,
    protocol_version::ProtocolVersion,
    signer::Signable,
    tree_kem::{
        node::{LeafIndex, NodeVec},
        tree_validator::TreeValidator,
        TreeKemPublic,
    },
    CipherSuiteProvider, CryptoProvider, ExtensionList,
};

#[cfg(feature = "external_proposal")]
use crate::extension::ExternalSendersExt;

use super::{
    confirmation_tag::ConfirmationTag, framing::Sender, message_signature::AuthenticatedContent,
    transcript_hash::InterimTranscriptHash, ConfirmedTranscriptHash, EncryptedGroupSecrets,
    GroupContext, GroupInfo,
};

#[cfg(feature = "external_commit")]
use super::message_processor::ProvisionalState;

#[derive(Clone, Debug)]
#[non_exhaustive]
pub(crate) struct JoinContext {
    pub group_info_extensions: ExtensionList,
    pub group_context: GroupContext,
    pub confirmation_tag: ConfirmationTag,
    pub public_tree: TreeKemPublic,
    pub signer_index: LeafIndex,
}

#[cfg(not(feature = "tree_index"))]
#[maybe_async::maybe_async]
pub(crate) async fn process_group_info<C>(
    msg_protocol_version: ProtocolVersion,
    group_info: GroupInfo,
    tree_data: Option<&[u8]>,
    cs: &C,
) -> Result<JoinContext, MlsError>
where
    C: CipherSuiteProvider,
{
    let public_tree = find_tree(tree_data, group_info.extensions.get_as()?).await?;
    process_group_info_with_tree(msg_protocol_version, group_info, public_tree, cs).await
}

#[cfg(feature = "tree_index")]
#[maybe_async::maybe_async]
pub(crate) async fn process_group_info<C, I>(
    msg_protocol_version: ProtocolVersion,
    group_info: GroupInfo,
    tree_data: Option<&[u8]>,
    id_provider: &I,
    cs: &C,
) -> Result<JoinContext, MlsError>
where
    C: CipherSuiteProvider,
    I: IdentityProvider,
{
    let public_tree = find_tree(tree_data, group_info.extensions.get_as()?, id_provider).await?;
    process_group_info_with_tree(msg_protocol_version, group_info, public_tree, cs).await
}

#[maybe_async::maybe_async]
async fn process_group_info_with_tree<C>(
    msg_protocol_version: ProtocolVersion,
    group_info: GroupInfo,
    public_tree: TreeKemPublic,
    cipher_suite_provider: &C,
) -> Result<JoinContext, MlsError>
where
    C: CipherSuiteProvider,
{
    let group_protocol_version = group_info.group_context.protocol_version;

    if msg_protocol_version != group_protocol_version {
        return Err(MlsError::ProtocolVersionMismatch);
    }

    let cipher_suite = cipher_suite_provider.cipher_suite();

    if group_info.group_context.cipher_suite != cipher_suite {
        return Err(MlsError::CipherSuiteMismatch);
    }

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

#[maybe_async::maybe_async]
pub(crate) async fn validate_group_info<I: IdentityProvider, C: CipherSuiteProvider>(
    msg_protocol_version: ProtocolVersion,
    group_info: GroupInfo,
    tree_data: Option<&[u8]>,
    identity_provider: &I,
    cipher_suite_provider: &C,
) -> Result<JoinContext, MlsError> {
    let mut join_context = process_group_info(
        msg_protocol_version,
        group_info,
        tree_data,
        #[cfg(feature = "tree_index")]
        identity_provider,
        cipher_suite_provider,
    )
    .await?;

    #[cfg(feature = "all_extensions")]
    let required_capabilities = join_context.group_context.extensions.get_as()?;

    // Verify the integrity of the ratchet tree
    let tree_validator = TreeValidator::new(
        cipher_suite_provider,
        &join_context.group_context.group_id,
        &join_context.group_context.tree_hash,
        #[cfg(feature = "all_extensions")]
        required_capabilities.as_ref(),
        &join_context.group_context.extensions,
        identity_provider,
    );

    tree_validator
        .validate(&mut join_context.public_tree)
        .await?;

    #[cfg(feature = "external_proposal")]
    if let Some(ext_senders) = join_context
        .group_context
        .extensions
        .get_as::<ExternalSendersExt>()?
    {
        // TODO do joiners verify group against current time??
        ext_senders
            .verify_all(
                identity_provider,
                None,
                &join_context.group_context.extensions,
            )
            .await
            .map_err(|e| MlsError::IdentityProviderError(e.into_any_error()))?;
    }

    Ok(join_context)
}

#[cfg(feature = "tree_index")]
#[maybe_async::maybe_async]
pub(crate) async fn find_tree<C>(
    tree_data: Option<&[u8]>,
    extension: Option<RatchetTreeExt>,
    identity_provider: &C,
) -> Result<TreeKemPublic, MlsError>
where
    C: IdentityProvider,
{
    TreeKemPublic::import_node_data(find_node_data(tree_data, extension)?, identity_provider).await
}

#[cfg(not(feature = "tree_index"))]
#[maybe_async::maybe_async]
pub(crate) async fn find_tree(
    tree_data: Option<&[u8]>,
    extension: Option<RatchetTreeExt>,
) -> Result<TreeKemPublic, MlsError> {
    TreeKemPublic::import_node_data(find_node_data(tree_data, extension)?).await
}

pub(crate) fn find_node_data(
    tree_data: Option<&[u8]>,
    extension: Option<RatchetTreeExt>,
) -> Result<NodeVec, MlsError> {
    match tree_data {
        Some(tree_data) => Ok(NodeVec::mls_decode(&mut &*tree_data)?),
        None => {
            let tree_extension = extension.ok_or(MlsError::RatchetTreeNotFound)?;
            Ok(tree_extension.tree_data)
        }
    }
}

pub(crate) fn commit_sender(
    sender: &Sender,
    #[cfg(feature = "external_commit")] provisional_state: &ProvisionalState,
) -> Result<LeafIndex, MlsError> {
    match sender {
        Sender::Member(index) => Ok(LeafIndex(*index)),
        #[cfg(feature = "external_proposal")]
        Sender::External(_) => Err(MlsError::ExternalSenderCannotCommit),
        #[cfg(feature = "by_ref_proposal")]
        Sender::NewMemberProposal => Err(MlsError::ExpectedAddProposalForNewMemberProposal),
        #[cfg(feature = "external_commit")]
        Sender::NewMemberCommit => provisional_state
            .external_init_index
            .ok_or(MlsError::ExternalCommitMissingExternalInit),
    }
}

pub(super) fn transcript_hashes<P: CipherSuiteProvider>(
    cipher_suite_provider: &P,
    prev_interim_transcript_hash: &InterimTranscriptHash,
    content: &AuthenticatedContent,
) -> Result<(InterimTranscriptHash, ConfirmedTranscriptHash), MlsError> {
    let confirmed_transcript_hash = ConfirmedTranscriptHash::create(
        cipher_suite_provider,
        prev_interim_transcript_hash,
        content,
    )?;

    let confirmation_tag = content
        .auth
        .confirmation_tag
        .as_ref()
        .ok_or(MlsError::InvalidConfirmationTag)?;

    let interim_transcript_hash = InterimTranscriptHash::create(
        cipher_suite_provider,
        &confirmed_transcript_hash,
        confirmation_tag,
    )?;

    Ok((interim_transcript_hash, confirmed_transcript_hash))
}

#[maybe_async::maybe_async]
pub(crate) async fn find_key_package_generation<'a, K: KeyPackageStorage>(
    key_package_repo: &K,
    secrets: &'a [EncryptedGroupSecrets],
) -> Result<(&'a EncryptedGroupSecrets, KeyPackageGeneration), MlsError> {
    for secret in secrets {
        if let Some(val) = key_package_repo
            .get(&secret.new_member)
            .await
            .map_err(|e| MlsError::KeyPackageRepoError(e.into_any_error()))
            .and_then(|maybe_data| {
                if let Some(data) = maybe_data {
                    KeyPackageGeneration::from_storage(secret.new_member.to_vec(), data)
                        .map(|kpg| Some((secret, kpg)))
                } else {
                    Ok::<_, MlsError>(None)
                }
            })?
        {
            return Ok(val);
        }
    }

    Err(MlsError::WelcomeKeyPackageNotFound)
}

pub(crate) fn cipher_suite_provider<P>(
    crypto: P,
    cipher_suite: CipherSuite,
) -> Result<P::CipherSuiteProvider, MlsError>
where
    P: CryptoProvider,
{
    crypto
        .cipher_suite_provider(cipher_suite)
        .ok_or(MlsError::UnsupportedCipherSuite(cipher_suite))
}
