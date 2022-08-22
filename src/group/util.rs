use tls_codec::Deserialize;

use crate::{
    cipher_suite::{CipherSuite, MaybeCipherSuite},
    client_config::{ClientConfig, CredentialValidator},
    extension::{ExtensionList, ExternalSendersExt, GroupContextExtension, RatchetTreeExt},
    key_package::{KeyPackageGeneration, KeyPackageRepository},
    protocol_version::{MaybeProtocolVersion, ProtocolVersion},
    psk::ExternalPskIdValidator,
    signer::Signable,
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
    Commit, ConfirmedTranscriptHash, GroupContext, GroupError, GroupInfo, ProposalCacheError,
    Welcome,
};

pub(crate) fn process_group_info(
    protocol_versions_allowed: &[ProtocolVersion],
    cipher_suites_allowed: &[CipherSuite],
    msg_protocol_version: ProtocolVersion,
    group_info: GroupInfo,
    tree_data: Option<&[u8]>,
) -> Result<(GroupContext, ConfirmationTag, TreeKemPublic, LeafIndex), GroupError> {
    let group_protocol_version = check_protocol_version(
        protocol_versions_allowed,
        group_info.group_context.protocol_version,
    )?;

    if msg_protocol_version != group_protocol_version {
        return Err(GroupError::ProtocolVersionMismatch {
            msg_version: msg_protocol_version,
            wire_format: WireFormat::GroupInfo,
            version: group_protocol_version,
        });
    }

    let cipher_suite =
        check_cipher_suite(cipher_suites_allowed, group_info.group_context.cipher_suite)?;

    let ratchet_tree_ext = group_info.extensions.get_extension::<RatchetTreeExt>()?;

    let public_tree = find_tree(tree_data, cipher_suite, ratchet_tree_ext)?;

    let sender_key_package = public_tree.get_leaf_node(group_info.signer)?;

    group_info.verify(
        &sender_key_package
            .signing_identity
            .public_key(public_tree.cipher_suite)?,
        &(),
    )?;

    let confirmation_tag = group_info.confirmation_tag;
    let signer = group_info.signer;

    let group_context = GroupContext {
        protocol_version: group_protocol_version,
        cipher_suite,
        group_id: group_info.group_context.group_id,
        epoch: group_info.group_context.epoch,
        tree_hash: group_info.group_context.tree_hash,
        confirmed_transcript_hash: group_info.group_context.confirmed_transcript_hash,
        extensions: group_info.group_context.extensions,
    };

    Ok((group_context, confirmation_tag, public_tree, signer))
}

pub(super) fn validate_group_info<C: CredentialValidator>(
    protocol_versions_allowed: &[ProtocolVersion],
    cipher_suites_allowed: &[CipherSuite],
    msg_protocol_version: ProtocolVersion,
    group_info: GroupInfo,
    tree_data: Option<&[u8]>,
    credential_validator: &C,
) -> Result<(GroupContext, ConfirmationTag, TreeKemPublic, LeafIndex), GroupError> {
    let (group_context, confirmation_tag, mut public_tree, signer) = process_group_info(
        protocol_versions_allowed,
        cipher_suites_allowed,
        msg_protocol_version,
        group_info,
        tree_data,
    )?;

    validate_existing_group(&mut public_tree, &group_context, credential_validator)?;

    Ok((group_context, confirmation_tag, public_tree, signer))
}

pub(super) fn find_tree(
    tree_data: Option<&[u8]>,
    cipher_suite: CipherSuite,
    extension: Option<RatchetTreeExt>,
) -> Result<TreeKemPublic, GroupError> {
    match tree_data {
        Some(tree_data) => Ok(TreeKemPublic::import_node_data(
            cipher_suite,
            NodeVec::tls_deserialize(&mut &*tree_data)?,
        )?),
        None => {
            let tree_extension = extension.ok_or(GroupError::RatchetTreeNotFound)?;

            Ok(TreeKemPublic::import_node_data(
                cipher_suite,
                tree_extension.tree_data,
            )?)
        }
    }
}

pub(super) fn validate_existing_group<C: CredentialValidator>(
    public_tree: &mut TreeKemPublic,
    group_context: &GroupContext,
    credential_validator: &C,
) -> Result<(), GroupError> {
    let required_capabilities = group_context.extensions.get_extension()?;

    // Verify the integrity of the ratchet tree
    let tree_validator = TreeValidator::new(
        group_context.cipher_suite,
        &group_context.group_id,
        &group_context.tree_hash,
        required_capabilities.as_ref(),
        credential_validator,
    );

    tree_validator.validate(public_tree)?;

    if let Some(ext_senders) = group_context
        .extensions
        .get_extension::<ExternalSendersExt>()?
    {
        ext_senders.verify_all(&credential_validator, group_context.cipher_suite)?;
    }

    Ok(())
}

pub(super) fn commit_sender(
    sender: &Sender,
    provisional_state: &ProvisionalState,
) -> Result<LeafIndex, GroupError> {
    match sender {
        Sender::Member(index) => Ok(*index),
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
pub(super) fn proposal_effects<C, F, P>(
    commit_receiver: Option<LeafIndex>,
    proposals: &ProposalCache,
    commit: &Commit,
    sender: &Sender,
    group_extensions: &ExtensionList<GroupContextExtension>,
    credential_validator: C,
    public_tree: &TreeKemPublic,
    external_psk_id_validator: P,
    user_filter: F,
) -> Result<ProposalSetEffects, ProposalCacheError>
where
    C: CredentialValidator,
    F: ProposalFilter,
    P: ExternalPskIdValidator,
{
    proposals.resolve_for_commit(
        sender.clone(),
        commit_receiver,
        commit.proposals.clone(),
        commit.path.as_ref().map(|path| &path.leaf_node),
        group_extensions,
        credential_validator,
        public_tree,
        external_psk_id_validator,
        user_filter,
    )
}

pub(super) fn transcript_hashes(
    cipher_suite: CipherSuite,
    prev_interim_transcript_hash: &InterimTranscriptHash,
    content: &MLSAuthenticatedContent,
) -> Result<(InterimTranscriptHash, ConfirmedTranscriptHash), GroupError> {
    let confirmed_transcript_hash =
        ConfirmedTranscriptHash::create(cipher_suite, prev_interim_transcript_hash, content)?;

    let confirmation_tag = content
        .auth
        .confirmation_tag
        .as_ref()
        .ok_or(GroupError::InvalidConfirmationTag)?;

    let interim_transcript_hash =
        InterimTranscriptHash::create(cipher_suite, &confirmed_transcript_hash, confirmation_tag)?;

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

pub(super) fn check_cipher_suite(
    allowed: &[CipherSuite],
    cipher_suite: MaybeCipherSuite,
) -> Result<CipherSuite, GroupError> {
    cipher_suite
        .into_enum()
        .filter(|cs| allowed.contains(cs))
        .ok_or(GroupError::UnsupportedCipherSuite(cipher_suite))
}

pub(super) fn find_key_package_generation<C>(
    config: &C,
    welcome_message: &Welcome,
) -> Result<KeyPackageGeneration, GroupError>
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
        })
        .transpose()
        .map_err(|e| GroupError::KeyPackageRepositoryError(e.into()))?
        .ok_or(GroupError::KeyPackageNotFound)
}
