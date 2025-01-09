// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// Copyright by contributors to this project.
// SPDX-License-Identifier: (Apache-2.0 OR MIT)

use mls_rs_core::{
    error::IntoAnyError,
    identity::{IdentityProvider, SigningIdentity},
};

use crate::{
    cipher_suite::CipherSuite,
    client::MlsError,
    extension::RatchetTreeExt,
    protocol_version::ProtocolVersion,
    signer::Signable,
    tree_kem::{tree_validator::TreeValidator, TreeKemPublic},
    CipherSuiteProvider, CryptoProvider,
};

#[cfg(feature = "by_ref_proposal")]
use crate::extension::ExternalSendersExt;

use super::{
    message_signature::AuthenticatedContent, transcript_hash::InterimTranscriptHash,
    ConfirmedTranscriptHash, ExportedTree, GroupInfo, GroupState,
};

#[cfg_attr(not(mls_build_async), maybe_async::must_be_sync)]
pub(crate) async fn validate_group_info_common<C: CipherSuiteProvider>(
    msg_version: ProtocolVersion,
    group_info: &GroupInfo,
    signer: &SigningIdentity,
    cs: &C,
) -> Result<(), MlsError> {
    if msg_version != group_info.group_context.protocol_version {
        return Err(MlsError::ProtocolVersionMismatch);
    }

    if group_info.group_context.cipher_suite != cs.cipher_suite() {
        return Err(MlsError::CipherSuiteMismatch);
    }

    group_info.verify(cs, &signer.signature_key, &()).await?;

    Ok(())
}

#[cfg_attr(not(mls_build_async), maybe_async::must_be_sync)]
pub(crate) async fn validate_group_info_member<C: CipherSuiteProvider>(
    self_state: &GroupState,
    msg_version: ProtocolVersion,
    group_info: &GroupInfo,
    cs: &C,
) -> Result<(), MlsError> {
    let signer = &self_state.public_tree.get_leaf_node(group_info.signer)?;
    validate_group_info_common(msg_version, group_info, &signer.signing_identity, cs).await?;

    let self_tree = ExportedTree::new_borrowed(&self_state.public_tree.nodes);

    if let Some(tree) = group_info.extensions.get_as::<RatchetTreeExt>()? {
        (tree.tree_data == self_tree)
            .then_some(())
            .ok_or(MlsError::InvalidGroupInfo)?;
    }

    (group_info.group_context == self_state.context
        && group_info.confirmation_tag == self_state.confirmation_tag)
        .then_some(())
        .ok_or(MlsError::InvalidGroupInfo)?;

    Ok(())
}

#[cfg_attr(not(mls_build_async), maybe_async::must_be_sync)]
pub(crate) async fn validate_tree_and_info_joiner<C: CipherSuiteProvider, I: IdentityProvider>(
    msg_version: ProtocolVersion,
    group_info: &GroupInfo,
    tree: Option<ExportedTree<'_>>,
    id_provider: &I,
    cs: &C,
) -> Result<TreeKemPublic, MlsError> {
    let public_tree = validate_tree_joiner(group_info, tree, id_provider, cs).await?;

    let signer = &public_tree
        .get_leaf_node(group_info.signer)?
        .signing_identity;

    validate_group_info_joiner(msg_version, group_info, signer, id_provider, cs).await?;

    Ok(public_tree)
}

#[cfg_attr(not(mls_build_async), maybe_async::must_be_sync)]
pub(crate) async fn validate_tree_joiner<C: CipherSuiteProvider, I: IdentityProvider>(
    group_info: &GroupInfo,
    tree: Option<ExportedTree<'_>>,
    id_provider: &I,
    cs: &C,
) -> Result<TreeKemPublic, MlsError> {
    let tree = match group_info.extensions.get_as::<RatchetTreeExt>()? {
        Some(ext) => ext.tree_data,
        None => tree.ok_or(MlsError::RatchetTreeNotFound)?,
    };

    let context = &group_info.group_context;

    let mut tree =
        TreeKemPublic::import_node_data(tree.into(), id_provider, &context.extensions).await?;

    // Verify the integrity of the ratchet tree
    TreeValidator::new(cs, context, id_provider)
        .validate(&mut tree)
        .await?;

    Ok(tree)
}

#[cfg_attr(not(mls_build_async), maybe_async::must_be_sync)]
pub(crate) async fn validate_group_info_joiner<C: CipherSuiteProvider, I: IdentityProvider>(
    msg_version: ProtocolVersion,
    group_info: &GroupInfo,
    signer: &SigningIdentity,
    #[cfg(feature = "by_ref_proposal")] id_provider: &I,
    #[cfg(not(feature = "by_ref_proposal"))] _id_provider: &I,
    cs: &C,
) -> Result<(), MlsError> {
    #[cfg(feature = "by_ref_proposal")]
    let context = &group_info.group_context;

    #[cfg(feature = "by_ref_proposal")]
    if let Some(ext_senders) = context.extensions.get_as::<ExternalSendersExt>()? {
        // TODO do joiners verify group against current time??
        ext_senders
            .verify_all(id_provider, None, &context.extensions)
            .await
            .map_err(|e| MlsError::IdentityProviderError(e.into_any_error()))?;
    }

    validate_group_info_common(msg_version, group_info, signer, cs).await?;

    Ok(())
}

#[cfg_attr(not(mls_build_async), maybe_async::must_be_sync)]
pub(super) async fn transcript_hashes<P: CipherSuiteProvider>(
    cipher_suite_provider: &P,
    prev_interim_transcript_hash: &InterimTranscriptHash,
    content: &AuthenticatedContent,
) -> Result<(InterimTranscriptHash, ConfirmedTranscriptHash), MlsError> {
    let confirmed_transcript_hash = super::transcript_hash::create(
        cipher_suite_provider,
        prev_interim_transcript_hash,
        content,
    )
    .await?;

    let confirmation_tag = content
        .auth
        .confirmation_tag
        .as_ref()
        .ok_or(MlsError::InvalidConfirmationTag)?;

    let interim_transcript_hash = InterimTranscriptHash::create(
        cipher_suite_provider,
        &confirmed_transcript_hash,
        confirmation_tag,
    )
    .await?;

    Ok((interim_transcript_hash, confirmed_transcript_hash))
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
