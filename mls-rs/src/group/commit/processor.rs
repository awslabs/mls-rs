// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// Copyright by contributors to this project.
// SPDX-License-Identifier: (Apache-2.0 OR MIT)

use mls_rs_core::{group::ConfirmedTranscriptHash, time::MlsTime};

use crate::{
    client_config::ClientConfig,
    error::MlsError,
    group::{
        message_processor::path_update_required, transcript_hashes, AuthenticatedContent,
        CommitEffect, CommitMessageDescription, ConfirmationTag, Content, EventOrContent,
        InterimTranscriptHash, MessageProcessor, NewEpoch,
    },
    mls_rules::{CommitDirection, CommitSource, ProposalBundle},
    tree_kem::{leaf_node::LeafNode, node::LeafIndex, validate_update_path, UpdatePath},
    Group, MlsMessage,
};

pub(crate) struct InternalCommitProcessor<'a, P: MessageProcessor> {
    // Group
    pub(crate) processor: &'a mut P,

    // Parsed commit
    pub(crate) proposals: ProposalBundle,
    pub(crate) path: Option<UpdatePath>,
    pub(crate) committer: CommitSource,
    pub(crate) authenticated_data: Vec<u8>,
    pub(crate) interim_transcript_hash: InterimTranscriptHash,
    pub(crate) confirmed_transcript_hash: ConfirmedTranscriptHash,
    pub(crate) confirmation_tag: ConfirmationTag,

    // Processing options
    pub(crate) time_sent: Option<MlsTime>,
}

#[cfg_attr(not(mls_build_async), maybe_async::must_be_sync)]
pub(crate) async fn new_commit_processor<P: MessageProcessor>(
    processor: &mut P,
    commit_message: MlsMessage,
) -> Result<InternalCommitProcessor<'_, P>, MlsError> {
    let event_or_content = processor
        .get_event_from_incoming_message(commit_message)
        .await?;

    let commit_content = match event_or_content {
        EventOrContent::Content(c) => c,
        _ => return Err(MlsError::UnexpectedMessageType),
    };

    commit_processor_from_content(processor, commit_content).await
}

#[cfg_attr(not(mls_build_async), maybe_async::must_be_sync)]
pub(crate) async fn commit_processor_from_content<P: MessageProcessor>(
    processor: &mut P,
    commit_content: AuthenticatedContent,
) -> Result<InternalCommitProcessor<'_, P>, MlsError> {
    if processor.group_state().pending_reinit.is_some() {
        return Err(MlsError::GroupUsedAfterReInit);
    }

    // Update the new GroupContext's confirmed and interim transcript hashes using the new Commit.
    let (interim_transcript_hash, confirmed_transcript_hash) = transcript_hashes(
        &processor.cipher_suite_provider(),
        &processor.group_state().interim_transcript_hash,
        &commit_content,
    )
    .await?;

    #[cfg(any(feature = "private_message", feature = "by_ref_proposal"))]
    let commit = match commit_content.content.content {
        Content::Commit(commit) => Ok(*commit),
        _ => Err(MlsError::UnexpectedMessageType),
    }?;

    #[cfg(not(any(feature = "private_message", feature = "by_ref_proposal")))]
    let Content::Commit(commit) = commit_content.content.content;

    #[cfg(feature = "by_ref_proposal")]
    let proposals = processor
        .group_state()
        .proposals
        .resolve_for_commit(commit_content.content.sender, commit.proposals)?;

    #[cfg(not(feature = "by_ref_proposal"))]
    let proposals = resolve_for_commit(commit_content.content.sender, commit.proposals)?;

    let committer = CommitSource::new(
        &commit_content.content.sender,
        &processor.group_state().public_tree,
        commit.path.as_ref().map(|p| &p.leaf_node),
    )?;

    Ok(InternalCommitProcessor {
        processor,
        proposals,
        path: commit.path,
        committer,
        authenticated_data: commit_content.content.authenticated_data,
        interim_transcript_hash,
        confirmed_transcript_hash,
        confirmation_tag: commit_content
            .auth
            .confirmation_tag
            .ok_or(MlsError::InvalidConfirmationTag)?,
        time_sent: None,
    })
}

#[cfg_attr(not(mls_build_async), maybe_async::must_be_sync)]
pub(crate) async fn process_commit<P: MessageProcessor>(
    commit_processor: InternalCommitProcessor<'_, P>,
) -> Result<CommitMessageDescription, MlsError> {
    let id_provider = commit_processor.processor.identity_provider();
    let cs_provider = commit_processor.processor.cipher_suite_provider();

    // TODO remove
    let user_rules = commit_processor.processor.mls_rules();
    let psk_storage = commit_processor.processor.psk_storage();

    let mut provisional_state = commit_processor
        .processor
        .group_state()
        .apply_resolved(
            commit_processor.proposals,
            commit_processor.path.as_ref().map(|path| &path.leaf_node),
            &id_provider,
            &cs_provider,
            commit_processor.time_sent,
            CommitDirection::Receive,
            &psk_storage,
            &user_rules,
            &commit_processor.committer,
        )
        .await?;

    let sender = match &commit_processor.committer {
        CommitSource::ExistingMember(m) => LeafIndex(m.index),
        CommitSource::NewMember(_) => provisional_state
            .external_init_index
            .ok_or(MlsError::ExternalCommitMissingExternalInit)?,
    };

    //Verify that the path value is populated if the proposals vector contains any Update
    // or Remove proposals, or if it's empty. Otherwise, the path value MAY be omitted.
    if path_update_required(&provisional_state.applied_proposals) && commit_processor.path.is_none()
    {
        return Err(MlsError::CommitMissingPath);
    }

    let self_removed = commit_processor
        .processor
        .removal_proposal(&provisional_state);

    let is_self_removed = self_removed.is_some();

    let update_path = match commit_processor.path {
        Some(update_path) => Some(
            validate_update_path(
                &id_provider,
                &cs_provider,
                update_path,
                &provisional_state,
                sender,
                commit_processor.time_sent,
                &provisional_state.group_context,
            )
            .await?,
        ),
        None => None,
    };

    let commit_effect = if let Some(reinit) =
        provisional_state.applied_proposals.reinitializations.pop()
    {
        commit_processor.processor.group_state_mut().pending_reinit = Some(reinit.proposal.clone());
        CommitEffect::ReInit(reinit)
    } else if let Some(remove_proposal) = self_removed {
        let new_epoch = NewEpoch::new(
            commit_processor.processor.group_state().clone(),
            &provisional_state,
        );

        CommitEffect::Removed {
            remover: remove_proposal.sender,
            new_epoch: Box::new(new_epoch),
        }
    } else {
        CommitEffect::NewEpoch(Box::new(NewEpoch::new(
            commit_processor.processor.group_state().clone(),
            &provisional_state,
        )))
    };

    let new_secrets = match update_path {
        Some(update_path) if !is_self_removed => {
            commit_processor
                .processor
                .apply_update_path(sender, &update_path, &mut provisional_state)
                .await
        }
        _ => Ok(None),
    }?;

    // Update the transcript hash to get the new context.
    provisional_state.group_context.confirmed_transcript_hash =
        commit_processor.confirmed_transcript_hash;

    // Update the parent hashes in the new context
    provisional_state
        .public_tree
        .update_hashes(&[sender], &cs_provider)
        .await?;

    // Update the tree hash in the new context
    provisional_state.group_context.tree_hash = provisional_state
        .public_tree
        .tree_hash(&cs_provider)
        .await?;

    if !is_self_removed {
        // Update the key schedule to calculate new private keys
        commit_processor
            .processor
            .update_key_schedule(
                new_secrets,
                commit_processor.interim_transcript_hash,
                &commit_processor.confirmation_tag,
                provisional_state,
            )
            .await?;
    }

    Ok(CommitMessageDescription {
        is_external: matches!(commit_processor.committer, CommitSource::NewMember(_)),
        authenticated_data: commit_processor.authenticated_data,
        committer: *sender,
        effect: commit_effect,
    })
}

pub struct CommitProcessor<'a, C: ClientConfig>(InternalCommitProcessor<'a, Group<C>>);

impl<C: ClientConfig> CommitProcessor<'_, C> {
    #[cfg_attr(not(mls_build_async), maybe_async::must_be_sync)]
    pub async fn process(self) -> Result<CommitMessageDescription, MlsError> {
        process_commit(self.0).await
    }

    // Settings
    pub fn time_sent(self, time_sent: MlsTime) -> Self {
        Self(InternalCommitProcessor {
            time_sent: Some(time_sent),
            ..self.0
        })
    }

    // Info
    pub fn proposals(&self) -> &ProposalBundle {
        &self.0.proposals
    }

    pub fn has_path(&self) -> bool {
        self.0.path.is_some()
    }

    pub fn committers_new_leaf(&self) -> Option<&LeafNode> {
        self.0.path.as_ref().map(|p| &p.leaf_node)
    }

    pub fn committer(&self) -> &CommitSource {
        &self.0.committer
    }

    pub fn authenticated_data(&self) -> &[u8] {
        &self.0.authenticated_data
    }
}

impl<C: ClientConfig> Group<C> {
    #[cfg_attr(not(mls_build_async), maybe_async::must_be_sync)]
    pub async fn commit_processor(
        &mut self,
        commit_message: MlsMessage,
    ) -> Result<CommitProcessor<'_, C>, MlsError> {
        let p = new_commit_processor(self, commit_message).await?;
        Ok(CommitProcessor(p))
    }
}
