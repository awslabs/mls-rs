use mls_rs_core::time::MlsTime;

use crate::{
    error::MlsError,
    group::{
        message_processor::{path_update_required, MessageProcessor},
        message_signature::AuthenticatedContent,
        util::{commit_sender, transcript_hashes},
        CommitEffect, CommitMessageDescription, ConfirmationTag, ConfirmedTranscriptHash, Content,
        InterimTranscriptHash, NewEpoch, Sender,
    },
    mls_rules::{CommitDirection, ProposalBundle},
    tree_kem::{validate_update_path, UpdatePath},
};

use super::{EventOrContent, MlsMessage};

pub struct CommitProcessor<'a, P> {
    processor: &'a mut P,

    // Extracted from commit
    interim_transcript_hash: InterimTranscriptHash,
    confirmed_transcript_hash: ConfirmedTranscriptHash,
    confirmation_tag: ConfirmationTag,
    proposals: ProposalBundle,
    path: Option<UpdatePath>,
    sender: Sender,
    authenticated_data: Vec<u8>,

    // Adjustable
    time_sent: Option<MlsTime>,
}

impl<'a, P> CommitProcessor<'a, P> {
    // Info
    pub fn proposals(&self) -> &ProposalBundle {
        &self.proposals
    }

    pub fn authenticated_data(&self) -> &[u8] {
        &self.authenticated_data
    }

    pub fn sender(&self) -> Sender {
        self.sender
    }

    pub fn has_update_path(&self) -> bool {
        self.path.is_some()
    }

    pub fn update_path(&self) -> Option<&UpdatePath> {
        self.path.as_ref()
    }

    // Adjusting
    pub fn with_time_sent(self, time_sent: Option<MlsTime>) -> Self {
        Self { time_sent, ..self }
    }

    pub fn proposals_mut(&mut self) -> &mut ProposalBundle {
        &mut self.proposals
    }
}

#[cfg_attr(not(mls_build_async), maybe_async::must_be_sync)]
pub(crate) async fn commit_processor<P: MessageProcessor>(
    processor: &mut P,
    message: MlsMessage,
) -> Result<CommitProcessor<'_, P>, MlsError> {
    let event = processor.get_event_from_incoming_message(message).await?;

    match event {
        EventOrContent::Content(auth_content) => {
            commit_processor_from_content(processor, auth_content).await
        }
        _ => Err(MlsError::UnexpectedMessageType),
    }
}

#[cfg_attr(not(mls_build_async), maybe_async::must_be_sync)]
pub(crate) async fn commit_processor_from_content<P: MessageProcessor>(
    processor: &mut P,
    auth_content: AuthenticatedContent,
) -> Result<CommitProcessor<'_, P>, MlsError> {
    let (interim_transcript_hash, confirmed_transcript_hash) = transcript_hashes(
        processor.cipher_suite_provider(),
        &processor.group_state().interim_transcript_hash,
        &auth_content,
    )
    .await?;

    let confirmation_tag = auth_content
        .auth
        .confirmation_tag
        .ok_or(MlsError::InvalidConfirmationTag)?;

    #[cfg(any(feature = "private_message", feature = "by_ref_proposal"))]
    let commit = match auth_content.content.content {
        Content::Commit(commit) => Ok(commit),
        _ => Err(MlsError::UnexpectedMessageType),
    }?;

    #[cfg(not(any(feature = "private_message", feature = "by_ref_proposal")))]
    let Content::Commit(commit) = auth_content.content.content;

    #[cfg(feature = "by_ref_proposal")]
    let proposals = processor
        .group_state()
        .proposals
        .resolve_for_commit(auth_content.content.sender, commit.proposals)?;

    #[cfg(not(feature = "by_ref_proposal"))]
    let proposals = resolve_for_commit(sender, commit.proposals)?;

    Ok(CommitProcessor {
        processor,
        interim_transcript_hash,
        confirmed_transcript_hash,
        confirmation_tag,
        proposals,
        path: commit.path,
        sender: auth_content.content.sender,
        authenticated_data: auth_content.content.authenticated_data,
        time_sent: None,
    })
}

#[cfg_attr(not(mls_build_async), maybe_async::must_be_sync)]
pub(crate) async fn commit<P: MessageProcessor>(
    commit_processor: CommitProcessor<'_, P>,
) -> Result<CommitMessageDescription, MlsError> {
    let mut provisional_state = commit_processor
        .processor
        .group_state()
        .apply_resolved(
            commit_processor.sender,
            commit_processor.proposals,
            commit_processor.path.as_ref().map(|path| &path.leaf_node),
            &commit_processor.processor.identity_provider(),
            commit_processor.processor.cipher_suite_provider(),
            &commit_processor.processor.psk_storage(),
            &commit_processor.processor.mls_rules(),
            commit_processor.time_sent,
            CommitDirection::Receive,
        )
        .await?;

    let committer = commit_sender(&commit_processor.sender, &provisional_state)?;

    //Verify that the path value is populated if the proposals vector contains any Update
    // or Remove proposals, or if it's empty. Otherwise, the path value MAY be omitted.
    if path_update_required(&provisional_state.applied_proposals) && commit_processor.path.is_none()
    {
        return Err(MlsError::CommitMissingPath);
    }

    if let Some(remove_proposal) = commit_processor
        .processor
        .removal_proposal(&provisional_state)
    {
        let new_epoch = NewEpoch::new(
            commit_processor.processor.group_state().clone(),
            &provisional_state,
        );

        return Ok(CommitMessageDescription {
            is_external: matches!(commit_processor.sender, Sender::NewMemberCommit),
            authenticated_data: commit_processor.authenticated_data,
            committer: *committer,
            effect: CommitEffect::Removed {
                remove_proposal,
                new_epoch: Box::new(new_epoch),
            },
        });
    }

    let update_path = match commit_processor.path {
        Some(update_path) => Some(
            validate_update_path(
                &commit_processor.processor.identity_provider(),
                commit_processor.processor.cipher_suite_provider(),
                update_path,
                &provisional_state,
                committer,
                commit_processor.time_sent,
                &commit_processor.processor.group_state().context,
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
    } else {
        CommitEffect::NewEpoch(Box::new(NewEpoch::new(
            commit_processor.processor.group_state().clone(),
            &provisional_state,
        )))
    };

    let new_secrets = match update_path {
        Some(update_path) => {
            commit_processor
                .processor
                .apply_update_path(committer, &update_path, &mut provisional_state)
                .await
        }
        None => Ok(None),
    }?;

    // Update the transcript hash to get the new context.
    provisional_state.group_context.confirmed_transcript_hash =
        commit_processor.confirmed_transcript_hash;

    // Update the parent hashes in the new context
    provisional_state
        .public_tree
        .update_hashes(
            &[committer],
            commit_processor.processor.cipher_suite_provider(),
        )
        .await?;

    // Update the tree hash in the new context
    provisional_state.group_context.tree_hash = provisional_state
        .public_tree
        .tree_hash(commit_processor.processor.cipher_suite_provider())
        .await?;

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

    Ok(CommitMessageDescription {
        is_external: matches!(commit_processor.sender, Sender::NewMemberCommit),
        authenticated_data: commit_processor.authenticated_data,
        committer: *committer,
        effect: commit_effect,
    })
}
