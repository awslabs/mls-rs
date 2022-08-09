use crate::{
    client_config::ClientConfig,
    group::{GroupContext, InterimTranscriptHash},
    tree_kem::{node::NodeVec, TreeKemPrivate, TreeKemPublic},
};
use ferriscrypt::hpke::kem::HpkeSecretKey;
use std::collections::HashMap;
use tls_codec::{Deserialize, Serialize};

use super::{
    confirmation_tag::ConfirmationTag, group_core::GroupCore, key_schedule::KeySchedule,
    proposal::ReInit, proposal_cache::CachedProposal, CommitGeneration, Group, GroupError,
    ProposalRef,
};

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub struct GroupState {
    pub(crate) context: GroupContext,
    pub(crate) private_tree: TreeKemPrivate,
    // TODO: This should be base64
    pub(crate) current_tree_data: Vec<u8>,
    pub(crate) key_schedule: KeySchedule,
    pub(crate) interim_transcript_hash: InterimTranscriptHash,
    pub(crate) confirmation_tag: ConfirmationTag,
    #[serde(with = "crate::serde_utils::map_as_seq")]
    proposals: HashMap<ProposalRef, CachedProposal>,
    #[serde(with = "crate::serde_utils::map_as_seq")]
    pub(crate) pending_updates: HashMap<Vec<u8>, HpkeSecretKey>,
    pub(crate) pending_reinit: Option<ReInit>,
    pub(crate) pending_commit: Option<CommitGeneration>,
}

impl<C> Group<C>
where
    C: ClientConfig + Clone,
{
    pub fn export(&self) -> Result<GroupState, GroupError> {
        Ok(GroupState {
            context: self.core.context.clone(),
            private_tree: self.private_tree.clone(),
            current_tree_data: self
                .core
                .current_tree
                .export_node_data()
                .tls_serialize_detached()?,
            key_schedule: self.key_schedule.clone(),
            interim_transcript_hash: self.core.interim_transcript_hash.clone(),
            confirmation_tag: self.core.confirmation_tag.clone(),
            proposals: self.core.proposals.proposals().clone(),
            pending_updates: self.core.pending_updates.clone(),
            pending_commit: self.core.pending_commit.clone(),
            pending_reinit: self.core.pending_reinit.clone(),
        })
    }

    pub fn import(config: C, state: GroupState) -> Result<Self, GroupError> {
        let imported_tree = TreeKemPublic::import_node_data(
            state.context.cipher_suite,
            NodeVec::tls_deserialize(&mut &*state.current_tree_data)?,
        )?;

        let core = GroupCore::import(
            state.context,
            imported_tree,
            state.interim_transcript_hash,
            state.proposals,
            state.pending_reinit,
            state.pending_updates,
            state.pending_commit,
            state.confirmation_tag,
        );

        Ok(Self {
            config,
            core,
            private_tree: state.private_tree,
            key_schedule: state.key_schedule,
        })
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        client::test_utils::{TEST_CIPHER_SUITE, TEST_PROTOCOL_VERSION},
        group::{test_utils::test_group, Event, Group},
    };
    use assert_matches::assert_matches;

    #[test]
    fn saved_group_can_be_resumed() {
        let mut alice_group = test_group(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE);
        let (mut bob_group, _) = alice_group.join("bob");

        // Commit so that Bob's group records a new epoch.
        let (commit, _) = bob_group
            .group
            .commit_proposals(Vec::new(), Vec::new())
            .unwrap();

        bob_group.process_pending_commit().unwrap();

        alice_group.group.process_incoming_message(commit).unwrap();

        let bob_group_bytes = serde_json::to_vec(&bob_group.group.export().unwrap()).unwrap();

        let mut bob_group = Group::import(
            bob_group.group.config.clone(),
            serde_json::from_slice(&bob_group_bytes).unwrap(),
        )
        .unwrap();

        let message = alice_group
            .group
            .encrypt_application_message(b"hello", vec![])
            .unwrap();

        let received_message = bob_group.process_incoming_message(message).unwrap();

        assert_matches!(
            received_message.event,
            Event::ApplicationMessage(bytes) if bytes == b"hello"
        );

        let (commit, _) = alice_group
            .group
            .commit_proposals(Vec::new(), Vec::new())
            .unwrap();

        alice_group.group.process_pending_commit().unwrap();
        bob_group.process_incoming_message(commit).unwrap();

        assert_eq!(
            alice_group.group.group_stats().unwrap().epoch,
            bob_group.group_stats().unwrap().epoch
        );
    }
}
