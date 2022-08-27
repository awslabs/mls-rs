use crate::{
    client_config::ClientConfig,
    credential::CredentialValidator,
    group::{
        key_schedule::KeySchedule, CachedProposal, CommitGeneration, ConfirmationTag, Group,
        GroupContext, GroupError, GroupState, InterimTranscriptHash, ProposalCache, ProposalRef,
        ReInit, TreeKemPublic,
    },
    serde_utils::vec_u8_as_base64::VecAsBase64,
    tree_kem::{node::NodeVec, TreeKemPrivate},
};
use ferriscrypt::hpke::kem::{HpkePublicKey, HpkeSecretKey};
use serde_with::serde_as;
use std::collections::HashMap;

#[serde_as]
#[derive(Debug, serde::Serialize, serde::Deserialize, PartialEq)]
pub struct Snapshot {
    state: RawGroupState,
    private_tree: TreeKemPrivate,
    key_schedule: KeySchedule,
    #[serde_as(as = "HashMap<VecAsBase64, VecAsBase64>")]
    pending_updates: HashMap<HpkePublicKey, HpkeSecretKey>,
    pending_commit: Option<CommitGeneration>,
}

#[derive(Debug, serde::Serialize, serde::Deserialize, PartialEq)]
struct RawGroupState {
    context: GroupContext,
    proposals: HashMap<ProposalRef, CachedProposal>,
    tree_data: NodeVec,
    interim_transcript_hash: InterimTranscriptHash,
    pending_reinit: Option<ReInit>,
    confirmation_tag: ConfirmationTag,
}

impl RawGroupState {
    fn export(state: &GroupState) -> Self {
        Self {
            context: state.context.clone(),
            proposals: state.proposals.proposals().clone(),
            tree_data: state.public_tree.export_node_data(),
            interim_transcript_hash: state.interim_transcript_hash.clone(),
            pending_reinit: state.pending_reinit.clone(),
            confirmation_tag: state.confirmation_tag.clone(),
        }
    }

    fn import<C>(self, credential_validator: C) -> Result<GroupState, GroupError>
    where
        C: CredentialValidator,
    {
        let context = self.context;

        let proposals = ProposalCache::import(
            context.protocol_version,
            context.cipher_suite,
            context.group_id.clone(),
            self.proposals,
        );

        let current_tree = TreeKemPublic::import_node_data(
            context.cipher_suite,
            self.tree_data,
            credential_validator,
        )?;

        Ok(GroupState {
            proposals,
            context,
            public_tree: current_tree,
            interim_transcript_hash: self.interim_transcript_hash,
            pending_reinit: self.pending_reinit,
            confirmation_tag: self.confirmation_tag,
        })
    }
}

impl<C> Group<C>
where
    C: ClientConfig + Clone,
{
    pub fn snapshot(&self) -> Snapshot {
        Snapshot {
            state: RawGroupState::export(&self.state),
            private_tree: self.private_tree.clone(),
            key_schedule: self.key_schedule.clone(),
            pending_updates: self.pending_updates.clone(),
            pending_commit: self.pending_commit.clone(),
        }
    }

    pub(crate) fn from_snapshot(config: C, snapshot: Snapshot) -> Result<Self, GroupError> {
        let credential_validator = config.credential_validator();
        Ok(Group {
            config,
            state: snapshot.state.import(credential_validator)?,
            private_tree: snapshot.private_tree,
            key_schedule: snapshot.key_schedule,
            pending_updates: snapshot.pending_updates,
            pending_commit: snapshot.pending_commit,
            #[cfg(test)]
            commit_modifiers: Default::default(),
        })
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        cipher_suite::CipherSuite,
        group::{
            test_utils::{test_group, TestGroup},
            Group,
        },
        protocol_version::ProtocolVersion,
    };

    use super::Snapshot;

    pub const TEST_PROTOCOL_VERSION: ProtocolVersion = ProtocolVersion::Mls10;
    pub const TEST_CIPHER_SUITE: CipherSuite = CipherSuite::Curve25519Aes128;

    fn serialize_to_json_test(group: TestGroup) {
        let snapshot = group.group.snapshot();
        let json = serde_json::to_vec(&snapshot).unwrap();
        let snapshot_restored: Snapshot = serde_json::from_slice(&json).unwrap();

        assert_eq!(snapshot, snapshot_restored);

        let group_restored =
            Group::from_snapshot(group.group.config.clone(), snapshot_restored).unwrap();

        assert!(Group::equal_group_state(&group.group, &group_restored));
    }

    #[test]
    fn snapshot_with_pending_commit_can_be_serialized_to_json() {
        let mut group = test_group(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE);
        group.group.commit(vec![]).unwrap();

        serialize_to_json_test(group)
    }

    #[test]
    fn snapshot_with_pending_updates_can_be_serialized_to_json() {
        let mut group = test_group(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE);

        // Creating the update proposal will add it to pending updates
        let update_proposal = group.group.update_proposal().unwrap();

        // This will insert the proposal into the internal proposal cache
        let _ = group.group.proposal_message(update_proposal, vec![]);

        serialize_to_json_test(group)
    }
}
