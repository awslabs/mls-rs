use super::{key_schedule::KeySchedule, state::GroupState, CommitGeneration, Group};
use crate::{
    client_config::ClientConfig, serde_utils::vec_u8_as_base64::VecAsBase64,
    tree_kem::TreeKemPrivate,
};
use ferriscrypt::hpke::kem::{HpkePublicKey, HpkeSecretKey};
use serde_with::serde_as;
use std::collections::HashMap;

#[serde_as]
#[derive(Debug, serde::Serialize, serde::Deserialize, PartialEq)]
pub struct Snapshot {
    pub(crate) state: GroupState,
    private_tree: TreeKemPrivate,
    key_schedule: KeySchedule,
    #[serde_as(as = "HashMap<VecAsBase64, VecAsBase64>")]
    pending_updates: HashMap<HpkePublicKey, HpkeSecretKey>,
    pending_commit: Option<CommitGeneration>,
}

impl<C> Group<C>
where
    C: ClientConfig + Clone,
{
    pub fn snapshot(&self) -> Snapshot {
        Snapshot {
            state: self.state.clone(),
            private_tree: self.private_tree.clone(),
            key_schedule: self.key_schedule.clone(),
            pending_updates: self.pending_updates.clone(),
            pending_commit: self.pending_commit.clone(),
        }
    }

    pub(crate) fn from_snapshot(config: C, snapshot: Snapshot) -> Group<C> {
        Group {
            config,
            state: snapshot.state,
            private_tree: snapshot.private_tree,
            key_schedule: snapshot.key_schedule,
            pending_updates: snapshot.pending_updates,
            pending_commit: snapshot.pending_commit,
            #[cfg(test)]
            commit_modifiers: Default::default(),
        }
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

        let group_restored = Group::from_snapshot(group.group.config.clone(), snapshot_restored);

        assert!(Group::equal_group_state(&group.group, &group_restored));
    }

    #[test]
    fn snapshot_with_pending_commit_can_be_serialized_to_json() {
        let mut group = test_group(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE);
        group.group.commit_proposals(vec![], vec![]).unwrap();

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
