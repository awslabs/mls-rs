use super::{key_schedule::KeySchedule, state::GroupState, CommitGeneration, Group};
use crate::{client_config::ClientConfig, tree_kem::TreeKemPrivate};
use ferriscrypt::hpke::kem::HpkeSecretKey;
use std::collections::HashMap;

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct Snapshot {
    pub(crate) state: GroupState,
    private_tree: TreeKemPrivate,
    key_schedule: KeySchedule,
    // TODO: HpkePublicKey does not have Eq and Hash
    pending_updates: HashMap<Vec<u8>, HpkeSecretKey>, // Hash of leaf node hpke public key to secret key
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
