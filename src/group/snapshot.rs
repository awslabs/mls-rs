use crate::{
    client_config::ClientConfig,
    external_client_config::ExternalClientConfig,
    group::{
        key_schedule::KeySchedule, CachedProposal, CommitGeneration, ConfirmationTag, Group,
        GroupContext, GroupError, GroupState, InterimTranscriptHash, ProposalCache, ProposalRef,
        ReInit, TreeKemPublic,
    },
    provider::identity::IdentityProvider,
    serde_utils::vec_u8_as_base64::VecAsBase64,
    tree_kem::{node::NodeVec, TreeKemPrivate},
};
use ferriscrypt::hpke::kem::{HpkePublicKey, HpkeSecretKey};
use serde_with::serde_as;
use std::collections::HashMap;

use super::{epoch::EpochSecrets, state_repo::GroupStateRepository, ExternalGroup};

#[serde_as]
#[derive(Debug, serde::Serialize, serde::Deserialize, PartialEq, Clone)]
pub struct Snapshot {
    version: u16,
    state: RawGroupState,
    private_tree: TreeKemPrivate,
    epoch_secrets: EpochSecrets,
    key_schedule: KeySchedule,
    #[serde_as(as = "HashMap<VecAsBase64, VecAsBase64>")]
    pending_updates: HashMap<HpkePublicKey, HpkeSecretKey>,
    pending_commit: Option<CommitGeneration>,
}

impl Snapshot {
    pub fn group_id(&self) -> &[u8] {
        &self.state.context.group_id
    }
}

#[derive(Debug, serde::Serialize, serde::Deserialize, PartialEq, Clone)]
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

    fn import<C>(self, identity_provider: C) -> Result<GroupState, GroupError>
    where
        C: IdentityProvider,
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
            identity_provider,
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
    pub fn write_to_storage(&mut self) -> Result<(), GroupError> {
        self.state_repo
            .write_to_storage(self.snapshot())
            .map_err(Into::into)
    }

    pub(crate) fn snapshot(&self) -> Snapshot {
        Snapshot {
            state: RawGroupState::export(&self.state),
            private_tree: self.private_tree.clone(),
            key_schedule: self.key_schedule.clone(),
            pending_updates: self.pending_updates.clone(),
            pending_commit: self.pending_commit.clone(),
            epoch_secrets: self.epoch_secrets.clone(),
            version: 1,
        }
    }

    pub(crate) fn from_snapshot(config: C, snapshot: Snapshot) -> Result<Self, GroupError> {
        let identity_provider = config.identity_provider();

        let state_repo = GroupStateRepository::new(
            snapshot.state.context.group_id.clone(),
            config.preferences().max_epoch_retention,
            config.group_state_storage(),
            config.key_package_repo(),
            None,
        )?;

        Ok(Group {
            config,
            state: snapshot.state.import(identity_provider)?,
            private_tree: snapshot.private_tree,
            key_schedule: snapshot.key_schedule,
            pending_updates: snapshot.pending_updates,
            pending_commit: snapshot.pending_commit,
            #[cfg(test)]
            commit_modifiers: Default::default(),
            epoch_secrets: snapshot.epoch_secrets,
            state_repo,
        })
    }
}

#[serde_as]
#[derive(Debug, serde::Serialize, serde::Deserialize, PartialEq, Clone)]
pub struct ExternalSnapshot {
    version: u16,
    state: RawGroupState,
}

impl<C> ExternalGroup<C>
where
    C: ExternalClientConfig + Clone,
{
    pub fn snapshot(&self) -> ExternalSnapshot {
        ExternalSnapshot {
            state: RawGroupState::export(self.group_state()),
            version: 1,
        }
    }

    pub fn from_snapshot(config: C, snapshot: ExternalSnapshot) -> Result<Self, GroupError> {
        let identity_provider = config.identity_provider();

        Ok(ExternalGroup {
            config,
            state: snapshot.state.import(identity_provider)?,
        })
    }
}

#[cfg(test)]
pub(crate) mod test_utils {
    use crate::{
        cipher_suite::CipherSuite,
        group::{
            confirmation_tag::ConfirmationTag, epoch::test_utils::get_test_epoch_secrets,
            key_schedule::test_utils::get_test_key_schedule, test_utils::get_test_group_context,
            transcript_hash::InterimTranscriptHash,
        },
        tree_kem::{node::LeafIndex, TreeKemPrivate},
    };

    use super::{RawGroupState, Snapshot};

    pub(crate) fn get_test_snapshot(cipher_suite: CipherSuite, epoch_id: u64) -> Snapshot {
        Snapshot {
            state: RawGroupState {
                context: get_test_group_context(epoch_id, cipher_suite),
                proposals: Default::default(),
                tree_data: Default::default(),
                interim_transcript_hash: InterimTranscriptHash::from(vec![]),
                pending_reinit: None,
                confirmation_tag: ConfirmationTag::empty(&cipher_suite).unwrap(),
            },
            private_tree: TreeKemPrivate::new(LeafIndex(0)),
            epoch_secrets: get_test_epoch_secrets(cipher_suite),
            key_schedule: get_test_key_schedule(cipher_suite),
            pending_updates: Default::default(),
            pending_commit: None,
            version: 1,
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        cipher_suite::CipherSuite,
        group::{
            external_group::test_utils::make_external_group,
            test_utils::{test_group, TestGroup},
            ExternalGroup, Group,
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

    #[test]
    fn external_group_can_be_serialized_to_json() {
        let server = make_external_group(&test_group(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE));

        let snapshot = serde_json::to_vec(&server.snapshot()).unwrap();
        let snapshot_restored = serde_json::from_slice(&snapshot).unwrap();

        let server_restored =
            ExternalGroup::from_snapshot(server.config.clone(), snapshot_restored).unwrap();

        assert_eq!(server.group_state(), server_restored.group_state());
    }
}
