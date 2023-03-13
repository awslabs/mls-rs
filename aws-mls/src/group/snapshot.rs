use crate::{
    client::MlsError,
    client_config::ClientConfig,
    crypto::{HpkePublicKey, HpkeSecretKey},
    group::{
        key_schedule::KeySchedule, CachedProposal, CommitGeneration, ConfirmationTag, Group,
        GroupContext, GroupState, InterimTranscriptHash, ProposalCache, ProposalRef,
        ReInitProposal, TreeKemPublic,
    },
    tree_kem::TreeKemPrivate,
};

use aws_mls_core::identity::IdentityProvider;
use serde_with::serde_as;
use std::collections::HashMap;

use super::{cipher_suite_provider, epoch::EpochSecrets, state_repo::GroupStateRepository};

#[cfg(feature = "benchmark")]
use crate::cipher_suite::CipherSuite;

#[serde_as]
#[derive(Debug, serde::Serialize, serde::Deserialize, PartialEq, Clone)]
pub(crate) struct Snapshot {
    version: u16,
    state: RawGroupState,
    private_tree: TreeKemPrivate,
    epoch_secrets: EpochSecrets,
    key_schedule: KeySchedule,
    pending_updates: HashMap<HpkePublicKey, HpkeSecretKey>,
    pending_commit: Option<CommitGeneration>,
}

impl Snapshot {
    pub(crate) fn group_id(&self) -> &[u8] {
        &self.state.context.group_id
    }

    #[cfg(feature = "benchmark")]
    pub(crate) fn cipher_suite(&self) -> CipherSuite {
        self.state.context.cipher_suite
    }
}

#[derive(Debug, serde::Serialize, serde::Deserialize, PartialEq, Clone)]
pub(crate) struct RawGroupState {
    pub(crate) context: GroupContext,
    pub(crate) proposals: HashMap<ProposalRef, CachedProposal>,
    pub(crate) public_tree: TreeKemPublic,
    pub(crate) interim_transcript_hash: InterimTranscriptHash,
    pub(crate) pending_reinit: Option<ReInitProposal>,
    pub(crate) confirmation_tag: ConfirmationTag,
}

impl RawGroupState {
    pub(crate) fn export(state: &GroupState, export_tree_internals: bool) -> Self {
        let public_tree = if export_tree_internals {
            state.public_tree.clone()
        } else {
            let mut tree = TreeKemPublic::new();
            tree.nodes = state.public_tree.export_node_data();
            tree
        };

        Self {
            context: state.context.clone(),
            proposals: state.proposals.proposals().clone(),
            public_tree,
            interim_transcript_hash: state.interim_transcript_hash.clone(),
            pending_reinit: state.pending_reinit.clone(),
            confirmation_tag: state.confirmation_tag.clone(),
        }
    }

    pub(crate) async fn import<C>(self, identity_provider: &C) -> Result<GroupState, MlsError>
    where
        C: IdentityProvider,
    {
        let context = self.context;

        let proposals = ProposalCache::import(
            context.protocol_version,
            context.group_id.clone(),
            self.proposals,
        );

        let mut public_tree = self.public_tree;

        public_tree
            .initialize_index_if_necessary(identity_provider)
            .await?;

        Ok(GroupState {
            proposals,
            context,
            public_tree,
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
    /// Write the current state of the group to the
    /// [`GroupStorageProvider`](crate::GroupStateStorage)
    /// that is currently in use by the group.
    pub async fn write_to_storage(&mut self, export_internals: bool) -> Result<(), MlsError> {
        self.state_repo
            .write_to_storage(self.snapshot(export_internals))
            .await
            .map_err(Into::into)
    }

    pub(crate) fn snapshot(&self, export_tree_internals: bool) -> Snapshot {
        Snapshot {
            state: RawGroupState::export(&self.state, export_tree_internals),
            private_tree: self.private_tree.clone(),
            key_schedule: self.key_schedule.clone(),
            pending_updates: self.pending_updates.clone(),
            pending_commit: self.pending_commit.clone(),
            epoch_secrets: self.epoch_secrets.clone(),
            version: 1,
        }
    }

    pub(crate) async fn from_snapshot(config: C, snapshot: Snapshot) -> Result<Self, MlsError> {
        let cipher_suite_provider = cipher_suite_provider(
            config.crypto_provider(),
            snapshot.state.context.cipher_suite,
        )?;

        let identity_provider = config.identity_provider();

        let state_repo = GroupStateRepository::new(
            snapshot.state.context.group_id.clone(),
            config.preferences().max_epoch_retention,
            config.group_state_storage(),
            config.key_package_repo(),
            None,
        )
        .await?;

        Ok(Group {
            config,
            state: snapshot.state.import(&identity_provider).await?,
            private_tree: snapshot.private_tree,
            key_schedule: snapshot.key_schedule,
            pending_updates: snapshot.pending_updates,
            pending_commit: snapshot.pending_commit,
            #[cfg(test)]
            commit_modifiers: Default::default(),
            epoch_secrets: snapshot.epoch_secrets,
            state_repo,
            cipher_suite_provider,
        })
    }
}

#[cfg(test)]
pub(crate) mod test_utils {
    use crate::{
        cipher_suite::CipherSuite,
        crypto::test_utils::test_cipher_suite_provider,
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
                public_tree: Default::default(),
                interim_transcript_hash: InterimTranscriptHash::from(vec![]),
                pending_reinit: None,
                confirmation_tag: ConfirmationTag::empty(&test_cipher_suite_provider(cipher_suite)),
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
        client::test_utils::{TEST_CIPHER_SUITE, TEST_PROTOCOL_VERSION},
        group::{
            test_utils::{test_group, TestGroup},
            Group,
        },
    };

    use super::Snapshot;

    async fn serialize_to_json_test(group: TestGroup, export_internals: bool) {
        let snapshot = group.group.snapshot(export_internals);
        let json = serde_json::to_vec(&snapshot).unwrap();
        let snapshot_restored: Snapshot = serde_json::from_slice(&json).unwrap();

        assert_eq!(snapshot, snapshot_restored);

        let group_restored = Group::from_snapshot(group.group.config.clone(), snapshot_restored)
            .await
            .unwrap();

        assert!(Group::equal_group_state(&group.group, &group_restored));

        if export_internals {
            assert!(group_restored
                .state
                .public_tree
                .equal_internals(&group.group.state.public_tree))
        }
    }

    #[futures_test::test]
    async fn snapshot_with_pending_commit_can_be_serialized_to_json() {
        let mut group = test_group(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE).await;
        group.group.commit(vec![]).await.unwrap();

        serialize_to_json_test(group, false).await
    }

    #[futures_test::test]
    async fn snapshot_with_pending_updates_can_be_serialized_to_json() {
        let mut group = test_group(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE).await;

        // Creating the update proposal will add it to pending updates
        let update_proposal = group.update_proposal().await;

        // This will insert the proposal into the internal proposal cache
        let _ = group.group.proposal_message(update_proposal, vec![]).await;

        serialize_to_json_test(group, false).await
    }

    #[futures_test::test]
    async fn snapshot_can_be_serialized_to_json_with_internals() {
        let group = test_group(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE).await;

        serialize_to_json_test(group, true).await
    }
}
