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

#[cfg(feature = "tree_index")]
use aws_mls_core::identity::IdentityProvider;

use serde_with::serde_as;

#[cfg(feature = "std")]
use std::collections::HashMap;

#[cfg(not(feature = "std"))]
use alloc::collections::BTreeMap;

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
    #[cfg(feature = "std")]
    pending_updates: HashMap<HpkePublicKey, HpkeSecretKey>,
    #[cfg(not(feature = "std"))]
    pending_updates: BTreeMap<HpkePublicKey, HpkeSecretKey>,
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
    #[cfg(feature = "std")]
    pub(crate) proposals: HashMap<ProposalRef, CachedProposal>,
    #[cfg(not(feature = "std"))]
    pub(crate) proposals: BTreeMap<ProposalRef, CachedProposal>,
    pub(crate) public_tree: TreeKemPublic,
    pub(crate) interim_transcript_hash: InterimTranscriptHash,
    pub(crate) pending_reinit: Option<ReInitProposal>,
    pub(crate) confirmation_tag: ConfirmationTag,
}

impl RawGroupState {
    pub(crate) fn export(state: &GroupState) -> Self {
        #[cfg(feature = "tree_index")]
        let public_tree = state.public_tree.clone();

        #[cfg(not(feature = "tree_index"))]
        let public_tree = {
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

    #[cfg(feature = "tree_index")]
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

    #[cfg(not(feature = "tree_index"))]
    pub(crate) async fn import(self) -> Result<GroupState, MlsError> {
        let context = self.context;

        let proposals = ProposalCache::import(
            context.protocol_version,
            context.group_id.clone(),
            self.proposals,
        );

        Ok(GroupState {
            proposals,
            context,
            public_tree: self.public_tree,
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
    pub async fn write_to_storage(&mut self) -> Result<(), MlsError> {
        self.state_repo
            .write_to_storage(self.snapshot())
            .await
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

    pub(crate) async fn from_snapshot(config: C, snapshot: Snapshot) -> Result<Self, MlsError> {
        let cipher_suite_provider = cipher_suite_provider(
            config.crypto_provider(),
            snapshot.state.context.cipher_suite,
        )?;

        #[cfg(feature = "tree_index")]
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
            state: snapshot
                .state
                .import(
                    #[cfg(feature = "tree_index")]
                    &identity_provider,
                )
                .await?,
            private_tree: snapshot.private_tree,
            key_schedule: snapshot.key_schedule,
            pending_updates: snapshot.pending_updates,
            pending_commit: snapshot.pending_commit,
            #[cfg(test)]
            commit_modifiers: Default::default(),
            epoch_secrets: snapshot.epoch_secrets,
            state_repo,
            cipher_suite_provider,
            previous_psk: None,
        })
    }
}

#[cfg(test)]
pub(crate) mod test_utils {
    use alloc::vec;

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
    use alloc::vec;

    use crate::{
        client::test_utils::{TEST_CIPHER_SUITE, TEST_PROTOCOL_VERSION},
        group::{
            test_utils::{test_group, TestGroup},
            Group,
        },
    };

    use super::Snapshot;

    async fn serialize_to_json_test(group: TestGroup) {
        let snapshot = group.group.snapshot();
        let json = serde_json::to_vec(&snapshot).unwrap();
        let snapshot_restored: Snapshot = serde_json::from_slice(&json).unwrap();

        assert_eq!(snapshot, snapshot_restored);

        let group_restored = Group::from_snapshot(group.group.config.clone(), snapshot_restored)
            .await
            .unwrap();

        assert!(Group::equal_group_state(&group.group, &group_restored));

        #[cfg(feature = "tree_index")]
        assert!(group_restored
            .state
            .public_tree
            .equal_internals(&group.group.state.public_tree))
    }

    #[futures_test::test]
    async fn snapshot_with_pending_commit_can_be_serialized_to_json() {
        let mut group = test_group(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE).await;
        group.group.commit(vec![]).await.unwrap();

        serialize_to_json_test(group).await
    }

    #[futures_test::test]
    async fn snapshot_with_pending_updates_can_be_serialized_to_json() {
        let mut group = test_group(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE).await;

        // Creating the update proposal will add it to pending updates
        let update_proposal = group.update_proposal().await;

        // This will insert the proposal into the internal proposal cache
        let _ = group.group.proposal_message(update_proposal, vec![]).await;

        serialize_to_json_test(group).await
    }

    #[futures_test::test]
    async fn snapshot_can_be_serialized_to_json_with_internals() {
        let group = test_group(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE).await;

        serialize_to_json_test(group).await
    }
}
