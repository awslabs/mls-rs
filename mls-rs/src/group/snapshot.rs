// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// Copyright by contributors to this project.
// SPDX-License-Identifier: (Apache-2.0 OR MIT)

use crate::{
    client::MlsError,
    client_config::ClientConfig,
    group::{
        key_schedule::KeySchedule, CommitGeneration, ConfirmationTag, Group, GroupContext,
        GroupState, InterimTranscriptHash, ReInitProposal,
    },
    tree_kem::TreeKemPrivate,
};

#[cfg(feature = "by_ref_proposal")]
use crate::{
    crypto::{HpkePublicKey, HpkeSecretKey},
    group::ProposalRef,
};

#[cfg(feature = "by_ref_proposal")]
use super::proposal_cache::{CachedProposal, ProposalCache};

use mls_rs_codec::{MlsDecode, MlsEncode, MlsSize};

use mls_rs_core::{crypto::SignatureSecretKey, identity::IdentityProvider};

#[cfg(all(feature = "std", feature = "by_ref_proposal"))]
use std::collections::HashMap;

use alloc::vec::Vec;

use super::{
    cipher_suite_provider, epoch::EpochSecrets, state_repo::GroupStateRepository, ExportedTree,
    TreeKemPublic,
};

#[derive(Debug, PartialEq, Clone, MlsEncode, MlsDecode, MlsSize)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[non_exhaustive]
pub struct Snapshot<'a> {
    pub version: u16,
    pub state: RawGroupState<'a>,
    pub private_tree: TreeKemPrivate,
    pub epoch_secrets: EpochSecrets,
    pub key_schedule: KeySchedule,
    #[cfg(all(feature = "std", feature = "by_ref_proposal"))]
    pub pending_updates: HashMap<HpkePublicKey, (HpkeSecretKey, Option<SignatureSecretKey>)>,
    #[cfg(all(not(feature = "std"), feature = "by_ref_proposal"))]
    pub pending_updates: Vec<(HpkePublicKey, (HpkeSecretKey, Option<SignatureSecretKey>))>,
    pub pending_commit: Option<CommitGeneration>,
    pub signer: SignatureSecretKey,
}

impl Snapshot<'_> {
    pub(crate) fn group_id(&self) -> &[u8] {
        &self.state.context.group_id
    }
}

#[derive(Debug, MlsEncode, MlsDecode, MlsSize, PartialEq, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[non_exhaustive]
pub struct RawGroupState<'a> {
    pub context: GroupContext,
    #[cfg(all(feature = "std", feature = "by_ref_proposal"))]
    pub proposals: HashMap<ProposalRef, CachedProposal>,
    #[cfg(all(not(feature = "std"), feature = "by_ref_proposal"))]
    pub proposals: Vec<(ProposalRef, CachedProposal)>,
    pub public_tree: ExportedTree<'a>,
    pub interim_transcript_hash: InterimTranscriptHash,
    pub pending_reinit: Option<ReInitProposal>,
    pub confirmation_tag: ConfirmationTag,
    tree_internals: TreeKemPublic,
}

impl RawGroupState<'_> {
    pub(crate) fn export(mut state: GroupState) -> RawGroupState<'static> {
        // TODO this clone isn't necessary if we make the storage trait take bytes
        let public_tree = ExportedTree::new(state.public_tree.nodes);
        state.public_tree.nodes = Vec::new().into();

        RawGroupState {
            context: state.context,
            #[cfg(feature = "by_ref_proposal")]
            proposals: state.proposals.proposals,
            public_tree,
            interim_transcript_hash: state.interim_transcript_hash,
            pending_reinit: state.pending_reinit,
            confirmation_tag: state.confirmation_tag,
            tree_internals: state.public_tree,
        }
    }

    #[cfg_attr(not(mls_build_async), maybe_async::must_be_sync)]
    pub(crate) async fn import<C: IdentityProvider>(
        mut self,
        #[cfg(feature = "tree_index")] identity_provider: &C,
        #[cfg(not(feature = "tree_index"))] _identity_provider: &C,
    ) -> Result<GroupState, MlsError> {
        let context = self.context;

        #[cfg(feature = "by_ref_proposal")]
        let proposals = ProposalCache::import(
            context.protocol_version,
            context.group_id.clone(),
            self.proposals,
        );

        self.tree_internals.nodes = self.public_tree.0.into_owned();

        #[cfg(feature = "tree_index")]
        self.tree_internals
            .initialize_index_if_necessary(identity_provider, &context.extensions)
            .await?;

        Ok(GroupState {
            #[cfg(feature = "by_ref_proposal")]
            proposals,
            context,
            public_tree: self.tree_internals,
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
    #[cfg_attr(not(mls_build_async), maybe_async::must_be_sync)]
    pub async fn write_to_storage(&mut self) -> Result<(), MlsError> {
        self.state_repo.write_to_storage(&self.snapshot()).await
    }

    pub(crate) fn snapshot(&self) -> Snapshot<'static> {
        Snapshot {
            state: RawGroupState::export(self.state.clone()),
            private_tree: self.private_tree.clone(),
            key_schedule: self.key_schedule.clone(),
            #[cfg(feature = "by_ref_proposal")]
            pending_updates: self.pending_updates.clone(),
            pending_commit: self.pending_commit.clone(),
            epoch_secrets: self.epoch_secrets.clone(),
            version: 1,
            signer: self.signer.clone(),
        }
    }

    #[cfg_attr(not(mls_build_async), maybe_async::must_be_sync)]
    pub(crate) async fn from_snapshot(config: C, snapshot: Snapshot<'_>) -> Result<Self, MlsError> {
        let cipher_suite_provider = cipher_suite_provider(
            config.crypto_provider(),
            snapshot.state.context.cipher_suite,
        )?;

        let identity_provider = config.identity_provider();

        let state_repo = GroupStateRepository::new(
            #[cfg(feature = "prior_epoch")]
            snapshot.state.context.group_id.clone(),
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
            #[cfg(feature = "by_ref_proposal")]
            pending_updates: snapshot.pending_updates,
            pending_commit: snapshot.pending_commit,
            #[cfg(test)]
            commit_modifiers: Default::default(),
            epoch_secrets: snapshot.epoch_secrets,
            state_repo,
            cipher_suite_provider,
            #[cfg(feature = "psk")]
            previous_psk: None,
            signer: snapshot.signer,
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
            transcript_hash::InterimTranscriptHash, ExportedTree,
        },
        tree_kem::{node::LeafIndex, TreeKemPrivate},
    };

    use super::{RawGroupState, Snapshot};

    #[cfg_attr(not(mls_build_async), maybe_async::must_be_sync)]
    pub(crate) async fn get_test_snapshot(
        cipher_suite: CipherSuite,
        epoch_id: u64,
    ) -> Snapshot<'static> {
        Snapshot {
            state: RawGroupState {
                context: get_test_group_context(epoch_id, cipher_suite).await,
                #[cfg(feature = "by_ref_proposal")]
                proposals: Default::default(),
                public_tree: ExportedTree::new(Default::default()),
                interim_transcript_hash: InterimTranscriptHash::from(vec![]),
                pending_reinit: None,
                confirmation_tag: ConfirmationTag::empty(&test_cipher_suite_provider(cipher_suite))
                    .await,
                tree_internals: Default::default(),
            },
            private_tree: TreeKemPrivate::new(LeafIndex(0)),
            epoch_secrets: get_test_epoch_secrets(cipher_suite),
            key_schedule: get_test_key_schedule(cipher_suite),
            #[cfg(feature = "by_ref_proposal")]
            pending_updates: Default::default(),
            pending_commit: None,
            version: 1,
            signer: vec![].into(),
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

    #[cfg_attr(not(mls_build_async), maybe_async::must_be_sync)]
    async fn snapshot_restore(group: TestGroup) {
        let snapshot = group.group.snapshot();

        let group_restored = Group::from_snapshot(group.group.config.clone(), snapshot)
            .await
            .unwrap();

        assert!(Group::equal_group_state(&group.group, &group_restored));

        #[cfg(feature = "tree_index")]
        assert!(group_restored
            .state
            .public_tree
            .equal_internals(&group.group.state.public_tree))
    }

    #[maybe_async::test(not(mls_build_async), async(mls_build_async, crate::futures_test))]
    async fn snapshot_with_pending_commit_can_be_serialized_to_json() {
        let mut group = test_group(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE).await;
        group.group.commit(vec![]).await.unwrap();

        snapshot_restore(group).await
    }

    #[cfg(feature = "by_ref_proposal")]
    #[maybe_async::test(not(mls_build_async), async(mls_build_async, crate::futures_test))]
    async fn snapshot_with_pending_updates_can_be_serialized_to_json() {
        let mut group = test_group(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE).await;

        // Creating the update proposal will add it to pending updates
        let update_proposal = group.update_proposal().await;

        // This will insert the proposal into the internal proposal cache
        let _ = group.group.proposal_message(update_proposal, vec![]).await;

        snapshot_restore(group).await
    }

    #[maybe_async::test(not(mls_build_async), async(mls_build_async, crate::futures_test))]
    async fn snapshot_can_be_serialized_to_json_with_internals() {
        let group = test_group(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE).await;

        snapshot_restore(group).await
    }

    #[cfg(feature = "serde")]
    #[maybe_async::test(not(mls_build_async), async(mls_build_async, crate::futures_test))]
    async fn serde() {
        let snapshot = super::test_utils::get_test_snapshot(TEST_CIPHER_SUITE, 5).await;
        let json = serde_json::to_string_pretty(&snapshot).unwrap();
        let recovered = serde_json::from_str(&json).unwrap();
        assert_eq!(snapshot, recovered);
    }
}
