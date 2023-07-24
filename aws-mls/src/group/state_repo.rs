use crate::client::MlsError;
use crate::{group::PriorEpoch, key_package::KeyPackageRef};

use alloc::collections::VecDeque;
use alloc::vec::Vec;
use aws_mls_core::{error::IntoAnyError, group::GroupStateStorage, key_package::KeyPackageStorage};

use super::snapshot::Snapshot;

#[cfg(feature = "psk")]
use crate::group::internal::ResumptionPsk;

#[cfg(feature = "psk")]
use aws_mls_core::psk::PreSharedKey;

pub(crate) const DEFAULT_EPOCH_RETENTION_LIMIT: u64 = 3;

/// A set of changes to apply to a GroupStateStorage implementation. These changes MUST
/// be made in a single transaction to avoid creating invalid states.
#[derive(Default, Clone, Debug)]
struct EpochStorageCommit {
    pub(crate) inserts: VecDeque<PriorEpoch>,
    pub(crate) updates: Vec<PriorEpoch>,
    pub(crate) delete_under: Option<u64>,
}

#[derive(Debug, Clone)]
pub(crate) struct GroupStateRepository<S, K>
where
    S: GroupStateStorage,
    K: KeyPackageStorage,
{
    pub max_epochs: u64,
    pending_commit: EpochStorageCommit,
    pending_key_package_removal: Option<KeyPackageRef>,
    group_id: Vec<u8>,
    storage: S,
    key_package_repo: K,
}

impl<S, K> GroupStateRepository<S, K>
where
    S: GroupStateStorage,
    K: KeyPackageStorage,
{
    #[maybe_async::maybe_async]
    pub async fn new(
        group_id: Vec<u8>,
        max_epoch_retention: u64,
        storage: S,
        key_package_repo: K,
        // Set to `None` if restoring from snapshot; set to `Some` when joining a group.
        key_package_to_remove: Option<KeyPackageRef>,
    ) -> Result<GroupStateRepository<S, K>, MlsError> {
        if max_epoch_retention == 0 {
            return Err(MlsError::NonZeroRetentionRequired);
        }

        let pending_commit = EpochStorageCommit {
            delete_under: storage
                .max_epoch_id(&group_id)
                .await
                .map_err(|e| MlsError::GroupStorageError(e.into_any_error()))?
                .and_then(|max| max.checked_sub(max_epoch_retention - 1)),
            ..Default::default()
        };

        Ok(GroupStateRepository {
            max_epochs: max_epoch_retention,
            group_id,
            storage,
            pending_key_package_removal: key_package_to_remove,
            pending_commit,
            key_package_repo,
        })
    }

    #[maybe_async::maybe_async]
    async fn find_max_id(&self) -> Result<Option<u64>, MlsError> {
        if let Some(max) = self.pending_commit.inserts.back().map(|e| e.epoch_id()) {
            Ok(Some(max))
        } else {
            self.storage
                .max_epoch_id(&self.group_id)
                .await
                .map_err(|e| MlsError::GroupStorageError(e.into_any_error()))
        }
    }

    #[cfg(feature = "psk")]
    #[maybe_async::maybe_async]
    pub async fn resumption_secret(
        &self,
        psk_id: &ResumptionPsk,
    ) -> Result<Option<PreSharedKey>, MlsError> {
        if self.epoch_pending_delete(psk_id.psk_epoch) {
            return Ok(None);
        }

        // Search the local inserts cache
        if let Some(min) = self.pending_commit.inserts.front().map(|e| e.epoch_id()) {
            if psk_id.psk_epoch >= min {
                return Ok(self
                    .pending_commit
                    .inserts
                    .get((psk_id.psk_epoch - min) as usize)
                    .map(|e| e.secrets.resumption_secret.clone()));
            }
        }

        // Search the local updates cache
        let maybe_pending = self.find_pending(psk_id.psk_epoch);

        if let Some(pending) = maybe_pending {
            return Ok(Some(
                self.pending_commit.updates[pending]
                    .secrets
                    .resumption_secret
                    .clone(),
            ));
        }

        // Search the stored cache
        self.storage
            .epoch::<PriorEpoch>(&psk_id.psk_group_id.0, psk_id.psk_epoch)
            .await
            .map_err(|e| MlsError::GroupStorageError(e.into_any_error()))
            .map(|e| e.map(|e| e.secrets.resumption_secret))
    }

    #[cfg(any(feature = "psk", feature = "private_message"))]
    fn epoch_pending_delete(&self, epoch_id: u64) -> bool {
        // Epochs pending deletion should not be found
        self.pending_commit
            .delete_under
            .map(|delete_threshold| epoch_id < delete_threshold)
            .unwrap_or(false)
    }

    #[cfg(feature = "private_message")]
    #[maybe_async::maybe_async]
    pub async fn get_epoch_mut(
        &mut self,
        epoch_id: u64,
    ) -> Result<Option<&mut PriorEpoch>, MlsError> {
        if self.epoch_pending_delete(epoch_id) {
            return Ok(None);
        }

        // Search the local inserts cache
        if let Some(min) = self.pending_commit.inserts.front().map(|e| e.epoch_id()) {
            if epoch_id >= min {
                return Ok(self
                    .pending_commit
                    .inserts
                    .get_mut((epoch_id - min) as usize));
            }
        }

        // Look in the cached updates map, and if not found look in disk storage
        // and insert into the updates map for future caching
        Ok(match self.find_pending(epoch_id) {
            Some(i) => self.pending_commit.updates.get_mut(i),
            None => self
                .storage
                .epoch(&self.group_id, epoch_id)
                .await
                .map_err(|e| MlsError::GroupStorageError(e.into_any_error()))?
                .and_then(|epoch| {
                    self.pending_commit.updates.push(epoch);
                    self.pending_commit.updates.last_mut()
                }),
        })
    }

    #[maybe_async::maybe_async]
    pub async fn insert(&mut self, epoch: PriorEpoch) -> Result<(), MlsError> {
        if epoch.group_id() != self.group_id {
            return Err(MlsError::GroupIdMismatch);
        }

        let epoch_id = epoch.epoch_id();

        if let Some(expected_id) = self.find_max_id().await?.map(|id| id + 1) {
            if epoch_id != expected_id {
                return Err(MlsError::InvalidEpoch);
            }
        }

        self.pending_commit.inserts.push_back(epoch);

        if epoch_id >= self.max_epochs {
            let min = epoch_id - self.max_epochs;
            self.pending_commit.delete_under = Some(min + 1);

            if self.pending_commit.inserts.len() > self.max_epochs as usize {
                self.pending_commit.inserts.pop_front();
            }

            let min = self
                .pending_commit
                .updates
                .iter()
                .position(|ep| ep.epoch_id() == min);

            if let Some(min) = min {
                self.pending_commit.updates.remove(min);
            }
        }

        Ok(())
    }

    #[maybe_async::maybe_async]
    pub async fn write_to_storage(&mut self, group_snapshot: Snapshot) -> Result<(), MlsError> {
        let inserts = self.pending_commit.inserts.iter().cloned().collect();
        let updates = self.pending_commit.updates.clone();
        let delete_under = self.pending_commit.delete_under;

        self.storage
            .write(group_snapshot, inserts, updates, delete_under)
            .await
            .map_err(|e| MlsError::GroupStorageError(e.into_any_error()))?;

        if let Some(ref key_package_ref) = self.pending_key_package_removal {
            self.key_package_repo
                .delete(key_package_ref)
                .await
                .map_err(|e| MlsError::KeyPackageRepoError(e.into_any_error()))?;
        }

        self.pending_commit.inserts.clear();
        self.pending_commit.updates.clear();

        Ok(())
    }

    #[cfg(any(feature = "psk", feature = "private_message"))]
    fn find_pending(&self, epoch_id: u64) -> Option<usize> {
        self.pending_commit
            .updates
            .iter()
            .position(|ep| ep.context.epoch == epoch_id)
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec;
    use assert_matches::assert_matches;
    use aws_mls_codec::MlsEncode;

    use crate::{
        client::test_utils::{TEST_CIPHER_SUITE, TEST_PROTOCOL_VERSION},
        group::{
            epoch::{test_utils::get_test_epoch_with_id, SenderDataSecret},
            internal::{PskGroupId, ResumptionPSKUsage},
            test_utils::{random_bytes, test_member, TEST_GROUP},
        },
        storage_provider::{
            group_state::EpochData,
            in_memory::{InMemoryGroupStateStorage, InMemoryKeyPackageStorage},
        },
    };

    use super::*;

    #[maybe_async::maybe_async]
    async fn test_group_state_repo(
        retention_limit: u64,
    ) -> GroupStateRepository<InMemoryGroupStateStorage, InMemoryKeyPackageStorage> {
        GroupStateRepository::new(
            TEST_GROUP.to_vec(),
            retention_limit,
            InMemoryGroupStateStorage::default(),
            InMemoryKeyPackageStorage::default(),
            None,
        )
        .await
        .unwrap()
    }

    fn test_epoch(epoch_id: u64) -> PriorEpoch {
        get_test_epoch_with_id(TEST_GROUP.to_vec(), TEST_CIPHER_SUITE, epoch_id)
    }

    fn test_snapshot(epoch_id: u64) -> Snapshot {
        crate::group::snapshot::test_utils::get_test_snapshot(TEST_CIPHER_SUITE, epoch_id)
    }

    #[maybe_async::test(sync, async(not(sync), crate::futures_test))]
    async fn test_zero_max_retention() {
        let res = GroupStateRepository::new(
            TEST_GROUP.to_vec(),
            0,
            InMemoryGroupStateStorage::default(),
            InMemoryKeyPackageStorage::default(),
            None,
        )
        .await;

        assert_matches!(res, Err(MlsError::NonZeroRetentionRequired))
    }

    #[maybe_async::test(sync, async(not(sync), crate::futures_test))]
    async fn test_epoch_inserts() {
        let mut test_repo = test_group_state_repo(1).await;
        let test_epoch = test_epoch(0);

        test_repo.insert(test_epoch.clone()).await.unwrap();

        // Check the in-memory state
        assert_eq!(
            test_repo.pending_commit.inserts.back().unwrap(),
            &test_epoch
        );

        assert!(test_repo.pending_commit.updates.is_empty());

        #[cfg(feature = "std")]
        assert!(test_repo.storage.inner.lock().unwrap().is_empty());
        #[cfg(not(feature = "std"))]
        assert!(test_repo.storage.inner.lock().is_empty());

        let psk_id = ResumptionPsk {
            psk_epoch: 0,
            psk_group_id: PskGroupId(test_repo.group_id.clone()),
            usage: ResumptionPSKUsage::Application,
        };

        // Make sure you can recall an epoch sitting as a pending insert
        let resumption = test_repo.resumption_secret(&psk_id).await.unwrap();
        let prior_epoch = test_repo.get_epoch_mut(0).await.unwrap().cloned();

        assert_eq!(
            prior_epoch.clone().unwrap().secrets.resumption_secret,
            resumption.unwrap()
        );

        assert_eq!(prior_epoch.unwrap(), test_epoch);

        // Write to the storage
        let snapshot = test_snapshot(test_epoch.epoch_id());
        test_repo.write_to_storage(snapshot.clone()).await.unwrap();

        // Make sure the memory cache cleared
        assert!(test_repo.pending_commit.inserts.is_empty());
        assert!(test_repo.pending_commit.updates.is_empty());

        // Make sure the storage was written
        #[cfg(feature = "std")]
        let storage = test_repo.storage.inner.lock().unwrap();
        #[cfg(not(feature = "std"))]
        let storage = test_repo.storage.inner.lock();

        assert_eq!(storage.len(), 1);

        let stored = storage.get(TEST_GROUP).unwrap();

        assert_eq!(stored.state_data, snapshot.mls_encode_to_vec().unwrap());

        assert_eq!(stored.epoch_data.len(), 1);

        assert_eq!(
            stored.epoch_data.back().unwrap(),
            &EpochData::new(test_epoch).unwrap()
        );
    }

    #[maybe_async::test(sync, async(not(sync), crate::futures_test))]
    async fn test_epoch_insert_over_limit() {
        let mut test_repo = test_group_state_repo(1).await;
        let test_epoch_0 = test_epoch(0);
        let test_epoch_1 = test_epoch(1);

        test_repo.insert(test_epoch_0).await.unwrap();
        test_repo.insert(test_epoch_1.clone()).await.unwrap();

        assert_eq!(
            test_repo.pending_commit.inserts.back().unwrap(),
            &test_epoch_1
        );

        assert!(test_repo.pending_commit.updates.is_empty());
        assert_eq!(test_repo.pending_commit.inserts.len(), 1);

        #[cfg(feature = "std")]
        assert!(test_repo.storage.inner.lock().unwrap().is_empty());
        #[cfg(not(feature = "std"))]
        assert!(test_repo.storage.inner.lock().is_empty());

        test_repo.write_to_storage(test_snapshot(1)).await.unwrap();

        // Make sure the storage was written
        #[cfg(feature = "std")]
        let storage = test_repo.storage.inner.lock().unwrap();
        #[cfg(not(feature = "std"))]
        let storage = test_repo.storage.inner.lock();

        assert_eq!(storage.len(), 1);

        let stored = storage.get(TEST_GROUP).unwrap();

        assert_eq!(stored.epoch_data.len(), 1);

        assert_eq!(
            stored.epoch_data.back().unwrap(),
            &EpochData::new(test_epoch_1).unwrap()
        );
    }

    #[maybe_async::test(sync, async(not(sync), crate::futures_test))]
    async fn test_epoch_insert_over_limit_with_update() {
        let mut test_repo = test_group_state_repo(1).await;
        let test_epoch_0 = test_epoch(0);
        test_repo.insert(test_epoch_0).await.unwrap();

        // Write epoch 0 to storage
        test_repo.write_to_storage(test_snapshot(0)).await.unwrap();

        // Pull epoch 0 back into memory
        test_repo.get_epoch_mut(0).await.unwrap().unwrap();

        // Insert epoch 1
        let test_epoch_1 = test_epoch(1);
        test_repo.insert(test_epoch_1).await.unwrap();

        // Insert epoch 2
        let test_epoch_2 = test_epoch(2);
        test_repo.insert(test_epoch_2.clone()).await.unwrap();

        assert_eq!(
            test_repo.pending_commit.inserts.back().unwrap(),
            &test_epoch_2
        );
        assert!(test_repo.pending_commit.updates.is_empty());
        assert_eq!(test_repo.pending_commit.inserts.len(), 1);

        test_repo.write_to_storage(test_snapshot(2)).await.unwrap();

        // Make sure the storage was written
        #[cfg(feature = "std")]
        let storage = test_repo.storage.inner.lock().unwrap();
        #[cfg(not(feature = "std"))]
        let storage = test_repo.storage.inner.lock();

        assert_eq!(storage.len(), 1);

        let stored = storage.get(TEST_GROUP).unwrap();

        assert_eq!(stored.epoch_data.len(), 1);

        assert_eq!(
            stored.epoch_data.back().unwrap(),
            &EpochData::new(test_epoch_2).unwrap()
        );
    }

    #[maybe_async::test(sync, async(not(sync), crate::futures_test))]
    async fn test_updates() {
        let mut test_repo = test_group_state_repo(2).await;
        let test_epoch_0 = test_epoch(0);

        test_repo.insert(test_epoch_0.clone()).await.unwrap();

        test_repo.write_to_storage(test_snapshot(0)).await.unwrap();

        // Update the stored epoch
        let to_update = test_repo.get_epoch_mut(0).await.unwrap().unwrap();
        assert_eq!(to_update, &test_epoch_0);

        let new_sender_secret = random_bytes(32);
        to_update.secrets.sender_data_secret = SenderDataSecret::from(new_sender_secret);
        let to_update = to_update.clone();

        assert_eq!(test_repo.pending_commit.updates.len(), 1);
        assert!(test_repo.pending_commit.inserts.is_empty());

        assert_eq!(test_repo.pending_commit.updates.get(0).unwrap(), &to_update);

        // Make sure you can access an epoch pending update
        let psk_id = ResumptionPsk {
            psk_epoch: 0,
            psk_group_id: PskGroupId(test_repo.group_id.clone()),
            usage: ResumptionPSKUsage::Application,
        };

        let owned = test_repo.resumption_secret(&psk_id).await.unwrap();
        assert_eq!(owned.as_ref(), Some(&to_update.secrets.resumption_secret));

        // Write the update to storage
        let snapshot = test_snapshot(1);
        test_repo.write_to_storage(snapshot.clone()).await.unwrap();

        assert!(test_repo.pending_commit.updates.is_empty());
        assert!(test_repo.pending_commit.inserts.is_empty());

        // Make sure the storage was written
        #[cfg(feature = "std")]
        let storage = test_repo.storage.inner.lock().unwrap();
        #[cfg(not(feature = "std"))]
        let storage = test_repo.storage.inner.lock();

        assert_eq!(storage.len(), 1);

        let stored = storage.get(TEST_GROUP).unwrap();

        assert_eq!(stored.state_data, snapshot.mls_encode_to_vec().unwrap());

        assert_eq!(stored.epoch_data.len(), 1);

        assert_eq!(
            stored.epoch_data.back().unwrap(),
            &EpochData::new(to_update).unwrap()
        );
    }

    #[maybe_async::test(sync, async(not(sync), crate::futures_test))]
    async fn test_insert_and_update() {
        let mut test_repo = test_group_state_repo(2).await;
        let test_epoch_0 = test_epoch(0);

        test_repo.insert(test_epoch_0).await.unwrap();

        test_repo.write_to_storage(test_snapshot(0)).await.unwrap();

        // Update the stored epoch
        let to_update = test_repo.get_epoch_mut(0).await.unwrap().unwrap();
        let new_sender_secret = random_bytes(32);
        to_update.secrets.sender_data_secret = SenderDataSecret::from(new_sender_secret);
        let to_update = to_update.clone();

        // Insert another epoch
        let test_epoch_1 = test_epoch(1);
        test_repo.insert(test_epoch_1.clone()).await.unwrap();

        test_repo.write_to_storage(test_snapshot(1)).await.unwrap();

        assert!(test_repo.pending_commit.inserts.is_empty());
        assert!(test_repo.pending_commit.updates.is_empty());

        // Make sure the storage was written
        #[cfg(feature = "std")]
        let storage = test_repo.storage.inner.lock().unwrap();
        #[cfg(not(feature = "std"))]
        let storage = test_repo.storage.inner.lock();

        assert_eq!(storage.len(), 1);

        let stored = storage.get(TEST_GROUP).unwrap();

        assert_eq!(stored.epoch_data.len(), 2);

        assert_eq!(
            stored.epoch_data.front().unwrap(),
            &EpochData::new(to_update).unwrap()
        );

        assert_eq!(
            stored.epoch_data.back().unwrap(),
            &EpochData::new(test_epoch_1).unwrap()
        );
    }

    #[maybe_async::test(sync, async(not(sync), crate::futures_test))]
    async fn test_many_epochs_in_storage() {
        let epochs = (0..10).map(test_epoch).collect::<Vec<_>>();

        let mut test_repo = test_group_state_repo(10).await;

        for epoch in epochs.iter().cloned() {
            test_repo.insert(epoch).await.unwrap()
        }

        test_repo.write_to_storage(test_snapshot(9)).await.unwrap();

        for mut epoch in epochs {
            let res = test_repo.get_epoch_mut(epoch.epoch_id()).await.unwrap();

            assert_eq!(res, Some(&mut epoch));
        }
    }

    #[maybe_async::test(sync, async(not(sync), crate::futures_test))]
    async fn test_disallowed_access_to_pending_deletes() {
        let mut test_repo = test_group_state_repo(1).await;
        let test_epoch_0 = test_epoch(0);
        let test_epoch_1 = test_epoch(1);

        test_repo.insert(test_epoch_0).await.unwrap();
        test_repo.insert(test_epoch_1).await.unwrap();

        let res = test_repo.get_epoch_mut(0).await.unwrap();

        assert!(res.is_none());

        let psk_id = ResumptionPsk {
            psk_epoch: 0,
            psk_group_id: PskGroupId(test_repo.group_id.clone()),
            usage: ResumptionPSKUsage::Application,
        };

        let res = test_repo.resumption_secret(&psk_id).await.unwrap();

        assert!(res.is_none());
    }

    #[maybe_async::test(sync, async(not(sync), crate::futures_test))]
    async fn test_stored_groups_list() {
        let mut test_repo = test_group_state_repo(2).await;
        let test_epoch_0 = test_epoch(0);

        test_repo.insert(test_epoch_0.clone()).await.unwrap();

        test_repo.write_to_storage(test_snapshot(0)).await.unwrap();

        assert_eq!(
            test_repo.storage.stored_groups(),
            vec![test_epoch_0.context.group_id]
        )
    }

    #[maybe_async::test(sync, async(not(sync), crate::futures_test))]
    async fn reducing_retention_limit_takes_effect_on_epoch_access() {
        let mut repo = test_group_state_repo(1).await;

        repo.insert(test_epoch(0)).await.unwrap();
        repo.insert(test_epoch(1)).await.unwrap();

        repo.write_to_storage(test_snapshot(0)).await.unwrap();

        let mut repo = GroupStateRepository {
            storage: repo.storage,
            ..test_group_state_repo(1).await
        };

        let res = repo.get_epoch_mut(0).await.unwrap();

        assert!(res.is_none());
    }

    #[maybe_async::test(sync, async(not(sync), crate::futures_test))]
    async fn in_memory_storage_obeys_retention_limit_after_saving() {
        let mut repo = test_group_state_repo(1).await;

        repo.insert(test_epoch(0)).await.unwrap();
        repo.write_to_storage(test_snapshot(0)).await.unwrap();
        repo.insert(test_epoch(1)).await.unwrap();
        repo.write_to_storage(test_snapshot(1)).await.unwrap();

        #[cfg(feature = "std")]
        let lock = repo.storage.inner.lock().unwrap();
        #[cfg(not(feature = "std"))]
        let lock = repo.storage.inner.lock();

        assert_eq!(lock.get(TEST_GROUP).unwrap().epoch_data.len(), 1);
    }

    #[maybe_async::maybe_async]
    async fn existing_storage_setup(
        count: u64,
    ) -> GroupStateRepository<InMemoryGroupStateStorage, InMemoryKeyPackageStorage> {
        // fill the repo to capacity
        let mut repo = test_group_state_repo(count).await;

        for i in 0..count {
            repo.insert(test_epoch(i)).await.unwrap()
        }

        repo.write_to_storage(test_snapshot(2)).await.unwrap();

        repo
    }

    #[maybe_async::test(sync, async(not(sync), crate::futures_test))]
    async fn existing_storage_can_be_imported_with_delete_under() {
        let mut repo = existing_storage_setup(3).await;
        repo.insert(test_epoch(3)).await.unwrap();
        repo.write_to_storage(test_snapshot(3)).await.unwrap();

        let new_repo = GroupStateRepository::new(
            TEST_GROUP.to_vec(),
            3,
            repo.storage.clone(),
            repo.key_package_repo.clone(),
            None,
        )
        .await
        .unwrap();

        assert_eq!(
            repo.pending_commit.delete_under,
            new_repo.pending_commit.delete_under
        );

        assert_eq!(new_repo.pending_commit.delete_under.unwrap(), 1);
    }

    #[maybe_async::test(sync, async(not(sync), crate::futures_test))]
    async fn existing_storage_can_have_larger_epoch_count() {
        let repo = existing_storage_setup(3).await;

        let mut new_repo = GroupStateRepository::new(
            TEST_GROUP.to_vec(),
            5,
            repo.storage,
            repo.key_package_repo,
            None,
        )
        .await
        .unwrap();

        new_repo.insert(test_epoch(3)).await.unwrap();
        new_repo.insert(test_epoch(4)).await.unwrap();

        new_repo.write_to_storage(test_snapshot(4)).await.unwrap();

        assert!(new_repo.pending_commit.delete_under.is_none());

        assert_eq!(
            new_repo.storage.export_epoch_data(TEST_GROUP).unwrap()[0].epoch_id(),
            0
        );
    }

    #[maybe_async::test(sync, async(not(sync), crate::futures_test))]
    async fn existing_storage_can_have_smaller_epoch_count() {
        let repo = existing_storage_setup(5).await;

        let mut new_repo = GroupStateRepository::new(
            TEST_GROUP.to_vec(),
            3,
            repo.storage,
            repo.key_package_repo,
            None,
        )
        .await
        .unwrap();

        assert_eq!(new_repo.pending_commit.delete_under.unwrap(), 2);

        // Writing to storage should clean up
        new_repo.write_to_storage(test_snapshot(4)).await.unwrap();

        assert_eq!(
            new_repo.storage.export_epoch_data(TEST_GROUP).unwrap()[0].epoch_id(),
            2
        );
    }

    #[maybe_async::test(sync, async(not(sync), crate::futures_test))]
    async fn used_key_package_is_deleted() {
        let key_package_repo = InMemoryKeyPackageStorage::default();

        let key_package = test_member(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE, b"member")
            .await
            .0;

        let (id, data) = key_package.to_storage().unwrap();

        key_package_repo.insert(id, data);

        let mut repo = GroupStateRepository::new(
            TEST_GROUP.to_vec(),
            4,
            InMemoryGroupStateStorage::default(),
            key_package_repo,
            Some(key_package.reference.clone()),
        )
        .await
        .unwrap();

        repo.key_package_repo.get(&key_package.reference).unwrap();

        repo.write_to_storage(test_snapshot(4)).await.unwrap();

        assert!(repo.key_package_repo.get(&key_package.reference).is_none());
    }
}
