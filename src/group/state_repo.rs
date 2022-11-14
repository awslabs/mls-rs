use crate::{
    group::Snapshot,
    key_package::KeyPackageRef,
    provider::{
        group_state::{EpochStorageCommit, GroupStateStorage},
        key_package::KeyPackageRepository,
    },
};

use hex::ToHex;
use std::collections::hash_map::Entry;
use thiserror::Error;

pub use crate::group::epoch::PriorEpoch;

pub(crate) const DEFAULT_EPOCH_RETENTION_LIMIT: u64 = 3;

#[derive(Debug, Error)]
pub enum GroupStateRepositoryError {
    #[error("invalid group id: expected {expected}, found {found}")]
    UnexpectedGroupId { expected: String, found: String },
    #[error("invalid insert: expected {expected} found {found}")]
    UnexpectedEpochId { expected: u64, found: u64 },
    #[error("storage retention can not be zero")]
    NonZeroRetentionRequired,
    #[error(transparent)]
    StorageError(Box<dyn std::error::Error + Sync + Send + 'static>),
    #[error(transparent)]
    KeyPackageRepoError(Box<dyn std::error::Error + Sync + Send + 'static>),
}

#[derive(Debug, Clone, Error)]
pub(crate) struct GroupStateRepository<S, K>
where
    S: GroupStateStorage,
    K: KeyPackageRepository,
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
    K: KeyPackageRepository,
{
    pub fn new(
        group_id: Vec<u8>,
        max_epoch_retention: u64,
        storage: S,
        key_package_repo: K,
        // Set to `None` if restoring from snapshot; set to `Some` when joining a group.
        key_package_to_remove: Option<KeyPackageRef>,
    ) -> Result<GroupStateRepository<S, K>, GroupStateRepositoryError> {
        if max_epoch_retention == 0 {
            return Err(GroupStateRepositoryError::NonZeroRetentionRequired);
        }

        let pending_commit = EpochStorageCommit {
            delete_under: storage
                .max_epoch_id(&group_id)
                .map_err(|e| GroupStateRepositoryError::StorageError(e.into()))?
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

    fn find_max_id(&self) -> Result<Option<u64>, GroupStateRepositoryError> {
        if let Some(max) = self.pending_commit.inserts.back().map(|e| e.epoch_id()) {
            Ok(Some(max))
        } else {
            self.storage
                .max_epoch_id(&self.group_id)
                .map_err(|e| GroupStateRepositoryError::StorageError(e.into()))
        }
    }

    pub fn get_epoch_owned(
        &self,
        epoch_id: u64,
    ) -> Result<Option<PriorEpoch>, GroupStateRepositoryError> {
        if self.epoch_pending_delete(epoch_id) {
            return Ok(None);
        }

        // Search the local inserts cache
        if let Some(min) = self.pending_commit.inserts.front().map(|e| e.epoch_id()) {
            if epoch_id >= min {
                return Ok(self
                    .pending_commit
                    .inserts
                    .get((epoch_id - min) as usize)
                    .cloned());
            }
        }

        self.pending_commit
            .updates
            .get(&epoch_id)
            .map(|epoch| Ok(epoch.clone()))
            .or_else(|| {
                self.storage
                    .get_epoch_data(&self.group_id, epoch_id)
                    .map_err(|e| GroupStateRepositoryError::StorageError(e.into()))
                    .transpose()
            })
            .transpose()
    }

    fn epoch_pending_delete(&self, epoch_id: u64) -> bool {
        // Epochs pending deletion should not be found
        self.pending_commit
            .delete_under
            .map(|delete_threshold| epoch_id < delete_threshold)
            .unwrap_or(false)
    }

    pub fn get_epoch_mut(
        &mut self,
        epoch_id: u64,
    ) -> Result<Option<&mut PriorEpoch>, GroupStateRepositoryError> {
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
        Ok(match self.pending_commit.updates.entry(epoch_id) {
            Entry::Vacant(entry) => self
                .storage
                .get_epoch_data(&self.group_id, epoch_id)
                .map_err(|e| GroupStateRepositoryError::StorageError(e.into()))?
                .map(|epoch| entry.insert(epoch)),
            Entry::Occupied(entry) => Some(entry.into_mut()),
        })
    }

    pub fn insert(&mut self, epoch: PriorEpoch) -> Result<(), GroupStateRepositoryError> {
        if epoch.group_id() != self.group_id {
            return Err(GroupStateRepositoryError::UnexpectedGroupId {
                expected: self.group_id.encode_hex_upper(),
                found: epoch.group_id().encode_hex_upper(),
            });
        }

        let epoch_id = epoch.epoch_id();

        if let Some(expected_id) = self.find_max_id()?.map(|id| id + 1) {
            if epoch_id != expected_id {
                return Err(GroupStateRepositoryError::UnexpectedEpochId {
                    expected: expected_id,
                    found: epoch_id,
                });
            }
        }

        self.pending_commit.inserts.push_back(epoch);

        if epoch_id >= self.max_epochs {
            let min = epoch_id - self.max_epochs;
            self.pending_commit.delete_under = Some(min + 1);

            if self.pending_commit.inserts.len() > self.max_epochs as usize {
                self.pending_commit.inserts.pop_front();
            }

            self.pending_commit.updates.remove(&min);
        }

        Ok(())
    }

    pub fn write_to_storage(
        &mut self,
        group_snapshot: Snapshot,
    ) -> Result<(), GroupStateRepositoryError> {
        self.storage
            .write(&self.group_id, group_snapshot, &self.pending_commit)
            .map_err(|e| GroupStateRepositoryError::StorageError(e.into()))?;

        if let Some(ref key_package_ref) = self.pending_key_package_removal {
            self.key_package_repo
                .delete(key_package_ref)
                .map_err(|e| GroupStateRepositoryError::KeyPackageRepoError(e.into()))?;
        }

        self.pending_commit.inserts.clear();
        self.pending_commit.updates.clear();

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use assert_matches::assert_matches;
    use ferriscrypt::rand::SecureRng;

    use crate::{
        client::test_utils::{TEST_CIPHER_SUITE, TEST_PROTOCOL_VERSION},
        group::{
            epoch::{test_utils::get_test_epoch_with_id, SenderDataSecret},
            snapshot::test_utils::get_test_snapshot,
            test_utils::test_member,
        },
        provider::{
            group_state::InMemoryGroupStateStorage, key_package::InMemoryKeyPackageRepository,
        },
    };

    use super::*;

    const TEST_GROUP_ID: &[u8] = b"test";

    fn test_group_state_repo(
        retention_limit: u64,
    ) -> GroupStateRepository<InMemoryGroupStateStorage, InMemoryKeyPackageRepository> {
        GroupStateRepository::new(
            TEST_GROUP_ID.to_vec(),
            retention_limit,
            InMemoryGroupStateStorage::default(),
            InMemoryKeyPackageRepository::default(),
            None,
        )
        .unwrap()
    }

    fn test_epoch(epoch_id: u64) -> PriorEpoch {
        get_test_epoch_with_id(TEST_GROUP_ID.to_vec(), TEST_CIPHER_SUITE, epoch_id)
    }

    fn test_snapshot(epoch_id: u64) -> Snapshot {
        get_test_snapshot(TEST_CIPHER_SUITE, epoch_id)
    }

    #[test]
    fn test_zero_max_retention() {
        assert_matches!(
            GroupStateRepository::new(
                TEST_GROUP_ID.to_vec(),
                0,
                InMemoryGroupStateStorage::default(),
                InMemoryKeyPackageRepository::default(),
                None,
            ),
            Err(GroupStateRepositoryError::NonZeroRetentionRequired)
        )
    }

    #[test]
    fn test_epoch_inserts() {
        let mut test_repo = test_group_state_repo(1);
        let test_epoch = test_epoch(0);

        test_repo.insert(test_epoch.clone()).unwrap();

        // Check the in-memory state
        assert_eq!(
            test_repo.pending_commit.inserts.back().unwrap(),
            &test_epoch
        );

        assert!(test_repo.pending_commit.updates.is_empty());
        assert!(test_repo.storage.inner.lock().unwrap().is_empty());

        // Make sure you can recall an epoch sitting as a pending insert
        let mut owned = test_repo.get_epoch_owned(0).unwrap();
        let borrowed = test_repo.get_epoch_mut(0).unwrap();
        assert_eq!(borrowed, owned.as_mut());
        assert_eq!(borrowed.unwrap(), &test_epoch);

        // Write to the storage
        let snapshot = test_snapshot(test_epoch.epoch_id());
        test_repo.write_to_storage(snapshot.clone()).unwrap();

        // Make sure the memory cache cleared
        assert!(test_repo.pending_commit.inserts.is_empty());
        assert!(test_repo.pending_commit.updates.is_empty());

        // Make sure the storage was written
        let storage = test_repo.storage.inner.lock().unwrap();
        assert_eq!(storage.len(), 1);

        let stored = storage.get(TEST_GROUP_ID).unwrap();

        assert_eq!(stored.current_snapshot, snapshot);
        assert_eq!(stored.epoch_data.len(), 1);
        assert_eq!(stored.epoch_data.back().unwrap(), &test_epoch);
    }

    #[test]
    fn test_epoch_insert_over_limit() {
        let mut test_repo = test_group_state_repo(1);
        let test_epoch_0 = test_epoch(0);
        let test_epoch_1 = test_epoch(1);

        test_repo.insert(test_epoch_0).unwrap();
        test_repo.insert(test_epoch_1.clone()).unwrap();

        assert_eq!(
            test_repo.pending_commit.inserts.back().unwrap(),
            &test_epoch_1
        );
        assert!(test_repo.pending_commit.updates.is_empty());
        assert_eq!(test_repo.pending_commit.inserts.len(), 1);
        assert!(test_repo.storage.inner.lock().unwrap().is_empty());

        test_repo.write_to_storage(test_snapshot(1)).unwrap();

        // Make sure the storage was written
        let storage = test_repo.storage.inner.lock().unwrap();
        assert_eq!(storage.len(), 1);

        let stored = storage.get(TEST_GROUP_ID).unwrap();

        assert_eq!(stored.epoch_data.len(), 1);
        assert_eq!(stored.epoch_data.back().unwrap(), &test_epoch_1);
    }

    #[test]
    fn test_epoch_insert_over_limit_with_update() {
        let mut test_repo = test_group_state_repo(1);
        let test_epoch_0 = test_epoch(0);
        test_repo.insert(test_epoch_0).unwrap();

        // Write epoch 0 to storage
        test_repo.write_to_storage(test_snapshot(0)).unwrap();

        // Pull epoch 0 back into memory
        test_repo.get_epoch_mut(0).unwrap().unwrap();

        // Insert epoch 1
        let test_epoch_1 = test_epoch(1);
        test_repo.insert(test_epoch_1).unwrap();

        // Insert epoch 2
        let test_epoch_2 = test_epoch(2);
        test_repo.insert(test_epoch_2.clone()).unwrap();

        assert_eq!(
            test_repo.pending_commit.inserts.back().unwrap(),
            &test_epoch_2
        );
        assert!(test_repo.pending_commit.updates.is_empty());
        assert_eq!(test_repo.pending_commit.inserts.len(), 1);

        test_repo.write_to_storage(test_snapshot(2)).unwrap();

        // Make sure the storage was written
        let storage = test_repo.storage.inner.lock().unwrap();
        assert_eq!(storage.len(), 1);

        let stored = storage.get(TEST_GROUP_ID).unwrap();

        assert_eq!(stored.epoch_data.len(), 1);
        assert_eq!(stored.epoch_data.back().unwrap(), &test_epoch_2);
    }

    #[test]
    fn test_updates() {
        let mut test_repo = test_group_state_repo(2);
        let test_epoch_0 = test_epoch(0);

        test_repo.insert(test_epoch_0.clone()).unwrap();

        test_repo.write_to_storage(test_snapshot(0)).unwrap();

        // Update the stored epoch
        let to_update = test_repo.get_epoch_mut(0).unwrap().unwrap();
        assert_eq!(to_update, &test_epoch_0);

        let new_sender_secret = SecureRng::gen(32).unwrap();
        to_update.secrets.sender_data_secret = SenderDataSecret::from(new_sender_secret);
        let to_update = to_update.clone();

        assert_eq!(test_repo.pending_commit.updates.len(), 1);
        assert!(test_repo.pending_commit.inserts.is_empty());

        assert_eq!(
            test_repo.pending_commit.updates.get(&0).unwrap(),
            &to_update
        );

        // Make sure you can access an epoch pending update
        let owned = test_repo.get_epoch_owned(0).unwrap();
        assert_eq!(owned.as_ref(), Some(&to_update));

        // Write the update to storage
        let snapshot = test_snapshot(1);
        test_repo.write_to_storage(snapshot.clone()).unwrap();

        assert!(test_repo.pending_commit.updates.is_empty());
        assert!(test_repo.pending_commit.inserts.is_empty());

        // Make sure the storage was written
        let storage = test_repo.storage.inner.lock().unwrap();
        assert_eq!(storage.len(), 1);

        let stored = storage.get(TEST_GROUP_ID).unwrap();

        assert_eq!(stored.current_snapshot, snapshot);
        assert_eq!(stored.epoch_data.len(), 1);
        assert_eq!(stored.epoch_data.back().unwrap(), &to_update);
    }

    #[test]
    fn test_insert_and_update() {
        let mut test_repo = test_group_state_repo(2);
        let test_epoch_0 = test_epoch(0);

        test_repo.insert(test_epoch_0).unwrap();

        test_repo.write_to_storage(test_snapshot(0)).unwrap();

        // Update the stored epoch
        let to_update = test_repo.get_epoch_mut(0).unwrap().unwrap();
        let new_sender_secret = SecureRng::gen(32).unwrap();
        to_update.secrets.sender_data_secret = SenderDataSecret::from(new_sender_secret);
        let to_update = to_update.clone();

        // Insert another epoch
        let test_epoch_1 = test_epoch(1);
        test_repo.insert(test_epoch_1.clone()).unwrap();

        test_repo.write_to_storage(test_snapshot(1)).unwrap();

        assert!(test_repo.pending_commit.inserts.is_empty());
        assert!(test_repo.pending_commit.updates.is_empty());

        // Make sure the storage was written
        let storage = test_repo.storage.inner.lock().unwrap();
        assert_eq!(storage.len(), 1);

        let stored = storage.get(TEST_GROUP_ID).unwrap();

        assert_eq!(stored.epoch_data.len(), 2);
        assert_eq!(stored.epoch_data.front().unwrap(), &to_update);
        assert_eq!(stored.epoch_data.back().unwrap(), &test_epoch_1);
    }

    #[test]
    fn test_many_epochs_in_storage() {
        let epochs = (0..10).map(test_epoch).collect::<Vec<_>>();

        let mut test_repo = test_group_state_repo(10);

        epochs
            .iter()
            .cloned()
            .for_each(|e| test_repo.insert(e).unwrap());

        test_repo.write_to_storage(test_snapshot(9)).unwrap();

        epochs.into_iter().for_each(|mut e| {
            assert_eq!(test_repo.get_epoch_mut(e.epoch_id()).unwrap(), Some(&mut e));
            assert_eq!(test_repo.get_epoch_owned(e.epoch_id()).unwrap(), Some(e));
        })
    }

    #[test]
    fn test_disallowed_access_to_pending_deletes() {
        let mut test_repo = test_group_state_repo(1);
        let test_epoch_0 = test_epoch(0);
        let test_epoch_1 = test_epoch(1);

        test_repo.insert(test_epoch_0).unwrap();
        test_repo.insert(test_epoch_1).unwrap();

        assert!(test_repo.get_epoch_mut(0).unwrap().is_none());
        assert!(test_repo.get_epoch_owned(0).unwrap().is_none());
    }

    #[test]
    fn test_stored_groups_list() {
        let mut test_repo = test_group_state_repo(2);
        let test_epoch_0 = test_epoch(0);

        test_repo.insert(test_epoch_0.clone()).unwrap();

        test_repo.write_to_storage(test_snapshot(0)).unwrap();

        assert_eq!(
            test_repo.storage.stored_groups().unwrap(),
            vec![test_epoch_0.context.group_id]
        )
    }

    #[test]
    fn reducing_retention_limit_takes_effect_on_epoch_access() {
        let mut repo = test_group_state_repo(1);

        repo.insert(test_epoch(0)).unwrap();
        repo.insert(test_epoch(1)).unwrap();

        repo.write_to_storage(test_snapshot(0)).unwrap();

        let mut repo = GroupStateRepository {
            storage: repo.storage,
            ..test_group_state_repo(1)
        };

        assert!(repo.get_epoch_mut(0).unwrap().is_none());
    }

    #[test]
    fn in_memory_storage_obeys_retention_limit_after_saving() {
        let mut repo = test_group_state_repo(1);
        repo.insert(test_epoch(0)).unwrap();
        repo.write_to_storage(test_snapshot(0)).unwrap();
        repo.insert(test_epoch(1)).unwrap();
        repo.write_to_storage(test_snapshot(1)).unwrap();

        assert_eq!(
            repo.storage
                .inner
                .lock()
                .unwrap()
                .get(TEST_GROUP_ID)
                .unwrap()
                .epoch_data
                .len(),
            1
        );
    }

    fn existing_storage_setup(
        count: u64,
    ) -> GroupStateRepository<InMemoryGroupStateStorage, InMemoryKeyPackageRepository> {
        // fill the repo to capacity
        let mut repo = test_group_state_repo(count);

        (0..count)
            .into_iter()
            .map(test_epoch)
            .for_each(|e| repo.insert(e).unwrap());

        repo.write_to_storage(test_snapshot(2)).unwrap();

        repo
    }

    #[test]
    fn existing_storage_can_be_imported_with_delete_under() {
        let mut repo = existing_storage_setup(3);
        repo.insert(test_epoch(3)).unwrap();
        repo.write_to_storage(test_snapshot(3)).unwrap();

        let new_repo = GroupStateRepository::new(
            TEST_GROUP_ID.to_vec(),
            3,
            repo.storage.clone(),
            repo.key_package_repo.clone(),
            None,
        )
        .unwrap();

        assert_eq!(
            repo.pending_commit.delete_under,
            new_repo.pending_commit.delete_under
        );

        assert_eq!(new_repo.pending_commit.delete_under.unwrap(), 1);
    }

    #[test]
    fn existing_storage_can_have_larger_epoch_count() {
        let repo = existing_storage_setup(3);

        let mut new_repo = GroupStateRepository::new(
            TEST_GROUP_ID.to_vec(),
            5,
            repo.storage,
            repo.key_package_repo,
            None,
        )
        .unwrap();

        new_repo.insert(test_epoch(3)).unwrap();
        new_repo.insert(test_epoch(4)).unwrap();

        new_repo.write_to_storage(test_snapshot(4)).unwrap();

        assert!(new_repo.pending_commit.delete_under.is_none());

        assert_eq!(
            new_repo.storage.export_epoch_data(TEST_GROUP_ID).unwrap()[0].epoch_id(),
            0
        );
    }

    #[test]
    fn existing_storage_can_have_smaller_epoch_count() {
        let repo = existing_storage_setup(5);

        let mut new_repo = GroupStateRepository::new(
            TEST_GROUP_ID.to_vec(),
            3,
            repo.storage,
            repo.key_package_repo,
            None,
        )
        .unwrap();

        assert_eq!(new_repo.pending_commit.delete_under.unwrap(), 2);

        // Writing to storage should clean up
        new_repo.write_to_storage(test_snapshot(4)).unwrap();

        assert_eq!(
            new_repo.storage.export_epoch_data(TEST_GROUP_ID).unwrap()[0].epoch_id(),
            2
        );
    }

    #[test]
    fn used_key_package_is_deleted() {
        let key_package_repo = InMemoryKeyPackageRepository::default();
        let key_package = test_member(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE, b"member").0;
        key_package_repo.insert(key_package.clone()).unwrap();

        let mut repo = GroupStateRepository::new(
            TEST_GROUP_ID.to_vec(),
            4,
            InMemoryGroupStateStorage::default(),
            key_package_repo,
            Some(key_package.reference().unwrap()),
        )
        .unwrap();

        repo.key_package_repo
            .get(&key_package.reference().unwrap())
            .unwrap();

        repo.write_to_storage(test_snapshot(4)).unwrap();

        assert!(repo
            .key_package_repo
            .get(&key_package.reference().unwrap())
            .is_none());
    }
}
