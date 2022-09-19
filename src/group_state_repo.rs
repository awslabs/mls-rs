use crate::group::Snapshot;

use hex::ToHex;
use std::{
    collections::{hash_map::Entry, HashMap, VecDeque},
    convert::Infallible,
    sync::{Arc, Mutex},
};
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
}

#[derive(Debug, Clone, Error)]
pub(crate) struct GroupStateRepository<S>
where
    S: GroupStateStorage,
{
    pub max_epochs: u64,
    inserts: VecDeque<PriorEpoch>,
    updates: HashMap<u64, PriorEpoch>,
    delete_under: Option<u64>,
    group_id: Vec<u8>,
    storage: S,
}

impl<S> GroupStateRepository<S>
where
    S: GroupStateStorage,
{
    pub fn new(
        group_id: Vec<u8>,
        max_epoch_retention: u64,
        storage: S,
    ) -> Result<GroupStateRepository<S>, GroupStateRepositoryError> {
        if max_epoch_retention == 0 {
            return Err(GroupStateRepositoryError::NonZeroRetentionRequired);
        }

        let delete_under = storage
            .max_epoch_id(&group_id)
            .map_err(|e| GroupStateRepositoryError::StorageError(e.into()))?
            .and_then(|max| max.checked_sub(max_epoch_retention - 1));

        Ok(GroupStateRepository {
            max_epochs: max_epoch_retention,
            inserts: Default::default(),
            updates: Default::default(),
            delete_under,
            group_id,
            storage,
        })
    }

    fn find_max_id(&self) -> Result<Option<u64>, GroupStateRepositoryError> {
        if let Some(max) = self.inserts.back().map(|e| e.epoch_id()) {
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
        if let Some(min) = self.inserts.front().map(|e| e.epoch_id()) {
            if epoch_id >= min {
                return Ok(self.inserts.get((epoch_id - min) as usize).cloned());
            }
        }

        self.updates
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
        self.delete_under
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
        if let Some(min) = self.inserts.front().map(|e| e.epoch_id()) {
            if epoch_id >= min {
                return Ok(self.inserts.get_mut((epoch_id - min) as usize));
            }
        }

        // Look in the cached updates map, and if not found look in disk storage
        // and insert into the updates map for future caching
        Ok(match self.updates.entry(epoch_id) {
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

        self.inserts.push_back(epoch);

        if epoch_id >= self.max_epochs {
            let min = epoch_id - self.max_epochs;
            self.delete_under = Some(min + 1);

            if self.inserts.len() > self.max_epochs as usize {
                self.inserts.pop_front();
            }

            self.updates.remove(&min);
        }

        Ok(())
    }

    pub fn write_to_storage(
        &mut self,
        group_snapshot: Snapshot,
    ) -> Result<(), GroupStateRepositoryError> {
        let epoch_commit = EpochStorageCommit {
            inserts: self.inserts.iter(),
            updates: self.updates.values(),
            delete_under: self.delete_under,
        };

        self.storage
            .write(&self.group_id, group_snapshot, epoch_commit)
            .map_err(|e| GroupStateRepositoryError::StorageError(e.into()))?;

        self.inserts.clear();
        self.updates.clear();

        Ok(())
    }
}

/// A set of changes to apply to a GroupStateStorage implementation. These changes MUST
/// be made in a single transaction to avoid creating invalid states.
pub struct EpochStorageCommit<'a, I, U>
where
    I: Iterator<Item = &'a PriorEpoch>,
    U: Iterator<Item = &'a PriorEpoch>,
{
    inserts: I,
    updates: U,
    delete_under: Option<u64>,
}

impl<'a, I, U> EpochStorageCommit<'a, I, U>
where
    I: Iterator<Item = &'a PriorEpoch>,
    U: Iterator<Item = &'a PriorEpoch>,
{
    /// Sequential epoch inserts to add to the store
    pub fn inserts(&self) -> &impl Iterator<Item = &'a PriorEpoch> {
        &self.inserts
    }

    /// Updates to existing epochs accessed by the GroupStateRepository since
    /// the last write
    pub fn updates(&self) -> &impl Iterator<Item = &'a PriorEpoch> {
        &self.updates
    }

    /// Optional request to delete old epoch data under a specific epoch_id
    pub fn delete_under(&self) -> Option<u64> {
        self.delete_under
    }
}

/// Group state storage
pub trait GroupStateStorage {
    type Error: std::error::Error + Send + Sync + 'static;

    fn stored_groups(&self) -> Result<Vec<Vec<u8>>, Self::Error>;

    fn get_snapshot(&self, group_id: &[u8]) -> Result<Option<Snapshot>, Self::Error>;

    fn get_epoch_data(
        &self,
        group_id: &[u8],
        epoch_id: u64,
    ) -> Result<Option<PriorEpoch>, Self::Error>;

    fn write<'a, I: Iterator<Item = &'a PriorEpoch>, U: Iterator<Item = &'a PriorEpoch>>(
        &mut self,
        group_id: &[u8],
        group_snapshot: Snapshot,
        epoch_commit: EpochStorageCommit<'a, I, U>,
    ) -> Result<(), Self::Error>;

    fn max_epoch_id(&self, group_id: &[u8]) -> Result<Option<u64>, Self::Error>;
}

#[derive(Debug, Clone)]
struct InMemoryGroupData {
    current_snapshot: Snapshot,
    epoch_data: VecDeque<PriorEpoch>,
}

impl InMemoryGroupData {
    pub fn new(snapshot: Snapshot) -> InMemoryGroupData {
        InMemoryGroupData {
            current_snapshot: snapshot,
            epoch_data: Default::default(),
        }
    }

    fn get_epoch_data_index(&self, epoch_id: u64) -> Option<u64> {
        self.epoch_data
            .front()
            .and_then(|e| epoch_id.checked_sub(e.epoch_id()))
    }

    pub fn get_epoch(&self, epoch_id: u64) -> Option<&PriorEpoch> {
        self.get_epoch_data_index(epoch_id)
            .and_then(|i| self.epoch_data.get(i as usize))
    }

    pub fn get_mut_epoch(&mut self, epoch_id: u64) -> Option<&mut PriorEpoch> {
        self.get_epoch_data_index(epoch_id)
            .and_then(|i| self.epoch_data.get_mut(i as usize))
    }

    pub fn insert_epoch(&mut self, epoch: PriorEpoch) {
        self.epoch_data.push_back(epoch)
    }

    // This function does not fail if an update can't be made. If the epoch
    // is not in the store, then it can no longer be accessed by future
    // get_epoch calls and is no longer relevant.
    pub fn update_epoch(&mut self, epoch: PriorEpoch) {
        if let Some(existing_epoch) = self.get_mut_epoch(epoch.epoch_id()) {
            *existing_epoch = epoch
        }
    }

    pub fn trim_epochs(&mut self, min_epoch: u64) {
        while let Some(min) = self.epoch_data.front() {
            if min.epoch_id() < min_epoch {
                self.epoch_data.pop_front();
            } else {
                break;
            }
        }
    }
}

#[derive(Clone, Debug)]
pub struct InMemoryGroupStateStorage {
    inner: Arc<Mutex<HashMap<Vec<u8>, InMemoryGroupData>>>,
}

impl InMemoryGroupStateStorage {
    pub fn new() -> Self {
        Self {
            inner: Default::default(),
        }
    }

    pub fn export_epoch_data(&self, group_id: &[u8]) -> Option<Vec<PriorEpoch>> {
        self.inner
            .lock()
            .unwrap()
            .get(group_id)
            .map(|data| Vec::from_iter(data.epoch_data.iter().cloned()))
    }

    #[cfg(feature = "benchmark")]
    pub fn from_benchmark_data(snapshot: Snapshot, epoch_data: Vec<PriorEpoch>) -> Self {
        let group_id = snapshot.group_id().to_vec();

        let mut group_data = InMemoryGroupData::new(snapshot);

        epoch_data
            .into_iter()
            .for_each(|epoch_data| group_data.epoch_data.push_back(epoch_data));

        let storage = InMemoryGroupStateStorage::new();

        storage.inner.lock().unwrap().insert(group_id, group_data);

        storage
    }
}

impl Default for InMemoryGroupStateStorage {
    fn default() -> Self {
        Self::new()
    }
}

impl GroupStateStorage for InMemoryGroupStateStorage {
    type Error = Infallible;

    fn get_epoch_data(
        &self,
        group_id: &[u8],
        epoch_id: u64,
    ) -> Result<Option<PriorEpoch>, Self::Error> {
        Ok(self
            .inner
            .lock()
            .unwrap()
            .get(group_id)
            .and_then(|group_data| group_data.get_epoch(epoch_id))
            .cloned())
    }

    fn write<'a, I: Iterator<Item = &'a PriorEpoch>, U: Iterator<Item = &'a PriorEpoch>>(
        &mut self,
        group_id: &[u8],
        group_snapshot: Snapshot,
        epoch_commit: EpochStorageCommit<'a, I, U>,
    ) -> Result<(), Self::Error> {
        let mut group_map = self.inner.lock().unwrap();

        let group_data = match group_map.entry(group_id.to_vec()) {
            Entry::Occupied(entry) => {
                let data = entry.into_mut();
                data.current_snapshot = group_snapshot;
                data
            }
            Entry::Vacant(entry) => entry.insert(InMemoryGroupData::new(group_snapshot)),
        };

        epoch_commit
            .inserts
            .for_each(|e| group_data.insert_epoch(e.clone()));

        epoch_commit
            .updates
            .for_each(|e| group_data.update_epoch(e.clone()));

        if let Some(min_epoch) = epoch_commit.delete_under {
            group_data.trim_epochs(min_epoch);
        }

        Ok(())
    }

    fn max_epoch_id(&self, group_id: &[u8]) -> Result<Option<u64>, Self::Error> {
        Ok(self
            .inner
            .lock()
            .unwrap()
            .get(group_id)
            .and_then(|group_data| group_data.epoch_data.back().map(|e| e.epoch_id())))
    }

    fn get_snapshot(&self, group_id: &[u8]) -> Result<Option<Snapshot>, Self::Error> {
        Ok(self
            .inner
            .lock()
            .unwrap()
            .get(group_id)
            .map(|v| v.current_snapshot.clone()))
    }

    fn stored_groups(&self) -> Result<Vec<Vec<u8>>, Self::Error> {
        Ok(self.inner.lock().unwrap().keys().cloned().collect())
    }
}

#[cfg(test)]
mod tests {
    use assert_matches::assert_matches;
    use ferriscrypt::rand::SecureRng;

    use crate::{
        client::test_utils::TEST_CIPHER_SUITE,
        group::{
            epoch::{test_utils::get_test_epoch_with_id, SenderDataSecret},
            snapshot::test_utils::get_test_snapshot,
        },
    };

    use super::*;

    const TEST_GROUP_ID: &[u8] = b"test";

    fn test_group_state_repo(
        retention_limit: u64,
    ) -> GroupStateRepository<InMemoryGroupStateStorage> {
        GroupStateRepository::new(
            TEST_GROUP_ID.to_vec(),
            retention_limit,
            InMemoryGroupStateStorage::default(),
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
                InMemoryGroupStateStorage::default()
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
        assert_eq!(test_repo.inserts.back().unwrap(), &test_epoch);
        assert!(test_repo.updates.is_empty());
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
        assert!(test_repo.inserts.is_empty());
        assert!(test_repo.updates.is_empty());

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

        assert_eq!(test_repo.inserts.back().unwrap(), &test_epoch_1);
        assert!(test_repo.updates.is_empty());
        assert_eq!(test_repo.inserts.len(), 1);
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

        assert_eq!(test_repo.inserts.back().unwrap(), &test_epoch_2);
        assert!(test_repo.updates.is_empty());
        assert_eq!(test_repo.inserts.len(), 1);

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

        assert_eq!(test_repo.updates.len(), 1);
        assert!(test_repo.inserts.is_empty());

        assert_eq!(test_repo.updates.get(&0).unwrap(), &to_update);

        // Make sure you can access an epoch pending update
        let owned = test_repo.get_epoch_owned(0).unwrap();
        assert_eq!(owned.as_ref(), Some(&to_update));

        // Write the update to storage
        let snapshot = test_snapshot(1);
        test_repo.write_to_storage(snapshot.clone()).unwrap();

        assert!(test_repo.updates.is_empty());
        assert!(test_repo.inserts.is_empty());

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

        assert!(test_repo.inserts.is_empty());
        assert!(test_repo.updates.is_empty());

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

    fn existing_storage_setup(count: u64) -> GroupStateRepository<InMemoryGroupStateStorage> {
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

        let new_repo =
            GroupStateRepository::new(TEST_GROUP_ID.to_vec(), 3, repo.storage.clone()).unwrap();

        assert_eq!(repo.delete_under, new_repo.delete_under);
        assert_eq!(new_repo.delete_under.unwrap(), 1);
    }

    #[test]
    fn existing_storage_can_have_larger_epoch_count() {
        let repo = existing_storage_setup(3);

        let mut new_repo =
            GroupStateRepository::new(TEST_GROUP_ID.to_vec(), 5, repo.storage).unwrap();

        new_repo.insert(test_epoch(3)).unwrap();
        new_repo.insert(test_epoch(4)).unwrap();

        new_repo.write_to_storage(test_snapshot(4)).unwrap();

        assert!(new_repo.delete_under.is_none());

        assert_eq!(
            new_repo.storage.export_epoch_data(TEST_GROUP_ID).unwrap()[0].epoch_id(),
            0
        );
    }

    #[test]
    fn existing_storage_can_have_smaller_epoch_count() {
        let repo = existing_storage_setup(5);

        let mut new_repo =
            GroupStateRepository::new(TEST_GROUP_ID.to_vec(), 3, repo.storage).unwrap();

        assert_eq!(new_repo.delete_under.unwrap(), 2);

        // Writing to storage should clean up
        new_repo.write_to_storage(test_snapshot(4)).unwrap();

        assert_eq!(
            new_repo.storage.export_epoch_data(TEST_GROUP_ID).unwrap()[0].epoch_id(),
            2
        );
    }
}
