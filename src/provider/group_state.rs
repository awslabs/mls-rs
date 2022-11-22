use std::{
    collections::{hash_map::Entry, HashMap, VecDeque},
    convert::Infallible,
    sync::{Arc, Mutex},
};

pub use crate::group::{snapshot::Snapshot, state_repo::PriorEpoch};

/// A set of changes to apply to a GroupStateStorage implementation. These changes MUST
/// be made in a single transaction to avoid creating invalid states.
#[derive(Default, Clone, Debug)]
pub struct EpochStorageCommit {
    pub(crate) inserts: VecDeque<PriorEpoch>,
    pub(crate) updates: HashMap<u64, PriorEpoch>,
    pub(crate) delete_under: Option<u64>,
}

impl EpochStorageCommit {
    pub fn inserts(&self) -> impl Iterator<Item = &PriorEpoch> {
        self.inserts.iter()
    }

    pub fn updates(&self) -> impl Iterator<Item = &PriorEpoch> {
        self.updates.values()
    }

    pub fn delete_under(&self) -> Option<u64> {
        self.delete_under
    }
}

/// Group state storage
pub trait GroupStateStorage {
    type Error: std::error::Error + Send + Sync + 'static;

    fn delete_group(&self, group_id: &[u8]) -> Result<(), Self::Error>;

    fn get_snapshot(&self, group_id: &[u8]) -> Result<Option<Snapshot>, Self::Error>;

    fn get_epoch_data(
        &self,
        group_id: &[u8],
        epoch_id: u64,
    ) -> Result<Option<PriorEpoch>, Self::Error>;

    fn write(
        &mut self,
        group_id: &[u8],
        group_snapshot: Snapshot,
        epoch_commit: &EpochStorageCommit,
    ) -> Result<(), Self::Error>;

    fn max_epoch_id(&self, group_id: &[u8]) -> Result<Option<u64>, Self::Error>;
}

#[derive(Debug, Clone)]
pub(crate) struct InMemoryGroupData {
    pub(crate) current_snapshot: Snapshot,
    pub(crate) epoch_data: VecDeque<PriorEpoch>,
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
    pub(crate) inner: Arc<Mutex<HashMap<Vec<u8>, InMemoryGroupData>>>,
}

impl InMemoryGroupStateStorage {
    pub fn new() -> Self {
        Self {
            inner: Default::default(),
        }
    }

    #[cfg(any(feature = "benchmark", test))]
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

    pub fn stored_groups(&self) -> Vec<Vec<u8>> {
        self.inner.lock().unwrap().keys().cloned().collect()
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

    fn write(
        &mut self,
        group_id: &[u8],
        group_snapshot: Snapshot,
        epoch_commit: &EpochStorageCommit,
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
            .inserts()
            .for_each(|e| group_data.insert_epoch(e.clone()));

        epoch_commit
            .updates()
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

    fn delete_group(&self, group_id: &[u8]) -> Result<(), Self::Error> {
        self.inner.lock().unwrap().remove(group_id);
        Ok(())
    }
}
