use std::{
    collections::{hash_map::Entry, HashMap, VecDeque},
    sync::{Arc, Mutex},
};

pub use aws_mls_core::group::GroupStateStorage;
use aws_mls_core::group::{EpochRecord, GroupState};

use crate::group::{epoch::PriorEpoch, snapshot::Snapshot};

impl EpochRecord for PriorEpoch {
    fn id(&self) -> u64 {
        self.epoch_id()
    }
}

impl GroupState for Snapshot {
    fn id(&self) -> Vec<u8> {
        self.group_id().to_vec()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub(crate) struct EpochData {
    pub(crate) id: u64,
    pub(crate) data: Vec<u8>,
}

impl EpochData {
    pub(crate) fn new<T>(value: T) -> Result<Self, bincode::Error>
    where
        T: serde::Serialize + EpochRecord,
    {
        Ok(Self {
            id: value.id(),
            data: bincode::serialize(&value)?,
        })
    }
}

#[derive(Debug, Clone)]
pub(crate) struct InMemoryGroupData {
    pub(crate) state_data: Vec<u8>,
    pub(crate) epoch_data: VecDeque<EpochData>,
}

impl InMemoryGroupData {
    pub fn new(state_data: Vec<u8>) -> InMemoryGroupData {
        InMemoryGroupData {
            state_data,
            epoch_data: Default::default(),
        }
    }

    fn get_epoch_data_index(&self, epoch_id: u64) -> Option<u64> {
        self.epoch_data
            .front()
            .and_then(|e| epoch_id.checked_sub(e.id))
    }

    pub fn get_epoch(&self, epoch_id: u64) -> Option<&EpochData> {
        self.get_epoch_data_index(epoch_id)
            .and_then(|i| self.epoch_data.get(i as usize))
    }

    pub fn get_mut_epoch(&mut self, epoch_id: u64) -> Option<&mut EpochData> {
        self.get_epoch_data_index(epoch_id)
            .and_then(|i| self.epoch_data.get_mut(i as usize))
    }

    pub fn insert_epoch(&mut self, epoch: EpochData) {
        self.epoch_data.push_back(epoch)
    }

    // This function does not fail if an update can't be made. If the epoch
    // is not in the store, then it can no longer be accessed by future
    // get_epoch calls and is no longer relevant.
    pub fn update_epoch(&mut self, epoch: EpochData) {
        if let Some(existing_epoch) = self.get_mut_epoch(epoch.id) {
            *existing_epoch = epoch
        }
    }

    pub fn trim_epochs(&mut self, min_epoch: u64) {
        while let Some(min) = self.epoch_data.front() {
            if min.id < min_epoch {
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
    pub(crate) fn export_epoch_data(&self, group_id: &[u8]) -> Option<Vec<PriorEpoch>> {
        self.inner.lock().unwrap().get(group_id).map(|data| {
            Vec::from_iter(
                data.epoch_data
                    .iter()
                    .map(|v| bincode::deserialize(&v.data).unwrap()),
            )
        })
    }

    #[cfg(feature = "benchmark")]
    pub(crate) fn from_benchmark_data(snapshot: Snapshot, epoch_data: Vec<PriorEpoch>) -> Self {
        let group_id = snapshot.group_id().to_vec();

        let mut group_data = InMemoryGroupData::new(bincode::serialize(&snapshot).unwrap());

        epoch_data.into_iter().for_each(|epoch| {
            group_data
                .epoch_data
                .push_back(EpochData::new(epoch).unwrap())
        });

        let storage = InMemoryGroupStateStorage::new();

        storage.inner.lock().unwrap().insert(group_id, group_data);

        storage
    }

    pub fn stored_groups(&self) -> Vec<Vec<u8>> {
        self.inner.lock().unwrap().keys().cloned().collect()
    }

    pub fn delete_group(&self, group_id: &[u8]) {
        self.inner.lock().unwrap().remove(group_id);
    }
}

impl Default for InMemoryGroupStateStorage {
    fn default() -> Self {
        Self::new()
    }
}

impl GroupStateStorage for InMemoryGroupStateStorage {
    type Error = bincode::Error;

    fn max_epoch_id(&self, group_id: &[u8]) -> Result<Option<u64>, Self::Error> {
        Ok(self
            .inner
            .lock()
            .unwrap()
            .get(group_id)
            .and_then(|group_data| group_data.epoch_data.back().map(|e| e.id)))
    }

    fn state<T>(&self, group_id: &[u8]) -> Result<Option<T>, Self::Error>
    where
        T: aws_mls_core::group::GroupState + serde::de::DeserializeOwned,
    {
        self.inner
            .lock()
            .unwrap()
            .get(group_id)
            .map(|v| bincode::deserialize(&v.state_data))
            .transpose()
    }

    fn epoch<T>(&self, group_id: &[u8], epoch_id: u64) -> Result<Option<T>, Self::Error>
    where
        T: aws_mls_core::group::EpochRecord + serde::Serialize + serde::de::DeserializeOwned,
    {
        self.inner
            .lock()
            .unwrap()
            .get(group_id)
            .and_then(|group_data| group_data.get_epoch(epoch_id))
            .map(|v| bincode::deserialize(&v.data))
            .transpose()
    }

    fn write<ST, ET>(
        &mut self,
        state: ST,
        epoch_inserts: Vec<ET>,
        epoch_updates: Vec<ET>,
        delete_epoch_under: Option<u64>,
    ) -> Result<(), Self::Error>
    where
        ST: GroupState + serde::Serialize + serde::de::DeserializeOwned,
        ET: EpochRecord + serde::Serialize + serde::de::DeserializeOwned,
    {
        let mut group_map = self.inner.lock().unwrap();

        let state_data = bincode::serialize(&state)?;

        let group_data = match group_map.entry(state.id()) {
            Entry::Occupied(entry) => {
                let data = entry.into_mut();
                data.state_data = state_data;
                data
            }
            Entry::Vacant(entry) => entry.insert(InMemoryGroupData::new(state_data)),
        };

        epoch_inserts.into_iter().try_for_each(|e| {
            group_data.insert_epoch(EpochData::new(e)?);
            Ok::<_, bincode::Error>(())
        })?;

        epoch_updates.into_iter().try_for_each(|e| {
            group_data.update_epoch(EpochData::new(e)?);
            Ok::<_, bincode::Error>(())
        })?;

        if let Some(min_epoch) = delete_epoch_under {
            group_data.trim_epochs(min_epoch);
        }

        Ok(())
    }
}
