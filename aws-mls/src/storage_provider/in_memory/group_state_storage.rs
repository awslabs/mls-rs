use alloc::boxed::Box;
use alloc::collections::VecDeque;

#[cfg(feature = "std")]
use alloc::sync::Arc;

#[cfg(not(feature = "std"))]
use portable_atomic_util::Arc;

use alloc::vec::Vec;
use async_trait::async_trait;
use aws_mls_core::group::{EpochRecord, GroupState, GroupStateStorage};
use bincode::{config::Configuration, de::read::SliceReader};

use crate::storage_provider::group_state::EpochData;

#[cfg(any(feature = "benchmark", test))]
use crate::group::epoch::PriorEpoch;

#[cfg(any(feature = "benchmark", test))]
use crate::group::snapshot::Snapshot;

#[cfg(feature = "std")]
use std::collections::{hash_map::Entry, HashMap};

#[cfg(not(feature = "std"))]
use alloc::collections::{btree_map::Entry, BTreeMap};

#[cfg(feature = "std")]
use std::sync::Mutex;

#[cfg(not(feature = "std"))]
use spin::Mutex;

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
/// In memory group state storage backed by a HashMap.
///
/// All clones of an instance of this type share the same underlying HashMap.
pub struct InMemoryGroupStateStorage {
    #[cfg(feature = "std")]
    pub(crate) inner: Arc<Mutex<HashMap<Vec<u8>, InMemoryGroupData>>>,
    #[cfg(not(feature = "std"))]
    pub(crate) inner: Arc<Mutex<BTreeMap<Vec<u8>, InMemoryGroupData>>>,
}

impl InMemoryGroupStateStorage {
    /// Create an empty group state storage.
    pub fn new() -> Self {
        Self {
            inner: Default::default(),
        }
    }

    #[cfg(any(feature = "benchmark", test))]
    pub(crate) fn export_epoch_data(&self, group_id: &[u8]) -> Option<Vec<PriorEpoch>> {
        #[cfg(feature = "std")]
        let lock = self.inner.lock().unwrap();
        #[cfg(not(feature = "std"))]
        let lock = self.inner.lock();

        lock.get(group_id).map(|data| {
            Vec::from_iter(data.epoch_data.iter().map(|v| {
                bincode::serde::decode_from_reader::<PriorEpoch, _, Configuration>(
                    SliceReader::new(&v.data),
                    Configuration::default(),
                )
                .unwrap()
            }))
        })
    }

    #[cfg(feature = "benchmark")]
    pub(crate) fn from_benchmark_data(snapshot: Snapshot, epoch_data: Vec<PriorEpoch>) -> Self {
        let group_id = snapshot.group_id().to_vec();

        let mut group_data = InMemoryGroupData::new(
            bincode::serde::encode_to_vec::<_, Configuration>(&snapshot, Configuration::default())
                .unwrap(),
        );

        epoch_data.into_iter().for_each(|epoch| {
            group_data
                .epoch_data
                .push_back(EpochData::new(epoch).unwrap())
        });

        let storage = InMemoryGroupStateStorage::new();

        storage.inner.lock().unwrap().insert(group_id, group_data);

        storage
    }

    /// Get the set of unique group ids that have data stored.
    pub fn stored_groups(&self) -> Vec<Vec<u8>> {
        #[cfg(feature = "std")]
        let res = self.inner.lock().unwrap().keys().cloned().collect();
        #[cfg(not(feature = "std"))]
        let res = self.inner.lock().keys().cloned().collect();

        res
    }

    /// Delete all data corresponding to `group_id`.
    pub fn delete_group(&self, group_id: &[u8]) {
        #[cfg(feature = "std")]
        self.inner.lock().unwrap().remove(group_id);
        #[cfg(not(feature = "std"))]
        self.inner.lock().remove(group_id);
    }
}

impl Default for InMemoryGroupStateStorage {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, thiserror::Error)]
pub enum BincodeError {
    #[error("bincode encode error")]
    Encode(bincode::error::EncodeError),
    #[error("bincode decode error")]
    Decode(bincode::error::DecodeError),
}

// Manual impl to help with no_std
impl From<bincode::error::EncodeError> for BincodeError {
    fn from(value: bincode::error::EncodeError) -> Self {
        BincodeError::Encode(value)
    }
}

// Manual impl to help with no_std
impl From<bincode::error::DecodeError> for BincodeError {
    fn from(value: bincode::error::DecodeError) -> Self {
        BincodeError::Decode(value)
    }
}

#[async_trait]
impl GroupStateStorage for InMemoryGroupStateStorage {
    type Error = BincodeError;

    async fn max_epoch_id(&self, group_id: &[u8]) -> Result<Option<u64>, Self::Error> {
        #[cfg(feature = "std")]
        let lock = self.inner.lock().unwrap();

        #[cfg(not(feature = "std"))]
        let lock = self.inner.lock();

        Ok(lock
            .get(group_id)
            .and_then(|group_data| group_data.epoch_data.back().map(|e| e.id)))
    }

    async fn state<T>(&self, group_id: &[u8]) -> Result<Option<T>, Self::Error>
    where
        T: aws_mls_core::group::GroupState + serde::de::DeserializeOwned,
    {
        #[cfg(feature = "std")]
        let lock = self.inner.lock().unwrap();
        #[cfg(not(feature = "std"))]
        let lock = self.inner.lock();

        lock.get(group_id)
            .map(|v| {
                bincode::serde::decode_from_reader::<T, _, Configuration>(
                    SliceReader::new(&v.state_data),
                    Configuration::default(),
                )
            })
            .transpose()
            .map_err(Into::into)
    }

    async fn epoch<T>(&self, group_id: &[u8], epoch_id: u64) -> Result<Option<T>, Self::Error>
    where
        T: aws_mls_core::group::EpochRecord + serde::Serialize + serde::de::DeserializeOwned,
    {
        #[cfg(feature = "std")]
        let lock = self.inner.lock().unwrap();

        #[cfg(not(feature = "std"))]
        let lock = self.inner.lock();

        lock.get(group_id)
            .and_then(|group_data| group_data.get_epoch(epoch_id))
            .map(|v| {
                bincode::serde::decode_from_reader::<T, _, Configuration>(
                    SliceReader::new(&v.data),
                    Configuration::default(),
                )
            })
            .transpose()
            .map_err(Into::into)
    }

    async fn write<ST, ET>(
        &mut self,
        state: ST,
        epoch_inserts: Vec<ET>,
        epoch_updates: Vec<ET>,
        delete_epoch_under: Option<u64>,
    ) -> Result<(), Self::Error>
    where
        ST: GroupState + serde::Serialize + serde::de::DeserializeOwned + Send + Sync,
        ET: EpochRecord + serde::Serialize + serde::de::DeserializeOwned + Send + Sync,
    {
        #[cfg(feature = "std")]
        let mut group_map = self.inner.lock().unwrap();

        #[cfg(not(feature = "std"))]
        let mut group_map = self.inner.lock();

        let state_data =
            bincode::serde::encode_to_vec::<_, Configuration>(&state, Configuration::default())?;

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
            Ok::<_, Self::Error>(())
        })?;

        epoch_updates.into_iter().try_for_each(|e| {
            group_data.update_epoch(EpochData::new(e)?);
            Ok::<_, Self::Error>(())
        })?;

        if let Some(min_epoch) = delete_epoch_under {
            group_data.trim_epochs(min_epoch);
        }

        Ok(())
    }
}
