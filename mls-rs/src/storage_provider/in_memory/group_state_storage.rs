// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// Copyright by contributors to this project.
// SPDX-License-Identifier: (Apache-2.0 OR MIT)

use alloc::collections::VecDeque;

#[cfg(target_has_atomic = "ptr")]
use alloc::sync::Arc;

#[cfg(mls_build_async)]
use alloc::boxed::Box;
use alloc::vec::Vec;
use mls_rs_codec::{MlsDecode, MlsEncode};
use mls_rs_core::group::{EpochRecord, GroupState, GroupStateStorage};
#[cfg(not(target_has_atomic = "ptr"))]
use portable_atomic_util::Arc;

use crate::{client::MlsError, storage_provider::group_state::EpochData};

#[cfg(feature = "std")]
use std::collections::{hash_map::Entry, HashMap};

#[cfg(not(feature = "std"))]
use alloc::collections::{btree_map::Entry, BTreeMap};

#[cfg(feature = "std")]
use std::sync::Mutex;

#[cfg(not(feature = "std"))]
use spin::Mutex;

pub(crate) const DEFAULT_EPOCH_RETENTION_LIMIT: usize = 3;

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

    pub fn trim_epochs(&mut self, max_epoch_retention: usize) {
        while self.epoch_data.len() > max_epoch_retention {
            self.epoch_data.pop_front();
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
    pub(crate) max_epoch_retention: usize,
}

impl InMemoryGroupStateStorage {
    /// Create an empty group state storage.
    pub fn new() -> Self {
        Self {
            inner: Default::default(),
            max_epoch_retention: DEFAULT_EPOCH_RETENTION_LIMIT,
        }
    }

    pub fn with_max_epoch_retention(self, max_epoch_retention: usize) -> Result<Self, MlsError> {
        (max_epoch_retention > 0)
            .then_some(())
            .ok_or(MlsError::NonZeroRetentionRequired)?;

        Ok(Self {
            inner: self.inner,
            max_epoch_retention,
        })
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

#[cfg_attr(not(mls_build_async), maybe_async::must_be_sync)]
#[cfg_attr(mls_build_async, maybe_async::must_be_async)]
impl GroupStateStorage for InMemoryGroupStateStorage {
    type Error = mls_rs_codec::Error;

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
        T: mls_rs_core::group::GroupState + MlsDecode,
    {
        #[cfg(feature = "std")]
        let lock = self.inner.lock().unwrap();
        #[cfg(not(feature = "std"))]
        let lock = self.inner.lock();

        lock.get(group_id)
            .map(|v| T::mls_decode(&mut v.state_data.as_slice()))
            .transpose()
            .map_err(Into::into)
    }

    async fn epoch<T>(&self, group_id: &[u8], epoch_id: u64) -> Result<Option<T>, Self::Error>
    where
        T: mls_rs_core::group::EpochRecord + MlsEncode + MlsDecode,
    {
        #[cfg(feature = "std")]
        let lock = self.inner.lock().unwrap();

        #[cfg(not(feature = "std"))]
        let lock = self.inner.lock();

        lock.get(group_id)
            .and_then(|group_data| group_data.get_epoch(epoch_id))
            .map(|v| T::mls_decode(&mut v.data.as_slice()))
            .transpose()
            .map_err(Into::into)
    }

    async fn write<ST, ET>(
        &mut self,
        state: ST,
        epoch_inserts: Vec<ET>,
        epoch_updates: Vec<ET>,
    ) -> Result<(), Self::Error>
    where
        ST: GroupState + MlsEncode + MlsDecode + Send + Sync,
        ET: EpochRecord + MlsEncode + MlsDecode + Send + Sync,
    {
        #[cfg(feature = "std")]
        let mut group_map = self.inner.lock().unwrap();

        #[cfg(not(feature = "std"))]
        let mut group_map = self.inner.lock();

        let state_data = state.mls_encode_to_vec()?;

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

        group_data.trim_epochs(self.max_epoch_retention);

        Ok(())
    }
}

#[cfg(all(test, feature = "prior_epoch"))]
mod tests {
    use alloc::{vec, vec::Vec};
    use assert_matches::assert_matches;

    use super::{InMemoryGroupData, InMemoryGroupStateStorage};
    use crate::{
        client::{test_utils::TEST_CIPHER_SUITE, MlsError},
        group::{
            epoch::{test_utils::get_test_epoch_with_id, PriorEpoch},
            snapshot::{test_utils::get_test_snapshot, Snapshot},
            test_utils::TEST_GROUP,
        },
        storage_provider::EpochData,
    };

    use mls_rs_codec::MlsEncode;
    use mls_rs_core::group::GroupStateStorage;

    impl InMemoryGroupStateStorage {
        fn test_data(&self) -> InMemoryGroupData {
            #[cfg(feature = "std")]
            let storage = self.inner.lock().unwrap();
            #[cfg(not(feature = "std"))]
            let storage = self.inner.lock();

            storage.get(TEST_GROUP).unwrap().clone()
        }
    }

    fn test_storage(retention_limit: usize) -> Result<InMemoryGroupStateStorage, MlsError> {
        InMemoryGroupStateStorage::new().with_max_epoch_retention(retention_limit)
    }

    fn test_epoch(epoch_id: u64) -> PriorEpoch {
        get_test_epoch_with_id(Vec::new(), TEST_CIPHER_SUITE, epoch_id)
    }

    #[cfg_attr(not(mls_build_async), maybe_async::must_be_sync)]
    async fn test_snapshot(epoch_id: u64) -> Snapshot {
        get_test_snapshot(TEST_CIPHER_SUITE, epoch_id).await
    }

    #[test]
    fn test_zero_max_retention() {
        assert_matches!(test_storage(0), Err(MlsError::NonZeroRetentionRequired))
    }

    #[maybe_async::test(not(mls_build_async), async(mls_build_async, crate::futures_test))]
    async fn existing_storage_can_have_larger_epoch_count() {
        let mut storage = test_storage(2).unwrap();

        let epoch_inserts = vec![test_epoch(0), test_epoch(1)];

        storage
            .write(test_snapshot(1).await, epoch_inserts, Vec::new())
            .await
            .unwrap();

        assert_eq!(storage.test_data().epoch_data.len(), 2);

        storage.max_epoch_retention = 4;

        let epoch_inserts = vec![test_epoch(3), test_epoch(4)];

        storage
            .write(test_snapshot(1).await, epoch_inserts, Vec::new())
            .await
            .unwrap();

        assert_eq!(storage.test_data().epoch_data.len(), 4);
    }

    #[maybe_async::test(not(mls_build_async), async(mls_build_async, crate::futures_test))]
    async fn existing_storage_can_have_smaller_epoch_count() {
        let mut storage = test_storage(4).unwrap();

        let epoch_inserts = vec![test_epoch(0), test_epoch(1), test_epoch(3), test_epoch(4)];

        storage
            .write(test_snapshot(1).await, epoch_inserts, Vec::new())
            .await
            .unwrap();

        assert_eq!(storage.test_data().epoch_data.len(), 4);

        storage.max_epoch_retention = 2;

        let epoch_inserts = vec![test_epoch(5)];

        storage
            .write(test_snapshot(1).await, epoch_inserts, Vec::new())
            .await
            .unwrap();

        assert_eq!(storage.test_data().epoch_data.len(), 2);
    }

    #[maybe_async::test(not(mls_build_async), async(mls_build_async, crate::futures_test))]
    async fn epoch_insert_over_limit() {
        test_epoch_insert_over_limit(false).await
    }

    #[maybe_async::test(not(mls_build_async), async(mls_build_async, crate::futures_test))]
    async fn epoch_insert_over_limit_with_update() {
        test_epoch_insert_over_limit(true).await
    }

    #[cfg_attr(not(mls_build_async), maybe_async::must_be_sync)]
    async fn test_epoch_insert_over_limit(with_update: bool) {
        let mut storage = test_storage(1).unwrap();

        let mut epoch_inserts = vec![test_epoch(0), test_epoch(1)];
        let updates = with_update
            .then_some(vec![test_epoch(0)])
            .unwrap_or_default();
        let snapshot = test_snapshot(1).await;

        storage
            .write(snapshot.clone(), epoch_inserts.clone(), updates)
            .await
            .unwrap();

        let stored = storage.test_data();

        assert_eq!(stored.state_data, snapshot.mls_encode_to_vec().unwrap());
        assert_eq!(stored.epoch_data.len(), 1);

        let expected = EpochData::new(epoch_inserts.pop().unwrap()).unwrap();
        assert_eq!(stored.epoch_data[0], expected);
    }
}
