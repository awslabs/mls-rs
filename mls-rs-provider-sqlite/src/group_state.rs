// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// Copyright by contributors to this project.
// SPDX-License-Identifier: (Apache-2.0 OR MIT)

use mls_rs_core::{
    group::{EpochRecord, GroupState, GroupStateStorage},
    mls_rs_codec::{MlsDecode, MlsEncode},
};
use rusqlite::{params, Connection, OptionalExtension};
use std::sync::{Arc, Mutex};

use crate::SqLiteDataStorageError;

pub(crate) const DEFAULT_EPOCH_RETENTION_LIMIT: u64 = 3;

#[derive(Debug, Clone)]
struct StoredEpoch {
    data: Vec<u8>,
    id: u64,
}

impl StoredEpoch {
    fn new(id: u64, data: Vec<u8>) -> Self {
        Self { id, data }
    }
}

#[derive(Debug, Clone)]
/// SQLite Storage for MLS group states.
pub struct SqLiteGroupStateStorage {
    connection: Arc<Mutex<Connection>>,
    max_epoch_retention: u64,
}

impl SqLiteGroupStateStorage {
    pub(crate) fn new(connection: Connection) -> SqLiteGroupStateStorage {
        SqLiteGroupStateStorage {
            connection: Arc::new(Mutex::new(connection)),
            max_epoch_retention: DEFAULT_EPOCH_RETENTION_LIMIT,
        }
    }

    pub fn with_max_epoch_retention(self, max_epoch_retention: u64) -> Self {
        Self {
            connection: self.connection,
            max_epoch_retention,
        }
    }

    /// List all the group ids for groups that are stored.
    pub fn group_ids(&self) -> Result<Vec<Vec<u8>>, SqLiteDataStorageError> {
        let connection = self.connection.lock().unwrap();

        let mut statement = connection
            .prepare("SELECT group_id FROM mls_group")
            .map_err(|e| SqLiteDataStorageError::SqlEngineError(e.into()))?;

        let res = statement
            .query_map([], |row| row.get(0))
            .map_err(|e| SqLiteDataStorageError::SqlEngineError(e.into()))?
            .try_fold(Vec::new(), |mut ids, id| {
                ids.push(id.map_err(|e| SqLiteDataStorageError::DataConversionError(e.into()))?);
                Ok::<_, SqLiteDataStorageError>(ids)
            })
            .map_err(|e| SqLiteDataStorageError::SqlEngineError(e.into()))?;

        Ok(res)
    }

    /// Delete a group from storage.
    pub fn delete_group(&self, group_id: &[u8]) -> Result<(), SqLiteDataStorageError> {
        let connection = self.connection.lock().unwrap();

        connection
            .execute(
                "DELETE FROM mls_group WHERE group_id = ?",
                params![group_id],
            )
            .map(|_| ())
            .map_err(|e| SqLiteDataStorageError::SqlEngineError(e.into()))
    }

    pub fn max_epoch_retention(&self) -> u64 {
        self.max_epoch_retention
    }

    fn get_snapshot_data(
        &self,
        group_id: &[u8],
    ) -> Result<Option<Vec<u8>>, SqLiteDataStorageError> {
        let connection = self.connection.lock().unwrap();

        connection
            .query_row(
                "SELECT snapshot FROM mls_group where group_id = ?",
                [group_id],
                |row| row.get::<_, Vec<u8>>(0),
            )
            .optional()
            .map_err(|e| SqLiteDataStorageError::SqlEngineError(e.into()))
    }

    fn get_epoch_data(
        &self,
        group_id: &[u8],
        epoch_id: u64,
    ) -> Result<Option<Vec<u8>>, SqLiteDataStorageError> {
        let connection = self.connection.lock().unwrap();

        connection
            .query_row(
                "SELECT epoch_data FROM epoch where group_id = ? AND epoch_id = ?",
                params![group_id, epoch_id],
                |row| row.get::<_, Vec<u8>>(0),
            )
            .optional()
            .map_err(|e| SqLiteDataStorageError::SqlEngineError(e.into()))
    }

    fn max_epoch_id(&self, group_id: &[u8]) -> Result<Option<u64>, SqLiteDataStorageError> {
        let connection = self.connection.lock().unwrap();

        connection
            .query_row(
                "SELECT MAX(epoch_id) FROM epoch WHERE group_id = ?",
                params![group_id],
                |row| row.get::<_, Option<u64>>(0),
            )
            .map_err(|e| SqLiteDataStorageError::SqlEngineError(e.into()))
    }

    fn update_group_state<I, U>(
        &self,
        group_id: &[u8],
        group_snapshot: Vec<u8>,
        inserts: I,
        mut updates: U,
    ) -> Result<(), SqLiteDataStorageError>
    where
        I: Iterator<Item = Result<StoredEpoch, SqLiteDataStorageError>>,
        U: Iterator<Item = Result<StoredEpoch, SqLiteDataStorageError>>,
    {
        let mut max_epoch_id = None;

        let mut connection = self.connection.lock().unwrap();
        let transaction = connection
            .transaction()
            .map_err(|e| SqLiteDataStorageError::SqlEngineError(e.into()))?;

        // Upsert into the group table to set the most recent snapshot
        transaction.execute(
            "INSERT INTO mls_group (group_id, snapshot) VALUES (?, ?) ON CONFLICT(group_id) DO UPDATE SET snapshot=excluded.snapshot",
            params![group_id, group_snapshot],
        ).map_err(|e| SqLiteDataStorageError::SqlEngineError(e.into()))?;

        // Insert new epochs as needed
        for epoch in inserts {
            let epoch = epoch.map_err(|e| SqLiteDataStorageError::SqlEngineError(e.into()))?;
            max_epoch_id = Some(epoch.id);

            transaction
                .execute(
                    "INSERT INTO epoch (group_id, epoch_id, epoch_data) VALUES (?, ?, ?)",
                    params![group_id, epoch.id, epoch.data],
                )
                .map(|_| ())
                .map_err(|e| SqLiteDataStorageError::SqlEngineError(e.into()))?;
        }

        // Update existing epochs as needed
        updates.try_for_each(|epoch| {
            let epoch = epoch.map_err(|e| SqLiteDataStorageError::SqlEngineError(e.into()))?;

            transaction
                .execute(
                    "UPDATE epoch SET epoch_data = ? WHERE group_id = ? AND epoch_id = ?",
                    params![epoch.data, group_id, epoch.id],
                )
                .map(|_| ())
                .map_err(|e| SqLiteDataStorageError::SqlEngineError(e.into()))
        })?;

        // Delete old epochs as needed
        if let Some(max_epoch_id) = max_epoch_id {
            if max_epoch_id >= self.max_epoch_retention {
                let delete_under = max_epoch_id - self.max_epoch_retention;

                transaction
                    .execute(
                        "DELETE FROM epoch WHERE group_id = ? AND epoch_id <= ?",
                        params![group_id, delete_under],
                    )
                    .map_err(|e| SqLiteDataStorageError::SqlEngineError(e.into()))?;
            }
        }

        // Execute the full transaction
        transaction
            .commit()
            .map_err(|e| SqLiteDataStorageError::SqlEngineError(e.into()))
    }
}

#[cfg_attr(not(mls_build_async), maybe_async::must_be_sync)]
#[cfg_attr(mls_build_async, maybe_async::must_be_async)]
impl GroupStateStorage for SqLiteGroupStateStorage {
    type Error = SqLiteDataStorageError;

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
        let group_id = state.id();

        let snapshot_data = state
            .mls_encode_to_vec()
            .map_err(|e| SqLiteDataStorageError::DataConversionError(e.into()))?;

        let inserts = epoch_inserts.iter().map(|e| {
            Ok(StoredEpoch::new(
                e.id(),
                e.mls_encode_to_vec()
                    .map_err(|e| SqLiteDataStorageError::DataConversionError(e.into()))?,
            ))
        });

        let updates = epoch_updates.iter().map(|e| {
            Ok(StoredEpoch::new(
                e.id(),
                e.mls_encode_to_vec()
                    .map_err(|err| SqLiteDataStorageError::DataConversionError(err.into()))?,
            ))
        });

        self.update_group_state(group_id.as_slice(), snapshot_data, inserts, updates)
    }

    async fn state<T>(&self, group_id: &[u8]) -> Result<Option<T>, Self::Error>
    where
        T: GroupState + MlsEncode + MlsDecode,
    {
        self.get_snapshot_data(group_id)?
            .map(|v| T::mls_decode(&mut v.as_slice()))
            .transpose()
            .map_err(|e| SqLiteDataStorageError::DataConversionError(e.into()))
    }

    async fn max_epoch_id(&self, group_id: &[u8]) -> Result<Option<u64>, Self::Error> {
        self.max_epoch_id(group_id)
    }

    async fn epoch<T>(&self, group_id: &[u8], epoch_id: u64) -> Result<Option<T>, Self::Error>
    where
        T: EpochRecord + MlsEncode + MlsDecode,
    {
        self.get_epoch_data(group_id, epoch_id)?
            .map(|v| T::mls_decode(&mut v.as_slice()))
            .transpose()
            .map_err(|e| SqLiteDataStorageError::DataConversionError(e.into()))
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        SqLiteDataStorageEngine,
        {connection_strategy::MemoryStrategy, test_utils::gen_rand_bytes},
    };

    use super::*;

    fn get_test_storage() -> SqLiteGroupStateStorage {
        SqLiteDataStorageEngine::new(MemoryStrategy)
            .unwrap()
            .group_state_storage()
            .unwrap()
    }

    fn test_group_id() -> Vec<u8> {
        gen_rand_bytes(32)
    }

    fn test_snapshot() -> Vec<u8> {
        gen_rand_bytes(1024)
    }

    fn test_epoch(id: u64) -> StoredEpoch {
        StoredEpoch {
            data: gen_rand_bytes(256),
            id,
        }
    }

    struct TestData {
        storage: SqLiteGroupStateStorage,
        snapshot: Vec<u8>,
        group_id: Vec<u8>,
        epoch_0: StoredEpoch,
    }

    fn setup_group_storage_test() -> TestData {
        let test_storage = get_test_storage();
        let test_group_id = test_group_id();
        let test_epoch_0 = test_epoch(0);
        let test_snapshot = test_snapshot();

        test_storage
            .update_group_state(
                &test_group_id,
                test_snapshot.clone(),
                vec![test_epoch_0.clone()].into_iter().map(Ok),
                vec![].into_iter(),
            )
            .unwrap();

        TestData {
            storage: test_storage,
            group_id: test_group_id,
            epoch_0: test_epoch_0,
            snapshot: test_snapshot,
        }
    }

    #[test]
    fn group_can_be_initially_stored() {
        let test_data = setup_group_storage_test();

        // Attempt to fetch the snapshot
        let snapshot = test_data
            .storage
            .get_snapshot_data(&test_data.group_id)
            .unwrap();
        assert_eq!(snapshot.unwrap(), test_data.snapshot);

        // Attempt to fetch the epoch data
        let epoch = test_data
            .storage
            .get_epoch_data(&test_data.group_id, 0)
            .unwrap();
        assert_eq!(epoch.unwrap(), test_data.epoch_0.data);
    }

    #[test]
    fn snapshot_and_epoch_can_be_updated() {
        let test_data = setup_group_storage_test();
        let test_snapshot = test_snapshot();

        let epoch_update = test_epoch(0);

        test_data
            .storage
            .update_group_state(
                &test_data.group_id,
                test_snapshot.clone(),
                vec![].into_iter(),
                vec![Ok(epoch_update.clone())].into_iter(),
            )
            .unwrap();

        // Attempt to fetch the new snapshot
        let snapshot = test_data
            .storage
            .get_snapshot_data(&test_data.group_id)
            .unwrap();

        assert_eq!(snapshot.unwrap(), test_snapshot);

        // Attempt to access the epochs
        assert_eq!(
            test_data
                .storage
                .get_epoch_data(&test_data.group_id, 0)
                .unwrap()
                .unwrap(),
            epoch_update.data
        );
    }

    #[test]
    fn epochs_are_truncated() {
        test_epochs_are_truncated(9);
        test_epochs_are_truncated(DEFAULT_EPOCH_RETENTION_LIMIT);
    }

    fn test_epochs_are_truncated(n: u64) {
        let test_data = setup_group_storage_test();

        let mut test_epochs = (1..n + 1).map(test_epoch).collect::<Vec<_>>();

        test_data
            .storage
            .update_group_state(
                &test_data.group_id,
                test_snapshot(),
                test_epochs.clone().into_iter().map(Ok),
                vec![].into_iter(),
            )
            .unwrap();

        test_epochs.insert(0, test_data.epoch_0);

        for epoch in test_epochs {
            let stored = test_data
                .storage
                .get_epoch_data(&test_data.group_id, epoch.id)
                .unwrap();

            if epoch.id <= n - DEFAULT_EPOCH_RETENTION_LIMIT {
                assert!(stored.is_none());
            } else {
                assert_eq!(stored.unwrap(), epoch.data);
            }
        }
    }

    #[test]
    fn epoch_insert_update_old_epoch() {
        let test_data = setup_group_storage_test();

        test_data
            .storage
            .update_group_state(
                &test_data.group_id,
                test_snapshot(),
                vec![test_epoch(1)].into_iter().map(Ok),
                vec![].into_iter(),
            )
            .unwrap();

        let test_epochs = (2..10).map(test_epoch).collect::<Vec<_>>();
        let new_epoch_1 = test_epoch(1);

        test_data
            .storage
            .update_group_state(
                &test_data.group_id,
                test_snapshot(),
                test_epochs.clone().into_iter().map(Ok),
                vec![Ok(new_epoch_1.clone())].into_iter(),
            )
            .unwrap();

        assert!(test_data
            .storage
            .get_epoch_data(&test_data.group_id, 1)
            .unwrap()
            .is_none());
    }

    #[test]
    fn max_epoch_is_none_for_non_persisted_group() {
        let storage = get_test_storage();

        let res = storage.max_epoch_id(&[0, 1, 2]).unwrap();

        assert!(res.is_none())
    }

    #[test]
    fn max_epoch_is_none_when_no_epochs() {
        let storage = get_test_storage();
        let group_id = b"test";

        storage
            .update_group_state(
                group_id,
                vec![0, 1, 2],
                vec![].into_iter(),
                vec![].into_iter().map(Ok),
            )
            .unwrap();

        let res = storage.max_epoch_id(group_id).unwrap();

        assert!(res.is_none())
    }

    #[test]
    fn max_epoch_can_be_calculated() {
        let test_data = setup_group_storage_test();

        test_data
            .storage
            .update_group_state(
                &test_data.group_id,
                test_snapshot(),
                (1..10).map(test_epoch).map(Ok),
                vec![].into_iter().map(Ok),
            )
            .unwrap();

        assert_eq!(
            test_data
                .storage
                .max_epoch_id(&test_data.group_id)
                .unwrap()
                .unwrap(),
            9
        );
    }

    #[test]
    fn muiltiple_groups_can_exist() {
        let test_data = setup_group_storage_test();

        let new_group = test_group_id();
        let new_group_epoch = test_epoch(0);

        test_data
            .storage
            .update_group_state(
                &new_group,
                test_snapshot(),
                vec![new_group_epoch.clone()].into_iter().map(Ok),
                vec![].into_iter(),
            )
            .unwrap();

        let all_groups = test_data.storage.group_ids().unwrap();

        // Order is not deterministic
        vec![test_data.group_id.clone(), new_group.clone()]
            .into_iter()
            .for_each(|id| {
                assert!(all_groups.contains(&id));
            });

        assert_eq!(
            test_data
                .storage
                .get_epoch_data(&new_group, 0)
                .unwrap()
                .unwrap(),
            new_group_epoch.data
        );
    }

    #[test]
    fn delete_group() {
        let test_data = setup_group_storage_test();

        test_data.storage.delete_group(&test_data.group_id).unwrap();

        assert!(test_data.storage.group_ids().unwrap().is_empty());
    }
}
