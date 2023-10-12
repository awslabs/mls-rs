// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// Copyright by contributors to this project.
// SPDX-License-Identifier: (Apache-2.0 OR MIT)

use std::sync::{Arc, Mutex};

use rusqlite::{params, Connection, OptionalExtension};

use crate::SqLiteDataStorageError;

#[derive(Debug, Clone)]
/// SQLite key-value storage for application specific data.
pub struct SqLiteApplicationStorage {
    connection: Arc<Mutex<Connection>>,
}

impl SqLiteApplicationStorage {
    pub(crate) fn new(connection: Connection) -> SqLiteApplicationStorage {
        SqLiteApplicationStorage {
            connection: Arc::new(Mutex::new(connection)),
        }
    }

    /// Insert `value` into storage indexed by `key`.
    ///
    /// If a value already exists for `key` it will be overwritten.
    pub fn insert(&self, key: Vec<u8>, value: Vec<u8>) -> Result<(), SqLiteDataStorageError> {
        let connection = self.connection.lock().unwrap();

        // Upsert into the database
        connection
            .execute(
                "INSERT INTO kvs (key, value) VALUES (?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                params![key, value],
            )
            .map(|_| ())
            .map_err(|e| SqLiteDataStorageError::SqlEngineError(e.into()))
    }

    /// Get a value from storage based on its `key`.
    pub fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, SqLiteDataStorageError> {
        let connection = self.connection.lock().unwrap();

        connection
            .query_row("SELECT value FROM kvs WHERE key = ?", params![key], |row| {
                row.get(0)
            })
            .optional()
            .map_err(|e| SqLiteDataStorageError::SqlEngineError(e.into()))
    }

    /// Delete a value from storage based on its `key`.
    pub fn delete(&self, key: &[u8]) -> Result<(), SqLiteDataStorageError> {
        let connection = self.connection.lock().unwrap();

        connection
            .execute("DELETE FROM kvs WHERE key = ?", params![key])
            .map(|_| ())
            .map_err(|e| SqLiteDataStorageError::SqlEngineError(e.into()))
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        connection_strategy::MemoryStrategy, test_utils::gen_rand_bytes, SqLiteDataStorageEngine,
    };

    use super::SqLiteApplicationStorage;

    fn test_kv() -> (Vec<u8>, Vec<u8>) {
        let key = gen_rand_bytes(32);
        let value = gen_rand_bytes(64);

        (key, value)
    }

    fn test_storage() -> SqLiteApplicationStorage {
        SqLiteDataStorageEngine::new(MemoryStrategy)
            .unwrap()
            .application_data_storage()
            .unwrap()
    }

    #[test]
    fn test_insert() {
        let (key, value) = test_kv();
        let storage = test_storage();

        storage.insert(key.clone(), value.clone()).unwrap();

        let from_storage = storage.get(&key).unwrap().unwrap();
        assert_eq!(from_storage, value);
    }

    #[test]
    fn test_insert_existing_overwrite() {
        let (key, value) = test_kv();
        let (_, new_value) = test_kv();

        let storage = test_storage();

        storage.insert(key.clone(), value).unwrap();
        storage.insert(key.clone(), new_value.clone()).unwrap();

        let from_storage = storage.get(&key).unwrap().unwrap();
        assert_eq!(from_storage, new_value);
    }

    #[test]
    fn test_delete() {
        let (key, value) = test_kv();
        let storage = test_storage();

        storage.insert(key.clone(), value).unwrap();
        storage.delete(&key).unwrap();

        assert!(storage.get(&key).unwrap().is_none());
    }
}
