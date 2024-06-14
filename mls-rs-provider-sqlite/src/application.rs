// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// Copyright by contributors to this project.
// SPDX-License-Identifier: (Apache-2.0 OR MIT)

use std::{
    borrow::Cow,
    fmt::{self, Debug},
    sync::{Arc, Mutex},
};

use rusqlite::{params, Connection, OptionalExtension};

use crate::SqLiteDataStorageError;

const INSERT_SQL: &str =
    "INSERT INTO kvs (key, value) VALUES (?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value";

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
    pub fn insert(&self, key: &str, value: &[u8]) -> Result<(), SqLiteDataStorageError> {
        let connection = self.connection.lock().unwrap();

        // Upsert into the database
        connection
            .execute(INSERT_SQL, params![key, value])
            .map(|_| ())
            .map_err(sql_engine_error)
    }

    /// Execute multiple [`SqLiteApplicationStorage::insert`] operations in a transaction.
    pub fn transact_insert(&self, items: Vec<Item>) -> Result<(), SqLiteDataStorageError> {
        let mut connection = self.connection.lock().unwrap();

        // Upsert into the database
        let tx = connection.transaction().map_err(sql_engine_error)?;

        items.into_iter().try_for_each(|item| {
            tx.execute(INSERT_SQL, params![item.key, item.value])
                .map_err(sql_engine_error)
                .map(|_| ())
        })?;

        tx.commit().map_err(sql_engine_error)?;

        Ok(())
    }

    /// Get a value from storage based on its `key`.
    pub fn get(&self, key: &str) -> Result<Option<Vec<u8>>, SqLiteDataStorageError> {
        let connection = self.connection.lock().unwrap();

        connection
            .query_row("SELECT value FROM kvs WHERE key = ?", params![key], |row| {
                row.get(0)
            })
            .optional()
            .map_err(sql_engine_error)
    }

    /// Delete a value from storage based on its `key`.
    pub fn delete(&self, key: &str) -> Result<(), SqLiteDataStorageError> {
        let connection = self.connection.lock().unwrap();

        connection
            .execute("DELETE FROM kvs WHERE key = ?", params![key])
            .map(|_| ())
            .map_err(sql_engine_error)
    }

    /// Get all keys and values from storage for which key starts with `key_prefix`.
    pub fn get_by_prefix(
        &self,
        key_prefix: &str,
    ) -> Result<Vec<Item<'static>>, SqLiteDataStorageError> {
        let connection = self.connection.lock().unwrap();
        let mut key_prefix = sanitize(key_prefix);
        key_prefix.push('%');

        let mut stmt = connection
            .prepare("SELECT key, value FROM kvs WHERE key LIKE ? ESCAPE '$'")
            .map_err(sql_engine_error)?;

        let rows = stmt
            .query(params![key_prefix])
            .map_err(sql_engine_error)?
            .mapped(|row| {
                Ok(Item {
                    key: Cow::Owned(row.get(0)?),
                    value: Cow::Owned(row.get(1)?),
                })
            });

        rows.collect::<Result<_, _>>().map_err(sql_engine_error)
    }

    /// Delete all values from storage for which key starts with `key_prefix`.
    pub fn delete_by_prefix(&self, key_prefix: &str) -> Result<(), SqLiteDataStorageError> {
        let connection = self.connection.lock().unwrap();
        let mut key_prefix = sanitize(key_prefix);
        key_prefix.push('%');

        connection
            .execute(
                "DELETE FROM kvs WHERE key LIKE ? ESCAPE '$'",
                params![key_prefix],
            )
            .map(|_| ())
            .map_err(sql_engine_error)
    }
}

fn sanitize(string: &str) -> String {
    string.replace('_', "$_").replace('%', "$%")
}

fn sql_engine_error(e: rusqlite::Error) -> SqLiteDataStorageError {
    SqLiteDataStorageError::SqlEngineError(e.into())
}

#[derive(Clone, Default, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub struct Item<'a> {
    pub key: Cow<'a, str>,
    pub value: Cow<'a, [u8]>,
}

impl<'a> Debug for Item<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Item")
            .field("key", &self.key)
            .field("value", &"***".to_string())
            .finish()
    }
}

impl<'a> Item<'a> {
    pub fn new(key: &'a str, value: &'a [u8]) -> Self {
        Self {
            key: Cow::Borrowed(key),
            value: Cow::Borrowed(value),
        }
    }

    pub fn key(&self) -> &str {
        &self.key
    }

    pub fn value(&self) -> &[u8] {
        &self.value
    }
}

#[cfg(test)]
mod tests {
    use std::borrow::Cow;

    use crate::{
        application::Item, connection_strategy::MemoryStrategy, test_utils::gen_rand_bytes,
        SqLiteDataStorageEngine,
    };

    use super::SqLiteApplicationStorage;

    fn test_kv() -> (String, Vec<u8>) {
        let key = hex::encode(gen_rand_bytes(32));
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

        storage.insert(&key, &value).unwrap();

        let from_storage = storage.get(&key).unwrap().unwrap();
        assert_eq!(from_storage, value);
    }

    #[test]
    fn test_insert_existing_overwrite() {
        let (key, value) = test_kv();
        let (_, new_value) = test_kv();

        let storage = test_storage();

        storage.insert(&key, &value).unwrap();
        storage.insert(&key, &new_value).unwrap();

        let from_storage = storage.get(&key).unwrap().unwrap();
        assert_eq!(from_storage, new_value);
    }

    #[test]
    fn test_delete() {
        let (key, value) = test_kv();
        let storage = test_storage();

        storage.insert(&key, &value).unwrap();
        storage.delete(&key).unwrap();

        assert!(storage.get(&key).unwrap().is_none());
    }

    #[test]
    fn test_by_prefix() {
        let keys = ["prefix one", "prefix two", "prefiy ", "prefiw "].map(ToString::to_string);
        let value = gen_rand_bytes(5);

        let storage = test_storage();

        keys.iter()
            .for_each(|k| storage.insert(&k, &value).unwrap());

        let mut expected = vec![Item::new(&keys[0], &value), Item::new(&keys[1], &value)];

        expected.sort();

        let mut result = storage.get_by_prefix("prefix").unwrap();
        result.sort();

        assert_eq!(result, expected);

        let result = storage.get_by_prefix("a").unwrap();
        assert!(result.is_empty());

        let result = storage.get_by_prefix("").unwrap();
        assert_eq!(result.len(), keys.len());

        storage.delete_by_prefix("prefix").unwrap();
        let result = storage.get_by_prefix("").unwrap();
        assert_eq!(result.len(), 2);
        assert!(result.contains(&Item::new("prefiy ", &value)));
        assert!(result.contains(&Item::new("prefiw ", &value)));
    }

    #[test]
    fn test_special_characters() {
        let storage = test_storage();

        storage.insert("%$_ƕ❤_$%", &gen_rand_bytes(5)).unwrap();
        storage.insert("%$_ƕ❤a$%", &gen_rand_bytes(5)).unwrap();
        storage.insert("%$_ƕ❤Ḉ$%", &gen_rand_bytes(5)).unwrap();

        let items = storage.get_by_prefix("%$_ƕ❤_").unwrap();
        let keys = items.into_iter().map(|i| i.key).collect::<Vec<_>>();
        assert_eq!(vec!["%$_ƕ❤_$%".to_string()], keys);
    }

    #[test]
    fn batch_insert() {
        let storage = test_storage();
        let items = vec![test_item(), test_item(), test_item()];

        storage.transact_insert(items.clone()).unwrap();

        for item in items {
            assert_eq!(
                storage.get(&item.key).unwrap(),
                Some(item.value.into_owned())
            );
        }
    }

    fn test_item() -> Item<'static> {
        Item {
            key: Cow::Owned(hex::encode(gen_rand_bytes(5))),
            value: Cow::Owned(gen_rand_bytes(5)),
        }
    }
}
