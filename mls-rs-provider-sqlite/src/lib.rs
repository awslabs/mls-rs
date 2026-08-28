// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// Copyright by contributors to this project.
// SPDX-License-Identifier: (Apache-2.0 OR MIT)

use connection_strategy::ConnectionStrategy;
use group_state::SqLiteGroupStateStorage;
use psk::SqLitePreSharedKeyStorage;
use rusqlite::Connection;
use std::sync::{Arc, Mutex};
use storage::{SqLiteApplicationStorage, SqLiteKeyPackageStorage};
use thiserror::Error;

/// A connection shared by every storage handed out by one engine.
pub(crate) type SharedConnection = Arc<Mutex<Connection>>;

mod application;
mod group_state;
mod key_package;
mod psk;

#[cfg(any(feature = "sqlcipher", feature = "sqlcipher-bundled"))]
mod cipher;

#[cfg(test)]
pub(crate) mod test_utils;

/// Connection strategies.
pub mod connection_strategy;

/// SQLite storage components.
pub mod storage {
    pub use {
        crate::application::{Item, SqLiteApplicationStorage},
        crate::group_state::SqLiteGroupStateStorage,
        crate::key_package::SqLiteKeyPackageStorage,
        crate::psk::SqLitePreSharedKeyStorage,
    };
}

#[derive(Debug, Error)]
/// SQLite data storage error.
pub enum SqLiteDataStorageError {
    #[error(transparent)]
    /// SQLite error.
    SqlEngineError(Box<dyn std::error::Error + Send + Sync + 'static>),
    #[error(transparent)]
    /// Stored data is not compatible with the expected data type.
    DataConversionError(Box<dyn std::error::Error + Send + Sync + 'static>),
    #[error("epoch ID {0} exceeds maximum supported value (i64::MAX)")]
    /// Epoch ID is too large to store in SQLite.
    ///
    /// SQLite uses signed 64-bit integers, limiting epoch IDs to values up to 9,223,372,036,854,775,807.
    EpochIdOverflow(u64),
    #[error("timestamp {0} exceeds maximum supported value (i64::MAX)")]
    /// Timestamp is too large to store in SQLite.
    ///
    /// SQLite uses signed 64-bit integers, limiting timestamps to values up to 9,223,372,036,854,775,807.
    TimestampOverflow(u64),
    #[cfg(any(feature = "sqlcipher", feature = "sqlcipher-bundled"))]
    #[error("invalid key, must use SqlCipherKey::RawKeyWithSalt with plaintext_header_size > 0")]
    /// Invalid SQLCipher key header.
    SqlCipherKeyInvalidWithHeader,
}

impl mls_rs_core::error::IntoAnyError for SqLiteDataStorageError {
    fn into_dyn_error(self) -> Result<Box<dyn std::error::Error + Send + Sync>, Self> {
        Ok(self.into())
    }
}

#[derive(Clone, Debug, PartialEq)]
/// Value assigned to a SQLite pragma.
pub enum PragmaValue {
    /// Textual value, e.g. `WAL` for `journal_mode`.
    Text(String),
    /// Integer value, e.g. `5000` for `busy_timeout`.
    Integer(i64),
    /// Floating point value.
    Real(f64),
}

impl From<&str> for PragmaValue {
    fn from(value: &str) -> Self {
        PragmaValue::Text(value.to_string())
    }
}

impl From<String> for PragmaValue {
    fn from(value: String) -> Self {
        PragmaValue::Text(value)
    }
}

impl From<i64> for PragmaValue {
    fn from(value: i64) -> Self {
        PragmaValue::Integer(value)
    }
}

impl From<i32> for PragmaValue {
    fn from(value: i32) -> Self {
        PragmaValue::Integer(value.into())
    }
}

impl From<u32> for PragmaValue {
    fn from(value: u32) -> Self {
        PragmaValue::Integer(value.into())
    }
}

impl From<bool> for PragmaValue {
    fn from(value: bool) -> Self {
        PragmaValue::Integer(value.into())
    }
}

impl From<f64> for PragmaValue {
    fn from(value: f64) -> Self {
        PragmaValue::Real(value)
    }
}

impl From<JournalMode> for PragmaValue {
    fn from(value: JournalMode) -> Self {
        PragmaValue::Text(value.as_str().to_string())
    }
}

impl rusqlite::ToSql for PragmaValue {
    fn to_sql(&self) -> rusqlite::Result<rusqlite::types::ToSqlOutput<'_>> {
        match self {
            PragmaValue::Text(value) => value.to_sql(),
            PragmaValue::Integer(value) => value.to_sql(),
            PragmaValue::Real(value) => value.to_sql(),
        }
    }
}

#[derive(Clone, Debug)]
pub enum JournalMode {
    Delete,
    Truncate,
    Persist,
    Memory,
    Wal,
    Off,
}

/// Note: for in-memory dbs (such as what the tests use), the only available options are MEMORY or OFF
/// Invalid modes do not error, only no-op
impl JournalMode {
    fn as_str(&self) -> &'static str {
        match self {
            JournalMode::Delete => "DELETE",
            JournalMode::Truncate => "TRUNCATE",
            JournalMode::Persist => "PERSIST",
            JournalMode::Memory => "MEMORY",
            JournalMode::Wal => "WAL",
            JournalMode::Off => "OFF",
        }
    }
}

#[derive(Clone, Debug)]
/// Builder for [`SqLiteDataStorageEngine`].
///
/// Collects the connection strategy and pragmas, then opens the single
/// connection the engine hands to all of its storages.
pub struct SqLiteDataStorageEngineBuilder<CS>
where
    CS: ConnectionStrategy,
{
    connection_strategy: CS,
    pragmas: Vec<(String, PragmaValue)>,
}

impl<CS> SqLiteDataStorageEngineBuilder<CS>
where
    CS: ConnectionStrategy,
{
    pub fn new(connection_strategy: CS) -> SqLiteDataStorageEngineBuilder<CS> {
        SqLiteDataStorageEngineBuilder {
            connection_strategy,
            pragmas: Vec::new(),
        }
    }

    /// Set a pragma to apply to the connection.
    ///
    /// Pragmas are applied in the order they are added, before the schema is
    /// created, so ordering-sensitive pragmas can be sequenced as needed.
    /// Adding the same pragma name twice keeps both entries, meaning the last
    /// one wins at connection time.
    pub fn with_pragma<V: Into<PragmaValue>>(mut self, name: &str, value: V) -> Self {
        self.pragmas.push((name.to_string(), value.into()));
        self
    }

    /// Set several pragmas at once, applied in iteration order after any
    /// pragmas already added.
    pub fn with_pragmas<N, V, I>(mut self, pragmas: I) -> Self
    where
        N: AsRef<str>,
        V: Into<PragmaValue>,
        I: IntoIterator<Item = (N, V)>,
    {
        self.pragmas.extend(
            pragmas
                .into_iter()
                .map(|(name, value)| (name.as_ref().to_string(), value.into())),
        );

        self
    }

    /// Pragmas applied to the connection, in application order.
    pub fn pragmas(&self) -> &[(String, PragmaValue)] {
        &self.pragmas
    }

    /// A `journal_mode` of `None` means the SQLite default is used.
    ///
    /// Convenience wrapper over [`with_pragma`](Self::with_pragma) that
    /// replaces any previously set `journal_mode`, keeping its position in the
    /// pragma order.
    pub fn with_journal_mode(mut self, journal_mode: Option<JournalMode>) -> Self {
        let existing = self
            .pragmas
            .iter()
            .position(|(name, _)| name.eq_ignore_ascii_case("journal_mode"));

        match (existing, journal_mode) {
            (Some(index), Some(mode)) => self.pragmas[index].1 = mode.into(),
            (Some(index), None) => {
                self.pragmas.remove(index);
            }
            (None, Some(mode)) => self.pragmas.push(("journal_mode".to_string(), mode.into())),
            (None, None) => (),
        }

        self
    }

    fn create_connection(&self) -> Result<Connection, SqLiteDataStorageError> {
        let connection = self.connection_strategy.make_connection()?;

        for (name, value) in &self.pragmas {
            connection
                .pragma_update(None, name, value)
                .map_err(|e| SqLiteDataStorageError::SqlEngineError(e.into()))?;
        }

        // Run SQL to establish the schema
        let current_schema = connection
            .pragma_query_value(None, "user_version", |rows| rows.get::<_, u32>(0))
            .map_err(|e| SqLiteDataStorageError::SqlEngineError(e.into()))?;

        if current_schema < 1 {
            create_tables_v1(&connection)?;
        }

        Ok(connection)
    }

    /// Opens the connection and applies the configured pragmas, creating the
    /// schema if the database is new.
    pub fn build(self) -> Result<SqLiteDataStorageEngine, SqLiteDataStorageError> {
        Ok(SqLiteDataStorageEngine {
            connection: Arc::new(Mutex::new(self.create_connection()?)),
        })
    }
}

#[derive(Clone, Debug)]
/// SQLite data storage engine.
///
/// All storages returned by one engine share the single connection opened by
/// [`SqLiteDataStorageEngineBuilder::build`], so the database file is only
/// opened once. This is what keeps the engine usable with
/// `locking_mode = EXCLUSIVE`, which a second connection to the same file would
/// otherwise fail against with `SQLITE_BUSY`.
pub struct SqLiteDataStorageEngine {
    connection: SharedConnection,
}

impl SqLiteDataStorageEngine {
    pub fn new<CS: ConnectionStrategy>(
        connection_strategy: CS,
    ) -> Result<Self, SqLiteDataStorageError> {
        Self::builder(connection_strategy).build()
    }

    /// Start configuring an engine that connects using `connection_strategy`.
    pub fn builder<CS: ConnectionStrategy>(
        connection_strategy: CS,
    ) -> SqLiteDataStorageEngineBuilder<CS> {
        SqLiteDataStorageEngineBuilder::new(connection_strategy)
    }

    /// Returns a struct that implements the `GroupStateStorage` trait for use in MLS.
    pub fn group_state_storage(&self) -> Result<SqLiteGroupStateStorage, SqLiteDataStorageError> {
        Ok(SqLiteGroupStateStorage::new(self.connection.clone()))
    }

    /// Returns a struct that implements the `KeyPackageStorage` trait for use in MLS.
    pub fn key_package_storage(&self) -> Result<SqLiteKeyPackageStorage, SqLiteDataStorageError> {
        Ok(SqLiteKeyPackageStorage::new(self.connection.clone()))
    }

    /// Returns a struct that implements the `PreSharedKeyStorage` trait for use in MLS.
    pub fn pre_shared_key_storage(
        &self,
    ) -> Result<SqLitePreSharedKeyStorage, SqLiteDataStorageError> {
        Ok(SqLitePreSharedKeyStorage::new(self.connection.clone()))
    }

    /// Returns a key value store that can be used to store application specific data.
    pub fn application_data_storage(
        &self,
    ) -> Result<SqLiteApplicationStorage, SqLiteDataStorageError> {
        Ok(SqLiteApplicationStorage::new(self.connection.clone()))
    }
}

fn create_tables_v1(connection: &Connection) -> Result<(), SqLiteDataStorageError> {
    connection
        .execute_batch(
            "BEGIN;
            CREATE TABLE mls_group (
                group_id BLOB PRIMARY KEY,
                snapshot BLOB NOT NULL
            ) WITHOUT ROWID;
            CREATE TABLE epoch (
                group_id BLOB,
                epoch_id INTEGER,
                epoch_data BLOB NOT NULL,
                FOREIGN KEY (group_id) REFERENCES mls_group (group_id) ON DELETE CASCADE
                PRIMARY KEY (group_id, epoch_id)
            ) WITHOUT ROWID;
            CREATE TABLE key_package (
                id BLOB PRIMARY KEY,
                expiration INTEGER,
                data BLOB NOT NULL
            ) WITHOUT ROWID;
            CREATE INDEX key_package_exp ON key_package (expiration);
            CREATE TABLE psk (
                psk_id BLOB PRIMARY KEY,
                data BLOB NOT NULL
            ) WITHOUT ROWID;
            CREATE TABLE kvs (
                key TEXT PRIMARY KEY,
                value BLOB NOT NULL
            ) WITHOUT ROWID;
            PRAGMA user_version = 1;
            COMMIT;",
        )
        .map_err(|e| SqLiteDataStorageError::SqlEngineError(e.into()))
}

#[cfg(test)]
mod tests {
    use tempfile::tempdir;

    use crate::{
        connection_strategy::{FileConnectionStrategy, MemoryStrategy},
        SqLiteDataStorageEngine,
    };

    #[test]
    pub fn user_version_test() {
        let database = SqLiteDataStorageEngine::builder(MemoryStrategy);

        let _connection = database.create_connection().unwrap();

        // Create another connection to make sure the migration doesn't try to happen again.
        let connection = database.create_connection().unwrap();

        // Run SQL to establish the schema
        let current_schema = connection
            .pragma_query_value(None, "user_version", |rows| rows.get::<_, u32>(0))
            .unwrap();

        assert_eq!(current_schema, 1);
    }

    #[test]
    pub fn journal_mode_test() {
        let temp = tempdir().unwrap();

        // Connect with journal_mode other than the default of MEMORY
        let database = SqLiteDataStorageEngine::builder(FileConnectionStrategy::new(
            &temp.path().join("test_db.sqlite"),
        ));

        let connection = database
            .with_journal_mode(Some(crate::JournalMode::Truncate))
            .create_connection()
            .unwrap();

        let journal_mode = connection
            .pragma_query_value(None, "journal_mode", |rows| rows.get::<_, String>(0))
            .unwrap();

        assert_eq!(journal_mode, "truncate");
    }

    #[test]
    pub fn arbitrary_pragmas_applied_in_order() {
        let temp = tempdir().unwrap();

        let database = SqLiteDataStorageEngine::builder(FileConnectionStrategy::new(
            &temp.path().join("pragma_db.sqlite"),
        ))
        .with_pragma("busy_timeout", 4321)
        // Last write of a repeated pragma wins, proving order is preserved.
        .with_pragma("journal_mode", crate::JournalMode::Memory)
        .with_pragmas([("journal_mode", crate::JournalMode::Truncate)]);

        assert_eq!(
            database
                .pragmas()
                .iter()
                .map(|(name, _)| name.as_str())
                .collect::<Vec<_>>(),
            ["busy_timeout", "journal_mode", "journal_mode"]
        );

        let connection = database.create_connection().unwrap();

        assert_eq!(
            connection
                .pragma_query_value(None, "busy_timeout", |rows| rows.get::<_, i64>(0))
                .unwrap(),
            4321
        );

        assert_eq!(
            connection
                .pragma_query_value(None, "journal_mode", |rows| rows.get::<_, String>(0))
                .unwrap(),
            "truncate"
        );
    }

    #[test]
    pub fn journal_mode_replaces_existing_pragma() {
        let database = SqLiteDataStorageEngine::builder(MemoryStrategy)
            .with_journal_mode(Some(crate::JournalMode::Wal))
            .with_pragma("busy_timeout", 1000)
            .with_journal_mode(Some(crate::JournalMode::Memory));

        assert_eq!(
            database
                .pragmas()
                .iter()
                .map(|(name, value)| (name.as_str(), value.clone()))
                .collect::<Vec<_>>(),
            [
                (
                    "journal_mode",
                    crate::PragmaValue::Text("MEMORY".to_string())
                ),
                ("busy_timeout", crate::PragmaValue::Integer(1000)),
            ]
        );

        let database = database.with_journal_mode(None);

        assert_eq!(
            database.pragmas(),
            [(
                "busy_timeout".to_string(),
                crate::PragmaValue::Integer(1000)
            )]
        );
    }

    #[test]
    pub fn invalid_pragma_name_is_rejected() {
        let res = SqLiteDataStorageEngine::builder(MemoryStrategy)
            .with_pragma("journal_mode; DROP TABLE kvs", "WAL")
            .create_connection();

        assert!(res.is_err());
    }

    #[test]
    pub fn extended_schema_version_test() {
        // Test that downstream applications can extend the schema beyond version 1
        // without breaking mls-rs connection creation
        let temp = tempdir().unwrap();
        let database = SqLiteDataStorageEngine::builder(FileConnectionStrategy::new(
            &temp.path().join("extended_schema_test.sqlite"),
        ));

        // Initialize database (creates v1 schema)
        let connection = database.create_connection().unwrap();

        // Simulate downstream application extending schema
        connection
            .execute_batch(
                "BEGIN;
                CREATE TABLE custom_table (
                    id INTEGER PRIMARY KEY,
                    data TEXT NOT NULL
                );
                PRAGMA user_version = 2;
                COMMIT;",
            )
            .unwrap();

        drop(connection);

        // Create new connection - should not try to recreate tables
        let connection2 = database.create_connection().unwrap();

        // Verify user_version is still 2
        let current_schema = connection2
            .pragma_query_value(None, "user_version", |rows| rows.get::<_, u32>(0))
            .unwrap();

        assert_eq!(current_schema, 2);

        // Verify both mls-rs tables and custom table exist
        let mls_table_exists: bool = connection2
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='mls_group'",
                [],
                |row| row.get(0),
            )
            .map(|count: i32| count > 0)
            .unwrap();

        let custom_table_exists: bool = connection2
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='custom_table'",
                [],
                |row| row.get(0),
            )
            .map(|count: i32| count > 0)
            .unwrap();

        assert!(mls_table_exists);
        assert!(custom_table_exists);
    }
}
