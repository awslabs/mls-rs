use connection_strategy::ConnectionStrategy;
use group_state::SqLiteGroupStateStorage;
use keychain::SqLiteKeychainStorage;
use psk::SqLitePreSharedKeyStorage;
use rusqlite::Connection;
use storage::SqLiteKeyPackageStorage;
use thiserror::Error;

mod group_state;
mod key_package;
mod keychain;
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
        crate::group_state::SqLiteGroupStateStorage, crate::key_package::SqLiteKeyPackageStorage,
        crate::keychain::SqLiteKeychainStorage, crate::psk::SqLitePreSharedKeyStorage,
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
    #[cfg(any(feature = "sqlcipher", feature = "sqlcipher-bundled"))]
    #[error("invalid key, must use SqlCipherKey::RawKeyWithSalt with plaintext_header_size > 0")]
    /// Invalid SQLCipher key header.
    SqlCipherKeyInvalidWithHeader,
}

#[derive(Clone, Debug)]
/// SQLite data storage engine.
pub struct SqLiteDataStorageEngine<CS>
where
    CS: ConnectionStrategy,
{
    connection_strategy: CS,
}

impl<CS> SqLiteDataStorageEngine<CS>
where
    CS: ConnectionStrategy,
{
    pub fn new(
        connection_strategy: CS,
    ) -> Result<SqLiteDataStorageEngine<CS>, SqLiteDataStorageError> {
        Ok(SqLiteDataStorageEngine {
            connection_strategy,
        })
    }

    fn create_connection(&self) -> Result<Connection, SqLiteDataStorageError> {
        let mut connection = self.connection_strategy.make_connection()?;

        // Run SQL to establish the schema
        let current_schema = connection
            .pragma_query_value(None, "user_version", |rows| rows.get::<_, u32>(0))
            .map_err(|e| SqLiteDataStorageError::SqlEngineError(e.into()))?;

        if current_schema != 1 {
            create_tables_v1(&mut connection)?;
        }

        Ok(connection)
    }

    /// Returns a struct that implements the `GroupStateStorage` trait for use in MLS.
    pub fn group_state_storage(&self) -> Result<SqLiteGroupStateStorage, SqLiteDataStorageError> {
        Ok(SqLiteGroupStateStorage::new(self.create_connection()?))
    }

    /// Returns a struct that implements the `KeyPackageStorage` trait for use in MLS.
    pub fn key_package_storage(&self) -> Result<SqLiteKeyPackageStorage, SqLiteDataStorageError> {
        Ok(SqLiteKeyPackageStorage::new(self.create_connection()?))
    }

    /// Returns a struct that implements the `KeychainStorage` trait for use in MLS.
    pub fn keychain_storage(&self) -> Result<SqLiteKeychainStorage, SqLiteDataStorageError> {
        Ok(SqLiteKeychainStorage::new(self.create_connection()?))
    }

    /// Returns a struct that implements the `PreSharedKeyStorage` trait for use in MLS.
    pub fn pre_shared_key_storage(
        &self,
    ) -> Result<SqLitePreSharedKeyStorage, SqLiteDataStorageError> {
        Ok(SqLitePreSharedKeyStorage::new(self.create_connection()?))
    }
}

fn create_tables_v1(connection: &mut Connection) -> Result<(), SqLiteDataStorageError> {
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
                data BLOB NOT NULL
            ) WITHOUT ROWID;
            CREATE TABLE keychain (
                identifier BLOB PRIMARY KEY,
                identity BLOB NOT NULL,
                signature_secret_key BLOB NOT NULL,
                cipher_suite INTEGER NOT NULL
            ) WITHOUT ROWID;
            CREATE INDEX idx_keychain_algorithm ON keychain(cipher_suite);
            CREATE TABLE psk (
                psk_id BLOB PRIMARY KEY,
                data BLOB NOT NULL
            ) WITHOUT ROWID;
            PRAGMA user_version = 1;
            COMMIT;",
        )
        .map_err(|e| SqLiteDataStorageError::SqlEngineError(e.into()))
}
