use rusqlite::Connection;
use sqlite_storage::{
    connection_strategy::ConnectionStrategy, group_state::SqLiteGroupStateStore,
    key_package::SqLiteKeyPackageStore, keychain::SqLiteKeychainStorage,
    psk::SqLitePreSharedKeyStorage,
};
use thiserror::Error;

pub mod sqlite_storage;

#[derive(Debug, Error)]
pub enum SqLiteDataStorageError {
    #[error(transparent)]
    SqlEngineError(Box<dyn std::error::Error + Send + Sync + 'static>),
    #[error(transparent)]
    DataConversionError(Box<dyn std::error::Error + Send + Sync + 'static>),
    #[cfg(any(feature = "sqlcipher", feature = "sqlcipher-bundled"))]
    #[error("invalid key, must use SqlCipherKey::RawKeyWithSalt with plaintext_header_size > 0")]
    SqlCipherKeyInvalidWithHeader,
}

#[derive(Clone, Debug)]
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

    pub fn group_state_storage(&self) -> Result<SqLiteGroupStateStore, SqLiteDataStorageError> {
        Ok(SqLiteGroupStateStore::new(self.create_connection()?))
    }

    pub fn key_package_repository(&self) -> Result<SqLiteKeyPackageStore, SqLiteDataStorageError> {
        Ok(SqLiteKeyPackageStore::new(self.create_connection()?))
    }

    pub fn keychain(&self) -> Result<SqLiteKeychainStorage, SqLiteDataStorageError> {
        Ok(SqLiteKeychainStorage::new(self.create_connection()?))
    }

    pub fn psk_store(&self) -> Result<SqLitePreSharedKeyStorage, SqLiteDataStorageError> {
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
