use std::path::{Path, PathBuf};

use rusqlite::Connection;

use crate::SqLiteDataStorageError;

pub trait ConnectionStrategy {
    fn make_connection(&self) -> Result<Connection, SqLiteDataStorageError>;
}

pub struct MemoryStrategy;

impl ConnectionStrategy for MemoryStrategy {
    fn make_connection(&self) -> Result<Connection, SqLiteDataStorageError> {
        Connection::open_in_memory().map_err(|e| SqLiteDataStorageError::SqlEngineError(e.into()))
    }
}

pub struct FileConnectionStrategy {
    db_path: PathBuf,
}

impl FileConnectionStrategy {
    pub fn new(db_path: &Path) -> FileConnectionStrategy {
        FileConnectionStrategy {
            db_path: db_path.to_owned(),
        }
    }
}

impl ConnectionStrategy for FileConnectionStrategy {
    fn make_connection(&self) -> Result<Connection, SqLiteDataStorageError> {
        Connection::open(&self.db_path)
            .map_err(|e| SqLiteDataStorageError::SqlEngineError(e.into()))
    }
}
