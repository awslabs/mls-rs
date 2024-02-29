use std::{fmt::Debug, sync::Arc};

use mls_rs::{
    client_builder::{self, WithGroupStateStorage},
    identity::basic,
};
use mls_rs_core::error::IntoAnyError;
use mls_rs_crypto_openssl::OpensslCryptoProvider;

use self::group_state::{GroupStateStorage, GroupStateStorageWrapper};

#[cfg(feature = "sqlite")]
use mls_rs::storage_provider::sqlite::{
    connection_strategy::{
        CipheredConnectionStrategy, FileConnectionStrategy, SqlCipherConfig, SqlCipherKey,
    },
    SqLiteDataStorageEngine, SqLiteDataStorageError,
};

mod group_state;

#[derive(Debug, thiserror::Error, uniffi::Error)]
#[uniffi(flat_error)]
#[non_exhaustive]
pub enum FFICallbackError {
    #[error("data preparation error")]
    DataPreparationError {
        #[from]
        inner: mls_rs_core::mls_rs_codec::Error,
    },
    #[error("unexpected callback error")]
    UnexpectedCallbackError {
        #[from]
        inner: uniffi::UnexpectedUniFFICallbackError,
    },
    #[cfg(feature = "sqlite")]
    #[error("sqlite error")]
    SqLiteError {
        #[from]
        inner: SqLiteDataStorageError,
    },
    #[error("custom error")]
    Custom { inner: String },
}

impl IntoAnyError for FFICallbackError {}

pub type UniFFIConfig = client_builder::WithIdentityProvider<
    basic::BasicIdentityProvider,
    client_builder::WithCryptoProvider<
        OpensslCryptoProvider,
        WithGroupStateStorage<GroupStateStorageWrapper, client_builder::BaseConfig>,
    >,
>;

#[derive(Debug, Clone, uniffi::Object)]
pub struct ClientConfig {
    pub group_state_storage: Arc<dyn GroupStateStorage>,
}

#[cfg(not(feature = "sqlite"))]
#[uniffi::export]
impl ClientConfig {
    #[uniffi::constructor]
    pub fn new(group_state_storage: Arc<dyn GroupStateStorage>) -> Self {
        Self {
            group_state_storage,
        }
    }
}

#[cfg(feature = "sqlite")]
#[uniffi::export]
impl ClientConfig {
    #[uniffi::constructor]
    pub fn new(group_state_storage: Arc<dyn GroupStateStorage>) -> Self {
        Self {
            group_state_storage,
        }
    }

    #[uniffi::constructor]
    pub fn new_sqlite(path: String, key: Vec<u8>) -> Result<Self, FFICallbackError> {
        let key = SqlCipherKey::RawKey(key.as_slice().try_into().map_err(|_| {
            FFICallbackError::Custom {
                inner: "key must have 32 bytes".into(),
            }
        })?);

        let connection = CipheredConnectionStrategy::new(
            FileConnectionStrategy::new(std::path::Path::new(&path)),
            SqlCipherConfig::new(key),
        );

        let engine = SqLiteDataStorageEngine::new(connection)?;

        Ok(Self {
            group_state_storage: Arc::new(engine.group_state_storage()?),
        })
    }
}
