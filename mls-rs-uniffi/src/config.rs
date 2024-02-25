use std::{fmt::Debug, sync::Arc};

use mls_rs::{
    client_builder::{self, WithGroupStateStorage},
    identity::basic,
};
use mls_rs_core::error::IntoAnyError;
use mls_rs_crypto_openssl::OpensslCryptoProvider;

use self::group_state::GroupStateStorageWrapper;

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
}

impl IntoAnyError for FFICallbackError {}

pub type UniFFIConfig = client_builder::WithIdentityProvider<
    basic::BasicIdentityProvider,
    client_builder::WithCryptoProvider<
        OpensslCryptoProvider,
        WithGroupStateStorage<GroupStateStorageWrapper, client_builder::BaseConfig>,
    >,
>;

#[derive(Debug, Clone, uniffi::Record)]
pub struct ClientConfig {
    pub group_state_storage: Arc<dyn group_state::GroupStateStorage>,
}
