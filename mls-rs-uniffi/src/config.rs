use std::{fmt::Debug, sync::Arc};

use mls_rs::{
    client_builder::{self, WithGroupStateStorage},
    identity::basic,
};
use mls_rs_crypto_openssl::OpensslCryptoProvider;

use self::group_state::{GroupStateStorage, GroupStateStorageWrapper};

pub mod group_state;

pub type UniFFIConfig = client_builder::WithIdentityProvider<
    basic::BasicIdentityProvider,
    client_builder::WithCryptoProvider<
        OpensslCryptoProvider,
        WithGroupStateStorage<GroupStateStorageWrapper, client_builder::BaseConfig>,
    >,
>;

#[derive(Debug, Clone, uniffi::Record)]
pub struct ClientConfig {
    pub group_state_storage: Arc<dyn GroupStateStorage>,
}
