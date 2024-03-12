use std::fmt::Debug;
use std::sync::Arc;

use mls_rs::{
    client_builder::{self, WithGroupStateStorage},
    identity::basic,
    storage_provider::in_memory::InMemoryGroupStateStorage,
};
use mls_rs_crypto_openssl::OpensslCryptoProvider;

use self::group_state::{GroupStateStorage, GroupStateStorageAdapter};
use crate::Error;

pub mod group_state;

#[derive(Debug, Clone)]
pub(crate) struct ClientGroupStorage(Arc<dyn GroupStateStorage>);

impl From<Arc<dyn GroupStateStorage>> for ClientGroupStorage {
    fn from(value: Arc<dyn GroupStateStorage>) -> Self {
        Self(value)
    }
}

#[cfg_attr(not(mls_build_async), maybe_async::must_be_sync)]
#[cfg_attr(mls_build_async, maybe_async::must_be_async)]
impl mls_rs_core::group::GroupStateStorage for ClientGroupStorage {
    type Error = Error;

    async fn state(&self, group_id: &[u8]) -> Result<Option<Vec<u8>>, Self::Error> {
        self.0.state(group_id.to_vec())
    }

    async fn epoch(&self, group_id: &[u8], epoch_id: u64) -> Result<Option<Vec<u8>>, Self::Error> {
        self.0.epoch(group_id.to_vec(), epoch_id)
    }

    async fn write(
        &mut self,
        state: mls_rs_core::group::GroupState,
        inserts: Vec<mls_rs_core::group::EpochRecord>,
        updates: Vec<mls_rs_core::group::EpochRecord>,
    ) -> Result<(), Self::Error> {
        self.0.write(
            state.into(),
            inserts.into_iter().map(Into::into).collect(),
            updates.into_iter().map(Into::into).collect(),
        )
    }

    async fn max_epoch_id(&self, group_id: &[u8]) -> Result<Option<u64>, Self::Error> {
        self.0.max_epoch_id(group_id.to_vec())
    }
}

pub type UniFFIConfig = client_builder::WithIdentityProvider<
    basic::BasicIdentityProvider,
    client_builder::WithCryptoProvider<
        OpensslCryptoProvider,
        WithGroupStateStorage<ClientGroupStorage, client_builder::BaseConfig>,
    >,
>;

#[derive(Debug, Clone, uniffi::Record)]
pub struct ClientConfig {
    pub group_state_storage: Arc<dyn GroupStateStorage>,
}

// TODO(mgeisler): turn into an associated function when UniFFI
// supports them: https://github.com/mozilla/uniffi-rs/issues/1074.
/// Create a client config with an in-memory group state storage.
#[uniffi::export]
pub fn client_config_default() -> ClientConfig {
    ClientConfig {
        group_state_storage: Arc::new(GroupStateStorageAdapter::new(
            InMemoryGroupStateStorage::new(),
        )),
    }
}
