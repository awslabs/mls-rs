use mls_rs::error::IntoAnyError;
use std::fmt::Debug;
#[cfg(not(mls_build_async))]
use std::sync::Mutex;
#[cfg(mls_build_async)]
use tokio::sync::Mutex;

use crate::Error;

// TODO(mulmarta): we'd like to use EpochRecord from mls-rs-core but
// this breaks the Python tests because using two crates makes UniFFI
// generate a Python module which must be in a subdirectory of the
// directory with test scripts which is not supported by the script we
// use.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, uniffi::Record)]
pub struct EpochRecord {
    /// A unique epoch identifier within a particular group.
    pub id: u64,
    pub data: Vec<u8>,
}

impl From<mls_rs_core::group::EpochRecord> for EpochRecord {
    fn from(mls_rs_core::group::EpochRecord { id, data }: mls_rs_core::group::EpochRecord) -> Self {
        Self { id, data }
    }
}

impl From<EpochRecord> for mls_rs_core::group::EpochRecord {
    fn from(EpochRecord { id, data }: EpochRecord) -> Self {
        Self { id, data }
    }
}

// When building for async, uniffi::export has to be applied _before_ maybe-async's injection of
// the async trait so that uniffi::export sees the definition before async_trait is expanded. When
// building for sync, the order has to be the opposite so that uniffi::export sees the sync
// definition of the trait.
#[cfg_attr(mls_build_async, uniffi::export(with_foreign))]
#[cfg_attr(mls_build_async, maybe_async::must_be_async)]
#[cfg_attr(not(mls_build_async), maybe_async::must_be_sync)]
#[cfg_attr(not(mls_build_async), uniffi::export(with_foreign))]
pub trait GroupStateStorage: Send + Sync + Debug {
    async fn state(&self, group_id: Vec<u8>) -> Result<Option<Vec<u8>>, Error>;
    async fn epoch(&self, group_id: Vec<u8>, epoch_id: u64) -> Result<Option<Vec<u8>>, Error>;

    async fn write(
        &self,
        group_id: Vec<u8>,
        group_state: Vec<u8>,
        epoch_inserts: Vec<EpochRecord>,
        epoch_updates: Vec<EpochRecord>,
    ) -> Result<(), Error>;

    async fn max_epoch_id(&self, group_id: Vec<u8>) -> Result<Option<u64>, Error>;
}

/// Adapt a mls-rs `GroupStateStorage` implementation.
///
/// This is used to adapt a mls-rs `GroupStateStorage` implementation
/// to our own `GroupStateStorage` trait. This way we can use any
/// standard mls-rs group state storage from the FFI layer.
#[derive(Debug)]
pub(crate) struct GroupStateStorageAdapter<S>(Mutex<S>);

impl<S> GroupStateStorageAdapter<S> {
    pub fn new(group_state_storage: S) -> GroupStateStorageAdapter<S> {
        Self(Mutex::new(group_state_storage))
    }

    #[cfg(not(mls_build_async))]
    fn inner(&self) -> std::sync::MutexGuard<'_, S> {
        self.0.lock().unwrap()
    }

    #[cfg(mls_build_async)]
    async fn inner(&self) -> tokio::sync::MutexGuard<'_, S> {
        self.0.lock().await
    }
}

#[cfg_attr(not(mls_build_async), maybe_async::must_be_sync)]
#[cfg_attr(mls_build_async, maybe_async::must_be_async)]
impl<S, Err> GroupStateStorage for GroupStateStorageAdapter<S>
where
    S: mls_rs::GroupStateStorage<Error = Err> + Debug,
    Err: IntoAnyError,
{
    async fn state(&self, group_id: Vec<u8>) -> Result<Option<Vec<u8>>, Error> {
        self.inner()
            .await
            .state(&group_id)
            .await
            .map_err(|err| err.into_any_error().into())
    }

    async fn epoch(&self, group_id: Vec<u8>, epoch_id: u64) -> Result<Option<Vec<u8>>, Error> {
        self.inner()
            .await
            .epoch(&group_id, epoch_id)
            .await
            .map_err(|err| err.into_any_error().into())
    }

    async fn write(
        &self,
        id: Vec<u8>,
        data: Vec<u8>,
        epoch_inserts: Vec<EpochRecord>,
        epoch_updates: Vec<EpochRecord>,
    ) -> Result<(), Error> {
        self.inner()
            .await
            .write(
                mls_rs_core::group::GroupState { id, data },
                epoch_inserts.into_iter().map(Into::into).collect(),
                epoch_updates.into_iter().map(Into::into).collect(),
            )
            .await
            .map_err(|err| err.into_any_error().into())
    }

    async fn max_epoch_id(&self, group_id: Vec<u8>) -> Result<Option<u64>, Error> {
        self.inner()
            .await
            .max_epoch_id(&group_id)
            .await
            .map_err(|err| err.into_any_error().into())
    }
}
