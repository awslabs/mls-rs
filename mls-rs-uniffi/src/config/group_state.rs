use mls_rs::error::IntoAnyError;
use std::fmt::Debug;
use std::sync::Mutex;

use crate::Error;

// TODO(mulmarta): we'd like to use GroupState and EpochRecord from mls-rs-core
// but this breaks python tests because using 2 crates makes uniffi generate
// a python module which must be in a subdirectory of the directory with test scripts
// which is not supported by the script we use.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, uniffi::Record)]
pub struct GroupState {
    /// A unique group identifier.
    pub id: Vec<u8>,
    pub data: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, uniffi::Record)]
pub struct EpochRecord {
    /// A unique epoch identifier within a particular group.
    pub id: u64,
    pub data: Vec<u8>,
}

impl From<mls_rs_core::group::GroupState> for GroupState {
    fn from(mls_rs_core::group::GroupState { id, data }: mls_rs_core::group::GroupState) -> Self {
        Self { id, data }
    }
}

impl From<GroupState> for mls_rs_core::group::GroupState {
    fn from(GroupState { id, data }: GroupState) -> Self {
        Self { id, data }
    }
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

#[cfg_attr(not(mls_build_async), maybe_async::must_be_sync)]
#[cfg_attr(mls_build_async, maybe_async::must_be_async)]
#[uniffi::export(with_foreign)]
pub trait GroupStateStorage: Send + Sync + Debug {
    async fn state(&self, group_id: Vec<u8>) -> Result<Option<Vec<u8>>, Error>;
    async fn epoch(&self, group_id: Vec<u8>, epoch_id: u64) -> Result<Option<Vec<u8>>, Error>;

    async fn write(
        &self,
        state: GroupState,
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

    fn inner(&self) -> std::sync::MutexGuard<'_, S> {
        self.0.lock().unwrap()
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
            .state(&group_id)
            .map_err(|err| err.into_any_error().into())
    }

    async fn epoch(&self, group_id: Vec<u8>, epoch_id: u64) -> Result<Option<Vec<u8>>, Error> {
        self.inner()
            .epoch(&group_id, epoch_id)
            .map_err(|err| err.into_any_error().into())
    }

    async fn write(
        &self,
        state: GroupState,
        epoch_inserts: Vec<EpochRecord>,
        epoch_updates: Vec<EpochRecord>,
    ) -> Result<(), Error> {
        self.inner()
            .write(
                state.into(),
                epoch_inserts.into_iter().map(Into::into).collect(),
                epoch_updates.into_iter().map(Into::into).collect(),
            )
            .map_err(|err| err.into_any_error().into())
    }

    async fn max_epoch_id(&self, group_id: Vec<u8>) -> Result<Option<u64>, Error> {
        self.inner()
            .max_epoch_id(&group_id)
            .map_err(|err| err.into_any_error().into())
    }
}
