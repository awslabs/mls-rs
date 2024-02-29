use std::{fmt::Debug, sync::Arc};

#[cfg(feature = "sqlite")]
use mls_rs::{
    storage_provider::sqlite::storage::SqLiteGroupStateStorage,
    GroupStateStorage as MlsRsGroupStateStorage,
};

use super::FFICallbackError;

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

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, uniffi::Record)]
pub struct EpochRecord {
    /// A unique epoch identifier within a particular group.
    pub id: u64,
    pub data: Vec<u8>,
}

impl From<mls_rs_core::group::GroupState> for GroupState {
    fn from(value: mls_rs_core::group::GroupState) -> Self {
        Self {
            id: value.id,
            data: value.data,
        }
    }
}

impl From<mls_rs_core::group::EpochRecord> for EpochRecord {
    fn from(value: mls_rs_core::group::EpochRecord) -> Self {
        Self {
            id: value.id,
            data: value.data,
        }
    }
}

impl From<GroupState> for mls_rs_core::group::GroupState {
    fn from(value: GroupState) -> Self {
        Self {
            id: value.id,
            data: value.data,
        }
    }
}

impl From<EpochRecord> for mls_rs_core::group::EpochRecord {
    fn from(value: EpochRecord) -> Self {
        Self {
            id: value.id,
            data: value.data,
        }
    }
}

#[cfg_attr(not(mls_build_async), maybe_async::must_be_sync)]
#[cfg_attr(mls_build_async, maybe_async::must_be_async)]
#[uniffi::export(with_foreign)]
pub trait GroupStateStorage: Send + Sync + Debug {
    async fn state(&self, group_id: Vec<u8>) -> Result<Option<Vec<u8>>, FFICallbackError>;
    async fn epoch(
        &self,
        group_id: Vec<u8>,
        epoch_id: u64,
    ) -> Result<Option<Vec<u8>>, FFICallbackError>;

    async fn write(
        &self,
        state: GroupState,
        epoch_inserts: Vec<EpochRecord>,
        epoch_updates: Vec<EpochRecord>,
    ) -> Result<(), FFICallbackError>;

    async fn max_epoch_id(&self, group_id: Vec<u8>) -> Result<Option<u64>, FFICallbackError>;
}

#[derive(Debug, Clone)]
pub(crate) struct GroupStateStorageWrapper(Arc<dyn GroupStateStorage>);

impl From<Arc<dyn GroupStateStorage>> for GroupStateStorageWrapper {
    fn from(value: Arc<dyn GroupStateStorage>) -> Self {
        Self(value)
    }
}

#[cfg_attr(not(mls_build_async), maybe_async::must_be_sync)]
#[cfg_attr(mls_build_async, maybe_async::must_be_async)]
impl mls_rs_core::group::GroupStateStorage for GroupStateStorageWrapper {
    type Error = FFICallbackError;

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

#[cfg(feature = "sqlite")]
#[cfg_attr(not(mls_build_async), maybe_async::must_be_sync)]
#[cfg_attr(mls_build_async, maybe_async::must_be_async)]
impl GroupStateStorage for SqLiteGroupStateStorage {
    async fn state(&self, group_id: Vec<u8>) -> Result<Option<Vec<u8>>, FFICallbackError> {
        Ok(<Self as MlsRsGroupStateStorage>::state(self, &group_id).await?)
    }

    async fn epoch(
        &self,
        group_id: Vec<u8>,
        epoch_id: u64,
    ) -> Result<Option<Vec<u8>>, FFICallbackError> {
        Ok(<Self as MlsRsGroupStateStorage>::epoch(self, &group_id, epoch_id).await?)
    }

    async fn write(
        &self,
        state: GroupState,
        inserts: Vec<EpochRecord>,
        updates: Vec<EpochRecord>,
    ) -> Result<(), FFICallbackError> {
        Ok(self.write_to_storage(
            state.into(),
            inserts.into_iter().map(Into::into).collect(),
            updates.into_iter().map(Into::into).collect(),
        )?)
    }

    async fn max_epoch_id(&self, group_id: Vec<u8>) -> Result<Option<u64>, FFICallbackError> {
        Ok(<Self as MlsRsGroupStateStorage>::max_epoch_id(self, &group_id).await?)
    }
}
