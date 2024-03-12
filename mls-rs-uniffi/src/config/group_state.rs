use std::fmt::Debug;

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
