use std::{fmt::Debug, sync::Arc};

use mls_rs_core::mls_rs_codec::{MlsDecode, MlsEncode};

use super::FFICallbackError;

#[derive(Clone, Debug, uniffi::Object)]
pub struct GroupState {
    pub id: Vec<u8>,
    pub data: Vec<u8>,
}

impl mls_rs_core::group::GroupState for GroupState {
    fn id(&self) -> Vec<u8> {
        self.id.clone()
    }
}

#[derive(Clone, Debug, uniffi::Object)]
pub struct EpochRecord {
    pub id: u64,
    pub data: Vec<u8>,
}

impl mls_rs_core::group::EpochRecord for EpochRecord {
    fn id(&self) -> u64 {
        self.id
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
        state: Arc<GroupState>,
        epoch_inserts: Vec<Arc<EpochRecord>>,
        epoch_updates: Vec<Arc<EpochRecord>>,
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

    async fn state<T>(&self, group_id: &[u8]) -> Result<Option<T>, Self::Error>
    where
        T: mls_rs_core::group::GroupState + MlsEncode + MlsDecode,
    {
        let state_data = self.0.state(group_id.to_vec())?;

        state_data
            .as_deref()
            .map(|v| T::mls_decode(&mut &*v))
            .transpose()
            .map_err(Into::into)
    }

    async fn epoch<T>(&self, group_id: &[u8], epoch_id: u64) -> Result<Option<T>, Self::Error>
    where
        T: mls_rs_core::group::EpochRecord + MlsEncode + MlsDecode,
    {
        let epoch_data = self.0.epoch(group_id.to_vec(), epoch_id)?;

        epoch_data
            .as_deref()
            .map(|v| T::mls_decode(&mut &*v))
            .transpose()
            .map_err(Into::into)
    }

    async fn write<ST, ET>(
        &mut self,
        state: ST,
        epoch_inserts: Vec<ET>,
        epoch_updates: Vec<ET>,
    ) -> Result<(), Self::Error>
    where
        ST: mls_rs_core::group::GroupState + MlsEncode + MlsDecode + Send + Sync,
        ET: mls_rs_core::group::EpochRecord + MlsEncode + MlsDecode + Send + Sync,
    {
        let state = Arc::new(GroupState {
            id: state.id(),
            data: state.mls_encode_to_vec().unwrap(),
        });

        let epoch_to_record = |v: ET| {
            Arc::new(EpochRecord {
                id: v.id(),
                data: v.mls_encode_to_vec().unwrap(),
            })
        };

        let inserts = epoch_inserts.into_iter().map(epoch_to_record).collect();
        let updates = epoch_updates.into_iter().map(epoch_to_record).collect();

        self.0.write(state, inserts, updates)
    }

    async fn max_epoch_id(&self, group_id: &[u8]) -> Result<Option<u64>, Self::Error> {
        self.0.max_epoch_id(group_id.to_vec())
    }
}
