use alloc::vec::Vec;
use aws_mls_codec::MlsEncode;
pub use aws_mls_core::group::{EpochRecord, GroupState};

use crate::group::snapshot::Snapshot;

#[cfg(feature = "prior_epoch")]
use crate::group::epoch::PriorEpoch;

#[cfg(feature = "prior_epoch")]
impl EpochRecord for PriorEpoch {
    fn id(&self) -> u64 {
        self.epoch_id()
    }
}

impl GroupState for Snapshot {
    fn id(&self) -> Vec<u8> {
        self.group_id().to_vec()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct EpochData {
    pub(crate) id: u64,
    pub(crate) data: Vec<u8>,
}

impl EpochData {
    pub(crate) fn new<T>(value: T) -> Result<Self, aws_mls_codec::Error>
    where
        T: MlsEncode + EpochRecord,
    {
        Ok(Self {
            id: value.id(),
            data: value.mls_encode_to_vec()?,
        })
    }
}
