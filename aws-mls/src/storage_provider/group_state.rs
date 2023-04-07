use alloc::vec::Vec;
pub use aws_mls_core::group::{EpochRecord, GroupState};
use bincode::config::Configuration;

use crate::group::{epoch::PriorEpoch, snapshot::Snapshot};

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

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub(crate) struct EpochData {
    pub(crate) id: u64,
    pub(crate) data: Vec<u8>,
}

impl EpochData {
    pub(crate) fn new<T>(value: T) -> Result<Self, bincode::error::EncodeError>
    where
        T: serde::Serialize + EpochRecord,
    {
        Ok(Self {
            id: value.id(),
            data: bincode::serde::encode_to_vec::<&T, Configuration>(
                &value,
                Configuration::default(),
            )?,
        })
    }
}
