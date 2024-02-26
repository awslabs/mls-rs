// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// Copyright by contributors to this project.
// SPDX-License-Identifier: (Apache-2.0 OR MIT)

use alloc::vec::Vec;
use core::fmt::{self, Debug};
use mls_rs_codec::MlsEncode;
pub use mls_rs_core::group::{EpochRecord, GroupState};

use crate::group::snapshot::Snapshot;

#[cfg(feature = "prior_epoch")]
use crate::group::epoch::PriorEpoch;

#[cfg(feature = "prior_epoch")]
impl EpochRecord for PriorEpoch {
    fn id(&self) -> u64 {
        self.epoch_id()
    }
}

impl GroupState for Snapshot<'_> {
    fn id(&self) -> Vec<u8> {
        self.group_id().to_vec()
    }
}

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct EpochData {
    pub(crate) id: u64,
    pub(crate) data: Vec<u8>,
}

impl Debug for EpochData {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EpochData")
            .field("id", &self.id)
            .field("data", &mls_rs_core::debug::pretty_bytes(&self.data))
            .finish()
    }
}

impl EpochData {
    pub(crate) fn new<T>(value: T) -> Result<Self, mls_rs_codec::Error>
    where
        T: MlsEncode + EpochRecord,
    {
        Ok(Self {
            id: value.id(),
            data: value.mls_encode_to_vec()?,
        })
    }
}
