// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// Copyright by contributors to this project.
// SPDX-License-Identifier: (Apache-2.0 OR MIT)

mod builder;
pub(crate) mod processor;

pub use builder::*;
pub use processor::*;

use alloc::vec::Vec;

use mls_rs_codec::{self, MlsDecode, MlsEncode, MlsSize};

use crate::group::ProposalOrRef;
use crate::tree_kem::UpdatePath;

#[derive(Clone, Debug, PartialEq, MlsSize, MlsEncode, MlsDecode)]
#[cfg_attr(feature = "arbitrary", derive(mls_rs_core::arbitrary::Arbitrary))]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub(crate) struct Commit {
    pub proposals: Vec<ProposalOrRef>,
    pub path: Option<UpdatePath>,
}
