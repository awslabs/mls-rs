// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// Copyright by contributors to this project.
// SPDX-License-Identifier: (Apache-2.0 OR MIT)

mod basic;
mod credential;
mod provider;
mod signing_identity;

#[cfg(feature = "x509")]
mod x509;

pub use basic::*;
pub use credential::*;
use mls_rs_codec::{MlsDecode, MlsEncode, MlsSize};
pub use provider::*;
pub use signing_identity::*;

#[cfg(feature = "x509")]
pub use x509::*;

use crate::crypto::SignatureSecretKey;

#[derive(Clone, Debug, MlsEncode, MlsSize, MlsDecode, PartialEq)]
pub struct SigningData {
    pub signing_identity: SigningIdentity,
    pub signing_key: SignatureSecretKey,
}
