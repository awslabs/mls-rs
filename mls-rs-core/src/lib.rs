// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// Copyright by contributors to this project.
// SPDX-License-Identifier: (Apache-2.0 OR MIT)

#![cfg_attr(not(feature = "std"), no_std)]
#![cfg_attr(coverage_nightly, feature(coverage_attribute))]
extern crate alloc;

#[cfg(all(test, target_arch = "wasm32"))]
wasm_bindgen_test::wasm_bindgen_test_configure!(run_in_browser);

pub mod crypto;
pub mod error;
pub mod extension;
pub mod group;
pub mod identity;
pub mod key_package;
pub mod protocol_version;
pub mod psk;
pub mod secret;
pub mod time;

pub use mls_rs_codec;

#[cfg(feature = "arbitrary")]
pub use arbitrary;
