#![cfg_attr(not(feature = "std"), no_std)]
#![cfg_attr(not(feature = "std"), feature(error_in_core))]
extern crate alloc;

#[cfg(all(test, target_arch = "wasm32"))]
wasm_bindgen_test::wasm_bindgen_test_configure!(run_in_browser);

pub mod crypto;
pub mod extension;
pub mod group;
pub mod identity;
pub mod key_package;
pub mod keychain;
pub mod protocol_version;
pub mod psk;
pub mod serde_util;
pub mod time;

pub use async_trait;

#[cfg(feature = "arbitrary")]
pub use arbitrary;
