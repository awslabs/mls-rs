#![cfg_attr(not(feature = "std"), no_std)]
#![cfg_attr(not(feature = "std"), feature(error_in_core))]
extern crate alloc;

mod aead;
mod dh;
mod kdf;
mod kem;

pub use aead::{AeadType, AEAD_ID_EXPORT_ONLY};
pub use dh::DhType;
pub use kdf::KdfType;
pub use kem::{KemResult, KemType};

#[cfg(feature = "mock")]
pub mod mock;
