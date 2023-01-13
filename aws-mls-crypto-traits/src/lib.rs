mod aead;
mod dh;
mod kdf;
mod kem;

pub use aead::{AeadType, AEAD_ID_EXPORT_ONLY};
pub use dh::DhType;
pub use kdf::KdfType;
pub use kem::{KemResult, KemType};

#[cfg(feature = "mock")]
pub use crate::{aead::MockAeadType, dh::MockDhType, kdf::MockKdfType, kem::MockKemType};

#[cfg(feature = "mock")]
#[derive(Debug)]
pub struct TestError {}

#[cfg(feature = "mock")]
impl std::error::Error for TestError {}

#[cfg(feature = "mock")]
impl std::fmt::Display for TestError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("TestError")
    }
}
