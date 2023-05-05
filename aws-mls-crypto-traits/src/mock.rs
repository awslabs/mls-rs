pub use crate::{aead::MockAeadType, dh::MockDhType, kdf::MockKdfType, kem::MockKemType};

#[derive(Debug)]
pub struct TestError {}

impl std::error::Error for TestError {}

impl std::fmt::Display for TestError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("TestError")
    }
}

impl aws_mls_core::error::IntoAnyError for TestError {
    fn into_dyn_error(self) -> Result<Box<dyn std::error::Error + Send + Sync>, Self> {
        Ok(self.into())
    }
}
