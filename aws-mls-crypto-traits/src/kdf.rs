#[cfg(feature = "mock")]
use mockall::automock;

/// A trait that provides the required KDF functions
#[cfg_attr(feature = "mock", automock(type Error = crate::mock::TestError;))]
pub trait KdfType {
    type Error: std::error::Error + Send + Sync + 'static;

    /// KDF Id, as specified in RFC 9180, Section 5.1 and Table 3.
    fn kdf_id(&self) -> u16;

    fn expand(&self, prk: &[u8], info: &[u8], len: usize) -> Result<Vec<u8>, Self::Error>;
    fn extract(&self, salt: &[u8], ikm: &[u8]) -> Result<Vec<u8>, Self::Error>;
    fn extract_size(&self) -> usize;
}
