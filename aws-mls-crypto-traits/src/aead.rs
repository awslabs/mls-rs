#[cfg(feature = "mock")]
use mockall::automock;

pub const AEAD_ID_EXPORT_ONLY: u16 = 0xFFFF;

/// A trait that provides the required AEAD functions
#[cfg_attr(feature = "mock", automock(type Error = crate::mock::TestError;))]
pub trait AeadType {
    type Error: std::error::Error + Send + Sync + 'static;

    /// AEAD Id, as specified in RFC 9180, Section 5.1 and Table 5.
    fn aead_id(&self) -> u16;

    fn seal<'a>(
        &self,
        key: &[u8],
        data: &[u8],
        aad: Option<&'a [u8]>,
        nonce: &[u8],
    ) -> Result<Vec<u8>, Self::Error>;

    fn open<'a>(
        &self,
        key: &[u8],
        ciphertext: &[u8],
        aad: Option<&'a [u8]>,
        nonce: &[u8],
    ) -> Result<Vec<u8>, Self::Error>;

    fn key_size(&self) -> usize;
    fn nonce_size(&self) -> usize;
}
