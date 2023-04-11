use aws_mls_core::crypto::{HpkePublicKey, HpkeSecretKey};

use alloc::vec::Vec;

#[cfg(feature = "mock")]
use mockall::automock;

/// A trait that provides the required KEM functions
#[cfg_attr(feature = "mock", automock(type Error = crate::mock::TestError;))]
pub trait KemType {
    #[cfg(feature = "std")]
    type Error: std::error::Error + Send + Sync + 'static;
    #[cfg(not(feature = "std"))]
    type Error: core::error::Error + Send + Sync + 'static;

    /// KEM Id, as specified in RFC 9180, Section 5.1 and Table 2.
    fn kem_id(&self) -> u16;

    fn derive(&self, ikm: &[u8]) -> Result<(HpkeSecretKey, HpkePublicKey), Self::Error>;
    fn generate(&self) -> Result<(HpkeSecretKey, HpkePublicKey), Self::Error>;
    fn public_key_validate(&self, key: &HpkePublicKey) -> Result<(), Self::Error>;

    fn encap(&self, remote_key: &HpkePublicKey) -> Result<KemResult, Self::Error>;
    fn decap(&self, enc: &[u8], secret_key: &HpkeSecretKey) -> Result<Vec<u8>, Self::Error>;
}

/// Struct to represent the output of the kem [encap](KemType::encap) function
pub struct KemResult {
    shared_secret: Vec<u8>,
    enc: Vec<u8>,
}

impl KemResult {
    pub fn new(shared_secret: Vec<u8>, enc: Vec<u8>) -> Self {
        Self { shared_secret, enc }
    }

    pub fn shared_secret(&self) -> &[u8] {
        &self.shared_secret
    }

    /// Returns the ciphertext encapsulating the shared secret.
    pub fn enc(&self) -> &[u8] {
        &self.enc
    }
}
