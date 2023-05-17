use core::ops::Deref;

use alloc::boxed::Box;
use alloc::vec::Vec;

use crate::error::IntoAnyError;
use aws_mls_codec::{MlsDecode, MlsEncode, MlsSize};
use zeroize::Zeroizing;

#[derive(Clone, Debug, PartialEq, Eq, MlsSize, MlsEncode, MlsDecode)]
/// Wrapper type that holds a pre-shared key value and zeroizes on drop.
pub struct PreSharedKey(#[mls_codec(with = "aws_mls_codec::byte_vec")] Zeroizing<Vec<u8>>);

impl PreSharedKey {
    /// Create a new PreSharedKey.
    pub fn new(data: Vec<u8>) -> Self {
        PreSharedKey(Zeroizing::new(data))
    }

    /// Raw byte value.
    pub fn raw_value(&self) -> &[u8] {
        &self.0
    }
}

impl From<Vec<u8>> for PreSharedKey {
    fn from(bytes: Vec<u8>) -> Self {
        Self::new(bytes)
    }
}

impl From<Zeroizing<Vec<u8>>> for PreSharedKey {
    fn from(bytes: Zeroizing<Vec<u8>>) -> Self {
        Self(bytes)
    }
}

impl AsRef<[u8]> for PreSharedKey {
    fn as_ref(&self) -> &[u8] {
        self.raw_value()
    }
}

impl Deref for PreSharedKey {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        self.raw_value()
    }
}

#[derive(Clone, Debug, Eq, Hash, Ord, PartialOrd, PartialEq, MlsSize, MlsEncode, MlsDecode)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
/// An external pre-shared key identifier.
pub struct ExternalPskId(#[mls_codec(with = "aws_mls_codec::byte_vec")] Vec<u8>);

impl ExternalPskId {
    pub fn new(id_data: Vec<u8>) -> Self {
        Self(id_data)
    }
}

impl AsRef<[u8]> for ExternalPskId {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl Deref for ExternalPskId {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl From<Vec<u8>> for ExternalPskId {
    fn from(value: Vec<u8>) -> Self {
        ExternalPskId(value)
    }
}

/// Storage trait to maintain a set of pre-shared key values.
#[maybe_async::maybe_async]
pub trait PreSharedKeyStorage: Send + Sync {
    /// Error type that the underlying storage mechanism returns on internal
    /// failure.
    type Error: IntoAnyError;

    /// Get a pre-shared key by [`ExternalPskId`](ExternalPskId).
    ///
    /// `None` should be returned if a pre-shared key can not be found for `id`.
    async fn get(&self, id: &ExternalPskId) -> Result<Option<PreSharedKey>, Self::Error>;

    /// Determines if a PSK is located within the store
    async fn contains(&self, id: &ExternalPskId) -> Result<bool, Self::Error> {
        self.get(id).await.map(|key| key.is_some())
    }
}
