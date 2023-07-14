#[cfg(not(sync))]
use alloc::boxed::Box;
use alloc::vec::Vec;
use aws_mls_codec::{MlsDecode, MlsEncode, MlsSize};

use crate::{crypto::HpkeSecretKey, error::IntoAnyError};

#[derive(Debug, Clone, PartialEq, Eq, MlsEncode, MlsDecode, MlsSize)]
#[non_exhaustive]
/// Representation of a generated key package and secret keys.
pub struct KeyPackageData {
    pub key_package_bytes: Vec<u8>,
    pub init_key: HpkeSecretKey,
    pub leaf_node_key: HpkeSecretKey,
}

impl KeyPackageData {
    pub fn new(
        key_package_bytes: Vec<u8>,
        init_key: HpkeSecretKey,
        leaf_node_key: HpkeSecretKey,
    ) -> KeyPackageData {
        Self {
            key_package_bytes,
            init_key,
            leaf_node_key,
        }
    }
}

/// Storage trait that maintains key package secrets.
#[maybe_async::maybe_async]
pub trait KeyPackageStorage: Send + Sync {
    /// Error type that the underlying storage mechanism returns on internal
    /// failure.
    type Error: IntoAnyError;

    /// Delete [`KeyPackageData`] referenced by `id`.
    ///
    /// This function is called automatically when the key package referenced
    /// by `id` is used to successfully join a group.
    ///
    /// # Warning
    ///
    /// [`KeyPackageData`] internally contains secret key values. The
    /// provided delete mechanism should securely erase data.
    async fn delete(&mut self, id: &[u8]) -> Result<(), Self::Error>;

    /// Store [`KeyPackageData`] that can be accessed by `id` in the future.
    ///
    /// This function is automatically called whenever a new key package is created.
    async fn insert(&mut self, id: Vec<u8>, pkg: KeyPackageData) -> Result<(), Self::Error>;

    /// Retrieve [`KeyPackageData`] by its `id`.
    ///
    /// `None` should be returned in the event that no key packages are found
    /// that match `id`.
    async fn get(&self, id: &[u8]) -> Result<Option<KeyPackageData>, Self::Error>;
}
