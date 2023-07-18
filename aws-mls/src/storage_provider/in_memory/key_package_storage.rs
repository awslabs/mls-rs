#[cfg(feature = "std")]
use alloc::sync::Arc;

#[cfg(not(feature = "std"))]
use portable_atomic_util::Arc;

use core::convert::Infallible;

#[cfg(feature = "std")]
use std::collections::HashMap;

#[cfg(not(feature = "std"))]
use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use aws_mls_core::key_package::{KeyPackageData, KeyPackageStorage};

#[cfg(feature = "std")]
use std::sync::Mutex;

#[cfg(not(sync))]
use alloc::boxed::Box;
#[cfg(not(feature = "std"))]
use spin::Mutex;

#[derive(Clone, Default, Debug)]
/// In memory key package storage backed by a HashMap.
///
/// All clones of an instance of this type share the same underlying HashMap.
pub struct InMemoryKeyPackageStorage {
    #[cfg(feature = "std")]
    inner: Arc<Mutex<HashMap<Vec<u8>, KeyPackageData>>>,
    #[cfg(not(feature = "std"))]
    inner: Arc<Mutex<BTreeMap<Vec<u8>, KeyPackageData>>>,
}

impl InMemoryKeyPackageStorage {
    /// Create an empty key package storage.
    pub fn new() -> Self {
        Default::default()
    }

    /// Insert key package data.
    pub fn insert(&self, id: Vec<u8>, pkg: KeyPackageData) {
        #[cfg(feature = "std")]
        let mut lock = self.inner.lock().unwrap();

        #[cfg(not(feature = "std"))]
        let mut lock = self.inner.lock();

        lock.insert(id, pkg);
    }

    /// Get a key package data by `id`.
    pub fn get(&self, id: &[u8]) -> Option<KeyPackageData> {
        #[cfg(feature = "std")]
        let lock = self.inner.lock().unwrap();

        #[cfg(not(feature = "std"))]
        let lock = self.inner.lock();

        lock.get(id).cloned()
    }

    /// Delete key package data by `id`.
    pub fn delete(&self, id: &[u8]) {
        #[cfg(feature = "std")]
        let mut lock = self.inner.lock().unwrap();

        #[cfg(not(feature = "std"))]
        let mut lock = self.inner.lock();

        lock.remove(id);
    }

    /// Get all key packages that are currently stored.
    pub fn key_packages(&self) -> Vec<(Vec<u8>, KeyPackageData)> {
        #[cfg(feature = "std")]
        let map = self.inner.lock().unwrap();

        #[cfg(not(feature = "std"))]
        let map = self.inner.lock();

        map.iter().map(|(k, v)| (k.clone(), v.clone())).collect()
    }
}

#[maybe_async::maybe_async]
impl KeyPackageStorage for InMemoryKeyPackageStorage {
    type Error = Infallible;

    async fn delete(&mut self, id: &[u8]) -> Result<(), Self::Error> {
        (*self).delete(id);
        Ok(())
    }

    async fn insert(&mut self, id: Vec<u8>, pkg: KeyPackageData) -> Result<(), Self::Error> {
        (*self).insert(id, pkg);
        Ok(())
    }

    async fn get(&self, id: &[u8]) -> Result<Option<KeyPackageData>, Self::Error> {
        Ok(self.get(id))
    }
}
