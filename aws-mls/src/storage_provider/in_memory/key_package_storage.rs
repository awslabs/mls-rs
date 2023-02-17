use std::{
    collections::HashMap,
    convert::Infallible,
    sync::{Arc, Mutex},
};

use async_trait::async_trait;
use aws_mls_core::key_package::{KeyPackageData, KeyPackageStorage};

#[derive(Clone, Default, Debug)]
/// In memory key package storage backed by a HashMap.
///
/// All clones of an instance of this type share the same underlying HashMap.
pub struct InMemoryKeyPackageStorage {
    inner: Arc<Mutex<HashMap<Vec<u8>, KeyPackageData>>>,
}

impl InMemoryKeyPackageStorage {
    /// Create an empty key package storage.
    pub fn new() -> Self {
        Default::default()
    }

    /// Insert key package data.
    pub fn insert(&self, id: Vec<u8>, pkg: KeyPackageData) {
        self.inner.lock().unwrap().insert(id, pkg);
    }

    /// Get a key package data by `id`.
    pub fn get(&self, id: &[u8]) -> Option<KeyPackageData> {
        self.inner.lock().unwrap().get(id).cloned()
    }

    /// Delete key package data by `id`.
    pub fn delete(&self, id: &[u8]) {
        self.inner.lock().unwrap().remove(id);
    }

    /// Get all key packages that are currently stored.
    pub fn key_packages(&self) -> Vec<(Vec<u8>, KeyPackageData)> {
        let map = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        map.iter().map(|(k, v)| (k.clone(), v.clone())).collect()
    }

    #[cfg(feature = "benchmark")]
    pub fn from_benchmark_data(key_packages: Vec<(Vec<u8>, KeyPackageData)>) -> Self {
        Self {
            inner: Arc::new(Mutex::new(key_packages.into_iter().collect())),
        }
    }
}

#[async_trait]
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
