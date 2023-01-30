use std::{
    collections::HashMap,
    convert::Infallible,
    sync::{Arc, Mutex},
};

use async_trait::async_trait;
pub use aws_mls_core::key_package::{KeyPackageData, KeyPackageRepository};

#[derive(Clone, Default, Debug)]
pub struct InMemoryKeyPackageRepository {
    inner: Arc<Mutex<HashMap<Vec<u8>, KeyPackageData>>>,
}

impl InMemoryKeyPackageRepository {
    pub fn insert(&self, id: Vec<u8>, pkg: KeyPackageData) {
        self.inner.lock().unwrap().insert(id, pkg);
    }

    pub fn get(&self, id: &[u8]) -> Option<KeyPackageData> {
        self.inner.lock().unwrap().get(id).cloned()
    }

    pub fn delete(&self, id: &[u8]) {
        self.inner.lock().unwrap().remove(id);
    }

    #[cfg(feature = "benchmark")]
    pub fn export(&self) -> Vec<(Vec<u8>, KeyPackageData)> {
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
impl KeyPackageRepository for InMemoryKeyPackageRepository {
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
