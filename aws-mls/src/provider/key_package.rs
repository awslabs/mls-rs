use crate::key_package::{KeyPackageError, KeyPackageRef};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

pub use crate::key_package::generator::KeyPackageGeneration;

pub trait KeyPackageRepository: Send + Sync {
    type Error: std::error::Error + Send + Sync + 'static;

    fn delete(&mut self, reference: &KeyPackageRef) -> Result<(), Self::Error>;

    fn insert(
        &mut self,
        reference: KeyPackageRef,
        key_pkg_gen: KeyPackageGeneration,
    ) -> Result<(), Self::Error>;

    fn get(&self, reference: &KeyPackageRef) -> Result<Option<KeyPackageGeneration>, Self::Error>;
}

#[derive(Clone, Default, Debug)]
pub struct InMemoryKeyPackageRepository {
    inner: Arc<Mutex<HashMap<KeyPackageRef, KeyPackageGeneration>>>,
}

impl InMemoryKeyPackageRepository {
    pub fn insert(&self, reference: KeyPackageRef, key_pkg_gen: KeyPackageGeneration) {
        self.inner.lock().unwrap().insert(reference, key_pkg_gen);
    }

    pub fn get(&self, r: &KeyPackageRef) -> Option<KeyPackageGeneration> {
        self.inner.lock().unwrap().get(r).cloned()
    }

    pub fn delete(&self, reference: &KeyPackageRef) {
        self.inner.lock().unwrap().remove(reference);
    }

    #[cfg(feature = "benchmark")]
    pub fn export(&self) -> Vec<(KeyPackageRef, KeyPackageGeneration)> {
        let map = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        map.iter().map(|(k, v)| (k.clone(), v.clone())).collect()
    }

    #[cfg(feature = "benchmark")]
    pub fn from_benchmark_data(key_packages: Vec<(KeyPackageRef, KeyPackageGeneration)>) -> Self {
        Self {
            inner: Arc::new(Mutex::new(key_packages.into_iter().collect())),
        }
    }
}

impl KeyPackageRepository for InMemoryKeyPackageRepository {
    type Error = KeyPackageError;

    fn insert(
        &mut self,
        reference: KeyPackageRef,
        key_pkg_gen: KeyPackageGeneration,
    ) -> Result<(), Self::Error> {
        (*self).insert(reference, key_pkg_gen);
        Ok(())
    }

    fn get(&self, key_pkg: &KeyPackageRef) -> Result<Option<KeyPackageGeneration>, Self::Error> {
        Ok(self.get(key_pkg))
    }

    fn delete(&mut self, reference: &KeyPackageRef) -> Result<(), Self::Error> {
        (*self).delete(reference);
        Ok(())
    }
}
