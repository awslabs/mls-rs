use crate::key_package::{KeyPackageError, KeyPackageGeneration, KeyPackageRef};
use ferriscrypt::asym::ec_key::PublicKey;
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

pub trait KeyPackageRepository {
    type Error: std::error::Error + Send + Sync + 'static;

    fn insert(&mut self, key_pkg_gen: KeyPackageGeneration) -> Result<(), Self::Error>;
    fn get(&self, key_pkg: &KeyPackageRef) -> Result<Option<KeyPackageGeneration>, Self::Error>;
}

pub trait ClientConfig {
    type KeyPackageRepository: KeyPackageRepository;

    fn external_signing_key(&self, external_key_id: &[u8]) -> Option<PublicKey> {
        DefaultClientConfig::default().external_signing_key(external_key_id)
    }

    fn encrypt_controls(&self) -> bool {
        DefaultClientConfig::default().encrypt_controls()
    }

    fn ratchet_tree_extension(&self) -> bool {
        DefaultClientConfig::default().ratchet_tree_extension()
    }

    fn external_key_id(&self) -> Option<Vec<u8>> {
        DefaultClientConfig::default().external_key_id()
    }

    fn key_package_repo(&self) -> Self::KeyPackageRepository;
}

#[derive(Clone, Default, Debug)]
pub struct InMemoryRepository {
    inner: Arc<Mutex<HashMap<KeyPackageRef, KeyPackageGeneration>>>,
}

impl InMemoryRepository {
    pub fn insert(&self, key_pkg_gen: KeyPackageGeneration) -> Result<(), KeyPackageError> {
        self.inner
            .lock()
            .unwrap()
            .insert(key_pkg_gen.key_package.to_reference()?, key_pkg_gen);
        Ok(())
    }

    pub fn get(&self, r: &KeyPackageRef) -> Option<KeyPackageGeneration> {
        self.inner.lock().unwrap().get(r).cloned()
    }
}

impl KeyPackageRepository for InMemoryRepository {
    type Error = KeyPackageError;

    fn insert(&mut self, key_pkg_gen: KeyPackageGeneration) -> Result<(), Self::Error> {
        (&*self).insert(key_pkg_gen)
    }

    fn get(&self, key_pkg: &KeyPackageRef) -> Result<Option<KeyPackageGeneration>, Self::Error> {
        Ok(self.get(key_pkg))
    }
}

#[derive(Clone, Debug, Default)]
#[non_exhaustive]
pub struct DefaultClientConfig {
    encrypt_controls: bool,
    ratchet_tree_extension: bool,
    external_signing_keys: HashMap<Vec<u8>, PublicKey>,
    external_key_id: Option<Vec<u8>>,
    key_packages: InMemoryRepository,
}

impl DefaultClientConfig {
    #[must_use]
    pub fn with_control_encryption(self, yes: bool) -> Self {
        Self {
            encrypt_controls: yes,
            ..self
        }
    }

    #[must_use]
    pub fn with_ratchet_tree_extension(self, yes: bool) -> Self {
        Self {
            ratchet_tree_extension: yes,
            ..self
        }
    }

    #[must_use]
    pub fn with_external_signing_key(mut self, id: Vec<u8>, key: PublicKey) -> Self {
        self.external_signing_keys.insert(id, key);
        self
    }

    #[must_use]
    pub fn with_external_key_id(self, id: Vec<u8>) -> Self {
        Self {
            external_key_id: Some(id),
            ..self
        }
    }

    #[must_use]
    pub fn with_key_packages(self, key_packages: InMemoryRepository) -> Self {
        Self {
            key_packages,
            ..self
        }
    }
}

impl ClientConfig for DefaultClientConfig {
    type KeyPackageRepository = InMemoryRepository;

    fn external_signing_key(&self, external_key_id: &[u8]) -> Option<PublicKey> {
        self.external_signing_keys.get(external_key_id).cloned()
    }

    fn encrypt_controls(&self) -> bool {
        self.encrypt_controls
    }

    fn ratchet_tree_extension(&self) -> bool {
        self.ratchet_tree_extension
    }

    fn external_key_id(&self) -> Option<Vec<u8>> {
        self.external_key_id.clone()
    }

    fn key_package_repo(&self) -> InMemoryRepository {
        self.key_packages.clone()
    }
}
