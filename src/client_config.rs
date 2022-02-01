use crate::{
    group::proposal::Proposal,
    key_package::{KeyPackageError, KeyPackageGeneration, KeyPackageRef},
};
use ferriscrypt::asym::ec_key::PublicKey;
use std::{
    collections::HashMap,
    fmt::{self, Debug},
    sync::{Arc, Mutex},
};
use thiserror::Error;

pub trait KeyPackageRepository {
    type Error: std::error::Error + Send + Sync + 'static;

    fn insert(&mut self, key_pkg_gen: KeyPackageGeneration) -> Result<(), Self::Error>;
    fn get(&self, key_pkg: &KeyPackageRef) -> Result<Option<KeyPackageGeneration>, Self::Error>;
}

pub trait ClientConfig {
    type KeyPackageRepository: KeyPackageRepository;
    type ProposalFilterError: std::error::Error + Send + Sync + 'static;

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
    fn filter_proposal(&self, proposal: &Proposal) -> Result<(), Self::ProposalFilterError>;
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
        (*self).insert(key_pkg_gen)
    }

    fn get(&self, key_pkg: &KeyPackageRef) -> Result<Option<KeyPackageGeneration>, Self::Error> {
        Ok(self.get(key_pkg))
    }
}

#[derive(Clone, Default)]
#[non_exhaustive]
pub struct DefaultClientConfig {
    encrypt_controls: bool,
    ratchet_tree_extension: bool,
    external_signing_keys: HashMap<Vec<u8>, PublicKey>,
    external_key_id: Option<Vec<u8>>,
    key_packages: InMemoryRepository,
    proposal_filter: Option<ProposalFilter>,
}

type ProposalFilter = Arc<dyn Fn(&Proposal) -> Result<(), String> + Send + Sync>;

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

    #[must_use]
    pub fn with_proposal_filter<F, E>(self, f: F) -> Self
    where
        F: Fn(&Proposal) -> Result<(), E> + Send + Sync + 'static,
        E: ToString,
    {
        Self {
            proposal_filter: Some(Arc::new(move |p| f(p).map_err(|e| e.to_string()))),
            ..self
        }
    }
}

impl Debug for DefaultClientConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DefaultClientConfig")
            .field("encrypt_controls", &self.encrypt_controls)
            .field("ratchet_tree_extension", &self.ratchet_tree_extension)
            .field("external_signing_keys", &self.external_signing_keys)
            .field("external_key_id", &self.external_key_id)
            .field("key_packages", &self.key_packages)
            .field(
                "proposal_filter",
                &self
                    .proposal_filter
                    .as_ref()
                    .map_or("None", |_| "Some(...)"),
            )
            .finish()
    }
}

impl ClientConfig for DefaultClientConfig {
    type KeyPackageRepository = InMemoryRepository;
    type ProposalFilterError = SimpleError;

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

    fn filter_proposal(&self, proposal: &Proposal) -> Result<(), SimpleError> {
        self.proposal_filter
            .as_ref()
            .map_or(Ok(()), |f| f(proposal))
            .map_err(SimpleError)
    }

    fn key_package_repo(&self) -> InMemoryRepository {
        self.key_packages.clone()
    }
}

#[derive(Debug, Error)]
#[error("{0}")]
pub struct SimpleError(String);
