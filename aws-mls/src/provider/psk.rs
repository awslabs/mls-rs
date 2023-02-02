use std::{
    collections::HashMap,
    convert::Infallible,
    sync::{Arc, Mutex},
};

use async_trait::async_trait;
use thiserror::Error;

use crate::psk::{ExternalPskId, ExternalPskIdValidator, PreSharedKey};

pub use aws_mls_core::psk::PreSharedKeyStorage;

#[derive(Debug, Clone)]
pub(crate) struct PskStoreIdValidator<T>(T);

impl<T> From<T> for PskStoreIdValidator<T>
where
    T: PreSharedKeyStorage,
{
    fn from(store: T) -> Self {
        PskStoreIdValidator(store)
    }
}

#[async_trait]
impl<T: PreSharedKeyStorage> ExternalPskIdValidator for PskStoreIdValidator<T> {
    type Error = PskStoreIdValidationError<T::Error>;

    async fn validate(&self, id: &ExternalPskId) -> Result<(), Self::Error> {
        self.0
            .get(id)
            .await?
            .map(|_| ())
            .ok_or_else(|| PskStoreIdValidationError::ExternalIdNotFound(id.clone()))
    }
}

#[derive(Debug, Error)]
pub(crate) enum PskStoreIdValidationError<E> {
    #[error("External PSK ID {0:?} not found")]
    ExternalIdNotFound(ExternalPskId),
    #[error(transparent)]
    Other(#[from] E),
}

#[derive(Clone, Debug, Default)]
pub struct InMemoryPreSharedKeyStorage {
    inner: Arc<Mutex<HashMap<ExternalPskId, PreSharedKey>>>,
}

impl InMemoryPreSharedKeyStorage {
    pub fn insert(&mut self, id: ExternalPskId, psk: PreSharedKey) {
        self.inner.lock().unwrap().insert(id, psk);
    }

    pub fn get(&self, id: &ExternalPskId) -> Option<PreSharedKey> {
        self.inner.lock().unwrap().get(id).cloned()
    }

    pub fn delete(&mut self, id: &ExternalPskId) {
        self.inner.lock().unwrap().remove(id);
    }
}

#[async_trait]
impl PreSharedKeyStorage for InMemoryPreSharedKeyStorage {
    type Error = Infallible;

    async fn get(&self, id: &ExternalPskId) -> Result<Option<PreSharedKey>, Self::Error> {
        Ok(self.get(id))
    }

    async fn delete(&mut self, id: &ExternalPskId) -> Result<(), Self::Error> {
        self.delete(id);
        Ok(())
    }

    async fn insert(&mut self, id: ExternalPskId, psk: PreSharedKey) -> Result<(), Self::Error> {
        self.insert(id, psk);
        Ok(())
    }
}
