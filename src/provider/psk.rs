use std::{
    collections::HashMap,
    convert::Infallible,
    sync::{Arc, Mutex},
};

use thiserror::Error;

use crate::psk::{ExternalPskId, ExternalPskIdValidator, Psk};

pub trait PskStore {
    type Error: std::error::Error + Send + Sync + 'static;

    fn psk(&self, id: &ExternalPskId) -> Result<Option<Psk>, Self::Error>;
}

#[derive(Debug, Clone)]
pub(crate) struct PskStoreIdValidator<T>(T);

impl<T> From<T> for PskStoreIdValidator<T>
where
    T: PskStore,
{
    fn from(store: T) -> Self {
        PskStoreIdValidator(store)
    }
}

impl<T: PskStore> ExternalPskIdValidator for PskStoreIdValidator<T> {
    type Error = PskStoreIdValidationError<T::Error>;

    fn validate(&self, id: &ExternalPskId) -> Result<(), Self::Error> {
        self.0
            .psk(id)?
            .map(|_| ())
            .ok_or_else(|| PskStoreIdValidationError::ExternalIdNotFound(id.clone()))
    }
}

#[derive(Debug, Error)]
pub enum PskStoreIdValidationError<E: std::error::Error> {
    #[error("External PSK ID {0:?} not found")]
    ExternalIdNotFound(ExternalPskId),
    #[error(transparent)]
    Other(#[from] E),
}

#[derive(Clone, Debug, Default)]
pub struct InMemoryPskStore {
    inner: Arc<Mutex<HashMap<ExternalPskId, Psk>>>,
}

impl InMemoryPskStore {
    pub fn insert(&mut self, id: ExternalPskId, psk: Psk) -> Option<Psk> {
        self.inner.lock().unwrap().insert(id, psk)
    }
}

impl PskStore for InMemoryPskStore {
    type Error = Infallible;

    fn psk(&self, id: &ExternalPskId) -> Result<Option<Psk>, Self::Error> {
        Ok(self.inner.lock().unwrap().get(id).cloned())
    }
}
