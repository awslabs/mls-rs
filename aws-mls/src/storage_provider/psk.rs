use crate::psk::ExternalPskIdValidator;

pub use crate::psk::{ExternalPskId, PreSharedKey};

use async_trait::async_trait;
use aws_mls_core::psk::PreSharedKeyStorage;
use thiserror::Error;

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
