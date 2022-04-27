use crate::client_config::{CredentialValidator, PassthroughCredentialValidator};
use crate::{EpochRepository, InMemoryEpochRepository};

pub trait GroupConfig {
    type EpochRepository: EpochRepository;
    type CredentialValidator: CredentialValidator;

    fn epoch_repo(&self) -> Self::EpochRepository;
    fn credential_validator(&self) -> Self::CredentialValidator;
}

#[derive(Clone, Debug, Default)]
pub struct InMemoryGroupConfig {
    pub epoch_repo: InMemoryEpochRepository,
}

impl GroupConfig for InMemoryGroupConfig {
    type EpochRepository = InMemoryEpochRepository;
    type CredentialValidator = PassthroughCredentialValidator;

    fn epoch_repo(&self) -> InMemoryEpochRepository {
        self.epoch_repo.clone()
    }

    fn credential_validator(&self) -> Self::CredentialValidator {
        PassthroughCredentialValidator::new()
    }
}
