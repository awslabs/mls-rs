use crate::{
    client_config::{CredentialValidator, PassthroughCredentialValidator},
    epoch::{InMemoryPublicEpochRepository, PublicEpochRepository},
};

pub trait ExternalGroupConfig {
    type EpochRepository: PublicEpochRepository;
    type CredentialValidator: CredentialValidator;

    fn epoch_repo(&self) -> Self::EpochRepository;
    fn credential_validator(&self) -> Self::CredentialValidator;
    fn signatures_are_checked(&self) -> bool;
}

#[derive(Clone, Debug, Default)]
pub struct InMemoryExternalGroupConfig {
    pub epoch_repo: InMemoryPublicEpochRepository,
    pub signatures_checked: bool,
}

impl ExternalGroupConfig for InMemoryExternalGroupConfig {
    type EpochRepository = InMemoryPublicEpochRepository;
    type CredentialValidator = PassthroughCredentialValidator;

    fn epoch_repo(&self) -> Self::EpochRepository {
        self.epoch_repo.clone()
    }

    fn credential_validator(&self) -> Self::CredentialValidator {
        PassthroughCredentialValidator::new()
    }

    fn signatures_are_checked(&self) -> bool {
        self.signatures_checked
    }
}
