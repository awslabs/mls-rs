use crate::{
    client_config::{
        CredentialValidator, MakeProposalFilter, PassthroughCredentialValidator,
        ProposalFilterInit, SimpleError,
    },
    epoch::{InMemoryPublicEpochRepository, PublicEpochRepository},
    BoxedProposalFilter, ProposalFilter,
};

pub trait ExternalGroupConfig {
    type EpochRepository: PublicEpochRepository;
    type CredentialValidator: CredentialValidator;
    type ProposalFilter: ProposalFilter;

    fn epoch_repo(&self) -> Self::EpochRepository;
    fn credential_validator(&self) -> Self::CredentialValidator;
    fn signatures_are_checked(&self) -> bool;
    fn proposal_filter(&self, init: ProposalFilterInit<'_>) -> Self::ProposalFilter;
}

#[derive(Clone, Debug, Default)]
pub struct InMemoryExternalGroupConfig {
    pub epoch_repo: InMemoryPublicEpochRepository,
    pub signatures_checked: bool,
    pub make_proposal_filter: MakeProposalFilter,
}

impl ExternalGroupConfig for InMemoryExternalGroupConfig {
    type EpochRepository = InMemoryPublicEpochRepository;
    type CredentialValidator = PassthroughCredentialValidator;
    type ProposalFilter = BoxedProposalFilter<SimpleError>;

    fn epoch_repo(&self) -> Self::EpochRepository {
        self.epoch_repo.clone()
    }

    fn credential_validator(&self) -> Self::CredentialValidator {
        PassthroughCredentialValidator::new()
    }

    fn signatures_are_checked(&self) -> bool {
        self.signatures_checked
    }

    fn proposal_filter(&self, init: ProposalFilterInit<'_>) -> Self::ProposalFilter {
        (self.make_proposal_filter.0)(init)
    }
}
