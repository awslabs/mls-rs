use crate::{
    client_config::{
        CredentialValidator, MakeProposalFilter, PassthroughCredentialValidator,
        ProposalFilterInit, SimpleError,
    },
    BoxedProposalFilter, EpochRepository, InMemoryEpochRepository, ProposalFilter,
};

pub trait GroupConfig {
    type EpochRepository: EpochRepository;
    type CredentialValidator: CredentialValidator;
    type ProposalFilter: ProposalFilter;

    fn epoch_repo(&self) -> Self::EpochRepository;
    fn credential_validator(&self) -> Self::CredentialValidator;
    fn proposal_filter(&self, init: ProposalFilterInit<'_>) -> Self::ProposalFilter;
}

#[derive(Clone, Debug, Default)]
pub struct InMemoryGroupConfig {
    pub epoch_repo: InMemoryEpochRepository,
    pub make_proposal_filter: MakeProposalFilter,
}

impl GroupConfig for InMemoryGroupConfig {
    type EpochRepository = InMemoryEpochRepository;
    type CredentialValidator = PassthroughCredentialValidator;
    type ProposalFilter = BoxedProposalFilter<SimpleError>;

    fn epoch_repo(&self) -> InMemoryEpochRepository {
        self.epoch_repo.clone()
    }

    fn credential_validator(&self) -> Self::CredentialValidator {
        PassthroughCredentialValidator::new()
    }

    fn proposal_filter(&self, init: ProposalFilterInit<'_>) -> Self::ProposalFilter {
        (self.make_proposal_filter.0)(init)
    }
}
