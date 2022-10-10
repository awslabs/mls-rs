use crate::{
    cipher_suite::{CipherSuite, MaybeCipherSuite},
    client_builder::Preferences,
    extension::{ExtensionList, ExtensionType, KeyPackageExtension, LeafNodeExtension},
    group::{
        framing::Sender,
        proposal::BorrowedProposal,
        proposal_filter::{
            ProposalBundle, ProposalFilter, ProposalFilterContext, SimpleProposalFilter,
        },
    },
    identity::CredentialType,
    protocol_version::{MaybeProtocolVersion, ProtocolVersion},
    provider::{
        group_state::GroupStateStorage, identity_validation::IdentityValidator,
        key_package::KeyPackageRepository, keychain::KeychainStorage, psk::PskStore,
    },
    tree_kem::{Capabilities, Lifetime},
};
use std::convert::Infallible;

pub trait ClientConfig: Clone {
    type KeyPackageRepository: KeyPackageRepository + Clone;
    type Keychain: KeychainStorage + Clone;
    type PskStore: PskStore + Clone;
    type GroupStateStorage: GroupStateStorage + Clone;
    type IdentityValidator: IdentityValidator + Clone;
    type MakeProposalFilter: MakeProposalFilter;

    fn supported_cipher_suites(&self) -> Vec<CipherSuite>;
    fn supported_extensions(&self) -> Vec<ExtensionType>;
    fn supported_protocol_versions(&self) -> Vec<ProtocolVersion>;

    fn preferences(&self) -> Preferences;
    fn key_package_repo(&self) -> Self::KeyPackageRepository;
    fn proposal_filter(
        &self,
        init: ProposalFilterInit,
    ) -> <Self::MakeProposalFilter as MakeProposalFilter>::Filter;
    fn keychain(&self) -> Self::Keychain;
    fn secret_store(&self) -> Self::PskStore;

    fn group_state_storage(&self) -> Self::GroupStateStorage;

    fn identity_validator(&self) -> Self::IdentityValidator;
    fn key_package_extensions(&self) -> ExtensionList<KeyPackageExtension>;
    fn leaf_node_extensions(&self) -> ExtensionList<LeafNodeExtension>;
    fn lifetime(&self) -> Lifetime;

    fn capabilities(&self) -> Capabilities {
        Capabilities {
            protocol_versions: self
                .supported_protocol_versions()
                .into_iter()
                .map(MaybeProtocolVersion::from)
                .collect(),
            cipher_suites: self
                .supported_cipher_suites()
                .into_iter()
                .map(MaybeCipherSuite::from)
                .collect(),
            extensions: self.supported_extensions(),
            proposals: vec![], // TODO: Support registering custom proposals here
            credentials: self.supported_credential_types(),
        }
    }

    fn version_supported(&self, version: ProtocolVersion) -> bool {
        self.supported_protocol_versions().contains(&version)
    }

    fn cipher_suite_supported(&self, cipher_suite: CipherSuite) -> bool {
        self.supported_cipher_suites().contains(&cipher_suite)
    }

    fn supported_credential_types(&self) -> Vec<CredentialType> {
        self.identity_validator().supported_types()
    }
}

pub trait MakeProposalFilter {
    type Filter: ProposalFilter;

    fn make(&self, init: ProposalFilterInit) -> Self::Filter;
}

#[derive(Clone, Debug)]
pub struct ProposalFilterInit {
    committer: Sender,
}

impl ProposalFilterInit {
    pub fn new(committer: Sender) -> Self {
        Self { committer }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct MakeSimpleProposalFilter<F>(pub(crate) F);

#[derive(Clone, Copy, Debug)]
pub struct KeepAllProposals;

impl MakeProposalFilter for KeepAllProposals {
    type Filter = Self;

    fn make(&self, _: ProposalFilterInit) -> Self {
        Self
    }
}

impl ProposalFilter for KeepAllProposals {
    type Error = Infallible;

    fn validate(&self, _: &ProposalBundle) -> Result<(), Infallible> {
        Ok(())
    }

    fn filter(&self, proposals: ProposalBundle) -> Result<ProposalBundle, Infallible> {
        Ok(proposals)
    }
}

impl<F, E> MakeProposalFilter for MakeSimpleProposalFilter<F>
where
    F: Fn(&ProposalFilterContext, &BorrowedProposal<'_>) -> Result<(), E> + Clone,
    E: std::error::Error + Send + Sync + 'static,
{
    type Filter = SimpleProposalFilter<F>;

    fn make(&self, init: ProposalFilterInit) -> Self::Filter {
        SimpleProposalFilter {
            committer: init.committer,
            filter: self.0.clone(),
        }
    }
}
