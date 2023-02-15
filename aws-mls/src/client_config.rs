use crate::{
    client_builder::Preferences,
    extension::ExtensionType,
    group::{
        framing::Sender,
        proposal::{BorrowedProposal, ProposalType},
        proposal_filter::{ProposalBundle, ProposalFilter, SimpleProposalFilter},
    },
    identity::CredentialType,
    protocol_version::ProtocolVersion,
    provider::{
        crypto::CryptoProvider, group_state::GroupStateStorage, key_package::KeyPackageStorage,
        keychain::KeychainStorage, psk::PreSharedKeyStorage,
    },
    tree_kem::{leaf_node::ConfigProperties, Capabilities, Lifetime},
    ExtensionList,
};
use async_trait::async_trait;
use aws_mls_core::identity::IdentityProvider;
use std::convert::Infallible;

pub use crate::group::proposal_filter::ProposalFilterContext;

#[async_trait]
pub trait ClientConfig: Clone + Send + Sync {
    type KeyPackageRepository: KeyPackageStorage + Clone;
    type Keychain: KeychainStorage + Clone;
    type PskStore: PreSharedKeyStorage + Clone;
    type GroupStateStorage: GroupStateStorage + Clone;
    type IdentityProvider: IdentityProvider + Clone;
    type MakeProposalFilter: MakeProposalFilter + Clone;
    type CryptoProvider: CryptoProvider + Clone;

    fn supported_extensions(&self) -> Vec<ExtensionType>;
    fn supported_custom_proposals(&self) -> Vec<ProposalType>;
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
    fn identity_provider(&self) -> Self::IdentityProvider;
    fn crypto_provider(&self) -> Self::CryptoProvider;

    fn key_package_extensions(&self) -> ExtensionList;
    fn leaf_node_extensions(&self) -> ExtensionList;
    fn lifetime(&self) -> Lifetime;

    fn capabilities(&self) -> Capabilities {
        Capabilities {
            protocol_versions: self.supported_protocol_versions(),
            cipher_suites: self.crypto_provider().supported_cipher_suites(),
            extensions: self.supported_extensions(),
            proposals: self.supported_custom_proposals(),
            credentials: self.supported_credential_types(),
        }
    }

    fn version_supported(&self, version: ProtocolVersion) -> bool {
        self.supported_protocol_versions().contains(&version)
    }

    fn supported_credential_types(&self) -> Vec<CredentialType> {
        self.identity_provider().supported_types()
    }

    fn leaf_properties(&self) -> ConfigProperties {
        ConfigProperties {
            capabilities: self.capabilities(),
            extensions: self.leaf_node_extensions(),
        }
    }
}

pub trait MakeProposalFilter: Send + Sync {
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
    F: Fn(&ProposalFilterContext, &BorrowedProposal<'_>) -> Result<(), E> + Clone + Send + Sync,
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
