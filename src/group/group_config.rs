use crate::{
    cipher_suite::CipherSuite,
    client_config::{CredentialValidator, ProposalFilterInit},
    extension::ExtensionList,
    signer::Signer,
    signing_identity::SigningIdentity,
    tree_kem::{Capabilities, Lifetime},
    EpochRepository, ProposalFilter,
};

pub trait GroupConfig {
    type EpochRepository: EpochRepository;
    type CredentialValidator: CredentialValidator;
    type ProposalFilter: ProposalFilter;
    type Signer: Signer;

    fn epoch_repo(&self) -> Self::EpochRepository;
    fn credential_validator(&self) -> Self::CredentialValidator;
    fn proposal_filter(&self, init: ProposalFilterInit<'_>) -> Self::ProposalFilter;
    fn leaf_node_extensions(&self) -> ExtensionList;
    fn lifetime(&self) -> Lifetime;
    fn capabilities(&self) -> Capabilities;
    fn signing_identity(
        &self,
        cipher_suite: CipherSuite,
    ) -> Option<(SigningIdentity, Self::Signer)>;
}
