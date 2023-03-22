use crate::{
    client_builder::Preferences,
    extension::ExtensionType,
    group::{proposal::ProposalType, proposal_filter::ProposalRules},
    identity::CredentialType,
    protocol_version::ProtocolVersion,
    tree_kem::{leaf_node::ConfigProperties, Capabilities, Lifetime},
    ExtensionList,
};
use async_trait::async_trait;
use aws_mls_core::{
    crypto::CryptoProvider, group::GroupStateStorage, identity::IdentityProvider,
    key_package::KeyPackageStorage, keychain::KeychainStorage, psk::PreSharedKeyStorage,
};

#[async_trait]
pub trait ClientConfig: Clone + Send + Sync {
    type KeyPackageRepository: KeyPackageStorage + Clone;
    type Keychain: KeychainStorage + Clone;
    type PskStore: PreSharedKeyStorage + Clone;
    type GroupStateStorage: GroupStateStorage + Clone;
    type IdentityProvider: IdentityProvider + Clone;
    type ProposalRules: ProposalRules + Clone;
    type CryptoProvider: CryptoProvider + Clone;

    fn supported_extensions(&self) -> Vec<ExtensionType>;
    fn supported_custom_proposals(&self) -> Vec<ProposalType>;
    fn supported_protocol_versions(&self) -> Vec<ProtocolVersion>;

    fn preferences(&self) -> Preferences;
    fn key_package_repo(&self) -> Self::KeyPackageRepository;

    fn proposal_rules(&self) -> Self::ProposalRules;

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
