use async_trait::async_trait;
use aws_mls_core::{identity::IdentityProvider, keychain::KeychainStorage};

use crate::{
    client_config::{MakeProposalFilter, ProposalFilterInit},
    crypto::SignaturePublicKey,
    extension::ExtensionType,
    group::proposal::ProposalType,
    identity::CredentialType,
    protocol_version::ProtocolVersion,
    tree_kem::Capabilities,
    CryptoProvider,
};

#[async_trait]
pub trait ExternalClientConfig: Clone + Send + Sync {
    type Keychain: KeychainStorage + Clone;
    type IdentityProvider: IdentityProvider + Clone;
    type MakeProposalFilter: MakeProposalFilter;
    type CryptoProvider: CryptoProvider;

    fn keychain(&self) -> Self::Keychain;
    fn supported_extensions(&self) -> Vec<ExtensionType>;
    fn supported_custom_proposals(&self) -> Vec<ProposalType>;
    fn supported_protocol_versions(&self) -> Vec<ProtocolVersion>;
    fn identity_provider(&self) -> Self::IdentityProvider;
    fn crypto_provider(&self) -> Self::CryptoProvider;
    fn external_signing_key(&self, external_key_id: &[u8]) -> Option<SignaturePublicKey>;
    fn proposal_filter(
        &self,
        init: ProposalFilterInit,
    ) -> <Self::MakeProposalFilter as MakeProposalFilter>::Filter;
    fn cache_proposals(&self) -> bool;

    fn max_epoch_jitter(&self) -> Option<u64> {
        None
    }

    fn capabilities(&self) -> Capabilities {
        Capabilities {
            protocol_versions: self.supported_protocol_versions(),
            cipher_suites: self.crypto_provider().supported_cipher_suites(),
            extensions: self.supported_extensions(),
            proposals: self.supported_custom_proposals(),
            credentials: self.supported_credentials(),
        }
    }

    fn version_supported(&self, version: ProtocolVersion) -> bool {
        self.supported_protocol_versions().contains(&version)
    }

    fn supported_credentials(&self) -> Vec<CredentialType> {
        self.identity_provider().supported_types()
    }
}
