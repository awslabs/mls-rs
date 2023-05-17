use aws_mls_core::{identity::IdentityProvider, keychain::KeychainStorage};

use crate::{
    crypto::SignaturePublicKey,
    extension::ExtensionType,
    group::{proposal::ProposalType, proposal_filter::ProposalRules},
    identity::CredentialType,
    protocol_version::ProtocolVersion,
    tree_kem::Capabilities,
    CryptoProvider,
};

pub trait ExternalClientConfig: Send + Sync + Clone {
    type Keychain: KeychainStorage + Clone;
    type IdentityProvider: IdentityProvider + Clone;
    type ProposalRules: ProposalRules + Clone;
    type CryptoProvider: CryptoProvider;

    fn keychain(&self) -> Self::Keychain;
    fn supported_extensions(&self) -> Vec<ExtensionType>;
    fn supported_custom_proposals(&self) -> Vec<ProposalType>;
    fn supported_protocol_versions(&self) -> Vec<ProtocolVersion>;
    fn identity_provider(&self) -> Self::IdentityProvider;
    fn crypto_provider(&self) -> Self::CryptoProvider;
    fn external_signing_key(&self, external_key_id: &[u8]) -> Option<SignaturePublicKey>;

    fn proposal_rules(&self) -> Self::ProposalRules;

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
