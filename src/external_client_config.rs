use crate::{
    cipher_suite::{CipherSuite, MaybeCipherSuite},
    client_config::{MakeProposalFilter, ProposalFilterInit},
    extension::ExtensionType,
    identity::CredentialType,
    protocol_version::{MaybeProtocolVersion, ProtocolVersion},
    provider::{identity::IdentityProvider, keychain::KeychainStorage},
    tree_kem::Capabilities,
};
use ferriscrypt::asym::ec_key::PublicKey;

pub trait ExternalClientConfig: Clone {
    type Keychain: KeychainStorage + Clone;
    type IdentityProvider: IdentityProvider + Clone;
    type MakeProposalFilter: MakeProposalFilter;

    fn keychain(&self) -> Self::Keychain;
    fn supported_cipher_suites(&self) -> Vec<CipherSuite>;
    fn supported_extensions(&self) -> Vec<ExtensionType>;
    fn supported_protocol_versions(&self) -> Vec<ProtocolVersion>;
    fn identity_provider(&self) -> Self::IdentityProvider;
    fn external_signing_key(&self, external_key_id: &[u8]) -> Option<PublicKey>;
    fn proposal_filter(
        &self,
        init: ProposalFilterInit,
    ) -> <Self::MakeProposalFilter as MakeProposalFilter>::Filter;

    fn max_epoch_jitter(&self) -> Option<u64> {
        None
    }

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
            credentials: self.supported_credentials(),
        }
    }

    fn version_supported(&self, version: ProtocolVersion) -> bool {
        self.supported_protocol_versions().contains(&version)
    }

    fn cipher_suite_supported(&self, cipher_suite: CipherSuite) -> bool {
        self.supported_cipher_suites().contains(&cipher_suite)
    }

    fn supported_credentials(&self) -> Vec<CredentialType> {
        self.identity_provider().supported_types()
    }
}
