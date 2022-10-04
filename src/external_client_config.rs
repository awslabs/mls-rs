use crate::{
    cipher_suite::{CipherSuite, MaybeCipherSuite},
    client_config::{KeepAllProposals, MakeProposalFilter, ProposalFilterInit},
    extension::ExtensionType,
    external_client::ExternalClient,
    group::proposal::ProposalFilter,
    identity::CredentialType,
    protocol_version::{MaybeProtocolVersion, ProtocolVersion},
    provider::{
        identity_validation::IdentityValidator,
        keychain::{InMemoryKeychain, Keychain},
    },
    signing_identity::SigningIdentity,
    tree_kem::Capabilities,
};
use ferriscrypt::asym::ec_key::{PublicKey, SecretKey};
use std::collections::HashMap;

pub trait ExternalClientConfig {
    type Keychain: Keychain;
    type IdentityValidator: IdentityValidator;
    type ProposalFilter: ProposalFilter;

    fn keychain(&self) -> Self::Keychain;
    fn supported_cipher_suites(&self) -> Vec<CipherSuite>;
    fn supported_extensions(&self) -> Vec<ExtensionType>;
    fn supported_protocol_versions(&self) -> Vec<ProtocolVersion>;
    fn identity_validator(&self) -> Self::IdentityValidator;
    fn external_signing_key(&self, external_key_id: &[u8]) -> Option<PublicKey>;
    fn proposal_filter(&self, init: ProposalFilterInit) -> Self::ProposalFilter;

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
        self.identity_validator().supported_types()
    }
}

#[derive(Clone)]
pub struct InMemoryExternalClientConfig<C: IdentityValidator> {
    supported_extensions: Vec<ExtensionType>,
    keychain: InMemoryKeychain,
    protocol_versions: Vec<ProtocolVersion>,
    cipher_suites: Vec<CipherSuite>,
    external_signing_keys: HashMap<Vec<u8>, PublicKey>,
    make_proposal_filter: KeepAllProposals,
    max_epoch_jitter: Option<u64>,
    identity_validator: C,
}

impl<C: IdentityValidator + Clone> InMemoryExternalClientConfig<C> {
    pub fn new(identity_validator: C) -> Self {
        Self {
            supported_extensions: Default::default(),
            keychain: Default::default(),
            protocol_versions: ProtocolVersion::all().collect(),
            cipher_suites: CipherSuite::all().collect(),
            external_signing_keys: Default::default(),
            make_proposal_filter: KeepAllProposals,
            max_epoch_jitter: Default::default(),
            identity_validator,
        }
    }

    #[must_use]
    pub fn with_supported_extension(mut self, extension: ExtensionType) -> Self {
        self.supported_extensions.push(extension);
        self
    }

    #[must_use]
    pub fn with_signing_identity(
        mut self,
        signing_identity: SigningIdentity,
        secret_key: SecretKey,
    ) -> Self {
        self.keychain.insert(signing_identity, secret_key);
        self
    }

    #[must_use]
    pub fn with_protocol_version(mut self, version: ProtocolVersion) -> Self {
        self.protocol_versions.push(version);
        self
    }

    #[must_use]
    pub fn clear_protocol_versions(mut self) -> Self {
        self.protocol_versions.clear();
        self
    }

    #[must_use]
    pub fn with_cipher_suite(mut self, cipher_suite: CipherSuite) -> Self {
        self.cipher_suites.push(cipher_suite);
        self
    }

    #[must_use]
    pub fn clear_cipher_suites(mut self) -> Self {
        self.cipher_suites.clear();
        self
    }

    #[must_use]
    pub fn with_external_signing_key(mut self, id: Vec<u8>, key: PublicKey) -> Self {
        self.external_signing_keys.insert(id, key);
        self
    }

    #[must_use]
    pub fn with_max_epoch_jitter(self, max_jitter: u64) -> Self {
        Self {
            max_epoch_jitter: Some(max_jitter),
            ..self
        }
    }

    pub fn build_client(self) -> ExternalClient<Self> {
        ExternalClient::new(self)
    }
}

impl<C: IdentityValidator + Clone> ExternalClientConfig for InMemoryExternalClientConfig<C> {
    type Keychain = InMemoryKeychain;
    type IdentityValidator = C;
    type ProposalFilter = KeepAllProposals;

    fn supported_cipher_suites(&self) -> Vec<CipherSuite> {
        self.cipher_suites.clone()
    }

    fn keychain(&self) -> Self::Keychain {
        self.keychain.clone()
    }

    fn supported_extensions(&self) -> Vec<ExtensionType> {
        self.supported_extensions.clone()
    }

    fn supported_protocol_versions(&self) -> Vec<ProtocolVersion> {
        self.protocol_versions.clone()
    }

    fn identity_validator(&self) -> Self::IdentityValidator {
        self.identity_validator.clone()
    }

    fn external_signing_key(&self, external_key_id: &[u8]) -> Option<PublicKey> {
        self.external_signing_keys.get(external_key_id).cloned()
    }

    fn proposal_filter(&self, init: ProposalFilterInit) -> Self::ProposalFilter {
        self.make_proposal_filter.make(init)
    }

    fn max_epoch_jitter(&self) -> Option<u64> {
        self.max_epoch_jitter
    }
}

#[cfg(test)]
pub mod test_utils {
    use crate::provider::identity_validation::BasicIdentityValidator;

    use super::InMemoryExternalClientConfig;

    pub type TestExternalClientConfig = InMemoryExternalClientConfig<BasicIdentityValidator>;

    impl Default for InMemoryExternalClientConfig<BasicIdentityValidator> {
        fn default() -> Self {
            InMemoryExternalClientConfig::new(BasicIdentityValidator::new())
        }
    }
}
