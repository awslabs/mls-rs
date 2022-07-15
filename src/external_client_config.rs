use crate::{
    cipher_suite::{CipherSuite, MaybeCipherSuite},
    client_config::{
        CredentialValidator, MakeProposalFilter, PassthroughCredentialValidator,
        ProposalFilterInit, SimpleError,
    },
    credential::{CredentialType, CREDENTIAL_TYPE_BASIC, CREDENTIAL_TYPE_X509},
    extension::ExtensionType,
    group::ExternalGroupConfig,
    keychain::{InMemoryKeychain, Keychain},
    signing_identity::SigningIdentity,
    tree_kem::Capabilities,
    BoxedProposalFilter, ExternalClient, ProposalFilter, ProtocolVersion,
};
use ferriscrypt::asym::ec_key::{PublicKey, SecretKey};
use std::collections::HashMap;

pub trait ExternalClientConfig {
    type Keychain: Keychain;
    type CredentialValidator: CredentialValidator;
    type ProposalFilter: ProposalFilter;

    fn keychain(&self) -> Self::Keychain;
    fn supported_cipher_suites(&self) -> Vec<CipherSuite>;
    fn supported_extensions(&self) -> Vec<ExtensionType>;
    fn supported_credentials(&self) -> Vec<CredentialType>;
    fn supported_protocol_versions(&self) -> Vec<ProtocolVersion>;
    fn credential_validator(&self) -> Self::CredentialValidator;
    fn external_signing_key(&self, external_key_id: &[u8]) -> Option<PublicKey>;
    fn signatures_are_checked(&self) -> bool;
    fn proposal_filter(&self, init: ProposalFilterInit<'_>) -> Self::ProposalFilter;

    fn capabilities(&self) -> Capabilities {
        Capabilities {
            protocol_versions: self.supported_protocol_versions(),
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
}

#[derive(Clone, Debug)]
pub struct InMemoryExternalClientConfig {
    supported_extensions: Vec<ExtensionType>,
    keychain: InMemoryKeychain,
    protocol_versions: Vec<ProtocolVersion>,
    cipher_suites: Vec<CipherSuite>,
    external_signing_keys: HashMap<Vec<u8>, PublicKey>,
    credential_types: Vec<CredentialType>,
    signatures_checked: bool,
    make_proposal_filter: MakeProposalFilter,
}

impl InMemoryExternalClientConfig {
    pub fn new() -> Self {
        Self {
            supported_extensions: Default::default(),
            keychain: Default::default(),
            protocol_versions: ProtocolVersion::all().collect(),
            cipher_suites: CipherSuite::all().collect(),
            external_signing_keys: Default::default(),
            credential_types: vec![CREDENTIAL_TYPE_BASIC, CREDENTIAL_TYPE_X509],
            signatures_checked: true,
            make_proposal_filter: Default::default(),
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
    pub fn with_credential_types(mut self, credential_types: Vec<CredentialType>) -> Self {
        self.credential_types = credential_types;
        self
    }

    #[must_use]
    pub fn check_signatures(self, checked: bool) -> Self {
        Self {
            signatures_checked: checked,
            ..self
        }
    }

    pub fn build_client(self) -> ExternalClient<Self> {
        ExternalClient::new(self)
    }
}

impl Default for InMemoryExternalClientConfig {
    fn default() -> Self {
        Self::new()
    }
}

impl ExternalClientConfig for InMemoryExternalClientConfig {
    type Keychain = InMemoryKeychain;
    type CredentialValidator = PassthroughCredentialValidator;
    type ProposalFilter = BoxedProposalFilter<SimpleError>;

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

    fn credential_validator(&self) -> Self::CredentialValidator {
        Default::default()
    }

    fn external_signing_key(&self, external_key_id: &[u8]) -> Option<PublicKey> {
        self.external_signing_keys.get(external_key_id).cloned()
    }

    fn signatures_are_checked(&self) -> bool {
        self.signatures_checked
    }

    fn supported_credentials(&self) -> Vec<CredentialType> {
        self.credential_types.clone()
    }

    fn proposal_filter(&self, init: ProposalFilterInit<'_>) -> Self::ProposalFilter {
        (self.make_proposal_filter.0)(init)
    }
}

#[derive(Clone, Debug)]
pub struct ExternalClientGroupConfig<C> {
    client_config: C,
    signatures_checked: bool,
}

impl<C> ExternalClientGroupConfig<C> {
    pub fn new(client_config: C) -> Self {
        Self {
            client_config,
            signatures_checked: true,
        }
    }
}

impl<C> ExternalGroupConfig for ExternalClientGroupConfig<C>
where
    C: ExternalClientConfig,
{
    type CredentialValidator = C::CredentialValidator;
    type ProposalFilter = C::ProposalFilter;

    fn credential_validator(&self) -> Self::CredentialValidator {
        self.client_config.credential_validator()
    }

    fn signatures_are_checked(&self) -> bool {
        self.signatures_checked
    }

    fn proposal_filter(&self, init: ProposalFilterInit<'_>) -> Self::ProposalFilter {
        self.client_config.proposal_filter(init)
    }
}
