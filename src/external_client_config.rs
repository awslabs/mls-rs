use crate::{
    cipher_suite::{CipherSuite, MaybeCipherSuite},
    client_config::{CredentialValidator, PassthroughCredentialValidator},
    credential::{CredentialType, CREDENTIAL_TYPE_BASIC, CREDENTIAL_TYPE_X509},
    epoch::{InMemoryPublicEpochRepository, PublicEpochRepository},
    extension::ExtensionType,
    group::ExternalGroupConfig,
    keychain::{InMemoryKeychain, Keychain},
    signing_identity::SigningIdentity,
    tree_kem::Capabilities,
    ExternalClient, ProtocolVersion,
};
use ferriscrypt::asym::ec_key::{PublicKey, SecretKey};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

pub trait ExternalClientConfig {
    type Keychain: Keychain;
    type EpochRepository: PublicEpochRepository;
    type CredentialValidator: CredentialValidator;

    fn external_key_id(&self) -> Option<Vec<u8>>;
    fn keychain(&self) -> Self::Keychain;
    fn supported_cipher_suites(&self) -> Vec<CipherSuite>;
    fn supported_extensions(&self) -> Vec<ExtensionType>;
    fn supported_credentials(&self) -> Vec<CredentialType>;
    fn supported_protocol_versions(&self) -> Vec<ProtocolVersion>;
    fn epoch_repo(&self, group_id: &[u8]) -> Self::EpochRepository;
    fn credential_validator(&self) -> Self::CredentialValidator;
    fn external_signing_key(&self, external_key_id: &[u8]) -> Option<PublicKey>;
    fn signatures_are_checked(&self) -> bool;

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
    external_key_id: Option<Vec<u8>>,
    supported_extensions: Vec<ExtensionType>,
    keychain: InMemoryKeychain,
    protocol_versions: Vec<ProtocolVersion>,
    cipher_suites: Vec<CipherSuite>,
    epochs: Arc<Mutex<HashMap<Vec<u8>, InMemoryPublicEpochRepository>>>,
    external_signing_keys: HashMap<Vec<u8>, PublicKey>,
    credential_types: Vec<CredentialType>,
    signatures_checked: bool,
}

impl InMemoryExternalClientConfig {
    pub fn new() -> Self {
        Self {
            external_key_id: None,
            supported_extensions: Default::default(),
            keychain: Default::default(),
            protocol_versions: ProtocolVersion::all().collect(),
            cipher_suites: CipherSuite::all().collect(),
            epochs: Default::default(),
            external_signing_keys: Default::default(),
            credential_types: vec![CREDENTIAL_TYPE_BASIC, CREDENTIAL_TYPE_X509],
            signatures_checked: true,
        }
    }

    #[must_use]
    pub fn with_external_key_id(self, id: Vec<u8>) -> Self {
        Self {
            external_key_id: Some(id),
            ..self
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
    type EpochRepository = InMemoryPublicEpochRepository;
    type CredentialValidator = PassthroughCredentialValidator;

    fn external_key_id(&self) -> Option<Vec<u8>> {
        self.external_key_id.clone()
    }

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

    fn epoch_repo(&self, group_id: &[u8]) -> Self::EpochRepository {
        self.epochs
            .lock()
            .unwrap()
            .entry(group_id.to_vec())
            .or_default()
            .clone()
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
}

#[derive(Clone, Debug)]
pub struct ExternalClientGroupConfig<C: ExternalClientConfig> {
    pub epoch_repo: C::EpochRepository,
    pub credential_validator: C::CredentialValidator,
    pub signatures_checked: bool,
}

impl<C: ExternalClientConfig> ExternalClientGroupConfig<C> {
    pub fn new(client_config: &C, group_id: &[u8]) -> Self {
        Self {
            epoch_repo: client_config.epoch_repo(group_id),
            credential_validator: client_config.credential_validator(),
            signatures_checked: true,
        }
    }
}

impl<C> ExternalGroupConfig for ExternalClientGroupConfig<C>
where
    C: ExternalClientConfig,
    C::EpochRepository: Clone,
    C::CredentialValidator: Clone,
{
    type EpochRepository = C::EpochRepository;
    type CredentialValidator = C::CredentialValidator;

    fn epoch_repo(&self) -> Self::EpochRepository {
        self.epoch_repo.clone()
    }

    fn credential_validator(&self) -> Self::CredentialValidator {
        self.credential_validator.clone()
    }

    fn signatures_are_checked(&self) -> bool {
        self.signatures_checked
    }
}
