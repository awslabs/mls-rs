use crate::{
    cipher_suite::{CipherSuite, MaybeCipherSuite},
    credential::Credential,
    extension::{CapabilitiesExt, ExtensionType},
    key_package::{InMemoryKeyPackageRepository, KeyPackageRepository},
    ExternalClient, InMemoryKeychain, Keychain, ProtocolVersion,
};
use ferriscrypt::asym::ec_key::SecretKey;

pub trait ExternalClientConfig {
    type Keychain: Keychain;
    type KeyPackageRepository: KeyPackageRepository;

    fn external_key_id(&self) -> Option<Vec<u8>>;
    fn keychain(&self) -> Self::Keychain;
    fn key_package_repo(&self) -> Self::KeyPackageRepository;
    fn supported_cipher_suites(&self) -> Vec<CipherSuite>;
    fn supported_extensions(&self) -> Vec<ExtensionType>;
    fn supported_protocol_versions(&self) -> Vec<ProtocolVersion>;

    fn capabilities(&self) -> CapabilitiesExt {
        CapabilitiesExt {
            protocol_versions: self.supported_protocol_versions(),
            cipher_suites: self
                .supported_cipher_suites()
                .into_iter()
                .map(MaybeCipherSuite::from)
                .collect(),
            extensions: self.supported_extensions(),
            proposals: vec![], // TODO: Support registering custom proposals here
        }
    }
}

#[derive(Clone, Debug)]
pub struct InMemoryExternalClientConfig {
    external_key_id: Option<Vec<u8>>,
    supported_extensions: Vec<ExtensionType>,
    key_packages: InMemoryKeyPackageRepository,
    keychain: InMemoryKeychain,
    protocol_versions: Vec<ProtocolVersion>,
    cipher_suites: Vec<CipherSuite>,
}

impl InMemoryExternalClientConfig {
    pub fn new() -> Self {
        Self {
            external_key_id: None,
            supported_extensions: Default::default(),
            key_packages: Default::default(),
            keychain: Default::default(),
            protocol_versions: ProtocolVersion::all().collect(),
            cipher_suites: CipherSuite::all().collect(),
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
    pub fn with_credential(mut self, credential: Credential, secret_key: SecretKey) -> Self {
        self.keychain.insert(credential, secret_key);
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
    type KeyPackageRepository = InMemoryKeyPackageRepository;
    type Keychain = InMemoryKeychain;

    fn external_key_id(&self) -> Option<Vec<u8>> {
        self.external_key_id.clone()
    }

    fn key_package_repo(&self) -> InMemoryKeyPackageRepository {
        self.key_packages.clone()
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
}
