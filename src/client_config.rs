use crate::{
    cipher_suite::{CipherSuite, MaybeCipherSuite},
    client::Client,
    credential::Credential,
    extension::{CapabilitiesExt, ExtensionType},
    group::{proposal::Proposal, ControlEncryptionMode},
    key_package::{KeyPackageError, KeyPackageGeneration, KeyPackageRef},
    psk::{ExternalPskId, Psk},
    signer::Signer,
    ProtocolVersion,
};
use ferriscrypt::asym::ec_key::{Curve, PublicKey, SecretKey};
use std::{
    collections::HashMap,
    convert::Infallible,
    fmt::{self, Debug},
    sync::{Arc, Mutex},
};
use thiserror::Error;

pub use crate::group::padding::PaddingMode;

pub trait KeyPackageRepository {
    type Error: std::error::Error + Send + Sync + 'static;

    fn insert(&mut self, key_pkg_gen: KeyPackageGeneration) -> Result<(), Self::Error>;
    fn get(&self, key_pkg: &KeyPackageRef) -> Result<Option<KeyPackageGeneration>, Self::Error>;
}

pub trait Keychain {
    type Signer: Signer;

    fn default_credential(&self, cipher_suite: CipherSuite) -> Option<(Credential, Self::Signer)>;
    fn signer(&self, credential: &Credential) -> Option<Self::Signer>;
}

pub trait PskStore {
    type Error: std::error::Error + Send + Sync + 'static;

    fn psk(&self, id: &ExternalPskId) -> Result<Option<Psk>, Self::Error>;
}

pub trait ClientConfig {
    type KeyPackageRepository: KeyPackageRepository;
    type ProposalFilterError: std::error::Error + Send + Sync + 'static;
    type Keychain: Keychain;
    type PskStore: PskStore;

    fn supported_cipher_suites(&self) -> Vec<CipherSuite>;
    fn supported_extensions(&self) -> Vec<ExtensionType>;
    fn supported_protocol_versions(&self) -> Vec<ProtocolVersion>;

    fn external_signing_key(&self, external_key_id: &[u8]) -> Option<PublicKey>;
    fn preferences(&self) -> Preferences;
    fn external_key_id(&self) -> Option<Vec<u8>>;
    fn key_package_repo(&self) -> Self::KeyPackageRepository;
    fn filter_proposal(&self, proposal: &Proposal) -> Result<(), Self::ProposalFilterError>;
    fn keychain(&self) -> Self::Keychain;
    fn secret_store(&self) -> Self::PskStore;

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

#[derive(Clone, Default, Debug)]
pub struct InMemoryRepository {
    inner: Arc<Mutex<HashMap<KeyPackageRef, KeyPackageGeneration>>>,
}

impl InMemoryRepository {
    pub fn insert(&self, key_pkg_gen: KeyPackageGeneration) -> Result<(), KeyPackageError> {
        self.inner
            .lock()
            .unwrap()
            .insert(key_pkg_gen.key_package.to_reference()?, key_pkg_gen);
        Ok(())
    }

    pub fn get(&self, r: &KeyPackageRef) -> Option<KeyPackageGeneration> {
        self.inner.lock().unwrap().get(r).cloned()
    }
}

impl KeyPackageRepository for InMemoryRepository {
    type Error = KeyPackageError;

    fn insert(&mut self, key_pkg_gen: KeyPackageGeneration) -> Result<(), Self::Error> {
        (*self).insert(key_pkg_gen)
    }

    fn get(&self, key_pkg: &KeyPackageRef) -> Result<Option<KeyPackageGeneration>, Self::Error> {
        Ok(self.get(key_pkg))
    }
}

#[derive(Clone, Debug, Default)]
pub struct InMemoryKeychain {
    secret_keys: Arc<Mutex<HashMap<Credential, SecretKey>>>,
}

impl InMemoryKeychain {
    pub fn insert(&mut self, credential: Credential, secret_key: SecretKey) -> Option<SecretKey> {
        self.secret_keys
            .lock()
            .unwrap()
            .insert(credential, secret_key)
    }
}

impl Keychain for InMemoryKeychain {
    fn default_credential(&self, cipher_suite: CipherSuite) -> Option<(Credential, SecretKey)> {
        let cipher_suite_curve = Curve::from(cipher_suite.signature_scheme());

        self.secret_keys
            .lock()
            .unwrap()
            .iter()
            .find_map(|(credential, sk)| {
                credential
                    .public_key()
                    .ok()
                    .filter(|pk| pk.curve() == cipher_suite_curve)
                    .map(|_| (credential.clone(), sk.clone()))
            })
    }

    type Signer = SecretKey;

    fn signer(&self, credential: &Credential) -> Option<Self::Signer> {
        self.secret_keys.lock().unwrap().get(credential).cloned()
    }
}

#[derive(Clone, Debug, Default)]
pub struct InMemoryPskStore {
    inner: Arc<Mutex<HashMap<ExternalPskId, Psk>>>,
}

impl InMemoryPskStore {
    pub fn insert(&mut self, id: ExternalPskId, psk: Psk) -> Option<Psk> {
        self.inner.lock().unwrap().insert(id, psk)
    }
}

impl PskStore for InMemoryPskStore {
    type Error = Infallible;

    fn psk(&self, id: &ExternalPskId) -> Result<Option<Psk>, Self::Error> {
        Ok(self.inner.lock().unwrap().get(id).cloned())
    }
}

#[derive(Clone, Debug, Default)]
pub struct Preferences {
    pub encrypt_controls: bool,
    pub ratchet_tree_extension: bool,
    pub padding_mode: PaddingMode,
}

impl Preferences {
    #[must_use]
    pub fn with_control_encryption(self, yes: bool) -> Self {
        Self {
            encrypt_controls: yes,
            ..self
        }
    }

    #[must_use]
    pub fn with_ratchet_tree_extension(self, yes: bool) -> Self {
        Self {
            ratchet_tree_extension: yes,
            ..self
        }
    }

    #[must_use]
    pub fn with_padding_mode(self, padding_mode: PaddingMode) -> Self {
        Self {
            padding_mode,
            ..self
        }
    }

    pub(crate) fn encryption_mode(&self) -> ControlEncryptionMode {
        if self.encrypt_controls {
            ControlEncryptionMode::Encrypted(self.padding_mode)
        } else {
            ControlEncryptionMode::Plaintext
        }
    }
}

#[derive(Clone)]
#[non_exhaustive]
pub struct InMemoryClientConfig {
    preferences: Preferences,
    external_signing_keys: HashMap<Vec<u8>, PublicKey>,
    external_key_id: Option<Vec<u8>>,
    supported_extensions: Vec<ExtensionType>,
    key_packages: InMemoryRepository,
    proposal_filter: Option<ProposalFilter>,
    keychain: InMemoryKeychain,
    psk_store: InMemoryPskStore,
    protocol_versions: Vec<ProtocolVersion>,
    cipher_suites: Vec<CipherSuite>,
}

type ProposalFilter = Arc<dyn Fn(&Proposal) -> Result<(), String> + Send + Sync>;

impl InMemoryClientConfig {
    pub fn new() -> Self {
        Self {
            preferences: Default::default(),
            external_signing_keys: Default::default(),
            external_key_id: Default::default(),
            supported_extensions: Default::default(),
            key_packages: Default::default(),
            proposal_filter: Default::default(),
            keychain: Default::default(),
            psk_store: Default::default(),
            protocol_versions: ProtocolVersion::all().collect(),
            cipher_suites: CipherSuite::all().collect(),
        }
    }

    #[must_use]
    pub fn with_preferences(self, preferences: Preferences) -> Self {
        Self {
            preferences,
            ..self
        }
    }

    #[must_use]
    pub fn with_supported_extension(mut self, extension: ExtensionType) -> Self {
        self.supported_extensions.push(extension);
        self
    }

    #[must_use]
    pub fn with_external_signing_key(mut self, id: Vec<u8>, key: PublicKey) -> Self {
        self.external_signing_keys.insert(id, key);
        self
    }

    #[must_use]
    pub fn with_external_key_id(self, id: Vec<u8>) -> Self {
        Self {
            external_key_id: Some(id),
            ..self
        }
    }

    #[must_use]
    pub fn with_proposal_filter<F, E>(self, f: F) -> Self
    where
        F: Fn(&Proposal) -> Result<(), E> + Send + Sync + 'static,
        E: ToString,
    {
        Self {
            proposal_filter: Some(Arc::new(move |p| f(p).map_err(|e| e.to_string()))),
            ..self
        }
    }

    #[must_use]
    pub fn with_psk(mut self, psk_id: ExternalPskId, psk: Psk) -> Self {
        self.psk_store.insert(psk_id, psk);
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

    pub fn build_client(self) -> Client<Self> {
        Client::new(self)
    }
}

impl Default for InMemoryClientConfig {
    fn default() -> Self {
        Self::new()
    }
}

impl Debug for InMemoryClientConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("InMemoryClientConfig")
            .field("preferences", &self.preferences)
            .field("external_signing_keys", &self.external_signing_keys)
            .field("external_key_id", &self.external_key_id)
            .field("key_packages", &self.key_packages)
            .field("psk_store", &self.psk_store)
            .field("supported_extensions", &self.supported_extensions)
            .field("keychain", &self.keychain)
            .field(
                "proposal_filter",
                &self
                    .proposal_filter
                    .as_ref()
                    .map_or("None", |_| "Some(...)"),
            )
            .finish()
    }
}

impl ClientConfig for InMemoryClientConfig {
    type KeyPackageRepository = InMemoryRepository;
    type ProposalFilterError = SimpleError;
    type Keychain = InMemoryKeychain;
    type PskStore = InMemoryPskStore;

    fn external_signing_key(&self, external_key_id: &[u8]) -> Option<PublicKey> {
        self.external_signing_keys.get(external_key_id).cloned()
    }

    fn preferences(&self) -> Preferences {
        self.preferences.clone()
    }

    fn external_key_id(&self) -> Option<Vec<u8>> {
        self.external_key_id.clone()
    }

    fn key_package_repo(&self) -> InMemoryRepository {
        self.key_packages.clone()
    }

    fn filter_proposal(&self, proposal: &Proposal) -> Result<(), SimpleError> {
        self.proposal_filter
            .as_ref()
            .map_or(Ok(()), |f| f(proposal))
            .map_err(SimpleError)
    }

    fn secret_store(&self) -> Self::PskStore {
        self.psk_store.clone()
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

#[derive(Debug, Error)]
#[error("{0}")]
pub struct SimpleError(String);
