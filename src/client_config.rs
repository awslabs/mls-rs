use crate::{
    cipher_suite::{CipherSuite, MaybeCipherSuite},
    client::Client,
    credential::{
        CredentialType, CredentialValidator, PassthroughCredentialValidator, CREDENTIAL_TYPE_BASIC,
        CREDENTIAL_TYPE_X509,
    },
    extension::{ExtensionList, ExtensionType, KeyPackageExtension, LeafNodeExtension},
    group::{
        framing::Sender, proposal::BoxedProposalFilter, proposal::PassThroughProposalFilter,
        proposal::ProposalFilter, ControlEncryptionMode, PaddingMode,
    },
    group_state_repo::{
        GroupStateStorage, InMemoryGroupStateStorage, DEFAULT_EPOCH_RETENTION_LIMIT,
    },
    key_package::{InMemoryKeyPackageRepository, KeyPackageRepository},
    keychain::{InMemoryKeychain, Keychain},
    protocol_version::{MaybeProtocolVersion, ProtocolVersion},
    psk::{ExternalPskId, ExternalPskIdValidator, Psk},
    signing_identity::SigningIdentity,
    time::MlsTime,
    tree_kem::Capabilities,
};
use ferriscrypt::asym::ec_key::SecretKey;
use std::{
    collections::HashMap,
    convert::Infallible,
    fmt::{self, Debug},
    sync::{Arc, Mutex},
};
use thiserror::Error;

pub use crate::tree_kem::{Lifetime, LifetimeError};

pub trait PskStore {
    type Error: std::error::Error + Send + Sync + 'static;

    fn psk(&self, id: &ExternalPskId) -> Result<Option<Psk>, Self::Error>;

    fn into_external_id_validator(self) -> PskStoreIdValidator<Self>
    where
        Self: Sized,
    {
        PskStoreIdValidator(self)
    }
}

#[derive(Debug, Clone)]
pub struct PskStoreIdValidator<T>(T);

impl<T: PskStore> ExternalPskIdValidator for PskStoreIdValidator<T> {
    type Error = PskStoreIdValidationError<T::Error>;

    fn validate(&self, id: &ExternalPskId) -> Result<(), Self::Error> {
        self.0
            .psk(id)?
            .map(|_| ())
            .ok_or_else(|| PskStoreIdValidationError::ExternalIdNotFound(id.clone()))
    }
}

#[derive(Debug, Error)]
pub enum PskStoreIdValidationError<E: std::error::Error> {
    #[error("External PSK ID {0:?} not found")]
    ExternalIdNotFound(ExternalPskId),
    #[error(transparent)]
    Other(#[from] E),
}

pub trait ClientConfig {
    type KeyPackageRepository: KeyPackageRepository;
    type ProposalFilter: ProposalFilter;
    type Keychain: Keychain;
    type PskStore: PskStore;
    type GroupStateStorage: GroupStateStorage;
    type CredentialValidator: CredentialValidator;

    fn supported_cipher_suites(&self) -> Vec<CipherSuite>;
    fn supported_extensions(&self) -> Vec<ExtensionType>;
    fn supported_protocol_versions(&self) -> Vec<ProtocolVersion>;
    fn supported_credential_types(&self) -> Vec<CredentialType>;

    fn preferences(&self) -> Preferences;
    fn key_package_repo(&self) -> Self::KeyPackageRepository;
    fn proposal_filter(&self, init: ProposalFilterInit) -> Self::ProposalFilter;
    fn keychain(&self) -> Self::Keychain;
    fn secret_store(&self) -> Self::PskStore;

    fn group_state_storage(&self) -> Self::GroupStateStorage;

    fn credential_validator(&self) -> Self::CredentialValidator;
    fn key_package_extensions(&self) -> ExtensionList<KeyPackageExtension>;
    fn leaf_node_extensions(&self) -> ExtensionList<LeafNodeExtension>;
    fn lifetime(&self) -> Lifetime;

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
            credentials: self.supported_credential_types(),
        }
    }

    fn version_supported(&self, version: ProtocolVersion) -> bool {
        self.supported_protocol_versions().contains(&version)
    }

    fn cipher_suite_supported(&self, cipher_suite: CipherSuite) -> bool {
        self.supported_cipher_suites().contains(&cipher_suite)
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

#[derive(Clone, Debug)]
pub struct Preferences {
    pub encrypt_controls: bool,
    pub ratchet_tree_extension: bool,
    pub padding_mode: PaddingMode,
    pub force_commit_path_update: bool,
    pub max_epoch_retention: u64,
}

impl Default for Preferences {
    fn default() -> Self {
        Self {
            encrypt_controls: Default::default(),
            ratchet_tree_extension: Default::default(),
            padding_mode: Default::default(),
            force_commit_path_update: true,
            max_epoch_retention: DEFAULT_EPOCH_RETENTION_LIMIT,
        }
    }
}

impl Preferences {
    #[must_use]
    pub fn with_control_encryption(self, enabled: bool) -> Self {
        Self {
            encrypt_controls: enabled,
            ..self
        }
    }

    #[must_use]
    pub fn with_ratchet_tree_extension(self, enabled: bool) -> Self {
        Self {
            ratchet_tree_extension: enabled,
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

    #[must_use]
    pub fn force_commit_path_update(self, enabled: bool) -> Self {
        Self {
            force_commit_path_update: enabled,
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
pub struct MakeProposalFilter(
    pub Arc<dyn Fn(ProposalFilterInit) -> BoxedProposalFilter<SimpleError> + Send + Sync>,
);

impl MakeProposalFilter {
    pub fn new<F, M>(make: M) -> Self
    where
        M: Fn(ProposalFilterInit) -> F + Send + Sync + 'static,
        F: ProposalFilter<Error = SimpleError> + Send + Sync + 'static,
    {
        Self(Arc::new(move |init| make(init).boxed()))
    }
}

impl Debug for MakeProposalFilter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("MakeProposalFilter")
    }
}

impl Default for MakeProposalFilter {
    fn default() -> Self {
        Self::new(|_| PassThroughProposalFilter::new())
    }
}

#[derive(Clone, Debug)]
pub struct ProposalFilterInit {
    committer: Sender,
}

impl ProposalFilterInit {
    pub(crate) fn new(committer: Sender) -> Self {
        Self { committer }
    }

    pub fn committer(&self) -> &Sender {
        &self.committer
    }
}

#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct InMemoryClientConfig {
    preferences: Preferences,
    pub(crate) supported_extensions: Vec<ExtensionType>,
    pub(crate) key_packages: InMemoryKeyPackageRepository,
    make_proposal_filter: MakeProposalFilter,
    pub(crate) keychain: InMemoryKeychain,
    psk_store: InMemoryPskStore,
    pub(crate) protocol_versions: Vec<ProtocolVersion>,
    pub(crate) cipher_suites: Vec<CipherSuite>,
    pub(crate) group_state_storage: InMemoryGroupStateStorage,
    leaf_node_extensions: ExtensionList<LeafNodeExtension>,
    key_package_extensions: ExtensionList<KeyPackageExtension>,
    lifetime_duration: u64,
    credential_types: Vec<CredentialType>,
}

impl InMemoryClientConfig {
    pub fn new() -> Self {
        Self {
            preferences: Default::default(),
            supported_extensions: Default::default(),
            key_packages: Default::default(),
            make_proposal_filter: Default::default(),
            keychain: Default::default(),
            psk_store: Default::default(),
            protocol_versions: ProtocolVersion::all().collect(),
            cipher_suites: CipherSuite::all().collect(),
            group_state_storage: Default::default(),
            leaf_node_extensions: Default::default(),
            key_package_extensions: Default::default(),
            lifetime_duration: 31536000, // One year
            credential_types: vec![CREDENTIAL_TYPE_BASIC, CREDENTIAL_TYPE_X509],
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
    pub fn with_proposal_filter<F, M>(self, make: M) -> Self
    where
        M: Fn(ProposalFilterInit) -> F + Send + Sync + 'static,
        F: ProposalFilter<Error = SimpleError> + Send + Sync + 'static,
    {
        Self {
            make_proposal_filter: MakeProposalFilter::new(make),
            ..self
        }
    }

    #[must_use]
    pub fn with_psk(mut self, psk_id: ExternalPskId, psk: Psk) -> Self {
        self.psk_store.insert(psk_id, psk);
        self
    }

    #[must_use]
    pub fn with_signing_identity(
        mut self,
        identity: SigningIdentity,
        secret_key: SecretKey,
    ) -> Self {
        self.keychain.insert(identity, secret_key);
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

    pub fn with_key_package_extensions(
        mut self,
        extensions: ExtensionList<KeyPackageExtension>,
    ) -> Self {
        self.key_package_extensions = extensions;
        self
    }

    pub fn with_leaf_node_extensions(
        mut self,
        extensions: ExtensionList<LeafNodeExtension>,
    ) -> Self {
        self.leaf_node_extensions = extensions;
        self
    }

    #[must_use]
    pub fn with_lifetime_duration(mut self, duration: u64) -> Self {
        self.lifetime_duration = duration;
        self
    }

    pub fn with_credential_types(mut self, credential_types: Vec<CredentialType>) -> Self {
        self.credential_types = credential_types;
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

impl ClientConfig for InMemoryClientConfig {
    type KeyPackageRepository = InMemoryKeyPackageRepository;
    type ProposalFilter = BoxedProposalFilter<SimpleError>;
    type Keychain = InMemoryKeychain;
    type PskStore = InMemoryPskStore;
    type GroupStateStorage = InMemoryGroupStateStorage;
    type CredentialValidator = PassthroughCredentialValidator;

    fn preferences(&self) -> Preferences {
        self.preferences.clone()
    }

    fn key_package_repo(&self) -> InMemoryKeyPackageRepository {
        self.key_packages.clone()
    }

    fn proposal_filter(&self, init: ProposalFilterInit) -> Self::ProposalFilter {
        (self.make_proposal_filter.0)(init)
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

    fn group_state_storage(&self) -> Self::GroupStateStorage {
        self.group_state_storage.clone()
    }

    fn credential_validator(&self) -> Self::CredentialValidator {
        PassthroughCredentialValidator::new()
    }

    fn key_package_extensions(&self) -> ExtensionList<KeyPackageExtension> {
        self.key_package_extensions.clone()
    }

    fn leaf_node_extensions(&self) -> ExtensionList<LeafNodeExtension> {
        self.leaf_node_extensions.clone()
    }

    fn lifetime(&self) -> Lifetime {
        let now_timestamp = MlsTime::now().seconds_since_epoch().unwrap();
        Lifetime {
            not_before: now_timestamp,
            not_after: now_timestamp + self.lifetime_duration,
        }
    }

    fn supported_credential_types(&self) -> Vec<CredentialType> {
        self.credential_types.clone()
    }
}

#[derive(Debug, Error)]
#[error("{0}")]
pub struct SimpleError(String);

impl From<String> for SimpleError {
    fn from(s: String) -> Self {
        Self(s)
    }
}

impl From<&str> for SimpleError {
    fn from(s: &str) -> Self {
        s.to_string().into()
    }
}

#[cfg(test)]
pub(crate) mod test_utils {
    use super::{InMemoryClientConfig, Preferences};
    use crate::key_package::KeyPackageGeneration;
    use ferriscrypt::asym::ec_key::SecretKey;

    pub(crate) fn test_config(
        secret_key: SecretKey,
        key_package: KeyPackageGeneration,
        preferences: Preferences,
    ) -> InMemoryClientConfig {
        let config = InMemoryClientConfig::default()
            .with_signing_identity(
                key_package.key_package.leaf_node.signing_identity.clone(),
                secret_key,
            )
            .with_preferences(preferences);

        config.key_packages.insert(key_package).unwrap();
        config
    }
}
