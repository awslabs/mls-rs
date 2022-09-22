use crate::{
    cipher_suite::{CipherSuite, MaybeCipherSuite},
    client::Client,
    extension::{ExtensionList, ExtensionType, KeyPackageExtension, LeafNodeExtension},
    group::{
        framing::Sender, proposal::BoxedProposalFilter, proposal::PassThroughProposalFilter,
        proposal::ProposalFilter, state_repo::DEFAULT_EPOCH_RETENTION_LIMIT, ControlEncryptionMode,
        PaddingMode,
    },
    identity::CredentialType,
    protocol_version::{MaybeProtocolVersion, ProtocolVersion},
    provider::{
        group_state::{GroupStateStorage, InMemoryGroupStateStorage},
        identity_validation::IdentityValidator,
        key_package::{InMemoryKeyPackageRepository, KeyPackageRepository},
        keychain::{InMemoryKeychain, Keychain},
        psk::{InMemoryPskStore, PskStore},
    },
    psk::{ExternalPskId, Psk},
    signing_identity::SigningIdentity,
    time::MlsTime,
    tree_kem::Capabilities,
};
use ferriscrypt::asym::ec_key::SecretKey;
use std::{
    fmt::{self, Debug},
    sync::Arc,
};
use thiserror::Error;

pub use crate::tree_kem::{Lifetime, LifetimeError};

pub trait ClientConfig {
    type KeyPackageRepository: KeyPackageRepository;
    type ProposalFilter: ProposalFilter;
    type Keychain: Keychain;
    type PskStore: PskStore;
    type GroupStateStorage: GroupStateStorage;
    type IdentityValidator: IdentityValidator;

    fn supported_cipher_suites(&self) -> Vec<CipherSuite>;
    fn supported_extensions(&self) -> Vec<ExtensionType>;
    fn supported_protocol_versions(&self) -> Vec<ProtocolVersion>;

    fn preferences(&self) -> Preferences;
    fn key_package_repo(&self) -> Self::KeyPackageRepository;
    fn proposal_filter(&self, init: ProposalFilterInit) -> Self::ProposalFilter;
    fn keychain(&self) -> Self::Keychain;
    fn secret_store(&self) -> Self::PskStore;

    fn group_state_storage(&self) -> Self::GroupStateStorage;

    fn identity_validator(&self) -> Self::IdentityValidator;
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

    fn supported_credential_types(&self) -> Vec<CredentialType> {
        self.identity_validator().supported_types()
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
pub struct InMemoryClientConfig<C: IdentityValidator> {
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
    identity_validator: C,
}

impl<C: IdentityValidator + Clone> InMemoryClientConfig<C> {
    pub fn new(identity_validator: C) -> Self {
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
            identity_validator,
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

    pub fn build_client(self) -> Client<Self> {
        Client::new(self)
    }
}

impl<C: IdentityValidator + Clone> ClientConfig for InMemoryClientConfig<C> {
    type KeyPackageRepository = InMemoryKeyPackageRepository;
    type ProposalFilter = BoxedProposalFilter<SimpleError>;
    type Keychain = InMemoryKeychain;
    type PskStore = InMemoryPskStore;
    type GroupStateStorage = InMemoryGroupStateStorage;
    type IdentityValidator = C;

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

    fn identity_validator(&self) -> Self::IdentityValidator {
        self.identity_validator.clone()
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

#[cfg(any(feature = "benchmark", test))]
pub mod test_utils {
    use super::InMemoryClientConfig;

    use crate::provider::identity_validation::BasicIdentityValidator;
    #[cfg(test)]
    use crate::{client_config::Preferences, key_package::KeyPackageGeneration};

    #[cfg(test)]
    use ferriscrypt::asym::ec_key::SecretKey;

    pub type TestClientConfig = InMemoryClientConfig<BasicIdentityValidator>;

    impl Default for InMemoryClientConfig<BasicIdentityValidator> {
        fn default() -> Self {
            InMemoryClientConfig::new(BasicIdentityValidator::new())
        }
    }

    #[cfg(test)]
    pub(crate) fn test_config(
        secret_key: SecretKey,
        key_package: KeyPackageGeneration,
        preferences: Preferences,
    ) -> TestClientConfig {
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
