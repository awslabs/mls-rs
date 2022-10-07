//! Definitions to build a [`Client`].
//!
//! See [`ClientBuilder`].

use crate::{
    cipher_suite::CipherSuite,
    client::Client,
    client_config::{
        ClientConfig, KeepAllProposals, MakeProposalFilter, MakeSimpleProposalFilter,
        ProposalFilterInit,
    },
    extension::{
        ExtensionError, ExtensionList, ExtensionType, KeyPackageExtension, LeafNodeExtension,
        MlsExtension,
    },
    group::{
        proposal::BorrowedProposal, proposal_filter::ProposalFilterContext,
        state_repo::DEFAULT_EPOCH_RETENTION_LIMIT, ControlEncryptionMode, PaddingMode,
    },
    identity::CredentialType,
    key_package::KeyPackageGeneration,
    protocol_version::ProtocolVersion,
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
    tree_kem::{Capabilities, Lifetime},
    Sealed,
};
use ferriscrypt::asym::ec_key::SecretKey;

/// Base client configuration type when instantiating `ClientBuilder`
pub type BaseConfig = Config<
    InMemoryKeyPackageRepository,
    Missing,
    InMemoryPskStore,
    InMemoryGroupStateStorage,
    Missing,
    KeepAllProposals,
>;

/// Builder for `Client`
///
/// This is returned by [`Client::builder`] and allows to tweak settings the `Client` will use. At a
/// minimum, the builder must be told the [`IdentityValidator`] and [`Keychain`] to use. Other
/// settings have default values. This means that the following methods must be called before
/// [`ClientBuilder::build`]:
///
/// - To specify the [`IdentityValidator`]: [`ClientBuilder::identity_validator`]
/// - To specify the [`Keychain`], one of:
///   - [`ClientBuilder::keychain`]
///   - [`ClientBuilder::single_signing_identity`]
///
/// # Example
///
/// ```
/// use aws_mls::{
///     client::Client,
///     provider::{identity_validation::BasicIdentityValidator, keychain::InMemoryKeychain},
/// };
///
/// let keychain = InMemoryKeychain::default();
/// // Add code to populate keychain here
///
/// let _client = Client::builder()
///     .identity_validator(BasicIdentityValidator::new())
///     .keychain(keychain)
///     .build();
/// ```
///
/// # Spelling out a `Client` type
///
/// There are two main ways to spell out a `Client` type if needed (e.g. function return type).
///
/// The first option uses `impl MlsConfig`:
/// ```
/// use aws_mls::{
///     client::{Client, MlsConfig},
///     provider::{identity_validation::BasicIdentityValidator, keychain::InMemoryKeychain},
/// };
///
/// fn make_client() -> Client<impl MlsConfig> {
///     Client::builder()
///         .identity_validator(BasicIdentityValidator::new())
///         .keychain(InMemoryKeychain::default())
///         .build()
/// }
///```
///
/// The second option is more verbose and consists in writing the full `Client` type:
/// ```
/// use aws_mls::{
///     client::{BaseConfig, Client, WithIdentityValidator, WithKeychain},
///     provider::{identity_validation::BasicIdentityValidator, keychain::InMemoryKeychain},
/// };
///
/// type MlsClient = Client<WithKeychain<InMemoryKeychain, WithIdentityValidator<
///     BasicIdentityValidator,
///     BaseConfig,
/// >>>;
///
/// fn make_client_2() -> MlsClient {
///     Client::builder()
///         .identity_validator(BasicIdentityValidator::new())
///         .keychain(InMemoryKeychain::default())
///         .build()
/// }
///
/// ```
#[derive(Debug)]
pub struct ClientBuilder<C>(C);

impl Default for ClientBuilder<BaseConfig> {
    fn default() -> Self {
        Self::new()
    }
}

impl ClientBuilder<BaseConfig> {
    pub fn new() -> Self {
        Self(Config(ConfigInner {
            settings: Default::default(),
            key_package_repo: Default::default(),
            keychain: Missing,
            psk_store: Default::default(),
            group_state_storage: Default::default(),
            identity_validator: Missing,
            make_proposal_filter: KeepAllProposals,
        }))
    }
}

impl<C: IntoConfig> ClientBuilder<C> {
    /// Add a cipher suite to the list of cipher suites supported by the client.
    ///
    /// If no cipher suite is explicitly added, the client will support all cipher suites supported
    /// by this crate.
    pub fn cipher_suite(self, cipher_suite: CipherSuite) -> ClientBuilder<IntoConfigOutput<C>> {
        self.cipher_suites(Some(cipher_suite))
    }

    /// Add multiple cipher suites to the list of cipher suites supported by the client.
    ///
    /// If no cipher suite is explicitly added, the client will support all cipher suites supported
    /// by this crate.
    pub fn cipher_suites<I>(self, cipher_suites: I) -> ClientBuilder<IntoConfigOutput<C>>
    where
        I: IntoIterator<Item = CipherSuite>,
    {
        let mut c = self.0.into_config();
        c.0.settings.cipher_suites.extend(cipher_suites);
        ClientBuilder(c)
    }

    /// Add an extension type to the list of extension types supported by the client.
    pub fn extension_type(self, type_: ExtensionType) -> ClientBuilder<IntoConfigOutput<C>> {
        self.extension_types(Some(type_))
    }

    /// Add multiple extension types to the list of extension types supported by the client.
    pub fn extension_types<I>(self, types: I) -> ClientBuilder<IntoConfigOutput<C>>
    where
        I: IntoIterator<Item = ExtensionType>,
    {
        let mut c = self.0.into_config();
        c.0.settings.extension_types.extend(types);
        ClientBuilder(c)
    }

    /// Add a protocol version to the list of protocol versions supported by the client.
    ///
    /// If no protocol version is explicitly added, the client will support all protocol versions
    /// supported by this crate.
    pub fn protocol_version(self, version: ProtocolVersion) -> ClientBuilder<IntoConfigOutput<C>> {
        self.protocol_versions(Some(version))
    }

    /// Add multiple protocol versions to the list of protocol versions supported by the client.
    ///
    /// If no protocol version is explicitly added, the client will support all protocol versions
    /// supported by this crate.
    pub fn protocol_versions<I>(self, versions: I) -> ClientBuilder<IntoConfigOutput<C>>
    where
        I: IntoIterator<Item = ProtocolVersion>,
    {
        let mut c = self.0.into_config();
        c.0.settings.protocol_versions.extend(versions);
        ClientBuilder(c)
    }

    /// Set preferences to be used by the client.
    pub fn preferences(self, prefs: Preferences) -> ClientBuilder<IntoConfigOutput<C>> {
        let mut c = self.0.into_config();
        c.0.settings.preferences = prefs;
        ClientBuilder(c)
    }

    /// Add a key package extension to the list of key package extensions supported by the client.
    pub fn key_package_extension<T>(
        self,
        extension: T,
    ) -> Result<ClientBuilder<IntoConfigOutput<C>>, ExtensionError>
    where
        T: MlsExtension<KeyPackageExtension>,
        Self: Sized,
    {
        let mut c = self.0.into_config();
        c.0.settings
            .key_package_extensions
            .set_extension(extension)?;
        Ok(ClientBuilder(c))
    }

    /// Add multiple key package extensions to the list of key package extensions supported by the
    /// client.
    pub fn key_package_extensions(
        self,
        extensions: ExtensionList<KeyPackageExtension>,
    ) -> ClientBuilder<IntoConfigOutput<C>> {
        let mut c = self.0.into_config();
        c.0.settings.key_package_extensions.append(extensions);
        ClientBuilder(c)
    }

    /// Add a leaf node extension to the list of leaf node extensions supported by the client.
    pub fn leaf_node_extension<T>(
        self,
        extension: T,
    ) -> Result<ClientBuilder<IntoConfigOutput<C>>, ExtensionError>
    where
        T: MlsExtension<LeafNodeExtension>,
        Self: Sized,
    {
        let mut c = self.0.into_config();
        c.0.settings.leaf_node_extensions.set_extension(extension)?;
        Ok(ClientBuilder(c))
    }

    /// Add multiple leaf node extensions to the list of leaf node extensions supported by the
    /// client.
    pub fn leaf_node_extensions(
        self,
        extensions: ExtensionList<LeafNodeExtension>,
    ) -> ClientBuilder<IntoConfigOutput<C>> {
        let mut c = self.0.into_config();
        c.0.settings.leaf_node_extensions.append(extensions);
        ClientBuilder(c)
    }

    /// Set the lifetime duration in seconds of key packages generated by the client.
    pub fn key_package_lifetime(self, duration_in_s: u64) -> ClientBuilder<IntoConfigOutput<C>> {
        let mut c = self.0.into_config();
        c.0.settings.lifetime_in_s = duration_in_s;
        ClientBuilder(c)
    }

    /// Set the keychain to be used by the client.
    pub fn keychain<K>(self, keychain: K) -> ClientBuilder<WithKeychain<K, C>>
    where
        K: Keychain,
    {
        let Config(c) = self.0.into_config();
        ClientBuilder(Config(ConfigInner {
            settings: c.settings,
            key_package_repo: c.key_package_repo,
            keychain,
            psk_store: c.psk_store,
            group_state_storage: c.group_state_storage,
            identity_validator: c.identity_validator,
            make_proposal_filter: c.make_proposal_filter,
        }))
    }

    /// Set an in-memory keychain with a single identity to be used by the client.
    pub fn single_signing_identity(
        self,
        identity: SigningIdentity,
        key: SecretKey,
    ) -> ClientBuilder<WithKeychain<InMemoryKeychain, C>> {
        self.keychain({
            let mut keychain = InMemoryKeychain::default();
            keychain.insert(identity, key);
            keychain
        })
    }

    /// Set the key package repository to be used by the client.
    ///
    /// By default, an in-memory repository is used.
    pub fn key_package_repo<K>(self, key_package_repo: K) -> ClientBuilder<WithKeyPackageRepo<K, C>>
    where
        K: KeyPackageRepository,
    {
        let Config(c) = self.0.into_config();
        ClientBuilder(Config(ConfigInner {
            settings: c.settings,
            key_package_repo,
            keychain: c.keychain,
            psk_store: c.psk_store,
            group_state_storage: c.group_state_storage,
            identity_validator: c.identity_validator,
            make_proposal_filter: c.make_proposal_filter,
        }))
    }

    /// Set the PSK store to be used by the client.
    ///
    /// By default, an in-memory store is used.
    pub fn psk_store<P>(self, psk_store: P) -> ClientBuilder<WithPskStore<P, C>>
    where
        P: PskStore,
    {
        let Config(c) = self.0.into_config();
        ClientBuilder(Config(ConfigInner {
            settings: c.settings,
            key_package_repo: c.key_package_repo,
            keychain: c.keychain,
            psk_store,
            group_state_storage: c.group_state_storage,
            identity_validator: c.identity_validator,
            make_proposal_filter: c.make_proposal_filter,
        }))
    }

    /// Set the group state storage to be used by the client.
    ///
    /// By default, an in-memory storage is used.
    pub fn group_state_storage<G>(
        self,
        group_state_storage: G,
    ) -> ClientBuilder<WithGroupStateStorage<G, C>>
    where
        G: GroupStateStorage,
    {
        let Config(c) = self.0.into_config();
        ClientBuilder(Config(ConfigInner {
            settings: c.settings,
            key_package_repo: c.key_package_repo,
            keychain: c.keychain,
            psk_store: c.psk_store,
            group_state_storage,
            identity_validator: c.identity_validator,
            make_proposal_filter: c.make_proposal_filter,
        }))
    }

    /// Set the identity validator to be used by the client.
    pub fn identity_validator<I>(
        self,
        identity_validator: I,
    ) -> ClientBuilder<WithIdentityValidator<I, C>>
    where
        I: IdentityValidator,
    {
        let Config(c) = self.0.into_config();
        ClientBuilder(Config(ConfigInner {
            settings: c.settings,
            key_package_repo: c.key_package_repo,
            keychain: c.keychain,
            psk_store: c.psk_store,
            group_state_storage: c.group_state_storage,
            identity_validator,
            make_proposal_filter: c.make_proposal_filter,
        }))
    }

    /// Set the user-defined proposal filter to be used by the client.
    ///
    /// This user-defined filter is called when sending and receiving commits, before internal
    /// filters enforcing the MLS protocol rules are applied. If the filter returns an error when
    /// receiving a commit, the entire commit is considered invalid. If the filter returns an error
    /// when sending a commit, the proposal the filter was called with is not included in the
    /// commit.
    pub fn proposal_filter<F, E>(self, f: F) -> ClientBuilder<WithProposalFilter<F, C>>
    where
        F: Fn(&ProposalFilterContext, &BorrowedProposal<'_>) -> Result<(), E> + Clone,
        E: std::error::Error + Send + Sync + 'static,
    {
        let Config(c) = self.0.into_config();
        ClientBuilder(Config(ConfigInner {
            settings: c.settings,
            key_package_repo: c.key_package_repo,
            keychain: c.keychain,
            psk_store: c.psk_store,
            group_state_storage: c.group_state_storage,
            identity_validator: c.identity_validator,
            make_proposal_filter: MakeSimpleProposalFilter(f),
        }))
    }
}

impl<C: IntoConfig> ClientBuilder<C>
where
    C::KeyPackageRepository: KeyPackageRepository + Clone,
    C::Keychain: Keychain + Clone,
    C::PskStore: PskStore + Clone,
    C::GroupStateStorage: GroupStateStorage + Clone,
    C::IdentityValidator: IdentityValidator + Clone,
    C::MakeProposalFilter: MakeProposalFilter + Clone,
{
    pub(crate) fn build_config(self) -> IntoConfigOutput<C> {
        let mut c = self.0.into_config();

        if c.0.settings.cipher_suites.is_empty() {
            c.0.settings.cipher_suites = CipherSuite::all().collect();
        }

        if c.0.settings.protocol_versions.is_empty() {
            c.0.settings.protocol_versions = ProtocolVersion::all().collect();
        }

        c
    }

    /// Build a client.
    ///
    /// See [`ClientBuilder`] documentation if the return type of this function needs to be spelled
    /// out.
    pub fn build(self) -> Client<IntoConfigOutput<C>> {
        Client::new(self.build_config())
    }
}

impl<C: IntoConfig<Keychain = InMemoryKeychain>> ClientBuilder<C> {
    /// Add an identity to the in-memory keychain.
    pub fn signing_identity(
        self,
        identity: SigningIdentity,
        secret_key: SecretKey,
    ) -> ClientBuilder<IntoConfigOutput<C>> {
        let mut c = self.0.into_config();
        c.0.keychain.insert(identity, secret_key);
        ClientBuilder(c)
    }
}

impl<C: IntoConfig<PskStore = InMemoryPskStore>> ClientBuilder<C> {
    /// Add a PSK to the in-memory PSK store.
    pub fn psk(self, psk_id: ExternalPskId, psk: Psk) -> ClientBuilder<IntoConfigOutput<C>> {
        let mut c = self.0.into_config();
        c.0.psk_store.insert(psk_id, psk);
        ClientBuilder(c)
    }
}

impl<C: IntoConfig<KeyPackageRepository = InMemoryKeyPackageRepository>> ClientBuilder<C> {
    /// Add a key package to the key package repository.
    pub fn key_package(
        self,
        key_pkg_gen: KeyPackageGeneration,
    ) -> Result<
        ClientBuilder<IntoConfigOutput<C>>,
        <C::KeyPackageRepository as KeyPackageRepository>::Error,
    > {
        let c = self.0.into_config();
        c.0.key_package_repo.insert(key_pkg_gen)?;
        Ok(ClientBuilder(c))
    }
}

/// Marker type for required `ClientBuilder` services that have not been specified yet.
#[derive(Debug)]
pub struct Missing;

/// Change the key package repository used by a client configuration.
///
/// See [`ClientBuilder::key_package_repo`].
pub type WithKeyPackageRepo<K, C> = Config<
    K,
    <C as IntoConfig>::Keychain,
    <C as IntoConfig>::PskStore,
    <C as IntoConfig>::GroupStateStorage,
    <C as IntoConfig>::IdentityValidator,
    <C as IntoConfig>::MakeProposalFilter,
>;

/// Change the keychain used by a client configuration.
///
/// See [`ClientBuilder::keychain`].
pub type WithKeychain<K, C> = Config<
    <C as IntoConfig>::KeyPackageRepository,
    K,
    <C as IntoConfig>::PskStore,
    <C as IntoConfig>::GroupStateStorage,
    <C as IntoConfig>::IdentityValidator,
    <C as IntoConfig>::MakeProposalFilter,
>;

/// Change the PSK store used by a client configuration.
///
/// See [`ClientBuilder::psk_store`].
pub type WithPskStore<P, C> = Config<
    <C as IntoConfig>::KeyPackageRepository,
    <C as IntoConfig>::Keychain,
    P,
    <C as IntoConfig>::GroupStateStorage,
    <C as IntoConfig>::IdentityValidator,
    <C as IntoConfig>::MakeProposalFilter,
>;

/// Change the group state storage used by a client configuration.
///
/// See [`ClientBuilder::group_state_storage`].
pub type WithGroupStateStorage<G, C> = Config<
    <C as IntoConfig>::KeyPackageRepository,
    <C as IntoConfig>::Keychain,
    <C as IntoConfig>::PskStore,
    G,
    <C as IntoConfig>::IdentityValidator,
    <C as IntoConfig>::MakeProposalFilter,
>;

/// Change the identity validator used by a client configuration.
///
/// See [`ClientBuilder::identity_validator`].
pub type WithIdentityValidator<I, C> = Config<
    <C as IntoConfig>::KeyPackageRepository,
    <C as IntoConfig>::Keychain,
    <C as IntoConfig>::PskStore,
    <C as IntoConfig>::GroupStateStorage,
    I,
    <C as IntoConfig>::MakeProposalFilter,
>;

/// Change the proposal filter used by a client configuration.
///
/// See [`ClientBuilder::proposal_filter`].
pub type WithProposalFilter<F, C> = Config<
    <C as IntoConfig>::KeyPackageRepository,
    <C as IntoConfig>::Keychain,
    <C as IntoConfig>::PskStore,
    <C as IntoConfig>::GroupStateStorage,
    <C as IntoConfig>::IdentityValidator,
    MakeSimpleProposalFilter<F>,
>;

/// Helper alias for `Config`.
pub type IntoConfigOutput<C> = Config<
    <C as IntoConfig>::KeyPackageRepository,
    <C as IntoConfig>::Keychain,
    <C as IntoConfig>::PskStore,
    <C as IntoConfig>::GroupStateStorage,
    <C as IntoConfig>::IdentityValidator,
    <C as IntoConfig>::MakeProposalFilter,
>;

impl<Kpr, K, Ps, Gss, Iv, Mpf> ClientConfig for ConfigInner<Kpr, K, Ps, Gss, Iv, Mpf>
where
    Kpr: KeyPackageRepository + Clone,
    K: Keychain + Clone,
    Ps: PskStore + Clone,
    Gss: GroupStateStorage + Clone,
    Iv: IdentityValidator + Clone,
    Mpf: MakeProposalFilter + Clone,
{
    type KeyPackageRepository = Kpr;
    type Keychain = K;
    type PskStore = Ps;
    type GroupStateStorage = Gss;
    type IdentityValidator = Iv;
    type MakeProposalFilter = Mpf;

    fn supported_cipher_suites(&self) -> Vec<CipherSuite> {
        self.settings.cipher_suites.clone()
    }

    fn supported_extensions(&self) -> Vec<ExtensionType> {
        self.settings.extension_types.clone()
    }

    fn supported_protocol_versions(&self) -> Vec<ProtocolVersion> {
        self.settings.protocol_versions.clone()
    }

    fn preferences(&self) -> Preferences {
        self.settings.preferences.clone()
    }

    fn key_package_repo(&self) -> Self::KeyPackageRepository {
        self.key_package_repo.clone()
    }

    fn proposal_filter(
        &self,
        init: ProposalFilterInit,
    ) -> <Self::MakeProposalFilter as MakeProposalFilter>::Filter {
        self.make_proposal_filter.make(init)
    }

    fn keychain(&self) -> Self::Keychain {
        self.keychain.clone()
    }

    fn secret_store(&self) -> Self::PskStore {
        self.psk_store.clone()
    }

    fn group_state_storage(&self) -> Self::GroupStateStorage {
        self.group_state_storage.clone()
    }

    fn identity_validator(&self) -> Self::IdentityValidator {
        self.identity_validator.clone()
    }

    fn key_package_extensions(&self) -> ExtensionList<KeyPackageExtension> {
        self.settings.key_package_extensions.clone()
    }

    fn leaf_node_extensions(&self) -> ExtensionList<LeafNodeExtension> {
        self.settings.leaf_node_extensions.clone()
    }

    fn lifetime(&self) -> Lifetime {
        let now_timestamp = MlsTime::now().seconds_since_epoch().unwrap();
        Lifetime {
            not_before: now_timestamp,
            not_after: now_timestamp + self.settings.lifetime_in_s,
        }
    }
}

impl<Kpr, K, Ps, Gss, Iv, Mpf> Sealed for Config<Kpr, K, Ps, Gss, Iv, Mpf> {}

impl<Kpr, K, Ps, Gss, Iv, Mpf> MlsConfig for Config<Kpr, K, Ps, Gss, Iv, Mpf>
where
    Kpr: KeyPackageRepository + Clone,
    K: Keychain + Clone,
    Ps: PskStore + Clone,
    Gss: GroupStateStorage + Clone,
    Iv: IdentityValidator + Clone,
    Mpf: MakeProposalFilter + Clone,
{
    type Output = ConfigInner<Kpr, K, Ps, Gss, Iv, Mpf>;

    fn get(&self) -> &Self::Output {
        &self.0
    }
}

/// Helper trait to allow consuming crates to easily write a client type as `Client<impl MlsConfig>`
///
/// It is not meant to be implemented by consuming crates. `T: MlsConfig` implies `T: ClientConfig`.
pub trait MlsConfig: Clone + Sealed {
    #[doc(hidden)]
    type Output: ClientConfig;

    #[doc(hidden)]
    fn get(&self) -> &Self::Output;
}

/// Blanket implementation so that `T: MlsConfig` implies `T: ClientConfig`
impl<T: MlsConfig> ClientConfig for T {
    type KeyPackageRepository = <T::Output as ClientConfig>::KeyPackageRepository;
    type Keychain = <T::Output as ClientConfig>::Keychain;
    type PskStore = <T::Output as ClientConfig>::PskStore;
    type GroupStateStorage = <T::Output as ClientConfig>::GroupStateStorage;
    type IdentityValidator = <T::Output as ClientConfig>::IdentityValidator;
    type MakeProposalFilter = <T::Output as ClientConfig>::MakeProposalFilter;

    fn supported_cipher_suites(&self) -> Vec<CipherSuite> {
        self.get().supported_cipher_suites()
    }

    fn supported_extensions(&self) -> Vec<ExtensionType> {
        self.get().supported_extensions()
    }

    fn supported_protocol_versions(&self) -> Vec<ProtocolVersion> {
        self.get().supported_protocol_versions()
    }

    fn preferences(&self) -> Preferences {
        self.get().preferences()
    }

    fn key_package_repo(&self) -> Self::KeyPackageRepository {
        self.get().key_package_repo()
    }

    fn proposal_filter(
        &self,
        init: ProposalFilterInit,
    ) -> <Self::MakeProposalFilter as MakeProposalFilter>::Filter {
        self.get().proposal_filter(init)
    }

    fn keychain(&self) -> Self::Keychain {
        self.get().keychain()
    }

    fn secret_store(&self) -> Self::PskStore {
        self.get().secret_store()
    }

    fn group_state_storage(&self) -> Self::GroupStateStorage {
        self.get().group_state_storage()
    }

    fn identity_validator(&self) -> Self::IdentityValidator {
        self.get().identity_validator()
    }

    fn key_package_extensions(&self) -> ExtensionList<KeyPackageExtension> {
        self.get().key_package_extensions()
    }

    fn leaf_node_extensions(&self) -> ExtensionList<LeafNodeExtension> {
        self.get().leaf_node_extensions()
    }

    fn lifetime(&self) -> Lifetime {
        self.get().lifetime()
    }

    fn capabilities(&self) -> Capabilities {
        self.get().capabilities()
    }

    fn version_supported(&self, version: ProtocolVersion) -> bool {
        self.get().version_supported(version)
    }

    fn cipher_suite_supported(&self, cipher_suite: CipherSuite) -> bool {
        self.get().cipher_suite_supported(cipher_suite)
    }

    fn supported_credential_types(&self) -> Vec<CredentialType> {
        self.get().supported_credential_types()
    }
}

#[derive(Clone, Debug)]
pub(crate) struct Settings {
    pub(crate) cipher_suites: Vec<CipherSuite>,
    pub(crate) extension_types: Vec<ExtensionType>,
    pub(crate) protocol_versions: Vec<ProtocolVersion>,
    pub(crate) preferences: Preferences,
    pub(crate) key_package_extensions: ExtensionList<KeyPackageExtension>,
    pub(crate) leaf_node_extensions: ExtensionList<LeafNodeExtension>,
    pub(crate) lifetime_in_s: u64,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            cipher_suites: Default::default(),
            extension_types: Default::default(),
            protocol_versions: Default::default(),
            preferences: Default::default(),
            key_package_extensions: Default::default(),
            leaf_node_extensions: Default::default(),
            lifetime_in_s: 365 * 24 * 3600,
        }
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

/// Definitions meant to be private that are inaccessible outside this crate. They need to be marked
/// `pub` because they appear in public definitions.
mod private {
    use crate::client_builder::{IntoConfigOutput, Settings};

    #[derive(Clone, Debug)]
    pub struct Config<Kpr, K, Ps, Gss, Iv, Mpf>(pub(crate) ConfigInner<Kpr, K, Ps, Gss, Iv, Mpf>);

    #[derive(Clone, Debug)]
    pub struct ConfigInner<Kpr, K, Ps, Gss, Iv, Mpf> {
        pub(crate) settings: Settings,
        pub(crate) key_package_repo: Kpr,
        pub(crate) keychain: K,
        pub(crate) psk_store: Ps,
        pub(crate) group_state_storage: Gss,
        pub(crate) identity_validator: Iv,
        pub(crate) make_proposal_filter: Mpf,
    }

    pub trait IntoConfig {
        type KeyPackageRepository;
        type Keychain;
        type PskStore;
        type GroupStateStorage;
        type IdentityValidator;
        type MakeProposalFilter;

        fn into_config(self) -> IntoConfigOutput<Self>;
    }

    impl<Kpr, K, Ps, Gss, Iv, Mpf> IntoConfig for Config<Kpr, K, Ps, Gss, Iv, Mpf> {
        type KeyPackageRepository = Kpr;
        type Keychain = K;
        type PskStore = Ps;
        type GroupStateStorage = Gss;
        type IdentityValidator = Iv;
        type MakeProposalFilter = Mpf;

        fn into_config(self) -> Self {
            self
        }
    }
}

use private::{Config, ConfigInner, IntoConfig};

#[cfg(any(test, feature = "benchmark"))]
pub mod test_utils {
    use crate::{
        client_builder::{
            BaseConfig, ClientBuilder, Preferences, WithIdentityValidator, WithKeychain,
        },
        key_package::KeyPackageGeneration,
        provider::{identity_validation::BasicIdentityValidator, keychain::InMemoryKeychain},
    };
    use ferriscrypt::asym::ec_key::SecretKey;

    pub type TestClientConfig =
        WithIdentityValidator<BasicIdentityValidator, WithKeychain<InMemoryKeychain, BaseConfig>>;

    pub type TestClientBuilder = ClientBuilder<TestClientConfig>;

    impl TestClientBuilder {
        pub fn new_for_test() -> Self {
            ClientBuilder::new()
                .identity_validator(BasicIdentityValidator::new())
                .keychain(InMemoryKeychain::default())
        }

        pub fn new_for_test_custom(
            secret_key: SecretKey,
            key_package: KeyPackageGeneration,
            preferences: Preferences,
        ) -> Self {
            Self::new_for_test()
                .preferences(preferences)
                .signing_identity(
                    key_package.key_package.leaf_node.signing_identity.clone(),
                    secret_key,
                )
                .key_package(key_package)
                .unwrap()
        }
    }
}
