//! Definitions to build an [`ExternalClient`].
//!
//! See [`ExternalClientBuilder`].

use crate::{
    cipher_suite::CipherSuite,
    client_config::{
        KeepAllProposals, MakeProposalFilter, MakeSimpleProposalFilter, ProposalFilterInit,
    },
    extension::ExtensionType,
    external_client::ExternalClient,
    external_client_config::ExternalClientConfig,
    group::{proposal::BorrowedProposal, proposal_filter::ProposalFilterContext},
    identity::CredentialType,
    identity::SigningIdentity,
    protocol_version::ProtocolVersion,
    provider::{
        identity::IdentityProvider,
        keychain::{FirstIdentitySelector, InMemoryKeychain, KeychainStorage},
    },
    tree_kem::Capabilities,
    Sealed,
};
use ferriscrypt::asym::ec_key::{PublicKey, SecretKey};
use std::collections::HashMap;

/// Base client configuration type when instantiating `ExternalClientBuilder`
pub type BaseConfig = Config<Missing, Missing, KeepAllProposals>;

/// Builder for `ExternalClient`
///
/// This is returned by [`ExternalClient::builder`] and allows to tweak settings the
/// `ExternalClient` will use. At a minimum, the builder must be told the [`IdentityProvider`] and
/// [`KeychainStorage`] to use. Other settings have default values. This means that the following methods
/// must be called before [`ExternalClientBuilder::build`]:
///
/// - To specify the [`IdentityProvider`]: [`ExternalClientBuilder::identity_provider`]
/// - To specify the [`KeychainStorage`], one of:
///   - [`ExternalClientBuilder::keychain`]
///   - [`ExternalClientBuilder::single_signing_identity`]
///
/// # Example
///
/// ```
/// use aws_mls::{
///     external_client::ExternalClient,
///     provider::{identity::BasicIdentityProvider, keychain::InMemoryKeychain},
/// };
///
/// let keychain = InMemoryKeychain::default();
/// // Add code to populate keychain here
///
/// let _client = ExternalClient::builder()
///     .identity_provider(BasicIdentityProvider::new())
///     .keychain(keychain)
///     .build();
/// ```
///
/// # Spelling out an `ExternalClient` type
///
/// There are two main ways to spell out an `ExternalClient` type if needed (e.g. function return type).
///
/// The first option uses `impl MlsConfig`:
/// ```
/// use aws_mls::{
///     external_client::{ExternalClient, MlsConfig},
///     provider::{identity::BasicIdentityProvider, keychain::InMemoryKeychain},
/// };
///
/// fn make_client() -> ExternalClient<impl MlsConfig> {
///     ExternalClient::builder()
///         .identity_provider(BasicIdentityProvider::new())
///         .keychain(InMemoryKeychain::default())
///         .build()
/// }
///```
///
/// The second option is more verbose and consists in writing the full `ExternalClient` type:
/// ```
/// use aws_mls::{
///     external_client::{BaseConfig, ExternalClient, WithIdentityProvider, WithKeychain},
///     provider::{
///         identity::BasicIdentityProvider,
///         keychain::{InMemoryKeychain, FirstIdentitySelector},
///     },
/// };
///
/// type MlsClient = ExternalClient<WithKeychain<InMemoryKeychain<FirstIdentitySelector>, WithIdentityProvider<
///     BasicIdentityProvider,
///     BaseConfig,
/// >>>;
///
/// fn make_client_2() -> MlsClient {
///     ExternalClient::builder()
///         .identity_provider(BasicIdentityProvider::new())
///         .keychain(InMemoryKeychain::default())
///         .build()
/// }
///
/// ```
#[derive(Debug)]
pub struct ExternalClientBuilder<C>(C);

impl Default for ExternalClientBuilder<BaseConfig> {
    fn default() -> Self {
        Self::new()
    }
}

impl ExternalClientBuilder<BaseConfig> {
    pub fn new() -> Self {
        Self(Config(ConfigInner {
            settings: Default::default(),
            keychain: Missing,
            identity_provider: Missing,
            make_proposal_filter: KeepAllProposals,
        }))
    }
}

impl<C: IntoConfig> ExternalClientBuilder<C> {
    /// Add a cipher suite to the list of cipher suites supported by the client.
    ///
    /// If no cipher suite is explicitly added, the client will support all cipher suites supported
    /// by this crate.
    pub fn cipher_suite(
        self,
        cipher_suite: CipherSuite,
    ) -> ExternalClientBuilder<IntoConfigOutput<C>> {
        self.cipher_suites(Some(cipher_suite))
    }

    /// Add multiple cipher suites to the list of cipher suites supported by the client.
    ///
    /// If no cipher suite is explicitly added, the client will support all cipher suites supported
    /// by this crate.
    pub fn cipher_suites<I>(self, cipher_suites: I) -> ExternalClientBuilder<IntoConfigOutput<C>>
    where
        I: IntoIterator<Item = CipherSuite>,
    {
        let mut c = self.0.into_config();
        c.0.settings.cipher_suites.extend(cipher_suites);
        ExternalClientBuilder(c)
    }

    /// Add an extension type to the list of extension types supported by the client.
    pub fn extension_type(
        self,
        type_: ExtensionType,
    ) -> ExternalClientBuilder<IntoConfigOutput<C>> {
        self.extension_types(Some(type_))
    }

    /// Add multiple extension types to the list of extension types supported by the client.
    pub fn extension_types<I>(self, types: I) -> ExternalClientBuilder<IntoConfigOutput<C>>
    where
        I: IntoIterator<Item = ExtensionType>,
    {
        let mut c = self.0.into_config();
        c.0.settings.extension_types.extend(types);
        ExternalClientBuilder(c)
    }

    /// Add a protocol version to the list of protocol versions supported by the client.
    ///
    /// If no protocol version is explicitly added, the client will support all protocol versions
    /// supported by this crate.
    pub fn protocol_version(
        self,
        version: ProtocolVersion,
    ) -> ExternalClientBuilder<IntoConfigOutput<C>> {
        self.protocol_versions(Some(version))
    }

    /// Add multiple protocol versions to the list of protocol versions supported by the client.
    ///
    /// If no protocol version is explicitly added, the client will support all protocol versions
    /// supported by this crate.
    pub fn protocol_versions<I>(self, versions: I) -> ExternalClientBuilder<IntoConfigOutput<C>>
    where
        I: IntoIterator<Item = ProtocolVersion>,
    {
        let mut c = self.0.into_config();
        c.0.settings.protocol_versions.extend(versions);
        ExternalClientBuilder(c)
    }

    /// Add an external signing key to be used by the client.
    pub fn external_signing_key(
        self,
        id: Vec<u8>,
        key: PublicKey,
    ) -> ExternalClientBuilder<IntoConfigOutput<C>> {
        let mut c = self.0.into_config();
        c.0.settings.external_signing_keys.insert(id, key);
        ExternalClientBuilder(c)
    }

    /// Specify the number of epochs before the current one to keep.
    ///
    /// By default, all epochs are kept.
    pub fn max_epoch_jitter(self, max_jitter: u64) -> ExternalClientBuilder<IntoConfigOutput<C>> {
        let mut c = self.0.into_config();
        c.0.settings.max_epoch_jitter = Some(max_jitter);
        ExternalClientBuilder(c)
    }

    /// Specify whether processed proposals should be cached by the external group. In case they
    /// are not cached by the group, they should be cached externally and inserted using
    /// `ExternalGroup::insert_proposal` before processing the next commit.
    pub fn cache_proposals(
        self,
        cache_proposals: bool,
    ) -> ExternalClientBuilder<IntoConfigOutput<C>> {
        let mut c = self.0.into_config();
        c.0.settings.cache_proposals = cache_proposals;
        ExternalClientBuilder(c)
    }

    /// Set the keychain to be used by the client.
    pub fn keychain<K>(self, keychain: K) -> ExternalClientBuilder<WithKeychain<K, C>>
    where
        K: KeychainStorage,
    {
        let Config(c) = self.0.into_config();
        ExternalClientBuilder(Config(ConfigInner {
            settings: c.settings,
            keychain,
            identity_provider: c.identity_provider,
            make_proposal_filter: c.make_proposal_filter,
        }))
    }

    /// Set an in-memory keychain with a single identity to be used by the client.
    pub fn single_signing_identity(
        self,
        identity: SigningIdentity,
        key: SecretKey,
    ) -> ExternalClientBuilder<WithKeychain<InMemoryKeychain<FirstIdentitySelector>, C>> {
        self.keychain({
            let mut keychain = InMemoryKeychain::default();
            keychain.insert(identity, key);
            keychain
        })
    }

    /// Set the identity validator to be used by the client.
    pub fn identity_provider<I>(
        self,
        identity_provider: I,
    ) -> ExternalClientBuilder<WithIdentityProvider<I, C>>
    where
        I: IdentityProvider,
    {
        let Config(c) = self.0.into_config();
        ExternalClientBuilder(Config(ConfigInner {
            settings: c.settings,
            keychain: c.keychain,
            identity_provider,
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
    pub fn proposal_filter<F, E>(self, f: F) -> ExternalClientBuilder<WithProposalFilter<F, C>>
    where
        F: Fn(&ProposalFilterContext, &BorrowedProposal<'_>) -> Result<(), E> + Clone,
        E: std::error::Error + Send + Sync + 'static,
    {
        let Config(c) = self.0.into_config();
        ExternalClientBuilder(Config(ConfigInner {
            settings: c.settings,
            keychain: c.keychain,
            identity_provider: c.identity_provider,
            make_proposal_filter: MakeSimpleProposalFilter(f),
        }))
    }
}

impl<C: IntoConfig> ExternalClientBuilder<C>
where
    C::Keychain: KeychainStorage + Clone,
    C::IdentityProvider: IdentityProvider + Clone,
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

    /// Build an external client.
    ///
    /// See [`ExternalClientBuilder`] documentation if the return type of this function needs to be
    /// spelled out.
    pub fn build(self) -> ExternalClient<IntoConfigOutput<C>> {
        ExternalClient::new(self.build_config())
    }
}

impl<C: IntoConfig<Keychain = InMemoryKeychain<FirstIdentitySelector>>> ExternalClientBuilder<C> {
    /// Add an identity to the in-memory keychain.
    pub fn signing_identity(
        self,
        identity: SigningIdentity,
        secret_key: SecretKey,
    ) -> ExternalClientBuilder<IntoConfigOutput<C>> {
        let mut c = self.0.into_config();
        c.0.keychain.insert(identity, secret_key);
        ExternalClientBuilder(c)
    }
}

/// Marker type for required `ExternalClientBuilder` services that have not been specified yet.
#[derive(Debug)]
pub struct Missing;

/// Change the keychain used by a client configuration.
///
/// See [`ExternalClientBuilder::keychain`].
pub type WithKeychain<K, C> =
    Config<K, <C as IntoConfig>::IdentityProvider, <C as IntoConfig>::MakeProposalFilter>;

/// Change the identity validator used by a client configuration.
///
/// See [`ExternalClientBuilder::identity_provider`].
pub type WithIdentityProvider<I, C> =
    Config<<C as IntoConfig>::Keychain, I, <C as IntoConfig>::MakeProposalFilter>;

/// Change the proposal filter used by a client configuration.
///
/// See [`ExternalClientBuilder::proposal_filter`].
pub type WithProposalFilter<F, C> = Config<
    <C as IntoConfig>::Keychain,
    <C as IntoConfig>::IdentityProvider,
    MakeSimpleProposalFilter<F>,
>;

/// Helper alias for `Config`.
pub type IntoConfigOutput<C> = Config<
    <C as IntoConfig>::Keychain,
    <C as IntoConfig>::IdentityProvider,
    <C as IntoConfig>::MakeProposalFilter,
>;

impl<K, Iv, Mpf> ExternalClientConfig for ConfigInner<K, Iv, Mpf>
where
    K: KeychainStorage + Clone,
    Iv: IdentityProvider + Clone,
    Mpf: MakeProposalFilter + Clone,
{
    type Keychain = K;
    type IdentityProvider = Iv;
    type MakeProposalFilter = Mpf;

    fn keychain(&self) -> Self::Keychain {
        self.keychain.clone()
    }

    fn supported_cipher_suites(&self) -> Vec<CipherSuite> {
        self.settings.cipher_suites.clone()
    }

    fn supported_extensions(&self) -> Vec<ExtensionType> {
        self.settings.extension_types.clone()
    }

    fn supported_protocol_versions(&self) -> Vec<ProtocolVersion> {
        self.settings.protocol_versions.clone()
    }

    fn identity_provider(&self) -> Self::IdentityProvider {
        self.identity_provider.clone()
    }

    fn external_signing_key(&self, external_key_id: &[u8]) -> Option<PublicKey> {
        self.settings
            .external_signing_keys
            .get(external_key_id)
            .cloned()
    }

    fn proposal_filter(
        &self,
        init: ProposalFilterInit,
    ) -> <Self::MakeProposalFilter as MakeProposalFilter>::Filter {
        self.make_proposal_filter.make(init)
    }

    fn max_epoch_jitter(&self) -> Option<u64> {
        self.settings.max_epoch_jitter
    }

    fn cache_proposals(&self) -> bool {
        self.settings.cache_proposals
    }
}

impl<K, Iv, Mpf> Sealed for Config<K, Iv, Mpf> {}

impl<K, Iv, Mpf> MlsConfig for Config<K, Iv, Mpf>
where
    K: KeychainStorage + Clone,
    Iv: IdentityProvider + Clone,
    Mpf: MakeProposalFilter + Clone,
{
    type Output = ConfigInner<K, Iv, Mpf>;

    fn get(&self) -> &Self::Output {
        &self.0
    }
}

/// Helper trait to allow consuming crates to easily write an external client type as
/// `ExternalClient<impl MlsConfig>`
///
/// It is not meant to be implemented by consuming crates. `T: MlsConfig` implies
/// `T: ExternalClientConfig`.
pub trait MlsConfig: Clone + Sealed {
    #[doc(hidden)]
    type Output: ExternalClientConfig;

    #[doc(hidden)]
    fn get(&self) -> &Self::Output;
}

/// Blanket implementation so that `T: MlsConfig` implies `T: ExternalClientConfig`
impl<T: MlsConfig> ExternalClientConfig for T {
    type Keychain = <T::Output as ExternalClientConfig>::Keychain;
    type IdentityProvider = <T::Output as ExternalClientConfig>::IdentityProvider;
    type MakeProposalFilter = <T::Output as ExternalClientConfig>::MakeProposalFilter;

    fn keychain(&self) -> Self::Keychain {
        self.get().keychain()
    }

    fn supported_cipher_suites(&self) -> Vec<CipherSuite> {
        self.get().supported_cipher_suites()
    }

    fn supported_extensions(&self) -> Vec<ExtensionType> {
        self.get().supported_extensions()
    }

    fn supported_protocol_versions(&self) -> Vec<ProtocolVersion> {
        self.get().supported_protocol_versions()
    }

    fn identity_provider(&self) -> Self::IdentityProvider {
        self.get().identity_provider()
    }

    fn external_signing_key(&self, external_key_id: &[u8]) -> Option<PublicKey> {
        self.get().external_signing_key(external_key_id)
    }

    fn proposal_filter(
        &self,
        init: ProposalFilterInit,
    ) -> <Self::MakeProposalFilter as MakeProposalFilter>::Filter {
        self.get().proposal_filter(init)
    }

    fn max_epoch_jitter(&self) -> Option<u64> {
        self.get().max_epoch_jitter()
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

    fn supported_credentials(&self) -> Vec<CredentialType> {
        self.get().supported_credentials()
    }

    fn cache_proposals(&self) -> bool {
        self.get().cache_proposals()
    }
}

#[derive(Clone, Debug)]
pub(crate) struct Settings {
    pub(crate) cipher_suites: Vec<CipherSuite>,
    pub(crate) extension_types: Vec<ExtensionType>,
    pub(crate) protocol_versions: Vec<ProtocolVersion>,
    pub(crate) external_signing_keys: HashMap<Vec<u8>, PublicKey>,
    pub(crate) max_epoch_jitter: Option<u64>,
    pub(crate) cache_proposals: bool,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            cache_proposals: true,
            cipher_suites: vec![],
            extension_types: vec![],
            protocol_versions: vec![],
            external_signing_keys: Default::default(),
            max_epoch_jitter: None,
        }
    }
}

/// Definitions meant to be private that are inaccessible outside this crate. They need to be marked
/// `pub` because they appear in public definitions.
mod private {
    use crate::external_client_builder::{IntoConfigOutput, Settings};

    #[derive(Clone, Debug)]
    pub struct Config<K, Iv, Mpf>(pub(crate) ConfigInner<K, Iv, Mpf>);

    #[derive(Clone, Debug)]
    pub struct ConfigInner<K, Iv, Mpf> {
        pub(crate) settings: Settings,
        pub(crate) keychain: K,
        pub(crate) identity_provider: Iv,
        pub(crate) make_proposal_filter: Mpf,
    }

    pub trait IntoConfig {
        type Keychain;
        type IdentityProvider;
        type MakeProposalFilter;

        fn into_config(self) -> IntoConfigOutput<Self>;
    }

    impl<K, Iv, Mpf> IntoConfig for Config<K, Iv, Mpf> {
        type Keychain = K;
        type IdentityProvider = Iv;
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
        external_client_builder::{
            BaseConfig, ExternalClientBuilder, WithIdentityProvider, WithKeychain,
        },
        provider::{
            identity::BasicIdentityProvider,
            keychain::{FirstIdentitySelector, InMemoryKeychain},
        },
    };

    pub type TestExternalClientConfig = WithIdentityProvider<
        BasicIdentityProvider,
        WithKeychain<InMemoryKeychain<FirstIdentitySelector>, BaseConfig>,
    >;

    pub type TestExternalClientBuilder = ExternalClientBuilder<TestExternalClientConfig>;

    impl TestExternalClientBuilder {
        pub fn new_for_test() -> Self {
            ExternalClientBuilder::new()
                .identity_provider(BasicIdentityProvider::new())
                .keychain(InMemoryKeychain::default())
        }
    }
}
