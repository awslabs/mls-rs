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
        crypto::{CryptoProvider, SignaturePublicKey, SignatureSecretKey},
        identity::IdentityProvider,
        keychain::{InMemoryKeychain, KeychainStorage},
    },
    tree_kem::Capabilities,
    Sealed,
};
use std::collections::HashMap;

/// Base client configuration type when instantiating `ExternalClientBuilder`
// TODO replace FerriscryptCryptoProvider by the default provider
pub type ExternalBaseConfig = Config<Missing, Missing, KeepAllProposals, FerriscryptCryptoProvider>;

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
///     external_client::{ExternalBaseConfig, ExternalClient, WithIdentityProvider, WithKeychain},
///     provider::{
///         identity::BasicIdentityProvider, keychain::InMemoryKeychain,
///     },
/// };
///
/// type MlsClient = ExternalClient<WithKeychain<InMemoryKeychain, WithIdentityProvider<
///     BasicIdentityProvider,
///     ExternalBaseConfig,
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

impl Default for ExternalClientBuilder<ExternalBaseConfig> {
    fn default() -> Self {
        Self::new()
    }
}

impl ExternalClientBuilder<ExternalBaseConfig> {
    pub fn new() -> Self {
        Self(Config(ConfigInner {
            settings: Default::default(),
            keychain: Missing,
            identity_provider: Missing,
            make_proposal_filter: KeepAllProposals,
            crypto_provider: Default::default(),
        }))
    }
}

impl<C: IntoConfig> ExternalClientBuilder<C> {
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
        key: SignaturePublicKey,
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
            crypto_provider: c.crypto_provider,
        }))
    }

    /// Set an in-memory keychain with a single identity to be used by the client.
    pub fn single_signing_identity(
        self,
        identity: SigningIdentity,
        key: SignatureSecretKey,
        cipher_suite: CipherSuite,
    ) -> ExternalClientBuilder<WithKeychain<InMemoryKeychain, C>> {
        self.keychain({
            let mut keychain = InMemoryKeychain::default();
            keychain.insert(identity, key, cipher_suite);
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
            crypto_provider: c.crypto_provider,
        }))
    }

    /// Set the crypto provider to be used by the client.
    ///
    // TODO add a comment once we have a default provider
    pub fn crypto_provider<Cp>(
        self,
        crypto_provider: Cp,
    ) -> ExternalClientBuilder<WithCryptoProvider<Cp, C>>
    where
        Cp: CryptoProvider,
    {
        let Config(c) = self.0.into_config();
        ExternalClientBuilder(Config(ConfigInner {
            settings: c.settings,
            keychain: c.keychain,
            identity_provider: c.identity_provider,
            make_proposal_filter: c.make_proposal_filter,
            crypto_provider,
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
            crypto_provider: c.crypto_provider,
        }))
    }
}

impl<C: IntoConfig> ExternalClientBuilder<C>
where
    C::Keychain: KeychainStorage + Clone,
    C::IdentityProvider: IdentityProvider + Clone,
    C::MakeProposalFilter: MakeProposalFilter + Clone,
    C::CryptoProvider: CryptoProvider + Clone,
{
    pub(crate) fn build_config(self) -> IntoConfigOutput<C> {
        let mut c = self.0.into_config();

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

impl<C: IntoConfig<Keychain = InMemoryKeychain>> ExternalClientBuilder<C> {
    /// Add an identity to the in-memory keychain.
    pub fn signing_identity(
        self,
        identity: SigningIdentity,
        secret_key: SignatureSecretKey,
        cipher_suite: CipherSuite,
    ) -> ExternalClientBuilder<IntoConfigOutput<C>> {
        let mut c = self.0.into_config();
        c.0.keychain.insert(identity, secret_key, cipher_suite);
        ExternalClientBuilder(c)
    }
}

/// Marker type for required `ExternalClientBuilder` services that have not been specified yet.
#[derive(Debug)]
pub struct Missing;

/// Change the keychain used by a client configuration.
///
/// See [`ExternalClientBuilder::keychain`].
pub type WithKeychain<K, C> = Config<
    K,
    <C as IntoConfig>::IdentityProvider,
    <C as IntoConfig>::MakeProposalFilter,
    <C as IntoConfig>::CryptoProvider,
>;

/// Change the identity validator used by a client configuration.
///
/// See [`ExternalClientBuilder::identity_provider`].
pub type WithIdentityProvider<I, C> = Config<
    <C as IntoConfig>::Keychain,
    I,
    <C as IntoConfig>::MakeProposalFilter,
    <C as IntoConfig>::CryptoProvider,
>;

/// Change the proposal filter used by a client configuration.
///
/// See [`ExternalClientBuilder::proposal_filter`].
pub type WithProposalFilter<F, C> = Config<
    <C as IntoConfig>::Keychain,
    <C as IntoConfig>::IdentityProvider,
    MakeSimpleProposalFilter<F>,
    <C as IntoConfig>::CryptoProvider,
>;

/// Change the crypto provider used by a client configuration.
///
/// See [`ExternalClientBuilder::crypto_provider`].
pub type WithCryptoProvider<Cp, C> = Config<
    <C as IntoConfig>::Keychain,
    <C as IntoConfig>::IdentityProvider,
    <C as IntoConfig>::MakeProposalFilter,
    Cp,
>;

/// Helper alias for `Config`.
pub type IntoConfigOutput<C> = Config<
    <C as IntoConfig>::Keychain,
    <C as IntoConfig>::IdentityProvider,
    <C as IntoConfig>::MakeProposalFilter,
    <C as IntoConfig>::CryptoProvider,
>;

impl<K, Ip, Mpf, Cp> ExternalClientConfig for ConfigInner<K, Ip, Mpf, Cp>
where
    K: KeychainStorage + Clone,
    Ip: IdentityProvider + Clone,
    Mpf: MakeProposalFilter + Clone,
    Cp: CryptoProvider + Clone,
{
    type Keychain = K;
    type IdentityProvider = Ip;
    type MakeProposalFilter = Mpf;
    type CryptoProvider = Cp;

    fn keychain(&self) -> Self::Keychain {
        self.keychain.clone()
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

    fn crypto_provider(&self) -> Self::CryptoProvider {
        self.crypto_provider.clone()
    }

    fn external_signing_key(&self, external_key_id: &[u8]) -> Option<SignaturePublicKey> {
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

impl<K, Ip, Mpf, Cp> Sealed for Config<K, Ip, Mpf, Cp> {}

impl<K, Ip, Mpf, Cp> MlsConfig for Config<K, Ip, Mpf, Cp>
where
    K: KeychainStorage + Clone,
    Ip: IdentityProvider + Clone,
    Mpf: MakeProposalFilter + Clone,
    Cp: CryptoProvider + Clone,
{
    type Output = ConfigInner<K, Ip, Mpf, Cp>;

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
    type CryptoProvider = <T::Output as ExternalClientConfig>::CryptoProvider;

    fn keychain(&self) -> Self::Keychain {
        self.get().keychain()
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

    fn crypto_provider(&self) -> Self::CryptoProvider {
        self.get().crypto_provider()
    }

    fn external_signing_key(&self, external_key_id: &[u8]) -> Option<SignaturePublicKey> {
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

    fn supported_credentials(&self) -> Vec<CredentialType> {
        self.get().supported_credentials()
    }

    fn cache_proposals(&self) -> bool {
        self.get().cache_proposals()
    }
}

#[derive(Clone, Debug)]
pub(crate) struct Settings {
    pub(crate) extension_types: Vec<ExtensionType>,
    pub(crate) protocol_versions: Vec<ProtocolVersion>,
    pub(crate) external_signing_keys: HashMap<Vec<u8>, SignaturePublicKey>,
    pub(crate) max_epoch_jitter: Option<u64>,
    pub(crate) cache_proposals: bool,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            cache_proposals: true,
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
    pub struct Config<K, Ip, Mpf, Cp>(pub(crate) ConfigInner<K, Ip, Mpf, Cp>);

    #[derive(Clone, Debug)]
    pub struct ConfigInner<K, Ip, Mpf, Cp> {
        pub(crate) settings: Settings,
        pub(crate) keychain: K,
        pub(crate) identity_provider: Ip,
        pub(crate) make_proposal_filter: Mpf,
        pub(crate) crypto_provider: Cp,
    }

    pub trait IntoConfig {
        type Keychain;
        type IdentityProvider;
        type MakeProposalFilter;
        type CryptoProvider;

        fn into_config(self) -> IntoConfigOutput<Self>;
    }

    impl<K, Ip, Mpf, Cp> IntoConfig for Config<K, Ip, Mpf, Cp> {
        type Keychain = K;
        type IdentityProvider = Ip;
        type MakeProposalFilter = Mpf;
        type CryptoProvider = Cp;

        fn into_config(self) -> Self {
            self
        }
    }
}

use aws_mls_crypto_ferriscrypt::FerriscryptCryptoProvider;
use private::{Config, ConfigInner, IntoConfig};

#[cfg(any(test, feature = "benchmark"))]
pub mod test_utils {
    use aws_mls_crypto_ferriscrypt::FerriscryptCryptoProvider;

    use crate::{
        cipher_suite::CipherSuite,
        external_client_builder::{
            ExternalBaseConfig, ExternalClientBuilder, WithIdentityProvider, WithKeychain,
        },
        provider::{identity::BasicIdentityProvider, keychain::InMemoryKeychain},
    };

    pub type TestExternalClientConfig = WithIdentityProvider<
        BasicIdentityProvider,
        WithKeychain<InMemoryKeychain, ExternalBaseConfig>,
    >;

    pub type TestExternalClientBuilder = ExternalClientBuilder<TestExternalClientConfig>;

    impl TestExternalClientBuilder {
        pub fn new_for_test() -> Self {
            ExternalClientBuilder::new()
                .identity_provider(BasicIdentityProvider::new())
                .keychain(InMemoryKeychain::default())
        }

        pub fn new_for_test_disabling_cipher_suite(cipher_suite: CipherSuite) -> Self {
            ExternalClientBuilder::new()
                .crypto_provider(FerriscryptCryptoProvider::with_disabled_cipher_suites(
                    vec![cipher_suite],
                ))
                .identity_provider(BasicIdentityProvider::new())
                .keychain(InMemoryKeychain::default())
        }
    }
}
