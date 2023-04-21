use cfg_if::cfg_if;

use aws_mls::{
    client_builder::{
        BaseConfig, ClientBuilder, Preferences, WithCryptoProvider, WithIdentityProvider,
        WithKeychain,
    },
    identity::{
        basic::{BasicCredential, BasicIdentityProvider},
        Credential, SigningIdentity,
    },
    psk::ExternalPskId,
    storage_provider::in_memory::InMemoryKeychainStorage,
    CipherSuite, CipherSuiteProvider, Client, CryptoProvider,
};

cfg_if! {
    if #[cfg(target_arch = "wasm32")] {
        pub use aws_mls_crypto_rustcrypto::RustCryptoProvider as TestCryptoProvider;
    } else {
        pub use aws_mls_crypto_openssl::OpensslCryptoProvider as TestCryptoProvider;
    }
}

pub type TestClientConfig = WithIdentityProvider<
    BasicIdentityProvider,
    WithKeychain<InMemoryKeychainStorage, WithCryptoProvider<TestCryptoProvider, BaseConfig>>,
>;

pub const TEST_EXT_PSK_ID: &[u8] = b"external psk";

pub fn make_test_ext_psk() -> Vec<u8> {
    b"secret psk key".to_vec()
}
pub struct TestClient {
    pub client: Client<TestClientConfig>,
    pub identity: SigningIdentity,
}

pub fn get_test_basic_credential(identity: Vec<u8>) -> Credential {
    BasicCredential::new(identity).into_credential()
}

pub fn generate_client(
    cipher_suite: CipherSuite,
    id: Vec<u8>,
    preferences: Preferences,
) -> TestClient {
    let cs = TestCryptoProvider::new()
        .cipher_suite_provider(cipher_suite)
        .unwrap();

    let (secret_key, public_key) = cs.signature_key_generate().unwrap();
    let credential = get_test_basic_credential(id);

    let identity = SigningIdentity::new(credential, public_key);

    let client = ClientBuilder::new()
        .crypto_provider(TestCryptoProvider::default())
        .identity_provider(BasicIdentityProvider::new())
        .single_signing_identity(identity.clone(), secret_key, cipher_suite)
        .preferences(preferences)
        .psk(
            ExternalPskId::new(TEST_EXT_PSK_ID.to_vec()),
            make_test_ext_psk().into(),
        )
        .build();

    TestClient { client, identity }
}
