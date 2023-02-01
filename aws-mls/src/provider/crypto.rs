pub use aws_mls_core::crypto::*;

#[cfg(any(test, feature = "benchmark"))]
pub mod test_utils {
    use aws_mls_core::crypto::CryptoProvider;
    use cfg_if::cfg_if;

    cfg_if! {
        if #[cfg(target_arch = "wasm32")] {
            pub use aws_mls_crypto_rustcrypto::RustCryptoProvider as TestCryptoProvider;
        } else {
            pub use aws_mls_crypto_openssl::OpensslCryptoProvider as TestCryptoProvider;
        }
    }

    use crate::cipher_suite::CipherSuite;

    pub fn test_cipher_suite_provider(
        cipher_suite: CipherSuite,
    ) -> <TestCryptoProvider as CryptoProvider>::CipherSuiteProvider {
        TestCryptoProvider::new()
            .cipher_suite_provider(cipher_suite)
            .unwrap()
    }

    pub fn try_test_cipher_suite_provider(
        cipher_suite: u16,
    ) -> Option<<TestCryptoProvider as CryptoProvider>::CipherSuiteProvider> {
        TestCryptoProvider::new().cipher_suite_provider(CipherSuite::from(cipher_suite))
    }
}
