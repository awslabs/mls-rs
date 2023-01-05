pub use aws_mls_core::crypto::*;

#[cfg(any(test, feature = "benchmark"))]
pub mod test_utils {
    use aws_mls_core::crypto::CryptoProvider;
    use aws_mls_crypto_ferriscrypt::{FerriscryptCipherSuite, FerriscryptCryptoProvider};

    use crate::cipher_suite::CipherSuite;

    pub fn test_cipher_suite_provider(cipher_suite: CipherSuite) -> FerriscryptCipherSuite {
        FerriscryptCryptoProvider::default()
            .cipher_suite_provider(cipher_suite)
            .unwrap()
    }
}
