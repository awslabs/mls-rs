mod ferriscrypt;

use std::ops::Deref;

use crate::cipher_suite::CipherSuite;
use crate::serde_utils::vec_u8_as_base64::VecAsBase64;
use serde_with::serde_as;
use tls_codec_derive::{TlsDeserialize, TlsSerialize, TlsSize};
use zeroize::Zeroize;

pub use self::ferriscrypt::*;

#[derive(Clone, Debug, PartialEq, Eq, TlsDeserialize, TlsSerialize, TlsSize)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct HpkeCiphertext {
    #[tls_codec(with = "crate::tls::ByteVec")]
    kem_output: Vec<u8>,
    #[tls_codec(with = "crate::tls::ByteVec")]
    ciphertext: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq, TlsDeserialize, TlsSerialize, TlsSize, Hash)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct HpkePublicKey(#[tls_codec(with = "crate::tls::ByteVec")] Vec<u8>);

impl From<Vec<u8>> for HpkePublicKey {
    fn from(data: Vec<u8>) -> Self {
        Self(data)
    }
}

impl AsRef<[u8]> for HpkePublicKey {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    TlsDeserialize,
    TlsSerialize,
    TlsSize,
    Zeroize,
    serde::Serialize,
    serde::Deserialize,
)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct HpkeSecretKey(#[tls_codec(with = "crate::tls::ByteVec")] Vec<u8>);

impl From<Vec<u8>> for HpkeSecretKey {
    fn from(data: Vec<u8>) -> Self {
        Self(data)
    }
}

impl AsRef<[u8]> for HpkeSecretKey {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

#[serde_as]
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    Hash,
    TlsDeserialize,
    TlsSerialize,
    TlsSize,
    serde::Deserialize,
    serde::Serialize,
)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct SignaturePublicKey(
    #[tls_codec(with = "crate::tls::ByteVec")]
    #[serde_as(as = "VecAsBase64")]
    Vec<u8>,
);

impl Deref for SignaturePublicKey {
    type Target = Vec<u8>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl From<Vec<u8>> for SignaturePublicKey {
    fn from(data: Vec<u8>) -> Self {
        SignaturePublicKey(data)
    }
}

#[serde_as]
#[derive(Clone, Debug, PartialEq, Eq, Zeroize, serde::Serialize, serde::Deserialize)]
pub struct SignatureSecretKey(#[serde_as(as = "VecAsBase64")] Vec<u8>);

impl From<Vec<u8>> for SignatureSecretKey {
    fn from(data: Vec<u8>) -> Self {
        Self(data)
    }
}

impl Deref for SignatureSecretKey {
    type Target = Vec<u8>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

pub trait CryptoProvider {
    type CipherSuiteProvider: CipherSuiteProvider + Clone + Send + Sync;

    fn supported_cipher_suites(&self) -> Vec<CipherSuite>;

    fn cipher_suite_provider(&self, cipher_suite: CipherSuite)
        -> Option<Self::CipherSuiteProvider>;
}

pub trait CipherSuiteProvider {
    type Error: std::error::Error + Send + Sync + 'static;

    // TODO: We will eventually eliminate CipherSuite in favor of just a number for flexibility
    fn cipher_suite(&self) -> CipherSuite;

    fn hash(&self, data: &[u8]) -> Result<Vec<u8>, Self::Error>;

    fn mac(&self, key: &[u8], data: &[u8]) -> Result<Vec<u8>, Self::Error>;

    fn aead_seal(
        &self,
        key: &[u8],
        data: &[u8],
        aad: Option<&[u8]>,
        nonce: &[u8],
    ) -> Result<Vec<u8>, Self::Error>;

    fn aead_open(
        &self,
        key: &[u8],
        cipher_text: &[u8],
        aad: Option<&[u8]>,
        nonce: &[u8],
    ) -> Result<Vec<u8>, Self::Error>;

    fn kdf_expand(&self, prk: &[u8], info: &[u8], len: usize) -> Result<Vec<u8>, Self::Error>;

    fn kdf_extract(&self, salt: &[u8], ikm: &[u8]) -> Result<Vec<u8>, Self::Error>;

    fn hpke_seal(
        &self,
        remote_key: &HpkePublicKey,
        info: &[u8],
        aad: Option<&[u8]>,
        pt: &[u8],
    ) -> Result<HpkeCiphertext, Self::Error>;

    fn hpke_open(
        &self,
        ciphertext: &HpkeCiphertext,
        local_secret: &HpkeSecretKey,
        info: &[u8],
        aad: Option<&[u8]>,
    ) -> Result<Vec<u8>, Self::Error>;

    fn kem_derive(&self, ikm: &[u8]) -> Result<(HpkeSecretKey, HpkePublicKey), Self::Error>;

    fn kem_generate(&self) -> Result<(HpkeSecretKey, HpkePublicKey), Self::Error>;

    fn random_bytes(&self, out: &mut [u8]) -> Result<(), Self::Error>;

    fn random_bytes_vec(&self, count: usize) -> Result<Vec<u8>, Self::Error> {
        let mut vec = vec![0u8; count];
        self.random_bytes(&mut vec)?;

        Ok(vec)
    }

    fn sign(&self, secret_key: &SignatureSecretKey, data: &[u8]) -> Result<Vec<u8>, Self::Error>;

    fn verify(
        &self,
        public_key: &SignaturePublicKey,
        signature: &[u8],
        data: &[u8],
    ) -> Result<(), Self::Error>;
}

#[cfg(any(test, feature = "benchmark"))]
pub mod test_utils {
    use crate::cipher_suite::CipherSuite;

    use super::{CryptoProvider, FerriscryptCipherSuite, FerriscryptCryptoProvider};

    pub fn test_cipher_suite_provider(cipher_suite: CipherSuite) -> FerriscryptCipherSuite {
        FerriscryptCryptoProvider::default()
            .cipher_suite_provider(cipher_suite)
            .unwrap()
    }
}
