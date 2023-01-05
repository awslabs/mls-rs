use std::ops::Deref;

use crate::serde::vec_u8_as_base64::VecAsBase64;
use serde_with::serde_as;
use tls_codec_derive::{TlsDeserialize, TlsSerialize, TlsSize};
use zeroize::Zeroize;

mod cipher_suite;
pub use self::cipher_suite::*;

#[derive(Clone, Debug, PartialEq, Eq, TlsDeserialize, TlsSerialize, TlsSize)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct HpkeCiphertext {
    #[tls_codec(with = "crate::tls::ByteVec")]
    pub kem_output: Vec<u8>,
    #[tls_codec(with = "crate::tls::ByteVec")]
    pub ciphertext: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq, TlsDeserialize, TlsSerialize, TlsSize, Hash)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct HpkePublicKey(#[tls_codec(with = "crate::tls::ByteVec")] Vec<u8>);

impl From<Vec<u8>> for HpkePublicKey {
    fn from(data: Vec<u8>) -> Self {
        Self(data)
    }
}

impl Deref for HpkePublicKey {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.0
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

impl Deref for HpkeSecretKey {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl AsRef<[u8]> for HpkeSecretKey {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

/// Represents the encryption context from RFC9180 (Section 5). Seal and open functions
/// are stateful, for example, `seal` increments the sequence number and derives a new nonce
pub trait HpkeContext {
    type Error: std::error::Error + Send + Sync + 'static;

    fn seal(&mut self, aad: Option<&[u8]>, data: &[u8]) -> Result<Vec<u8>, Self::Error>;
    fn open(&mut self, aad: Option<&[u8]>, ciphertext: &[u8]) -> Result<Vec<u8>, Self::Error>;
    fn export(&self, exporter_context: &[u8], len: usize) -> Result<Vec<u8>, Self::Error>;
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
    type Target = [u8];

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
    type HpkeContext: HpkeContext + Send + Sync;

    fn cipher_suite(&self) -> CipherSuite;

    fn hash(&self, data: &[u8]) -> Result<Vec<u8>, Self::Error>;

    /// As required by the RFC, key length must be equal to `self.kdf_extract_size()`
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

    fn aead_key_size(&self) -> usize;

    fn aead_nonce_size(&self) -> usize;

    fn kdf_expand(&self, prk: &[u8], info: &[u8], len: usize) -> Result<Vec<u8>, Self::Error>;

    fn kdf_extract(&self, salt: &[u8], ikm: &[u8]) -> Result<Vec<u8>, Self::Error>;

    fn kdf_extract_size(&self) -> usize;

    /// Corresponds to the one-shot API in base mode in RFC9180
    fn hpke_seal(
        &self,
        remote_key: &HpkePublicKey,
        info: &[u8],
        aad: Option<&[u8]>,
        pt: &[u8],
    ) -> Result<HpkeCiphertext, Self::Error>;

    /// Corresponds to the one-shot API in base mode in RFC9180
    fn hpke_open(
        &self,
        ciphertext: &HpkeCiphertext,
        local_secret: &HpkeSecretKey,
        info: &[u8],
        aad: Option<&[u8]>,
    ) -> Result<Vec<u8>, Self::Error>;

    /// Setup sender in the base mode in RFC9180
    fn hpke_setup_s(
        &self,
        remote_key: &HpkePublicKey,
        info: &[u8],
    ) -> Result<(Vec<u8>, Self::HpkeContext), Self::Error>;

    /// Setup receiver in the base mode in RFC9180
    fn hpke_setup_r(
        &self,
        enc: &[u8],
        local_secret: &HpkeSecretKey,
        info: &[u8],
    ) -> Result<Self::HpkeContext, Self::Error>;

    fn kem_derive(&self, ikm: &[u8]) -> Result<(HpkeSecretKey, HpkePublicKey), Self::Error>;

    fn kem_generate(&self) -> Result<(HpkeSecretKey, HpkePublicKey), Self::Error>;

    fn kem_public_key_validate(&self, key: &HpkePublicKey) -> Result<(), Self::Error>;

    fn random_bytes(&self, out: &mut [u8]) -> Result<(), Self::Error>;

    fn random_bytes_vec(&self, count: usize) -> Result<Vec<u8>, Self::Error> {
        let mut vec = vec![0u8; count];
        self.random_bytes(&mut vec)?;

        Ok(vec)
    }

    fn signature_key_generate(
        &self,
    ) -> Result<(SignatureSecretKey, SignaturePublicKey), Self::Error>;

    fn signature_key_derive_public(
        &self,
        secret_key: &SignatureSecretKey,
    ) -> Result<SignaturePublicKey, Self::Error>;

    fn sign(&self, secret_key: &SignatureSecretKey, data: &[u8]) -> Result<Vec<u8>, Self::Error>;

    fn verify(
        &self,
        public_key: &SignaturePublicKey,
        signature: &[u8],
        data: &[u8],
    ) -> Result<(), Self::Error>;
}
