mod ferriscrypt;

use tls_codec_derive::{TlsDeserialize, TlsSerialize, TlsSize};
use zeroize::Zeroize;

use crate::cipher_suite::CipherSuite;

pub use self::ferriscrypt::*;

#[derive(Clone, Debug, PartialEq, Eq, TlsDeserialize, TlsSerialize, TlsSize)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct HpkeCiphertext {
    #[tls_codec(with = "crate::tls::ByteVec")]
    kem_output: Vec<u8>,
    #[tls_codec(with = "crate::tls::ByteVec")]
    ciphertext: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq, TlsDeserialize, TlsSerialize, TlsSize)]
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

#[derive(Clone, Debug, PartialEq, Eq, TlsDeserialize, TlsSerialize, TlsSize, Zeroize)]
#[cfg_attr(
    any(test, feature = "benchmark"),
    derive(serde::Deserialize, serde::Serialize)
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

pub trait CryptoProvider {
    type Error: std::error::Error + Send + Sync + 'static;

    fn hash(&self, cipher_suite: CipherSuite, data: &[u8]) -> Result<Vec<u8>, Self::Error>;

    fn mac(
        &self,
        cipher_suite: CipherSuite,
        key: &[u8],
        data: &[u8],
    ) -> Result<Vec<u8>, Self::Error>;

    fn aead_seal(
        &self,
        cipher_suite: CipherSuite,
        key: &[u8],
        data: &[u8],
        aad: Option<&[u8]>,
        nonce: &[u8],
    ) -> Result<Vec<u8>, Self::Error>;

    fn aead_open(
        &self,
        cipher_suite: CipherSuite,
        key: &[u8],
        cipher_text: &[u8],
        aad: Option<&[u8]>,
        nonce: &[u8],
    ) -> Result<Vec<u8>, Self::Error>;

    fn kdf_expand(
        &self,
        cipher_suite: CipherSuite,
        prk: &[u8],
        info: &[u8],
        len: usize,
    ) -> Result<Vec<u8>, Self::Error>;

    fn kdf_extract(
        &self,
        cipher_suite: CipherSuite,
        salt: &[u8],
        ikm: &[u8],
    ) -> Result<Vec<u8>, Self::Error>;

    fn hpke_seal(
        &self,
        cipher_suite: CipherSuite,
        remote_key: &HpkePublicKey,
        info: &[u8],
        aad: Option<&[u8]>,
        pt: &[u8],
    ) -> Result<HpkeCiphertext, Self::Error>;

    fn hpke_open(
        &self,
        cipher_suite: CipherSuite,
        ciphertext: &HpkeCiphertext,
        local_secret: &HpkeSecretKey,
        info: &[u8],
        aad: Option<&[u8]>,
    ) -> Result<Vec<u8>, Self::Error>;

    fn kem_derive(
        &self,
        cipher_suite: CipherSuite,
        ikm: &[u8],
    ) -> Result<(HpkeSecretKey, HpkePublicKey), Self::Error>;
}
