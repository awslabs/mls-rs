use std::ops::Deref;

use async_trait::async_trait;
use serde_with::serde_as;
use tls_codec_derive::{TlsDeserialize, TlsSerialize, TlsSize};
use zeroize::Zeroize;

#[serde_as]
#[derive(Clone, Debug, PartialEq, Eq, Zeroize, serde::Serialize, serde::Deserialize)]
#[zeroize(drop)]
pub struct PreSharedKey(#[serde_as(as = "crate::serde::vec_u8_as_base64::VecAsBase64")] Vec<u8>);

impl From<Vec<u8>> for PreSharedKey {
    fn from(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }
}

impl AsRef<[u8]> for PreSharedKey {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl Deref for PreSharedKey {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[serde_as]
#[derive(
    Clone,
    Debug,
    Eq,
    Hash,
    PartialEq,
    TlsDeserialize,
    TlsSerialize,
    TlsSize,
    serde::Deserialize,
    serde::Serialize,
)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct ExternalPskId(
    #[tls_codec(with = "crate::tls::ByteVec")]
    #[serde_as(as = "crate::serde::vec_u8_as_base64::VecAsBase64")]
    Vec<u8>,
);

impl ExternalPskId {
    pub fn new(id_data: Vec<u8>) -> Self {
        Self(id_data)
    }
}

impl AsRef<[u8]> for ExternalPskId {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl Deref for ExternalPskId {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl From<Vec<u8>> for ExternalPskId {
    fn from(value: Vec<u8>) -> Self {
        ExternalPskId(value)
    }
}

#[async_trait]
pub trait PreSharedKeyStorage: Send + Sync {
    type Error: std::error::Error + Send + Sync + 'static;

    async fn insert(&mut self, id: ExternalPskId, psk: PreSharedKey) -> Result<(), Self::Error>;
    async fn delete(&mut self, id: &ExternalPskId) -> Result<(), Self::Error>;
    async fn get(&self, id: &ExternalPskId) -> Result<Option<PreSharedKey>, Self::Error>;
}
