use std::ops::Deref;

use async_trait::async_trait;
use serde_with::serde_as;
use tls_codec_derive::{TlsDeserialize, TlsSerialize, TlsSize};
use zeroize::Zeroize;

#[serde_as]
#[derive(Clone, Debug, PartialEq, Eq, Zeroize, serde::Serialize, serde::Deserialize)]
#[zeroize(drop)]
pub struct Psk(#[serde_as(as = "crate::serde::vec_u8_as_base64::VecAsBase64")] Vec<u8>);

impl From<Vec<u8>> for Psk {
    fn from(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }
}

impl AsRef<[u8]> for Psk {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl Deref for Psk {
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
    pub Vec<u8>,
);

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

#[async_trait]
pub trait PskStore: Send + Sync {
    type Error: std::error::Error + Send + Sync + 'static;

    async fn insert(&mut self, id: ExternalPskId, psk: Psk) -> Result<(), Self::Error>;
    async fn delete(&mut self, id: &ExternalPskId) -> Result<(), Self::Error>;
    async fn get(&self, id: &ExternalPskId) -> Result<Option<Psk>, Self::Error>;
}
