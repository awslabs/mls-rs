use std::ops::Deref;

use serde_with::serde_as;
use tls_codec_derive::{TlsDeserialize, TlsSerialize, TlsSize};

#[derive(
    Debug,
    PartialEq,
    Eq,
    Hash,
    Clone,
    Copy,
    TlsSize,
    TlsSerialize,
    TlsDeserialize,
    serde::Serialize,
    serde::Deserialize,
)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct CredentialType(u16);

impl CredentialType {
    pub fn new(raw_value: u16) -> Self {
        CredentialType(raw_value)
    }

    pub fn raw_value(&self) -> u16 {
        self.0
    }
}

impl From<u16> for CredentialType {
    fn from(value: u16) -> Self {
        CredentialType(value)
    }
}

impl Deref for CredentialType {
    type Target = u16;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[serde_as]
#[derive(
    Clone,
    Debug,
    TlsDeserialize,
    TlsSerialize,
    TlsSize,
    PartialEq,
    Eq,
    Hash,
    serde::Deserialize,
    serde::Serialize,
)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct Credential {
    pub credential_type: CredentialType,
    #[tls_codec(with = "crate::tls::ByteVec")]
    #[serde_as(as = "crate::serde::vec_u8_as_base64::VecAsBase64")]
    pub credential_data: Vec<u8>,
}

pub trait MlsCredential: Sized {
    type Error;

    fn credential_type() -> CredentialType;
    fn into_credential(self) -> Result<Credential, Self::Error>;
}
