use std::convert::Infallible;

use serde_with::serde_as;
use tls_codec_derive::{TlsDeserialize, TlsSerialize, TlsSize};

use super::{Credential, CredentialType, MlsCredential};

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
    serde::Serialize,
    serde::Deserialize,
)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct BasicCredential {
    #[serde_as(as = "crate::serde::vec_u8_as_base64::VecAsBase64")]
    #[tls_codec(with = "crate::tls::ByteVec")]
    identifier: Vec<u8>,
}

impl BasicCredential {
    pub fn new(identifier: Vec<u8>) -> BasicCredential {
        BasicCredential { identifier }
    }

    pub fn identifier(&self) -> &[u8] {
        &self.identifier
    }
}

impl BasicCredential {
    pub fn credential_type() -> CredentialType {
        CredentialType::BASIC
    }

    pub fn into_credential(self) -> Credential {
        Credential::Basic(self)
    }
}

impl MlsCredential for BasicCredential {
    type Error = Infallible;

    fn credential_type() -> CredentialType {
        Self::credential_type()
    }

    fn into_credential(self) -> Result<Credential, Self::Error> {
        Ok(self.into_credential())
    }
}
