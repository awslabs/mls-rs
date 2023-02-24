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
/// Bare assertion of an identity without any additional information.
///
/// The format of the encoded identity is defined by the application.
///
///
/// # Warning
///
/// Basic credentials are inherently insecure since they can not be
/// properly validated. It is not recommended to use [`BasicCredential`]
/// in production applications.
pub struct BasicCredential {
    #[serde_as(as = "crate::serde::vec_u8_as_base64::VecAsBase64")]
    #[tls_codec(with = "crate::tls::ByteVec")]
    identifier: Vec<u8>,
}

impl BasicCredential {
    /// Create a new basic credential with raw bytes.
    pub fn new(identifier: Vec<u8>) -> BasicCredential {
        BasicCredential { identifier }
    }

    /// Underlying identifier as raw bytes.
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
