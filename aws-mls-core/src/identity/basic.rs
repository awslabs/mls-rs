use core::convert::Infallible;

use alloc::vec::Vec;
use aws_mls_codec::{MlsDecode, MlsEncode, MlsSize};

use super::{Credential, CredentialType, MlsCredential};

#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, MlsSize, MlsEncode, MlsDecode)]
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
    #[mls_codec(with = "aws_mls_codec::byte_vec")]
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
