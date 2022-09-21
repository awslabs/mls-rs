use crate::{
    cipher_suite::CipherSuite,
    serde_utils::vec_u8_as_base64::VecAsBase64,
    signing_identity::{SigningIdentity, SigningIdentityError},
    x509::CertificateChain,
};
use serde_with::serde_as;
use thiserror::Error;
use tls_codec::{Deserialize, Serialize};
use tls_codec_derive::{TlsDeserialize, TlsSerialize, TlsSize};

#[derive(Error, Debug)]
pub enum CredentialError {
    #[error(transparent)]
    SigningIdentityError(#[from] SigningIdentityError),
    #[error(transparent)]
    SerializationError(#[from] tls_codec::Error),
    #[error("Unexpected extension type: {0}, expected: {1}")]
    UnexpectedCredentialType(CredentialType, CredentialType),
}

pub type CredentialType = u16;
pub const CREDENTIAL_TYPE_BASIC: u16 = 1;
pub const CREDENTIAL_TYPE_X509: u16 = 2;

pub trait MlsCredential: Sized + Serialize + Deserialize {
    const IDENTIFIER: CredentialType;

    fn to_credential(&self) -> Result<Credential, CredentialError> {
        Ok(Credential {
            credential_type: Self::IDENTIFIER,
            credential_data: self.tls_serialize_detached()?,
        })
    }

    fn from_credential(credential: &Credential) -> Result<Self, CredentialError> {
        if credential.credential_type != Self::IDENTIFIER {
            Err(CredentialError::UnexpectedCredentialType(
                credential.credential_type,
                Self::IDENTIFIER,
            ))
        } else {
            Self::tls_deserialize(&mut &*credential.credential_data).map_err(|e| e.into())
        }
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
    #[serde_as(as = "VecAsBase64")]
    pub credential_data: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq, TlsDeserialize, TlsSerialize, TlsSize)]
pub struct BasicCredential {
    #[tls_codec(with = "crate::tls::ByteVec")]
    pub credential: Vec<u8>,
}

impl MlsCredential for BasicCredential {
    const IDENTIFIER: CredentialType = CREDENTIAL_TYPE_BASIC;
}

#[derive(Clone, Debug, PartialEq, Eq, TlsDeserialize, TlsSerialize, TlsSize)]
pub struct X509Credential {
    pub credential: CertificateChain,
}

impl MlsCredential for X509Credential {
    const IDENTIFIER: CredentialType = CREDENTIAL_TYPE_X509;
}

pub trait CredentialValidator {
    type Error: std::error::Error + Send + Sync + 'static;

    fn validate(
        &self,
        signing_identity: &SigningIdentity,
        cipher_suite: CipherSuite,
    ) -> Result<(), Self::Error>;

    fn identity(&self, signing_id: &SigningIdentity) -> Result<Vec<u8>, Self::Error>;

    fn valid_successor(
        &self,
        predecessor: &SigningIdentity,
        successor: &SigningIdentity,
    ) -> Result<bool, Self::Error>;

    fn supported_types(&self) -> Vec<CredentialType>;
}

impl<T: CredentialValidator> CredentialValidator for &T {
    type Error = T::Error;

    fn validate(
        &self,
        signing_identity: &SigningIdentity,
        cipher_suite: CipherSuite,
    ) -> Result<(), Self::Error> {
        (*self).validate(signing_identity, cipher_suite)
    }

    fn identity(&self, signing_id: &SigningIdentity) -> Result<Vec<u8>, Self::Error> {
        (*self).identity(signing_id)
    }

    fn valid_successor(
        &self,
        predecessor: &SigningIdentity,
        successor: &SigningIdentity,
    ) -> Result<bool, Self::Error> {
        (*self).valid_successor(predecessor, successor)
    }

    fn supported_types(&self) -> Vec<CredentialType> {
        vec![CREDENTIAL_TYPE_X509]
    }
}

#[derive(Clone, Debug, Default)]
pub struct BasicCredentialValidator;

impl BasicCredentialValidator {
    pub fn new() -> Self {
        Self
    }
}

impl CredentialValidator for BasicCredentialValidator {
    type Error = CredentialError;

    fn validate(
        &self,
        signing_identity: &SigningIdentity,
        cipher_suite: CipherSuite,
    ) -> Result<(), Self::Error> {
        // Check that using the public key won't cause errors later
        signing_identity
            .public_key(cipher_suite)
            .map(|_| ())
            .map_err(Into::into)
    }

    fn identity(&self, signing_id: &SigningIdentity) -> Result<Vec<u8>, Self::Error> {
        Ok(signing_id.credential.credential_data.clone())
    }

    fn valid_successor(
        &self,
        predecessor: &SigningIdentity,
        successor: &SigningIdentity,
    ) -> Result<bool, Self::Error> {
        Ok(predecessor.credential.credential_data == successor.credential.credential_data)
    }

    fn supported_types(&self) -> Vec<CredentialType> {
        vec![CREDENTIAL_TYPE_BASIC]
    }
}

#[cfg(any(test, feature = "benchmark"))]
pub mod test_utils {
    use ferriscrypt::asym::ec_key::Curve;

    use crate::x509::test_utils::test_cert;

    use super::*;

    pub fn get_test_basic_credential(identity: Vec<u8>) -> Credential {
        BasicCredential {
            credential: identity,
        }
        .to_credential()
        .unwrap()
    }

    pub fn get_test_certificate_credential() -> Credential {
        let test_certificate = test_cert(Curve::Ed25519);
        let chain = vec![test_certificate].into();
        X509Credential { credential: chain }
            .to_credential()
            .unwrap()
    }

    pub fn get_test_x509_credential(chain: CertificateChain) -> Credential {
        X509Credential { credential: chain }
            .to_credential()
            .unwrap()
    }
}
