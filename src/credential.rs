use crate::{
    cipher_suite::CipherSuite,
    serde_utils::vec_u8_as_base64::VecAsBase64,
    signing_identity::{SigningIdentity, SigningIdentityError},
    x509::{CertificateChain, X509Error},
};
use ferriscrypt::asym::ec_key::EcKeyError;
use serde_with::serde_as;
use thiserror::Error;
use tls_codec::Serialize;
use tls_codec_derive::{TlsDeserialize, TlsSerialize, TlsSize};

#[derive(Error, Debug)]
pub enum CredentialError {
    #[error(transparent)]
    EcKeyError(#[from] EcKeyError),
    #[error(transparent)]
    CertificateError(#[from] X509Error),
    #[error(transparent)]
    SigningIdentityError(#[from] SigningIdentityError),
    #[error(transparent)]
    SerializationError(#[from] tls_codec::Error),
}

pub type CredentialType = u16;
pub const CREDENTIAL_TYPE_BASIC: u16 = 1;
pub const CREDENTIAL_TYPE_X509: u16 = 2;

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
#[repr(u16)]
pub enum Credential {
    #[tls_codec(discriminant = 1)]
    Basic(
        #[tls_codec(with = "crate::tls::ByteVec")]
        #[serde_as(as = "VecAsBase64")]
        Vec<u8>,
    ),
    #[tls_codec(discriminant = 2)]
    X509(CertificateChain),
}

impl Credential {
    pub fn credential_type(&self) -> CredentialType {
        match self {
            Credential::Basic(_) => CREDENTIAL_TYPE_BASIC,
            Credential::X509(_) => CREDENTIAL_TYPE_X509,
        }
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, tls_codec::Error> {
        self.tls_serialize_detached()
    }
}

pub trait CredentialValidator {
    type Error: std::error::Error + Send + Sync + 'static;

    fn validate(
        &self,
        signing_identity: &SigningIdentity,
        cipher_suite: CipherSuite,
    ) -> Result<(), Self::Error>;

    fn identity(&self, signing_id: &SigningIdentity) -> Result<Vec<u8>, Self::Error>;
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
}

#[derive(Clone, Debug, Default)]
pub struct PassthroughCredentialValidator;

impl PassthroughCredentialValidator {
    pub fn new() -> Self {
        Self
    }
}

impl CredentialValidator for PassthroughCredentialValidator {
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
        match &signing_id.credential {
            Credential::Basic(cred) => Ok(cred.clone()),
            Credential::X509(cred) => cred
                .get(0)
                .cloned()
                .map(|cert| cert.to_vec())
                .ok_or_else(|| X509Error::EmptyCertificateChain.into()),
        }
    }
}

#[cfg(any(test, feature = "benchmark"))]
pub mod test_utils {
    use ferriscrypt::asym::ec_key::Curve;

    use crate::x509::test_utils::test_cert;

    use super::*;

    pub fn get_test_basic_credential(identity: Vec<u8>) -> Credential {
        Credential::Basic(identity)
    }

    pub fn get_test_certificate_credential() -> Credential {
        let test_certificate = test_cert(Curve::Ed25519);
        let chain = CertificateChain::from(vec![test_certificate]);

        Credential::X509(chain)
    }
}
