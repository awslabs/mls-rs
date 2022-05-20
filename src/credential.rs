use crate::x509::{CertificateChain, X509Error};
use ferriscrypt::asym::ec_key::EcKeyError;
use thiserror::Error;
use tls_codec_derive::{TlsDeserialize, TlsSerialize, TlsSize};

#[derive(Error, Debug)]
pub enum CredentialError {
    #[error(transparent)]
    EcKeyError(#[from] EcKeyError),
    #[error(transparent)]
    CertificateError(#[from] X509Error),
}

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
#[repr(u16)]
pub enum Credential {
    #[tls_codec(discriminant = 1)]
    Basic(#[tls_codec(with = "crate::tls::ByteVec")] Vec<u8>),
    #[tls_codec(discriminant = 2)]
    Certificate(CertificateChain),
}

pub(crate) trait CredentialConvertible {
    fn into_credential(self) -> Credential;
}

impl CredentialConvertible for Vec<u8> {
    fn into_credential(self) -> Credential {
        Credential::Basic(self)
    }
}

impl CredentialConvertible for CertificateChain {
    fn into_credential(self) -> Credential {
        Credential::Certificate(self)
    }
}

#[cfg(test)]
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

        Credential::Certificate(chain)
    }
}
