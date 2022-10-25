use crate::{provider::identity::X509Error, serde_utils::vec_u8_as_base64::VecAsBase64};
use der::Decode;
use serde_with::serde_as;
use std::ops::{Deref, DerefMut};
use thiserror::Error;
use tls_codec::{Deserialize, Serialize};
use tls_codec_derive::{TlsDeserialize, TlsSerialize, TlsSize};
use x509_cert::Certificate;

mod signing_identity;

pub use signing_identity::*;

#[derive(Error, Debug)]
pub enum CredentialError {
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

#[serde_as]
#[derive(
    Clone,
    Debug,
    PartialEq,
    TlsSize,
    TlsSerialize,
    TlsDeserialize,
    Eq,
    Hash,
    serde::Deserialize,
    serde::Serialize,
)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct CertificateData(
    #[tls_codec(with = "crate::tls::ByteVec")]
    #[serde_as(as = "VecAsBase64")]
    Vec<u8>,
);

impl From<Vec<u8>> for CertificateData {
    fn from(data: Vec<u8>) -> Self {
        CertificateData(data)
    }
}

impl Deref for CertificateData {
    type Target = Vec<u8>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl CertificateData {
    pub fn parse(&self) -> Result<Certificate, X509Error> {
        Certificate::from_der(&self.0).map_err(Into::into)
    }
}

#[derive(
    Clone,
    Debug,
    PartialEq,
    TlsSize,
    TlsSerialize,
    TlsDeserialize,
    Eq,
    Hash,
    serde::Deserialize,
    serde::Serialize,
)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct CertificateChain(#[tls_codec(with = "crate::tls::DefVec")] Vec<CertificateData>);

impl From<Vec<CertificateData>> for CertificateChain {
    fn from(cert_data: Vec<CertificateData>) -> Self {
        CertificateChain(cert_data)
    }
}

impl Deref for CertificateChain {
    type Target = Vec<CertificateData>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for CertificateChain {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl CertificateChain {
    pub fn empty() -> Self {
        Self(vec![])
    }

    pub fn leaf(&self) -> Option<&CertificateData> {
        self.0.first()
    }

    pub fn ca(&self) -> Option<&CertificateData> {
        self.0.last()
    }

    pub fn parse(&self) -> Result<Vec<Certificate>, X509Error> {
        self.iter()
            .map(|c| c.parse())
            .collect::<Result<Vec<_>, _>>()
    }
}

#[cfg(any(test, feature = "benchmark"))]
pub mod test_utils {
    use der::Decode;
    use ferriscrypt::asym::ec_key::{self, Curve};
    use x509_cert::Certificate;

    use crate::provider::identity::get_public_key;
    pub use signing_identity::test_utils::*;

    use super::*;

    pub fn test_cert(curve: ec_key::Curve) -> CertificateData {
        let data = match curve {
            ec_key::Curve::P256 => include_bytes!("../test_data/p256_cert.der").to_vec(),
            #[cfg(feature = "openssl_engine")]
            ec_key::Curve::P384 => include_bytes!("../test_data/p384_cert.der").to_vec(),
            #[cfg(feature = "openssl_engine")]
            ec_key::Curve::P521 => include_bytes!("../test_data/p521_cert.der").to_vec(),
            ec_key::Curve::Ed25519 => include_bytes!("../test_data/ed25519_cert.der").to_vec(),
            #[cfg(feature = "openssl_engine")]
            ec_key::Curve::Ed448 => include_bytes!("../test_data/ed448_cert.der").to_vec(),
            _ => panic!("invalid test curve"),
        };

        CertificateData::from(data)
    }

    pub fn test_chain() -> (CertificateChain, ec_key::PublicKey) {
        let ca_data = include_bytes!("../test_data/cert_chain/id3-ca.der").to_vec();
        let id2_data = include_bytes!("../test_data/cert_chain/id2.der").to_vec();
        let id1_data = include_bytes!("../test_data/cert_chain/id1.der").to_vec();
        let id0_data = include_bytes!("../test_data/cert_chain/id0-leaf.der").to_vec();

        let leaf_cert = Certificate::from_der(&id0_data).unwrap();
        let leaf_pk = get_public_key(&leaf_cert).unwrap();

        let chain = [id0_data, id1_data, id2_data, ca_data]
            .into_iter()
            .map(CertificateData::from)
            .collect::<Vec<_>>()
            .into();

        (chain, leaf_pk)
    }

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
