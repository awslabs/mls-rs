use std::{
    convert::Infallible,
    ops::{Deref, DerefMut},
};

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
pub struct DerCertificate(
    #[serde_as(as = "crate::serde::vec_u8_as_base64::VecAsBase64")]
    #[tls_codec(with = "crate::tls::ByteVec")]
    Vec<u8>,
);

impl From<Vec<u8>> for DerCertificate {
    fn from(data: Vec<u8>) -> Self {
        DerCertificate(data)
    }
}

impl Deref for DerCertificate {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl AsRef<[u8]> for DerCertificate {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

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
pub struct CertificateChain(#[tls_codec(with = "crate::tls::DefVec")] Vec<DerCertificate>);

impl Deref for CertificateChain {
    type Target = Vec<DerCertificate>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for CertificateChain {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl From<Vec<DerCertificate>> for CertificateChain {
    fn from(cert_data: Vec<DerCertificate>) -> Self {
        CertificateChain(cert_data)
    }
}

impl From<Vec<Vec<u8>>> for CertificateChain {
    fn from(value: Vec<Vec<u8>>) -> Self {
        CertificateChain(value.into_iter().map(DerCertificate).collect())
    }
}

impl FromIterator<DerCertificate> for CertificateChain {
    fn from_iter<T: IntoIterator<Item = DerCertificate>>(iter: T) -> Self {
        CertificateChain::from(iter.into_iter().collect::<Vec<_>>())
    }
}

impl CertificateChain {
    pub fn credential_type() -> CredentialType {
        CredentialType::X509
    }

    pub fn leaf(&self) -> Option<&DerCertificate> {
        self.0.first()
    }

    pub fn ca(&self) -> Option<&DerCertificate> {
        self.0.last()
    }

    pub fn into_credential(self) -> Credential {
        Credential::X509(self)
    }
}

impl MlsCredential for CertificateChain {
    type Error = Infallible;

    fn credential_type() -> CredentialType {
        Self::credential_type()
    }

    fn into_credential(self) -> Result<Credential, Self::Error> {
        Ok(self.into_credential())
    }
}
