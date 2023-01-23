use std::ops::Deref;

mod builder;
mod error;
mod identity_extractor;
mod provider;
mod traits;
mod util;

pub use builder::*;
pub use error::*;
pub use identity_extractor::*;
pub use provider::*;
pub use traits::*;

use aws_mls_core::{
    identity::{Credential, CredentialType, MlsCredential},
    tls::tls_codec::{self, Serialize},
    tls::tls_codec_derive::{TlsDeserialize, TlsSerialize, TlsSize},
};

pub const CERTIFICATE_CREDENTIAL_ID: u16 = 2;

#[derive(Clone, Debug, PartialEq, Eq, TlsDeserialize, TlsSerialize, TlsSize)]
pub struct DerCertificate(#[tls_codec(with = "aws_mls_core::tls::ByteVec")] Vec<u8>);

impl From<Vec<u8>> for DerCertificate {
    fn from(data: Vec<u8>) -> Self {
        DerCertificate(data)
    }
}

impl Deref for DerCertificate {
    type Target = Vec<u8>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[derive(Clone, Debug, PartialEq, Eq, TlsDeserialize, TlsSerialize, TlsSize)]
pub struct CertificateChain(#[tls_codec(with = "aws_mls_core::tls::DefVec")] Vec<DerCertificate>);

impl Deref for CertificateChain {
    type Target = Vec<DerCertificate>;

    fn deref(&self) -> &Self::Target {
        &self.0
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
    pub fn leaf(&self) -> Option<&DerCertificate> {
        self.0.first()
    }

    pub fn ca(&self) -> Option<&DerCertificate> {
        self.0.last()
    }

    pub fn into_credential(self) -> Result<aws_mls_core::identity::Credential, X509IdentityError> {
        Ok(Credential {
            credential_type: CredentialType::new(CERTIFICATE_CREDENTIAL_ID),
            credential_data: self
                .tls_serialize_detached()
                .map_err(|e| X509IdentityError::CredentialEncodingError(e.into()))?,
        })
    }
}

impl MlsCredential for CertificateChain {
    type Error = X509IdentityError;

    fn credential_type() -> aws_mls_core::identity::CredentialType {
        CredentialType::new(CERTIFICATE_CREDENTIAL_ID)
    }

    fn into_credential(self) -> Result<aws_mls_core::identity::Credential, Self::Error> {
        self.into_credential()
    }
}

#[cfg(test)]
pub mod test_utils {
    use aws_mls_core::{crypto::SignaturePublicKey, identity::SigningIdentity};
    use rand::{thread_rng, Rng};

    use crate::{CertificateChain, DerCertificate};

    #[derive(Debug, thiserror::Error)]
    #[error("test error")]
    pub struct TestError;

    pub fn test_certificate_chain() -> CertificateChain {
        (0..3)
            .into_iter()
            .map(|_| {
                let mut data = [0u8; 32];
                thread_rng().fill(&mut data);
                DerCertificate(data.to_vec())
            })
            .collect::<CertificateChain>()
    }

    pub fn test_signing_identity() -> SigningIdentity {
        let chain = test_certificate_chain();
        test_signing_identity_with_chain(chain)
    }

    pub fn test_signing_identity_with_chain(chain: CertificateChain) -> SigningIdentity {
        SigningIdentity {
            signature_key: SignaturePublicKey::from(vec![0u8; 128]),
            credential: chain.into_credential().unwrap(),
        }
    }
}
