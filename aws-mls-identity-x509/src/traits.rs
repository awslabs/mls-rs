use crate::{
    CertificateRequest, CertificateRequestParameters, DerCertificate, SubjectAltName,
    SubjectComponent,
};

use aws_mls_core::crypto::{CipherSuite, SignatureSecretKey};
#[cfg(test)]
use mockall::automock;

#[cfg_attr(test, automock(type Error = crate::test_utils::TestError;))]
pub trait X509CertificateWriter {
    type Error: std::error::Error + Send + Sync + 'static;

    fn build_csr(
        &self,
        cipher_suite: CipherSuite,
        signer: Option<SignatureSecretKey>,
        params: CertificateRequestParameters,
    ) -> Result<CertificateRequest, Self::Error>;
}

#[cfg_attr(test, automock(type Error = crate::test_utils::TestError;))]
pub trait X509CertificateReader {
    type Error: std::error::Error + Send + Sync + 'static;

    fn subject_bytes(&self, certificate: &DerCertificate) -> Result<Vec<u8>, Self::Error>;

    fn subject_components(
        &self,
        certificate: &DerCertificate,
    ) -> Result<Vec<SubjectComponent>, Self::Error>;

    fn subject_alt_names(
        &self,
        certificate: &DerCertificate,
    ) -> Result<Vec<SubjectAltName>, Self::Error>;
}
