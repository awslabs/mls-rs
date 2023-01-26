use crate::{
    CertificateGeneration, CertificateIssuer, CertificateParameters, CertificateRequest,
    DerCertificate, SubjectAltName, SubjectComponent,
};

use aws_mls_core::crypto::{CipherSuite, SignaturePublicKey, SignatureSecretKey};
#[cfg(test)]
use mockall::automock;

#[cfg_attr(test, automock(type Error = crate::test_utils::TestError;))]
pub trait X509CertificateWriter {
    type Error: std::error::Error + Send + Sync + 'static;

    fn build_csr(
        &self,
        cipher_suite: CipherSuite,
        signer: Option<SignatureSecretKey>,
        params: CertificateParameters,
    ) -> Result<CertificateRequest, Self::Error>;

    fn build_cert_chain(
        &self,
        subject_cipher_suite: CipherSuite,
        issuer: &CertificateIssuer,
        subject_pubkey: Option<SignaturePublicKey>,
        subject_params: CertificateParameters,
    ) -> Result<CertificateGeneration, Self::Error>;
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
