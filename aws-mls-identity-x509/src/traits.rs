use crate::{
    CertificateGeneration, CertificateIssuer, CertificateParameters, CertificateRequest,
    DerCertificate, SubjectAltName, SubjectComponent,
};

use aws_mls_core::crypto::{CipherSuite, SignaturePublicKey, SignatureSecretKey};
#[cfg(test)]
use mockall::automock;

#[cfg_attr(test, automock(type Error = crate::test_utils::TestError;))]
/// Trait for X.509 certificate writing.
pub trait X509CertificateWriter {
    type Error: std::error::Error + Send + Sync + 'static;

    /// Build a CSR from parameters.
    ///
    /// `cipher_suite` is used to indicate
    /// what type of key pair should be generated if `signer` is set
    /// to `None`.
    fn build_csr(
        &self,
        cipher_suite: CipherSuite,
        signer: Option<SignatureSecretKey>,
        params: CertificateParameters,
    ) -> Result<CertificateRequest, Self::Error>;

    /// Build a certificate chain from parameters.
    ///
    /// `subject_cipher_suite` is used to indicate what type of key
    /// pair should be generated if `subject_pubkey` is set to `None`.
    fn build_cert_chain(
        &self,
        subject_cipher_suite: CipherSuite,
        issuer: &CertificateIssuer,
        subject_pubkey: Option<SignaturePublicKey>,
        subject_params: CertificateParameters,
    ) -> Result<CertificateGeneration, Self::Error>;
}

#[cfg_attr(test, automock(type Error = crate::test_utils::TestError;))]
/// Trait for X.509 certificate parsing.
pub trait X509CertificateReader {
    type Error: std::error::Error + Send + Sync + 'static;

    /// Der encoded bytes of a certificate subject field.
    fn subject_bytes(&self, certificate: &DerCertificate) -> Result<Vec<u8>, Self::Error>;

    /// Parsed certificate subject field components.
    fn subject_components(
        &self,
        certificate: &DerCertificate,
    ) -> Result<Vec<SubjectComponent>, Self::Error>;

    /// Parsed subject alt name extensions of a certificate.
    fn subject_alt_names(
        &self,
        certificate: &DerCertificate,
    ) -> Result<Vec<SubjectAltName>, Self::Error>;

    /// Get the subject public key of a certificate.
    fn public_key(&self, certificate: &DerCertificate) -> Result<SignaturePublicKey, Self::Error>;
}
