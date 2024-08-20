// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// Copyright by contributors to this project.
// SPDX-License-Identifier: (Apache-2.0 OR MIT)

use mls_rs_core::crypto::SignaturePublicKey;
use mls_rs_identity_x509::{
    DerCertificate, SubjectAltName, SubjectComponent, X509CertificateReader,
};

use crate::AwsLcCryptoError;

use super::certificate::Certificate;

#[derive(Debug, Clone, Copy, Default)]
pub struct CertificateParser;

impl CertificateParser {
    pub fn new() -> Self {
        Default::default()
    }
}

impl X509CertificateReader for CertificateParser {
    type Error = AwsLcCryptoError;

    #[doc = " Der encoded bytes of a certificate subject field."]
    fn subject_bytes(&self, certificate: &DerCertificate) -> Result<Vec<u8>, Self::Error> {
        let parsed = Certificate::try_from(certificate)?;
        parsed.subject_bytes()
    }

    #[doc = " Parsed certificate subject field components."]
    fn subject_components(
        &self,
        certificate: &DerCertificate,
    ) -> Result<Vec<SubjectComponent>, Self::Error> {
        let parsed = Certificate::try_from(certificate)?;
        parsed.subject_components()
    }

    #[doc = " Parsed subject alt name extensions of a certificate."]
    fn subject_alt_names(
        &self,
        certificate: &DerCertificate,
    ) -> Result<Vec<SubjectAltName>, Self::Error> {
        let parsed = Certificate::try_from(certificate)?;
        parsed.subject_alt_names()
    }

    #[doc = " Get the subject public key of a certificate."]
    fn public_key(&self, certificate: &DerCertificate) -> Result<SignaturePublicKey, Self::Error> {
        let parsed = Certificate::try_from(certificate)?;
        parsed.public_key()
    }
}

#[cfg(test)]
mod tests {
    use mls_rs_core::crypto::CipherSuite;
    use mls_rs_identity_x509::{SubjectAltName, SubjectComponent, X509CertificateReader};

    use crate::ecdsa::AwsLcEcdsa;
    use crate::x509::component::X509Name;
    use crate::x509::test_utils::{
        load_github_leaf, load_ip_cert, load_test_ca, test_leaf, test_leaf_key,
    };

    use super::CertificateParser;

    #[test]
    fn will_return_public_key_of_leaf() {
        let leaf = test_leaf();

        let expected = AwsLcEcdsa::new(CipherSuite::CURVE25519_AES128)
            .unwrap()
            .signature_key_derive_public(&test_leaf_key())
            .unwrap();

        let reader = CertificateParser;
        let read = reader.public_key(&leaf).unwrap();

        assert_eq!(expected, read);
    }

    #[test]
    fn subject_parser_bytes() {
        let test_cert = load_test_ca();

        let expected = X509Name::new_components(&[SubjectComponent::CommonName("CA".to_string())])
            .unwrap()
            .to_der()
            .unwrap();

        assert_eq!(
            CertificateParser.subject_bytes(&test_cert).unwrap(),
            expected
        );
    }

    #[test]
    fn subject_parser_components() {
        let test_cert = load_github_leaf();

        let expected = vec![
            SubjectComponent::CountryName(String::from("US")),
            SubjectComponent::State(String::from("California")),
            SubjectComponent::Locality(String::from("San Francisco")),
            SubjectComponent::OrganizationName(String::from("GitHub, Inc.")),
            SubjectComponent::CommonName(String::from("github.com")),
        ];

        assert_eq!(
            CertificateParser::new()
                .subject_components(&test_cert)
                .unwrap(),
            expected
        )
    }

    #[test]
    fn subject_alt_names() {
        let test_cert = load_github_leaf();

        let expected = vec![
            SubjectAltName::Dns(String::from("github.com")),
            SubjectAltName::Dns(String::from("www.github.com")),
        ];

        assert_eq!(
            CertificateParser::new()
                .subject_alt_names(&test_cert)
                .unwrap(),
            expected
        )
    }

    #[test]
    fn subject_alt_names_ip() {
        let test_cert = load_ip_cert();

        let expected = vec![
            SubjectAltName::Ip(String::from("97.97.97.254")),
            SubjectAltName::Ip(String::from("97.97.97.253")),
        ];

        assert_eq!(
            CertificateParser::new()
                .subject_alt_names(&test_cert)
                .unwrap(),
            expected
        )
    }
}
