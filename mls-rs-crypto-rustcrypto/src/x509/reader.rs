// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// Copyright by contributors to this project.
// SPDX-License-Identifier: (Apache-2.0 OR MIT)

use mls_rs_identity_x509::{
    DerCertificate, SubjectAltName as MlsSubjectAltName, SubjectComponent, X509CertificateReader,
};
use spki::der::oid::AssociatedOid;
use spki::der::{Decode, Encode};
use x509_cert::ext::pkix::name::GeneralNames;
use x509_cert::ext::pkix::SubjectAltName;
use x509_cert::Certificate;

use crate::ec::pub_key_to_uncompressed;
use crate::ec_for_x509::pub_key_from_spki;

use super::util::{general_names_to_alt_names, parse_x509_name};
use super::X509Error;

#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub struct X509Reader {}

impl X509Reader {
    pub fn new() -> X509Reader {
        Self {}
    }
}

impl X509CertificateReader for X509Reader {
    type Error = X509Error;

    fn subject_bytes(&self, certificate: &DerCertificate) -> Result<Vec<u8>, Self::Error> {
        Certificate::from_der(certificate)?
            .tbs_certificate
            .subject
            .to_der()
            .map_err(Into::into)
    }

    fn subject_components(
        &self,
        certificate: &DerCertificate,
    ) -> Result<Vec<SubjectComponent>, Self::Error> {
        parse_x509_name(&Certificate::from_der(certificate)?.tbs_certificate.subject)
    }

    fn subject_alt_names(
        &self,
        certificate: &DerCertificate,
    ) -> Result<Vec<MlsSubjectAltName>, Self::Error> {
        Ok(Certificate::from_der(certificate)?
            .tbs_certificate
            .extensions
            .unwrap_or_default()
            .iter()
            .filter(|ext| ext.extn_id == SubjectAltName::OID)
            .map(|ext| {
                general_names_to_alt_names(&GeneralNames::from_der(ext.extn_value.as_bytes())?)
            })
            .collect::<Result<Vec<_>, _>>()?
            .into_iter()
            .flatten()
            .collect::<Vec<_>>())
    }

    fn public_key(
        &self,
        certificate: &DerCertificate,
    ) -> Result<mls_rs_core::crypto::SignaturePublicKey, Self::Error> {
        let spki = Certificate::from_der(certificate)?
            .tbs_certificate
            .subject_public_key_info;

        let pub_key = pub_key_from_spki(&spki)?;

        pub_key_to_uncompressed(&pub_key)
            .map_err(Into::into)
            .map(Into::into)
    }
}

#[cfg(test)]
mod tests {
    use mls_rs_identity_x509::{SubjectAltName, SubjectComponent, X509CertificateReader};
    use spki::der::asn1::{SetOfVec, Utf8StringRef};
    use spki::der::oid::db::rfc4519;
    use spki::der::{Any, Encode};
    use x509_cert::attr::AttributeTypeAndValue;
    use x509_cert::name::RelativeDistinguishedName;

    use crate::x509::util::test_utils::{load_github_leaf, load_ip_cert, load_test_ca};
    use crate::x509::X509Reader;

    #[test]
    fn subject_parser_bytes() {
        let test_cert = load_test_ca();

        let expected_type_and_value = AttributeTypeAndValue {
            oid: rfc4519::CN,
            value: Any::from(Utf8StringRef::new("CA").unwrap()),
        };

        let expected_rdn = RelativeDistinguishedName::from(
            SetOfVec::try_from(vec![expected_type_and_value]).unwrap(),
        );

        let expected_name = vec![expected_rdn].to_der().unwrap();

        assert_eq!(
            X509Reader::new().subject_bytes(&test_cert).unwrap(),
            expected_name
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
            X509Reader::new().subject_components(&test_cert).unwrap(),
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
            X509Reader::new().subject_alt_names(&test_cert).unwrap(),
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
            X509Reader::new().subject_alt_names(&test_cert).unwrap(),
            expected
        )
    }
}
