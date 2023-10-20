use std::{ffi::c_long, ptr::null_mut};

use aws_lc_sys::{
    d2i_X509, i2d_X509_NAME, ASN1_STRING_data, ASN1_STRING_length, EC_KEY_get0_group,
    EC_KEY_get0_public_key, EC_POINT_point2oct, EVP_PKEY_get0_EC_KEY, EVP_PKEY_get_raw_public_key,
    NID_commonName, NID_countryName, NID_distinguishedName, NID_domainComponent,
    NID_generationQualifier, NID_givenName, NID_initials, NID_localityName, NID_organizationName,
    NID_organizationalUnitName, NID_pkcs9_emailAddress, NID_pseudonym, NID_serialNumber,
    NID_stateOrProvinceName, NID_streetAddress, NID_subject_alt_name, NID_surname, NID_title,
    NID_userId, OBJ_obj2nid, X509_NAME_ENTRY_get_data, X509_NAME_ENTRY_get_object,
    X509_NAME_entry_count, X509_NAME_get_entry, X509_free, X509_get0_pubkey, X509_get_ext_d2i,
    X509_get_subject_name, X509,
};
use aws_mls_core::crypto::SignaturePublicKey;
use aws_mls_identity_x509::{
    DerCertificate, SubjectAltName, SubjectComponent, X509CertificateReader,
};

use crate::{check_int_return, check_non_null, check_res, AwsLcCryptoError};

use super::component::{GeneralName, Stack};

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
        let parsed = ParsedCert::try_from(certificate)?;
        parsed.subject_bytes()
    }

    #[doc = " Parsed certificate subject field components."]
    fn subject_components(
        &self,
        certificate: &DerCertificate,
    ) -> Result<Vec<SubjectComponent>, Self::Error> {
        let parsed = ParsedCert::try_from(certificate)?;
        parsed.subject_components()
    }

    #[doc = " Parsed subject alt name extensions of a certificate."]
    fn subject_alt_names(
        &self,
        certificate: &DerCertificate,
    ) -> Result<Vec<SubjectAltName>, Self::Error> {
        let parsed = ParsedCert::try_from(certificate)?;
        parsed.subject_alt_names()
    }

    #[doc = " Get the subject public key of a certificate."]
    fn public_key(&self, certificate: &DerCertificate) -> Result<SignaturePublicKey, Self::Error> {
        let parsed = ParsedCert::try_from(certificate)?;
        parsed.public_key()
    }
}

struct ParsedCert(*mut X509);

impl ParsedCert {
    pub fn subject_bytes(&self) -> Result<Vec<u8>, AwsLcCryptoError> {
        unsafe {
            let name = check_non_null(X509_get_subject_name(self.0))?;

            let len = check_int_return(i2d_X509_NAME(name, null_mut()))?;
            let mut out = vec![0u8; len as usize];
            check_res(i2d_X509_NAME(name, &mut out.as_mut_ptr()))?;

            Ok(out)
        }
    }

    #[allow(non_upper_case_globals)]
    pub fn subject_components(&self) -> Result<Vec<SubjectComponent>, AwsLcCryptoError> {
        unsafe {
            let name = check_non_null(X509_get_subject_name(self.0))?;

            (0..X509_NAME_entry_count(name)).try_fold(Vec::new(), |mut components, i| {
                let entry = check_non_null(X509_NAME_get_entry(name, i))?;
                let nid = OBJ_obj2nid(X509_NAME_ENTRY_get_object(entry));

                let entry = check_non_null(X509_NAME_ENTRY_get_data(entry))?;

                let len = check_int_return(ASN1_STRING_length(entry))?;
                let data = check_non_null(ASN1_STRING_data(entry))?;

                let slice = core::slice::from_raw_parts(data, len as usize);

                let data =
                    String::from_utf8(slice.to_vec()).map_err(|_| AwsLcCryptoError::CryptoError)?;

                if let Some(component) = match nid {
                    NID_commonName => Some(SubjectComponent::CommonName(data)),
                    NID_surname => Some(SubjectComponent::Surname(data)),
                    NID_serialNumber => Some(SubjectComponent::SerialNumber(data)),
                    NID_countryName => Some(SubjectComponent::CountryName(data)),
                    NID_localityName => Some(SubjectComponent::Locality(data)),
                    NID_stateOrProvinceName => Some(SubjectComponent::State(data)),
                    NID_streetAddress => Some(SubjectComponent::StreetAddress(data)),
                    NID_organizationName => Some(SubjectComponent::OrganizationName(data)),
                    NID_organizationalUnitName => Some(SubjectComponent::OrganizationalUnit(data)),
                    NID_title => Some(SubjectComponent::Title(data)),
                    NID_givenName => Some(SubjectComponent::GivenName(data)),
                    NID_pkcs9_emailAddress => Some(SubjectComponent::EmailAddress(data)),
                    NID_userId => Some(SubjectComponent::UserId(data)),
                    NID_domainComponent => Some(SubjectComponent::DomainComponent(data)),
                    NID_initials => Some(SubjectComponent::Initials(data)),
                    NID_generationQualifier => Some(SubjectComponent::GenerationQualifier(data)),
                    NID_distinguishedName => {
                        Some(SubjectComponent::DistinguishedNameQualifier(data))
                    }
                    NID_pseudonym => Some(SubjectComponent::Pseudonym(data)),
                    _ => None,
                } {
                    components.push(component);
                }

                Ok(components)
            })
        }
    }

    pub fn public_key(&self) -> Result<SignaturePublicKey, AwsLcCryptoError> {
        unsafe {
            let pub_key = X509_get0_pubkey(self.0);
            let ec_key = EVP_PKEY_get0_EC_KEY(pub_key);

            if !ec_key.is_null() {
                let mut out_buf = vec![0u8; 256];

                let len = EC_POINT_point2oct(
                    EC_KEY_get0_group(ec_key),
                    EC_KEY_get0_public_key(ec_key),
                    aws_lc_sys::point_conversion_form_t::POINT_CONVERSION_UNCOMPRESSED,
                    out_buf.as_mut_ptr(),
                    256,
                    null_mut(),
                );

                if len == 0 {
                    return Err(AwsLcCryptoError::InvalidKeyData);
                }

                out_buf.truncate(len);

                Ok(out_buf.into())
            } else {
                let mut len = 0;

                check_res(EVP_PKEY_get_raw_public_key(pub_key, null_mut(), &mut len))?;

                let mut out = vec![0u8; len];

                check_res(EVP_PKEY_get_raw_public_key(
                    pub_key,
                    out.as_mut_ptr(),
                    &mut len,
                ))?;

                Ok(out.into())
            }
        }
    }

    pub fn subject_alt_names(&self) -> Result<Vec<SubjectAltName>, AwsLcCryptoError> {
        unsafe {
            let subject_alt_names =
                X509_get_ext_d2i(self.0, NID_subject_alt_name, null_mut(), null_mut());

            if subject_alt_names.is_null() {
                return Ok(Vec::default());
            }

            let stack: Stack<GeneralName> = Stack::from(subject_alt_names.cast());

            stack
                .into_vec()
                .into_iter()
                .rev()
                .map(|name| name.subject_alt_name())
                .collect()
        }
    }
}

impl Drop for ParsedCert {
    fn drop(&mut self) {
        unsafe { X509_free(self.0) }
    }
}

impl TryFrom<&DerCertificate> for ParsedCert {
    type Error = AwsLcCryptoError;

    fn try_from(value: &DerCertificate) -> Result<Self, Self::Error> {
        let mut result_holder = value.as_ptr();

        unsafe {
            check_non_null(d2i_X509(
                null_mut(),
                &mut result_holder,
                value.len() as c_long,
            ))
            .map(ParsedCert)
        }
    }
}

#[cfg(test)]
mod tests {
    use aws_mls_core::crypto::CipherSuite;
    use aws_mls_identity_x509::{SubjectAltName, SubjectComponent, X509CertificateReader};

    use crate::{
        ecdsa::AwsLcEcdsa,
        x509::{
            component::X509Name,
            test_utils::{load_github_leaf, load_ip_cert, load_test_ca, test_leaf, test_leaf_key},
        },
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
