use aws_mls_core::crypto::{CipherSuite, SignatureSecretKey};

use crate::X509CertificateWriter;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum SubjectAltName {
    Email(String),
    Uri(String),
    Dns(String),
    Rid(String),
    Ip(String),
    DirName(String),
    OtherName(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum SubjectComponent {
    CommonName(String),
    Surname(String),
    SerialNumber(String),
    CountryName(String),
    Locality(String),
    State(String),
    StreetAddress(String),
    OrganizationName(String),
    OrganizationalUnit(String),
    Title(String),
    GivenName(String),
    EmailAddress(String),
    UserId(String),
    DomainComponent(String),
    Initials(String),
    GenerationQualifier(String),
    DistinguishedNameQualifier(String),
    Pseudonym(String),
}

#[derive(Debug, Clone)]
pub struct CertificateRequestBuilder {
    cipher_suite: CipherSuite,
    signature_key: Option<SignatureSecretKey>,
    params: CertificateRequestParameters,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CertificateRequestParameters {
    pub subject: Vec<SubjectComponent>,
    pub subject_alt_names: Vec<SubjectAltName>,
    pub is_ca: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertificateRequest {
    pub req_data: Vec<u8>,
    pub secret_key: SignatureSecretKey,
}

impl CertificateRequestBuilder {
    pub fn new(cipher_suite: CipherSuite) -> Self {
        Self {
            cipher_suite,
            params: Default::default(),
            signature_key: None,
        }
    }

    pub fn with_subject_component(mut self, component: SubjectComponent) -> Self {
        self.params.subject.push(component);
        self
    }

    pub fn with_subject_alt_name(mut self, alt_name: SubjectAltName) -> Self {
        self.params.subject_alt_names.push(alt_name);
        self
    }

    pub fn set_ca_flag(self) -> Self {
        Self {
            params: CertificateRequestParameters {
                is_ca: true,
                ..self.params
            },
            ..self
        }
    }

    pub fn build<B: X509CertificateWriter>(
        self,
        x509_writer: &B,
    ) -> Result<CertificateRequest, B::Error> {
        x509_writer.build_csr(self.cipher_suite, self.signature_key, self.params)
    }
}

#[cfg(test)]
pub mod test_utils {
    use crate::{SubjectAltName, SubjectComponent};

    pub fn test_subject_components() -> Vec<SubjectComponent> {
        vec![
            SubjectComponent::CommonName("test name".to_string()),
            SubjectComponent::CountryName("US".to_string()),
        ]
    }

    pub fn test_subject_alt_names() -> Vec<SubjectAltName> {
        vec![
            SubjectAltName::Dns("example.org".to_string()),
            SubjectAltName::Ip("1.1.1.1".to_string()),
        ]
    }
}

#[cfg(test)]
mod tests {
    use aws_mls_core::crypto::CipherSuite;

    use crate::{
        builder::test_utils::test_subject_components, CertificateRequest,
        CertificateRequestBuilder, CertificateRequestParameters, MockX509CertificateWriter,
    };

    use super::test_utils::test_subject_alt_names;

    const TEST_CIPHER_SUITE: CipherSuite = CipherSuite::Curve25519Aes128;

    #[test]
    fn requests_leaf_by_default() {
        let builder = CertificateRequestBuilder::new(TEST_CIPHER_SUITE);
        assert!(!builder.params.is_ca)
    }

    #[test]
    fn can_request_ca() {
        let builder = CertificateRequestBuilder::new(TEST_CIPHER_SUITE).set_ca_flag();
        assert!(builder.params.is_ca);
    }

    #[test]
    fn can_request_subject_components() {
        let test_components = test_subject_components();

        let builder = test_components.iter().fold(
            CertificateRequestBuilder::new(TEST_CIPHER_SUITE),
            |builder, value| builder.with_subject_component(value.clone()),
        );

        assert_eq!(builder.params.subject, test_components);
        assert!(builder.params.subject_alt_names.is_empty());
    }

    #[test]
    fn can_request_subject_alt_names() {
        let test_components = test_subject_alt_names();

        let builder = test_components.iter().fold(
            CertificateRequestBuilder::new(TEST_CIPHER_SUITE),
            |builder, value| builder.with_subject_alt_name(value.clone()),
        );

        assert_eq!(builder.params.subject_alt_names, test_components);
        assert!(builder.params.subject.is_empty());
    }

    #[test]
    fn build_via_a_writer() {
        let expected_params = CertificateRequestParameters {
            subject: test_subject_components(),
            subject_alt_names: test_subject_alt_names(),
            is_ca: true,
        };

        let mut writer = MockX509CertificateWriter::new();

        let expected_request = CertificateRequest {
            req_data: vec![0u8; 32],
            secret_key: vec![1u8; 32].into(),
        };

        let mock_request = expected_request.clone();

        writer
            .expect_build_csr()
            .once()
            .with(
                mockall::predicate::eq(TEST_CIPHER_SUITE),
                mockall::predicate::eq(None),
                mockall::predicate::eq(expected_params.clone()),
            )
            .return_once_st(|_, _, _| Ok(mock_request));

        let builder = CertificateRequestBuilder::new(TEST_CIPHER_SUITE).set_ca_flag();

        let builder = expected_params
            .subject
            .iter()
            .fold(builder, |builder, value| {
                builder.with_subject_component(value.clone())
            });

        let builder = expected_params
            .subject_alt_names
            .iter()
            .fold(builder, |builder, value| {
                builder.with_subject_alt_name(value.clone())
            });

        assert_eq!(builder.build(&writer).unwrap(), expected_request);
    }
}
