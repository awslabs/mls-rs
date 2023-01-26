use aws_mls_core::crypto::{CipherSuite, SignaturePublicKey, SignatureSecretKey};

use crate::{CertificateChain, X509CertificateWriter};

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

#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct CertificateIssuer {
    pub signing_key: SignatureSecretKey,
    pub cipher_suite: CipherSuite,
    pub chain: CertificateChain,
    pub lifetime: u64,
}

impl CertificateIssuer {
    pub fn new(
        signing_key: SignatureSecretKey,
        cipher_suite: CipherSuite,
        chain: CertificateChain,
        lifetime: u64,
    ) -> CertificateIssuer {
        Self {
            signing_key,
            cipher_suite,
            chain,
            lifetime,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertificateRequest {
    pub req_data: Vec<u8>,
    pub secret_key: SignatureSecretKey,
}

impl CertificateRequest {
    // TODO: When Keychain is moved into core, we should have a method that processes the response,
    // validates it against the request, and stores the resulting secret key + SigningIdentity for further use
}

pub struct CertificateGeneration {
    pub chain: CertificateChain,
    pub secret_key: Option<SignatureSecretKey>,
}

impl CertificateGeneration {
    // TODO: When Keychain is moved into core, we should have a method that stores this value there
}

#[derive(Debug, Clone)]
pub struct CertificateBuilder {
    subject_cipher_suite: CipherSuite,
    subject_params: CertificateParameters,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CertificateParameters {
    pub subject: Vec<SubjectComponent>,
    pub subject_alt_names: Vec<SubjectAltName>,
    pub is_ca: bool,
}

impl CertificateBuilder {
    pub fn new(cipher_suite: CipherSuite) -> Self {
        Self {
            subject_cipher_suite: cipher_suite,
            subject_params: Default::default(),
        }
    }

    pub fn with_subject_component(mut self, component: SubjectComponent) -> Self {
        self.subject_params.subject.push(component);
        self
    }

    pub fn with_subject_alt_name(mut self, alt_name: SubjectAltName) -> Self {
        self.subject_params.subject_alt_names.push(alt_name);
        self
    }

    pub fn set_ca_flag(self) -> Self {
        Self {
            subject_params: CertificateParameters {
                is_ca: true,
                ..self.subject_params
            },
            ..self
        }
    }

    pub fn build_cert_chain<B: X509CertificateWriter>(
        self,
        issuer: &CertificateIssuer,
        subject_public: Option<SignaturePublicKey>,
        x509_writer: &B,
    ) -> Result<CertificateGeneration, B::Error> {
        x509_writer.build_cert_chain(
            self.subject_cipher_suite,
            issuer,
            subject_public,
            self.subject_params,
        )
    }

    pub fn build_csr<B: X509CertificateWriter>(
        self,
        signer: Option<SignatureSecretKey>,
        x509_writer: &B,
    ) -> Result<CertificateRequest, B::Error> {
        x509_writer.build_csr(self.subject_cipher_suite, signer, self.subject_params)
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
        builder::test_utils::test_subject_components, CertificateBuilder, CertificateParameters,
        CertificateRequest, MockX509CertificateWriter,
    };

    use super::test_utils::test_subject_alt_names;

    const TEST_CIPHER_SUITE: CipherSuite = CipherSuite::Curve25519Aes128;

    #[test]
    fn requests_leaf_by_default() {
        let builder = CertificateBuilder::new(TEST_CIPHER_SUITE);
        assert!(!builder.subject_params.is_ca)
    }

    #[test]
    fn can_request_ca() {
        let builder = CertificateBuilder::new(TEST_CIPHER_SUITE).set_ca_flag();
        assert!(builder.subject_params.is_ca);
    }

    #[test]
    fn can_request_subject_components() {
        let test_components = test_subject_components();

        let builder = test_components.iter().fold(
            CertificateBuilder::new(TEST_CIPHER_SUITE),
            |builder, value| builder.with_subject_component(value.clone()),
        );

        assert_eq!(builder.subject_params.subject, test_components);
        assert!(builder.subject_params.subject_alt_names.is_empty());
    }

    #[test]
    fn can_request_subject_alt_names() {
        let test_components = test_subject_alt_names();

        let builder = test_components.iter().fold(
            CertificateBuilder::new(TEST_CIPHER_SUITE),
            |builder, value| builder.with_subject_alt_name(value.clone()),
        );

        assert_eq!(builder.subject_params.subject_alt_names, test_components);
        assert!(builder.subject_params.subject.is_empty());
    }

    #[test]
    fn build_via_a_writer() {
        let expected_params = CertificateParameters {
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

        let builder = CertificateBuilder::new(TEST_CIPHER_SUITE).set_ca_flag();

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

        assert_eq!(builder.build_csr(None, &writer).unwrap(), expected_request);
    }
}
