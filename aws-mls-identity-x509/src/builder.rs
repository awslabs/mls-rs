use aws_mls_core::{
    crypto::{CipherSuite, SignaturePublicKey, SignatureSecretKey},
    identity::SigningIdentity,
};

use crate::{CertificateChain, X509CertificateReader, X509CertificateWriter, X509IdentityError};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
/// Subject alt name extension values.
pub enum SubjectAltName {
    Email(String),
    Uri(String),
    Dns(String),
    Rid(String),
    Ip(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
/// X.509 name components.
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
/// A certificate authority that can create additional certificates.
pub struct CertificateIssuer {
    pub signing_key: SignatureSecretKey,
    pub cipher_suite: CipherSuite,
    pub chain: CertificateChain,
    pub lifetime: u64,
}

impl CertificateIssuer {
    /// Create a new certificate issuer from components.
    ///
    /// `chain` represents a hierarchy of Root / Intermediate CA certificates.
    /// The first entry in the chain will be used to issue new certificates.
    /// Any additional certificates in the chain will also be included in the
    /// resulting [`CertificateChain`] that is created by this issuer.
    ///
    /// # Warning
    ///
    /// `signing_key` MUST be the private key associated with the public key
    /// within the first entry of the `chain`.
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
/// Representation of a certificate request.
pub struct CertificateRequest {
    pub(crate) req_data: Vec<u8>,
    pub(crate) public_key: SignaturePublicKey,
    pub(crate) secret_key: SignatureSecretKey,
}

impl CertificateRequest {
    /// Create a new certificate request from raw components.
    pub fn new(
        req_data: Vec<u8>,
        public_key: SignaturePublicKey,
        secret_key: SignatureSecretKey,
    ) -> CertificateRequest {
        CertificateRequest {
            req_data,
            public_key,
            secret_key,
        }
    }

    /// Request data to send to a CA.
    pub fn request_data(&self) -> &[u8] {
        &self.req_data
    }

    /// Secret key that was used to sign this request.
    pub fn secret_key(&self) -> &SignatureSecretKey {
        &self.secret_key
    }

    /// Convert this request into a [`CertificateGeneration`] based upon the
    /// certificate chain data received from a CA.
    ///
    /// The leaf of `issued_certificate` is expected to contain the public key
    /// value associated with the `secret_key` used to sign the request.
    pub fn finalize<R, K>(
        self,
        issued_certificate: CertificateChain,
        reader: &R,
    ) -> Result<CertificateGeneration, X509IdentityError>
    where
        R: X509CertificateReader,
    {
        let issued_public_key = reader
            .public_key(
                issued_certificate
                    .leaf()
                    .ok_or(X509IdentityError::EmptyCertificateChain)?,
            )
            .map_err(|e| X509IdentityError::X509ReaderError(e.into()))?;

        if issued_public_key != self.public_key {
            return Err(X509IdentityError::SignatureKeyMismatch);
        }

        Ok(CertificateGeneration {
            chain: issued_certificate,
            public_key: issued_public_key,
            generated_secret: Some(self.secret_key),
        })
    }
}

/// Representation of a newly generated certificate chain
/// along with the [`SignatureSecretKey`] of the leaf certificate
/// if it was generated randomly as part of creating this certificate.
#[derive(Debug, Clone)]
pub struct CertificateGeneration {
    pub(crate) chain: CertificateChain,
    pub(crate) public_key: SignaturePublicKey,
    pub(crate) generated_secret: Option<SignatureSecretKey>,
}

impl CertificateGeneration {
    /// Create a new certificate generation.
    pub fn new(
        chain: CertificateChain,
        public_key: SignaturePublicKey,
        generated_secret: Option<SignatureSecretKey>,
    ) -> CertificateGeneration {
        CertificateGeneration {
            chain,
            public_key,
            generated_secret,
        }
    }

    /// Convert this certificate generation into a [`SigningIdentity`]
    /// that can be used for MLS.
    pub fn to_signing_identity(&self) -> SigningIdentity {
        SigningIdentity {
            signature_key: self.public_key.clone(),
            credential: self.chain.clone().into_credential(),
        }
    }

    /// `Some` if a secret key was generated as part of generating the certificate.
    pub fn generated_secret(&self) -> Option<&SignatureSecretKey> {
        self.generated_secret.as_ref()
    }

    /// Created certificate chain.
    pub fn certificate_chain(&self) -> &CertificateChain {
        &self.chain
    }
}

#[derive(Debug, Clone)]
/// Builder to aid with the creation of both certificate requests
/// and new certificate chains.
pub struct CertificateBuilder {
    subject_cipher_suite: CipherSuite,
    subject_params: CertificateParameters,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
/// Parameters used to generate certificates and certificate requests.
pub struct CertificateParameters {
    pub subject: Vec<SubjectComponent>,
    pub subject_alt_names: Vec<SubjectAltName>,
    pub is_ca: bool,
}

impl CertificateBuilder {
    /// Create a new certificate builder for
    /// a particular [`CipherSuite`].
    ///
    /// `cipher_suite` is used to determine what type of signature key should be
    /// used as part of generating the certificate.
    pub fn new(cipher_suite: CipherSuite) -> Self {
        Self {
            subject_cipher_suite: cipher_suite,
            subject_params: Default::default(),
        }
    }

    /// Add a subject component.
    pub fn with_subject_component(mut self, component: SubjectComponent) -> Self {
        self.subject_params.subject.push(component);
        self
    }

    /// Add a subject alt name.
    pub fn with_subject_alt_name(mut self, alt_name: SubjectAltName) -> Self {
        self.subject_params.subject_alt_names.push(alt_name);
        self
    }

    /// Flag to indicate the resulting certificate or certificate request
    /// is for an intermediate CA rather than a leaf certificate.
    pub fn set_ca_flag(self) -> Self {
        Self {
            subject_params: CertificateParameters {
                is_ca: true,
                ..self.subject_params
            },
            ..self
        }
    }

    /// Produce a new certificate chain.
    ///
    /// Issuer is used to sign the newly created certificate. The resulting
    /// chain will contain the newly created certificate followed by the
    /// certificates held within the issuer.
    ///
    /// A [`SignaturePublicKey`] may be optionally passed in to indicate
    /// that a new key pair should not be generated. `subject_pubkey`
    /// will be used for the subject public key info component of the newly
    /// generated leaf certificate.
    pub fn build_cert_chain<B: X509CertificateWriter>(
        self,
        issuer: &CertificateIssuer,
        subject_pubkey: Option<SignaturePublicKey>,
        x509_writer: &B,
    ) -> Result<CertificateGeneration, B::Error> {
        x509_writer.build_cert_chain(
            self.subject_cipher_suite,
            issuer,
            subject_pubkey,
            self.subject_params,
        )
    }

    /// Produce a certificate signing request.
    ///
    /// A [`SignatureSecretKey`] can be optionally provided to indicate
    /// that a new key pair should not be generated to sign this request.
    pub fn build_csr<B: X509CertificateWriter>(
        self,
        signer: Option<SignatureSecretKey>,
        x509_writer: &B,
    ) -> Result<CertificateRequest, B::Error> {
        x509_writer.build_csr(self.subject_cipher_suite, signer, self.subject_params)
    }
}

#[cfg(test)]
pub(crate) mod test_utils {
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

    const TEST_CIPHER_SUITE: CipherSuite = CipherSuite::CURVE25519_AES128;

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
            public_key: vec![2u8; 32].into(),
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
