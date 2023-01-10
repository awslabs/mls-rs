use crate::{DerCertificate, X509IdentityError, X509IdentityExtractor};

#[cfg(test)]
use mockall::automock;

#[cfg_attr(test, automock(type Error = crate::test_utils::TestError;))]
pub trait SubjectParser {
    type Error: std::error::Error + Send + Sync + 'static;

    fn parse_subject(&self, certificate: &DerCertificate) -> Result<String, Self::Error>;
}

#[derive(Debug, Clone)]
pub struct SubjectIdentityExtractor<SP: SubjectParser> {
    offset: usize,
    parser: SP,
}

impl<SP> SubjectIdentityExtractor<SP>
where
    SP: SubjectParser,
{
    pub fn new(offset: usize, parser: SP) -> Self {
        Self { offset, parser }
    }

    pub fn identity(
        &self,
        certificate_chain: &crate::CertificateChain,
    ) -> Result<Vec<u8>, X509IdentityError> {
        let cert = get_certificate(certificate_chain, self.offset)?;

        self.parser
            .parse_subject(cert)
            .map(|s| s.into_bytes())
            .map_err(|e| X509IdentityError::CertificateParserError(e.into()))
    }

    fn parse_subject(&self, certificate: &DerCertificate) -> Result<String, X509IdentityError> {
        self.parser
            .parse_subject(certificate)
            .map_err(|e| X509IdentityError::CertificateParserError(e.into()))
    }

    pub fn valid_successor(
        &self,
        predecessor: &crate::CertificateChain,
        successor: &crate::CertificateChain,
    ) -> Result<bool, X509IdentityError> {
        let predecessor_cert = get_certificate(predecessor, 0)?;
        let successor_cert = get_certificate(successor, 0)?;

        Ok(self.parse_subject(predecessor_cert)? == self.parse_subject(successor_cert)?)
    }
}

impl<SP> X509IdentityExtractor for SubjectIdentityExtractor<SP>
where
    SP: SubjectParser,
{
    type Error = X509IdentityError;

    fn identity(
        &self,
        certificate_chain: &crate::CertificateChain,
    ) -> Result<Vec<u8>, Self::Error> {
        self.identity(certificate_chain)
    }

    fn valid_successor(
        &self,
        predecessor: &crate::CertificateChain,
        successor: &crate::CertificateChain,
    ) -> Result<bool, Self::Error> {
        self.valid_successor(predecessor, successor)
    }
}

fn get_certificate(
    certificate_chain: &crate::CertificateChain,
    offset: usize,
) -> Result<&DerCertificate, X509IdentityError> {
    certificate_chain
        .get(offset)
        .ok_or(X509IdentityError::InvalidOffset)
}

#[cfg(test)]
mod tests {
    use crate::{
        test_utils::test_certificate_chain, MockSubjectParser, SubjectIdentityExtractor,
        X509IdentityError,
    };

    use assert_matches::assert_matches;

    #[cfg(target_arch = "wasm32")]
    use wasm_bindgen_test::wasm_bindgen_test as test;

    fn test_setup<F>(
        offset: usize,
        mut mock_setup: F,
    ) -> SubjectIdentityExtractor<MockSubjectParser>
    where
        F: FnMut(&mut MockSubjectParser),
    {
        let mut subject_parser = MockSubjectParser::new();

        mock_setup(&mut subject_parser);

        SubjectIdentityExtractor {
            offset,
            parser: subject_parser,
        }
    }

    #[test]
    fn invalid_offset_is_rejected() {
        let subject_extractor = test_setup(4, |subject_extractor| {
            subject_extractor.expect_parse_subject().never();
        });

        assert_matches!(
            subject_extractor.identity(&test_certificate_chain()),
            Err(X509IdentityError::InvalidOffset)
        );
    }

    #[test]
    fn subject_can_be_retrived_as_identity() {
        let test_subject = "subject".to_string();
        let cert_chain = test_certificate_chain();

        let expected_certificate = cert_chain[1].clone();

        let subject_extractor = test_setup(1, |parser| {
            let test_subject = test_subject.clone();

            parser
                .expect_parse_subject()
                .once()
                .with(mockall::predicate::eq(expected_certificate.clone()))
                .return_once_st(|_| Ok(test_subject));
        });

        assert_eq!(
            subject_extractor.identity(&cert_chain).unwrap(),
            test_subject.into_bytes()
        );
    }

    #[test]
    fn valid_successor() {
        let predecessor = test_certificate_chain();
        let mut successor = test_certificate_chain();

        // Make sure both chains have the same leaf
        successor.0[0] = predecessor[0].clone();

        let subject_extractor = test_setup(1, |parser| {
            let predecessor = predecessor[0].clone();
            let successor = successor[0].clone();

            parser
                .expect_parse_subject()
                .with(mockall::predicate::eq(predecessor))
                .times(1)
                .return_once_st(|_| Ok("subject".to_string()));

            parser
                .expect_parse_subject()
                .with(mockall::predicate::eq(successor))
                .times(1)
                .return_once_st(|_| Ok("subject".to_string()));
        });

        assert!(subject_extractor
            .valid_successor(&predecessor, &successor)
            .unwrap());
    }
}
