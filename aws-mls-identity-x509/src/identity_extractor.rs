use crate::{DerCertificate, X509CertificateReader, X509IdentityError, X509IdentityExtractor};

#[derive(Debug, Clone)]
pub struct SubjectIdentityExtractor<R: X509CertificateReader> {
    offset: usize,
    reader: R,
}

impl<R> SubjectIdentityExtractor<R>
where
    R: X509CertificateReader,
{
    pub fn new(offset: usize, reader: R) -> Self {
        Self { offset, reader }
    }

    pub fn identity(
        &self,
        certificate_chain: &crate::CertificateChain,
    ) -> Result<Vec<u8>, X509IdentityError> {
        let cert = get_certificate(certificate_chain, self.offset)?;

        self.subject_bytes(cert)
    }

    fn subject_bytes(&self, certificate: &DerCertificate) -> Result<Vec<u8>, X509IdentityError> {
        self.reader
            .subject_bytes(certificate)
            .map_err(|e| X509IdentityError::CertificateParserError(e.into()))
    }

    pub fn valid_successor(
        &self,
        predecessor: &crate::CertificateChain,
        successor: &crate::CertificateChain,
    ) -> Result<bool, X509IdentityError> {
        let predecessor_cert = get_certificate(predecessor, 0)?;
        let successor_cert = get_certificate(successor, 0)?;

        Ok(self.subject_bytes(predecessor_cert)? == self.subject_bytes(successor_cert)?)
    }
}

impl<R> X509IdentityExtractor for SubjectIdentityExtractor<R>
where
    R: X509CertificateReader,
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
        test_utils::test_certificate_chain, MockX509CertificateReader, SubjectIdentityExtractor,
        X509IdentityError,
    };

    use assert_matches::assert_matches;

    #[cfg(target_arch = "wasm32")]
    use wasm_bindgen_test::wasm_bindgen_test as test;

    fn test_setup<F>(
        offset: usize,
        mut mock_setup: F,
    ) -> SubjectIdentityExtractor<MockX509CertificateReader>
    where
        F: FnMut(&mut MockX509CertificateReader),
    {
        let mut x509_reader = MockX509CertificateReader::new();

        mock_setup(&mut x509_reader);

        SubjectIdentityExtractor {
            offset,
            reader: x509_reader,
        }
    }

    #[test]
    fn invalid_offset_is_rejected() {
        let subject_extractor = test_setup(4, |subject_extractor| {
            subject_extractor.expect_subject_bytes().never();
        });

        assert_matches!(
            subject_extractor.identity(&test_certificate_chain()),
            Err(X509IdentityError::InvalidOffset)
        );
    }

    #[test]
    fn subject_can_be_retrived_as_identity() {
        let test_subject = b"subject".to_vec();
        let cert_chain = test_certificate_chain();

        let expected_certificate = cert_chain[1].clone();

        let subject_extractor = test_setup(1, |parser| {
            let test_subject = test_subject.clone();

            parser
                .expect_subject_bytes()
                .once()
                .with(mockall::predicate::eq(expected_certificate.clone()))
                .return_once_st(|_| Ok(test_subject));
        });

        assert_eq!(
            subject_extractor.identity(&cert_chain).unwrap(),
            test_subject
        );
    }

    #[test]
    fn valid_successor() {
        let predecessor = test_certificate_chain();
        let mut successor = test_certificate_chain();

        // Make sure both chains have the same leaf
        successor.0[0] = predecessor[0].clone();

        let subject_extractor = test_setup(1, |reader| {
            let predecessor = predecessor[0].clone();
            let successor = successor[0].clone();

            reader
                .expect_subject_bytes()
                .with(mockall::predicate::eq(predecessor))
                .times(1)
                .return_once_st(|_| Ok(b"subject".to_vec()));

            reader
                .expect_subject_bytes()
                .with(mockall::predicate::eq(successor))
                .times(1)
                .return_once_st(|_| Ok(b"subject".to_vec()));
        });

        assert!(subject_extractor
            .valid_successor(&predecessor, &successor)
            .unwrap());
    }
}
