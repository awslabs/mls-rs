use aws_mls_core::crypto::{CipherSuite, SignatureSecretKey};
use aws_mls_identity_x509::{
    CertificateRequestParameters, DerCertificateRequest, X509RequestWriter,
};

use crate::{ecdsa::AwsLcEcdsa, AwsLcCryptoError};

use super::{
    component::{KeyUsage, Stack, X509Extension, X509Name},
    request::{self, X509Request},
};

pub struct CertificateRequestWriter {
    signer: AwsLcEcdsa,
    signing_key: SignatureSecretKey,
}

impl CertificateRequestWriter {
    pub fn new(
        cipher_suite: CipherSuite,
        signing_key: SignatureSecretKey,
    ) -> Result<Self, AwsLcCryptoError> {
        let signer =
            AwsLcEcdsa::new(cipher_suite).ok_or(AwsLcCryptoError::UnsupportedCipherSuite)?;

        Ok(Self {
            signer,
            signing_key,
        })
    }
}

impl X509RequestWriter for CertificateRequestWriter {
    type Error = AwsLcCryptoError;

    fn write(
        &self,
        params: CertificateRequestParameters,
    ) -> Result<DerCertificateRequest, Self::Error> {
        let mut request = X509Request::new()?;

        request.set_version(request::X509RequestVersion::V1)?;
        request.set_subject(X509Name::new_components(&params.subject)?)?;

        let mut extensions = Stack::new()?;

        if !params.subject_alt_names.is_empty() {
            extensions.push(X509Extension::subject_alt_name(&params.subject_alt_names)?);
        }

        extensions.push(X509Extension::basic_constraints(true, params.is_ca, None)?);

        if params.is_ca {
            extensions.push(X509Extension::key_usage(
                true,
                &[KeyUsage::KeyCertSign, KeyUsage::CrlSign],
            )?);
        }

        request.add_extensions(extensions)?;

        request
            .sign(&self.signer, &self.signing_key)
            .map(DerCertificateRequest::new)
    }
}

#[cfg(test)]
mod tests {
    use aws_mls_core::crypto::{CipherSuite, CipherSuiteProvider, CryptoProvider};
    use aws_mls_identity_x509::{
        CertificateRequestParameters, DerCertificateRequest, SubjectAltName, SubjectComponent,
        X509RequestWriter,
    };

    use crate::{
        x509::{
            test_utils::{csr_pem_to_der, ec_key_from_pem},
            CertificateRequestWriter,
        },
        AwsLcCryptoProvider,
    };

    fn test_writing_csr(ca: bool) {
        let subject_seckey = if ca {
            include_bytes!("../../test_data/x509/root_ca/key.pem")
        } else {
            include_bytes!("../../test_data/x509/leaf/key.pem")
        };

        let subject_seckey = ec_key_from_pem(subject_seckey);

        let writer =
            CertificateRequestWriter::new(CipherSuite::CURVE25519_AES128, subject_seckey).unwrap();

        let expected_csr = if ca {
            include_bytes!("../../test_data/x509/root_ca/csr.pem").to_vec()
        } else {
            include_bytes!("../../test_data/x509/leaf/csr.pem").to_vec()
        };

        let common_name = if ca { "RootCA" } else { "Leaf" };
        let alt_name = if ca { "rootca.org" } else { "leaf.org" };

        let params = CertificateRequestParameters {
            subject: vec![
                SubjectComponent::CommonName(common_name.to_string()),
                SubjectComponent::CountryName("CH".to_string()),
            ],
            subject_alt_names: vec![SubjectAltName::Dns(alt_name.to_string())],
            is_ca: ca,
        };

        let expected_csr = csr_pem_to_der(&expected_csr);

        let built_csr = writer.write(params).unwrap();

        assert_eq!(DerCertificateRequest::new(expected_csr), built_csr);
    }

    #[test]
    fn writing_ca_csr() {
        test_writing_csr(true)
    }

    #[test]
    fn writing_csr() {
        test_writing_csr(false)
    }

    #[maybe_async::test(not(mls_build_async), async(mls_build_async, futures_test::test))]
    async fn test_csr_nist() {
        let (secret, _) = AwsLcCryptoProvider::new()
            .cipher_suite_provider(CipherSuite::P256_AES128)
            .unwrap()
            .signature_key_generate()
            .await
            .unwrap();

        let writer = CertificateRequestWriter::new(CipherSuite::P256_AES128, secret).unwrap();

        let params = CertificateRequestParameters {
            subject: vec![SubjectComponent::CommonName("name".to_string())],
            subject_alt_names: vec![],
            is_ca: true,
        };

        writer.write(params).unwrap();
    }
}
