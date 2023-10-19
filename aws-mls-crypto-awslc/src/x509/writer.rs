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
    use std::ptr::null_mut;

    use aws_lc_sys::{
        i2d_X509_REQ, BIO_free, BIO_new_mem_buf, EVP_PKEY_free, EVP_PKEY_get_raw_private_key,
        EVP_PKEY_get_raw_public_key, PEM_read_bio_PrivateKey, PEM_read_bio_X509_REQ, X509_REQ_free,
    };
    use aws_mls_core::crypto::{
        CipherSuite, CipherSuiteProvider, CryptoProvider, SignatureSecretKey,
    };
    use aws_mls_identity_x509::{
        CertificateRequestParameters, DerCertificateRequest, SubjectAltName, SubjectComponent,
        X509RequestWriter,
    };

    use crate::{x509::CertificateRequestWriter, AwsLcCryptoProvider};

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

    // NOTE: This only works with Ed25519 keys, but that is what we use for our test CSR
    fn ec_key_from_pem(pem_bytes: &[u8]) -> SignatureSecretKey {
        unsafe {
            let mem = BIO_new_mem_buf(pem_bytes.as_ptr().cast(), pem_bytes.len() as isize);
            let key = PEM_read_bio_PrivateKey(mem, null_mut(), None, null_mut());
            BIO_free(mem);

            let mut len = 0;

            EVP_PKEY_get_raw_private_key(key, null_mut(), &mut len);
            let mut secret_key_data = vec![0u8; len];
            EVP_PKEY_get_raw_private_key(key, secret_key_data.as_mut_ptr(), &mut len);

            EVP_PKEY_get_raw_public_key(key, null_mut(), &mut len);
            let mut public_key_data = vec![0u8; len];
            EVP_PKEY_get_raw_public_key(key, public_key_data.as_mut_ptr(), &mut len);

            EVP_PKEY_free(key);

            SignatureSecretKey::new([secret_key_data, public_key_data].concat())
        }
    }

    fn csr_pem_to_der(data: &[u8]) -> Vec<u8> {
        unsafe {
            let mem = BIO_new_mem_buf(data.as_ptr().cast(), data.len() as isize);
            let request = PEM_read_bio_X509_REQ(mem, null_mut(), None, null_mut());
            BIO_free(mem);

            let out_len = i2d_X509_REQ(request, null_mut());
            let mut out_buffer = vec![0u8; out_len as usize];

            i2d_X509_REQ(request, &mut out_buffer.as_mut_ptr());
            X509_REQ_free(request);

            out_buffer
        }
    }
}
