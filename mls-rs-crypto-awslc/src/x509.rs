mod certificate;
mod component;
mod parser;
mod request;
mod validator;
mod writer;

pub use certificate::Certificate;
pub use component::{X509Extension, X509ExtensionContext};
pub use parser::CertificateParser;
pub use validator::CertificateValidator;
pub use writer::CertificateRequestWriter;

#[cfg(test)]
mod test_utils {
    use std::ptr::null_mut;

    use crate::aws_lc_sys_impl::{
        i2d_X509_REQ, BIO_free, BIO_new_mem_buf, EVP_PKEY_free, EVP_PKEY_get_raw_private_key,
        EVP_PKEY_get_raw_public_key, PEM_read_bio_PrivateKey, PEM_read_bio_X509_REQ, X509_REQ_free,
    };
    use mls_rs_core::crypto::SignatureSecretKey;
    use mls_rs_identity_x509::{CertificateChain, DerCertificate};

    pub fn load_test_ca() -> DerCertificate {
        DerCertificate::from(include_bytes!("../test_data/x509/ca.der").to_vec())
    }

    pub fn load_github_leaf() -> DerCertificate {
        DerCertificate::from(include_bytes!("../test_data/x509/github_leaf.der").to_vec())
    }

    pub fn load_ip_cert() -> DerCertificate {
        DerCertificate::from(include_bytes!("../test_data/x509/cert_ip.der").to_vec())
    }

    pub fn test_leaf() -> DerCertificate {
        DerCertificate::from(include_bytes!("../test_data/x509/leaf/cert.der").to_vec())
    }

    pub fn test_leaf_key() -> SignatureSecretKey {
        ec_key_from_pem(include_bytes!("../test_data/x509/leaf/key.pem"))
    }

    pub fn test_root_ca_key() -> SignatureSecretKey {
        ec_key_from_pem(include_bytes!("../test_data/x509/root_ca/key.pem"))
    }

    pub fn test_root_ca() -> DerCertificate {
        DerCertificate::from(include_bytes!("../test_data/x509/root_ca/cert.der").to_vec())
    }

    pub fn load_test_cert_chain() -> CertificateChain {
        let entry0 = include_bytes!("../test_data/x509/leaf.der").to_vec();
        let entry1 = include_bytes!("../test_data/x509/intermediate.der").to_vec();
        let entry2 = include_bytes!("../test_data/x509/ca.der").to_vec();

        CertificateChain::from_iter(
            [entry0, entry1, entry2]
                .into_iter()
                .map(DerCertificate::from),
        )
    }

    pub fn load_test_invalid_chain() -> CertificateChain {
        let entry0 = include_bytes!("../test_data/x509/github_leaf.der").to_vec();
        let entry1 = include_bytes!("../test_data/x509/intermediate.der").to_vec();

        CertificateChain::from_iter([entry0, entry1].into_iter().map(DerCertificate::from))
    }

    pub fn load_test_invalid_ca_chain() -> CertificateChain {
        let entry0 = include_bytes!("../test_data/x509/leaf.der").to_vec();
        let entry1 = include_bytes!("../test_data/x509/intermediate.der").to_vec();
        let entry2 = include_bytes!("../test_data/x509/another_ca.der").to_vec();

        CertificateChain::from_iter(
            [entry0, entry1, entry2]
                .into_iter()
                .map(DerCertificate::from),
        )
    }

    // NOTE: This only works with Ed25519 keys, but that is what we use for our test CSR
    pub fn ec_key_from_pem(pem_bytes: &[u8]) -> SignatureSecretKey {
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

    pub fn csr_pem_to_der(data: &[u8]) -> Vec<u8> {
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
