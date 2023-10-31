// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// Copyright by contributors to this project.
// SPDX-License-Identifier: (Apache-2.0 OR MIT)

use mls_rs_core::crypto::{CipherSuite, SignatureSecretKey};

use mls_rs_identity_x509::{
    CertificateRequestParameters, DerCertificateRequest, X509RequestWriter,
};

use spki::{
    der::{asn1::BitString, Decode},
    AlgorithmIdentifier, SubjectPublicKeyInfo,
};

use x509_cert::{attr::Attributes, der::Encode};

use x509_cert::request::{CertReq, CertReqInfo};

use crate::{ec::pub_key_from_uncompressed, ec_for_x509::pub_key_to_spki, ec_signer::EcSigner};

use super::{
    util::{build_x509_name, extension_req, object_id_for_ciphersuite, request_extensions},
    X509Error,
};

#[derive(Debug, Clone)]
pub struct CertificateRequestWriter {
    cipher_suite: CipherSuite,
    signer: EcSigner,
    signing_key: SignatureSecretKey,
}

impl CertificateRequestWriter {
    pub fn new(
        cipher_suite: CipherSuite,
        signing_key: SignatureSecretKey,
    ) -> Result<Self, X509Error> {
        let signer = EcSigner::new(cipher_suite).ok_or(X509Error::UnsupportedCipherSuite)?;

        Ok(Self {
            signing_key,
            signer,
            cipher_suite,
        })
    }

    pub fn new_generate_key(cipher_suite: CipherSuite) -> Result<Self, X509Error> {
        let signer = EcSigner::new(cipher_suite).ok_or(X509Error::UnsupportedCipherSuite)?;

        let (secret, _) = signer.signature_key_generate()?;

        Ok(Self {
            signer,
            signing_key: secret,
            cipher_suite,
        })
    }

    pub fn signing_key(&self) -> &SignatureSecretKey {
        &self.signing_key
    }
}

impl X509RequestWriter for CertificateRequestWriter {
    type Error = X509Error;

    fn write(
        &self,
        params: CertificateRequestParameters,
    ) -> Result<DerCertificateRequest, Self::Error> {
        let public_key = self.signer.signature_key_derive_public(&self.signing_key)?;

        let ec_public_key = pub_key_from_uncompressed(&public_key, *self.signer)?;
        let der_public_key = pub_key_to_spki(&ec_public_key)?;
        let spki = SubjectPublicKeyInfo::from_der(&der_public_key)?;

        let extensions = request_extensions(&params)?;

        let attribute = (!extensions.is_empty())
            .then_some(extension_req(extensions))
            .transpose()?;

        let subject = build_x509_name(&params.subject)?;

        let info = CertReqInfo {
            version: x509_cert::request::Version::V1,
            subject,
            public_key: spki,
            attributes: attribute
                .map(|attr| Attributes::try_from([attr]))
                .transpose()?
                .unwrap_or_default(),
        };

        let algorithm = AlgorithmIdentifier {
            oid: object_id_for_ciphersuite(self.cipher_suite)?,
            parameters: None,
        };

        let signature_data = self.signer.sign(&self.signing_key, &info.to_der()?)?;
        let signature = BitString::from_bytes(&signature_data)?;

        let req = CertReq {
            info,
            algorithm,
            signature,
        };

        Ok(DerCertificateRequest::new(req.to_der()?))
    }
}

#[cfg(test)]
mod tests {
    use mls_rs_core::crypto::CipherSuite;

    use mls_rs_identity_x509::{
        CertificateRequestParameters, SubjectAltName, SubjectComponent, X509RequestWriter,
    };

    use crate::{ec::test_utils::ed25519_seed_to_private_key, x509::CertificateRequestWriter};

    #[test]
    fn writing_ca_csr() {
        test_writing_csr(true)
    }

    #[test]
    fn writing_csr() {
        test_writing_csr(false)
    }

    fn test_writing_csr(ca: bool) {
        let subject_seckey = if ca {
            include_bytes!("../../test_data/x509/root_ca/key")
        } else {
            include_bytes!("../../test_data/x509/leaf/key")
        };

        let subject_seckey = ed25519_seed_to_private_key(subject_seckey).into();

        let writer =
            CertificateRequestWriter::new(CipherSuite::CURVE25519_AES128, subject_seckey).unwrap();

        let expected_csr = if ca {
            include_bytes!("../../test_data/x509/root_ca/csr.der").to_vec()
        } else {
            include_bytes!("../../test_data/x509/leaf/csr.der").to_vec()
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

        let built_csr = writer.write(params).unwrap();

        assert_eq!(expected_csr, built_csr.into_vec());
    }
}
