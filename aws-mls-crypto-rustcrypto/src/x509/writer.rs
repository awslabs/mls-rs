use std::time::Duration;

use aws_mls_core::{
    crypto::{CipherSuite, SignaturePublicKey, SignatureSecretKey},
    time::MlsTime,
};

use aws_mls_identity_x509::{
    CertificateGeneration, CertificateIssuer, CertificateParameters, CertificateRequest,
    DerCertificate, X509CertificateWriter,
};

use rand_core::{OsRng, RngCore};

use spki::{
    der::{
        asn1::{BitStringRef, UIntRef, UtcTime},
        Decode,
    },
    AlgorithmIdentifier, SubjectPublicKeyInfo,
};

use x509_cert::{
    der::Encode,
    time::{Time, Validity},
    Certificate, TbsCertificate,
};

use x509_cert::request::{CertReq, CertReqInfo};

use crate::{ec::pub_key_from_uncompressed, ec_for_x509::pub_key_to_spki, ec_signer::EcSigner};

use super::{
    util::{
        build_x509_name, common_extensions, object_id_for_ciphersuite, OwnedAttribute,
        OwnedExtension,
    },
    X509Error,
};

#[derive(Debug, Clone, Default)]
pub struct X509Writer {
    #[cfg(test)]
    test_serial: Option<Vec<u8>>,
    #[cfg(test)]
    test_not_before: Option<Duration>,
}

impl X509Writer {
    pub fn new() -> Self {
        Default::default()
    }
}

impl X509CertificateWriter for X509Writer {
    type Error = X509Error;

    fn build_cert_chain(
        &self,
        subject_cipher_suite: CipherSuite,
        issuer: &CertificateIssuer,
        subject_pubkey: Option<SignaturePublicKey>,
        subject_params: CertificateParameters,
    ) -> Result<CertificateGeneration, Self::Error> {
        let issuer_cert = Certificate::from_der(
            issuer
                .chain
                .leaf()
                .ok_or(X509Error::EmptyCertificateChain)?,
        )?;

        // TODO check if the issuer cert makes sense and matches issuer signer

        // Get or generate subject public key in DER format
        let signer = EcSigner::new(subject_cipher_suite)?;

        let (subjet_seckey, subject_pubkey) = match subject_pubkey {
            Some(pub_key) => (None, pub_key),
            None => signer
                .signature_key_generate()
                .map(|(sk, pk)| (Some(sk), pk))?,
        };

        let subject_pubkey_ec = pub_key_from_uncompressed(&subject_pubkey, *signer)?;
        let subject_pubkey_der = pub_key_to_spki(&subject_pubkey_ec)?;

        // Generate a serial number
        let mut serial_number = vec![0; 20];
        OsRng.try_fill_bytes(&mut serial_number)?;
        let serial_number = UIntRef::new(&serial_number)?;

        #[cfg(test)]
        let serial_number = self
            .test_serial
            .as_ref()
            .map(|s| UIntRef::new(s))
            .transpose()?
            .unwrap_or(serial_number);

        // Create extensions
        let mut extensions = common_extensions(&subject_params)?;
        extensions.push(OwnedExtension::authority_key_id(&issuer_cert)?);
        extensions.push(OwnedExtension::subject_key_id(&subject_pubkey)?);

        // Compute validity. Consider the current time to be 1 hour earlier to avoid clock drift issues
        let not_before = MlsTime::now()
            .seconds_since_epoch()?
            .checked_sub(3600)
            .map(Duration::from_secs)
            .ok_or(X509Error::InvalidCertificateLifetime)?;

        #[cfg(test)]
        let not_before = self.test_not_before.unwrap_or(not_before);

        let not_after = not_before
            .checked_add(Duration::from_secs(issuer.lifetime))
            .ok_or(X509Error::InvalidCertificateLifetime)?;

        let validity = Validity {
            not_before: Time::UtcTime(UtcTime::from_unix_duration(not_before)?),
            not_after: Time::UtcTime(UtcTime::from_unix_duration(not_after)?),
        };

        let tbs_cert = TbsCertificate {
            version: x509_cert::certificate::Version::V3,
            serial_number,
            signature: issuer_cert.tbs_certificate.signature,
            issuer: issuer_cert.tbs_certificate.subject.clone(),
            validity,
            subject: build_x509_name(&subject_params.subject)?,
            subject_public_key_info: SubjectPublicKeyInfo::from_der(&subject_pubkey_der)?,
            // Should not be used according to RFC 5280, 4.1.2.8
            issuer_unique_id: None,
            subject_unique_id: None,
            extensions: Some(extensions.iter().map(Into::into).collect()),
        };

        let issuer_signer = EcSigner::new(issuer.cipher_suite)?;
        let signature = issuer_signer.sign(&issuer.signing_key, &tbs_cert.to_vec()?)?;

        let built_cert = Certificate {
            tbs_certificate: tbs_cert,
            signature_algorithm: issuer_cert.tbs_certificate.signature,
            signature: signature.as_slice().try_into()?,
        }
        .to_vec()?;

        let chain = [&[built_cert.into()] as &[DerCertificate], &issuer.chain].concat();

        Ok(CertificateGeneration::new(
            chain.into(),
            subject_pubkey,
            subjet_seckey,
        ))
    }

    fn build_csr(
        &self,
        cipher_suite: CipherSuite,
        signature_key: Option<SignatureSecretKey>,
        params: CertificateParameters,
    ) -> Result<CertificateRequest, Self::Error> {
        let signer = EcSigner::new(cipher_suite)?;

        let (secret_key, public_key) = match signature_key {
            Some(key) => {
                let public = signer.signature_key_derive_public(&key)?;
                Ok((key, public))
            }
            None => signer.signature_key_generate(),
        }?;

        let ec_public_key = pub_key_from_uncompressed(&public_key, *signer)?;
        let der_public_key = pub_key_to_spki(&ec_public_key)?;
        let spki = SubjectPublicKeyInfo::from_der(&der_public_key)?;

        let extensions = common_extensions(&params)?;

        let attribute = (!extensions.is_empty())
            .then_some(OwnedAttribute::extension_req(extensions))
            .transpose()?;

        let subject = build_x509_name(&params.subject)?;

        let info = CertReqInfo {
            version: x509_cert::request::Version::V1,
            subject,
            public_key: spki,
            attributes: attribute
                .as_ref()
                .map(TryFrom::try_from)
                .transpose()?
                .unwrap_or_default(),
        };

        let algorithm = AlgorithmIdentifier {
            oid: object_id_for_ciphersuite(cipher_suite)?,
            parameters: None,
        };

        let signature_data = signer.sign(&secret_key, &info.to_vec()?)?;
        let signature = BitStringRef::new(0, &signature_data)?;

        let req = CertReq {
            info,
            algorithm,
            signature,
        };

        Ok(CertificateRequest::new(
            req.to_vec()?,
            public_key,
            secret_key,
        ))
    }
}

#[cfg(test)]
pub(crate) mod test_utils {
    use super::X509Writer;
    use std::time::Duration;

    impl X509Writer {
        pub fn set_test_serial(&mut self, serial: Option<Vec<u8>>) {
            self.test_serial = serial
        }

        pub fn set_test_not_before(&mut self, not_before: Option<Duration>) {
            self.test_not_before = not_before
        }
    }
}

#[cfg(test)]
mod tests {
    use aws_mls_core::crypto::CipherSuite;

    use aws_mls_identity_x509::{
        CertificateIssuer, CertificateParameters, DerCertificate, SubjectAltName, SubjectComponent,
        X509CertificateWriter,
    };

    use spki::der::Decode;
    use x509_cert::{request::CertReq, Certificate};

    use crate::{
        ec::{
            private_key_from_bytes, private_key_to_public, pub_key_to_uncompressed, Curve,
            EcPrivateKey,
        },
        x509::X509Writer,
    };

    #[test]
    fn writing_ca_csr() {
        test_writing_csr(true)
    }

    #[test]
    fn writing_csr() {
        test_writing_csr(false)
    }

    fn test_writing_csr(ca: bool) {
        let writer = X509Writer::default();

        let subject_seckey = if ca {
            include_bytes!("../../test_data/x509/root_ca/key")
        } else {
            include_bytes!("../../test_data/x509/leaf/key")
        };

        let subject_seckey = subject_seckey.to_vec().into();

        let expected_csr = if ca {
            include_bytes!("../../test_data/x509/root_ca/csr.der").to_vec()
        } else {
            include_bytes!("../../test_data/x509/leaf/csr.der").to_vec()
        };

        let common_name = if ca { "RootCA" } else { "Leaf" };
        let alt_name = if ca { "rootca.org" } else { "leaf.org" };

        let params = CertificateParameters {
            subject: vec![
                SubjectComponent::CommonName(common_name.to_string()),
                SubjectComponent::CountryName("CH".to_string()),
            ],
            subject_alt_names: vec![SubjectAltName::Dns(alt_name.to_string())],
            is_ca: ca,
        };

        let built_csr = writer
            .build_csr(CipherSuite::CURVE25519_AES128, Some(subject_seckey), params)
            .unwrap();

        assert_eq!(expected_csr, built_csr.request_data());

        let built_secret = private_key_from_bytes(built_csr.secret_key(), Curve::Ed25519).unwrap();
        let expected_public = private_key_to_public(&built_secret).unwrap();
        let expected_public = pub_key_to_uncompressed(&expected_public).unwrap();

        let public_key = CertReq::from_der(built_csr.request_data())
            .unwrap()
            .info
            .public_key
            .subject_public_key;

        assert_eq!(public_key, &expected_public);
    }

    #[test]
    fn writing_ca_crt() {
        test_writing_crt(true)
    }

    #[test]
    fn writing_crt() {
        test_writing_crt(false)
    }

    fn test_writing_crt(ca: bool) {
        let mut writer = X509Writer::default();

        let expected_crt_bytes = if ca {
            include_bytes!("../../test_data/x509/intermediate_ca/cert.der").to_vec()
        } else {
            include_bytes!("../../test_data/x509/leaf/cert.der").to_vec()
        };

        let signer = if ca {
            include_str!("../../test_data/x509/intermediate_ca/key.pem")
        } else {
            include_str!("../../test_data/x509/leaf/key.pem")
        };

        let expected_crt = Certificate::from_der(&expected_crt_bytes).unwrap();

        writer.set_test_serial(Some(
            expected_crt
                .tbs_certificate
                .serial_number
                .as_bytes()
                .to_vec(),
        ));

        writer.set_test_not_before(Some(
            expected_crt
                .tbs_certificate
                .validity
                .not_before
                .to_unix_duration(),
        ));

        let subject_signer = if ca {
            EcPrivateKey::P256(p256::SecretKey::from_sec1_pem(signer).unwrap())
        } else {
            // ed25519_dalek doesn't have pkcs8 so we can borrow that
            // utility from p256 crate to parse out raw key bytes.

            let (_, document) = p256::pkcs8::SecretDocument::from_pem(signer).unwrap();

            let key_data: p256::pkcs8::PrivateKeyInfo = document.decode_msg().unwrap();

            let keypair_bytes =
                p256::pkcs8::der::asn1::OctetString::from_der(key_data.private_key).unwrap();

            EcPrivateKey::Ed25519(
                ed25519_dalek::SecretKey::from_bytes(keypair_bytes.as_bytes()).unwrap(),
            )
        };

        let subject_pubkey =
            pub_key_to_uncompressed(&private_key_to_public(&subject_signer).unwrap()).unwrap();

        let common_name = if ca { "IntermediateCA" } else { "Leaf" };
        let alt_name = if ca { "intermediateca.org" } else { "leaf.org" };

        let params = CertificateParameters {
            subject: vec![
                SubjectComponent::CommonName(common_name.to_string()),
                SubjectComponent::CountryName("CH".to_string()),
            ],
            subject_alt_names: vec![SubjectAltName::Dns(alt_name.to_string())],
            is_ca: ca,
        };

        let built_crt = writer
            .build_cert_chain(
                get_subject_ciphersuite(ca),
                &get_test_root_ca(),
                Some(subject_pubkey.into()),
                params,
            )
            .unwrap();

        let built_crt_bytes = built_crt.certificate_chain().leaf().unwrap().to_vec();

        assert_eq!(&built_crt_bytes, &expected_crt_bytes);

        assert!(built_crt.generated_secret().is_none());
    }

    #[test]
    fn generating_subject_key() {
        let writer = X509Writer::new();
        let issuer = get_test_root_ca();
        let params = CertificateParameters::default();
        let ciphersuite = CipherSuite::P256_AES128;

        let crt = writer
            .build_cert_chain(ciphersuite, &issuer, None, params.clone())
            .unwrap();

        let other_crt = writer
            .build_cert_chain(ciphersuite, &issuer, None, params)
            .unwrap();

        let secret = crt.generated_secret().unwrap();

        assert_ne!(secret, other_crt.generated_secret().unwrap());

        let secret = private_key_from_bytes(secret, Curve::P256).unwrap();
        let public = private_key_to_public(&secret).unwrap();
        let public = pub_key_to_uncompressed(&public).unwrap();

        let crt_public = Certificate::from_der(crt.certificate_chain().leaf().unwrap())
            .unwrap()
            .tbs_certificate
            .subject_public_key_info
            .subject_public_key;

        assert_eq!(crt_public, &public);
    }

    fn get_test_root_ca() -> CertificateIssuer {
        let ca_key = include_bytes!("../../test_data/x509/root_ca/key");

        let ca_cert =
            DerCertificate::from(include_bytes!("../../test_data/x509/root_ca/cert.der").to_vec());

        let lifetime = 10 * 365 * 24 * 3600;

        CertificateIssuer::new(
            ca_key.to_vec().into(),
            CipherSuite::CURVE25519_AES128,
            vec![ca_cert].into(),
            lifetime,
        )
    }

    fn get_subject_ciphersuite(ca: bool) -> CipherSuite {
        if ca {
            CipherSuite::P256_AES128
        } else {
            CipherSuite::CURVE25519_AES128
        }
    }
}
