use crate::cipher_suite::SignatureScheme;
use ferriscrypt::asym::ec_key::{EcKeyError, PublicKey};
use ferriscrypt::x509::{CertificateChain, CertificateError};
use ferriscrypt::Verifier;
use std::convert::TryInto;
use thiserror::Error;
use tls_codec_derive::{TlsDeserialize, TlsSerialize, TlsSize};

#[derive(Error, Debug)]
pub enum CredentialError {
    #[error(transparent)]
    EcKeyError(#[from] EcKeyError),
    #[error(transparent)]
    CertificateError(#[from] CertificateError),
}

#[derive(Clone, Debug, TlsDeserialize, TlsSerialize, TlsSize)]
#[repr(u16)]
pub enum Credential {
    #[tls_codec(discriminant = 1)]
    Basic(BasicCredential),
    #[tls_codec(discriminant = 2)]
    Certificate(#[tls_codec(with = "crate::tls::CertificateChainSer")] CertificateChain),
}

impl Credential {
    #[inline(always)]
    pub fn public_key(&self) -> Result<PublicKey, CredentialError> {
        match self {
            Credential::Basic(b) => b.public_key(),
            Credential::Certificate(c) => c.public_key(),
        }
    }
}

impl Verifier for Credential {
    type ErrorType = CredentialError;
    type SignatureType = Vec<u8>;

    fn verify(
        &self,
        signature: &Self::SignatureType,
        data: &[u8],
    ) -> Result<bool, Self::ErrorType> {
        self.public_key()?
            .verify(signature, data)
            .map_err(Into::into)
    }
}

pub(crate) trait CredentialConvertible {
    fn into_credential(self) -> Credential;
    fn public_key(&self) -> Result<PublicKey, CredentialError>;
}

#[derive(Clone, Debug, PartialEq, TlsDeserialize, TlsSerialize, TlsSize)]
pub struct BasicCredential {
    #[tls_codec(with = "crate::tls::ByteVec::<u32>")]
    pub identity: Vec<u8>,
    pub signature_scheme: SignatureScheme,
    #[tls_codec(with = "crate::tls::ByteVec::<u32>")]
    signature_key: Vec<u8>,
}

impl CredentialConvertible for BasicCredential {
    fn into_credential(self) -> Credential {
        Credential::Basic(self)
    }

    fn public_key(&self) -> Result<PublicKey, CredentialError> {
        PublicKey::from_uncompressed_bytes(&self.signature_key, self.signature_scheme.into())
            .map_err(Into::into)
    }
}

impl BasicCredential {
    pub fn new(
        identity: Vec<u8>,
        signature_key: PublicKey,
    ) -> Result<BasicCredential, CredentialError> {
        Ok(BasicCredential {
            identity,
            signature_scheme: signature_key.curve.try_into()?,
            signature_key: signature_key.to_uncompressed_bytes()?,
        })
    }
}

impl CredentialConvertible for CertificateChain {
    fn into_credential(self) -> Credential {
        Credential::Certificate(self)
    }

    fn public_key(&self) -> Result<PublicKey, CredentialError> {
        PublicKey::try_from(self.leaf()?.pub_key()?).map_err(Into::into)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use ferriscrypt::asym::ec_key::{generate_keypair, Curve, SecretKey};
    use ferriscrypt::rand::SecureRng;
    use ferriscrypt::x509::{
        CertificateBuilder, CertificatePublicKey, CertificateSigningKey, Name, X509Properties,
    };
    use ferriscrypt::Signer;

    struct TestCredentialData {
        public: PublicKey,
        secret: SecretKey,
        credential: Credential,
    }

    fn get_test_basic_credential(identity: Vec<u8>, scheme: SignatureScheme) -> TestCredentialData {
        let (public, secret) = generate_keypair(Curve::from(scheme)).unwrap();
        let credential = Credential::Basic(BasicCredential::new(identity, public.clone()).unwrap());

        TestCredentialData {
            public,
            secret,
            credential,
        }
    }

    fn get_test_certificate_credential() -> TestCredentialData {
        let (public, secret) = generate_keypair(Curve::Ed25519).unwrap();

        let subject_name = Name {
            common_name: Some("foo.bar".to_string()),
            ..Name::default()
        };

        let properties = X509Properties {
            not_after: 0,
            not_before: 0,
            serial_number: b"0".to_vec(),
            subject_name,
            public_key: CertificatePublicKey::from(public.clone()),
        };

        let certificate_builder = CertificateBuilder::new(properties, None).unwrap();

        let certificate = certificate_builder
            .build(CertificateSigningKey::from(secret.clone()), None)
            .unwrap();

        TestCredentialData {
            public,
            secret,
            credential: CertificateChain::from(vec![certificate]).into_credential(),
        }
    }

    #[test]
    fn test_new_basic_credential() {
        for one_scheme in SignatureScheme::all() {
            let identity = SecureRng::gen(32).unwrap();
            let secret = SecretKey::generate(Curve::from(one_scheme)).unwrap();
            let cred = BasicCredential::new(identity.clone(), secret.to_public().unwrap()).unwrap();
            assert_eq!(cred.identity, identity);
            assert_eq!(cred.signature_scheme, one_scheme);
            assert_eq!(
                cred.signature_key,
                secret.to_public().unwrap().to_uncompressed_bytes().unwrap()
            );
        }
    }

    #[test]
    fn test_basic_credential_signature_data() {
        for one_scheme in SignatureScheme::all() {
            println!(
                "Testing basic credential data with signature scheme: {:?}",
                one_scheme
            );

            let test_id = SecureRng::gen(32).unwrap();
            let test_data = get_test_basic_credential(test_id, one_scheme);

            // Signature key
            let cred_sig_key = test_data.credential.public_key().unwrap();
            assert_eq!(
                cred_sig_key.to_uncompressed_bytes().unwrap(),
                test_data.public.to_uncompressed_bytes().unwrap()
            )
        }
    }

    #[test]
    fn test_certificate_credential_pub_key() {
        let test_data = get_test_certificate_credential();

        assert_eq!(test_data.public, test_data.credential.public_key().unwrap());
    }

    fn test_credential_signature(test_data: TestCredentialData) {
        let test_signature_input = b"Don't Panic" as &[u8];
        let valid_signature = test_data.secret.sign(test_signature_input).unwrap();
        let invalid_signature_data = test_data.secret.sign(b"foo" as &[u8]).unwrap();

        let invalid_signature_key = SecretKey::generate(test_data.secret.curve)
            .unwrap()
            .sign(test_signature_input)
            .unwrap();

        assert!(test_data
            .credential
            .verify(&valid_signature, test_signature_input)
            .unwrap());
        assert!(!test_data
            .credential
            .verify(&invalid_signature_data, test_signature_input)
            .unwrap());
        assert!(!test_data
            .credential
            .verify(&invalid_signature_key, test_signature_input)
            .unwrap());
    }

    #[test]
    fn test_basic_credential_verify() {
        for one_scheme in SignatureScheme::all() {
            println!(
                "Testing basic credential verify with signature scheme: {:?}",
                one_scheme
            );

            let test_data = get_test_basic_credential(vec![], one_scheme);
            test_credential_signature(test_data);
        }
    }

    #[test]
    fn test_certificate_credential_verify() {
        let test_data = get_test_certificate_credential();
        test_credential_signature(test_data);
    }
}
