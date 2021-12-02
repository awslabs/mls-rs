use crate::cipher_suite::SignatureScheme;
use ferriscrypt::asym::ec_key::{EcKeyError, PublicKey};
use ferriscrypt::Verifier;
use std::convert::TryInto;
use thiserror::Error;
use tls_codec_derive::{TlsDeserialize, TlsSerialize, TlsSize};

#[derive(Clone, Debug, PartialEq, TlsDeserialize, TlsSerialize, TlsSize)]
#[repr(u16)]
pub enum CredentialIdentifier {
    Basic = 0x0001,
}

#[derive(Error, Debug)]
pub enum CredentialError {
    #[error(transparent)]
    EcKeyError(#[from] EcKeyError),
}

#[derive(Clone, Debug, PartialEq, TlsDeserialize, TlsSerialize, TlsSize)]
#[repr(u16)]
pub enum Credential {
    #[tls_codec(discriminant = 1)]
    Basic(BasicCredential), //TODO: X509
}

impl Credential {
    #[inline(always)]
    pub fn get_signature_scheme(&self) -> SignatureScheme {
        match self {
            Credential::Basic(credential) => credential.signature_scheme,
        }
    }

    #[inline(always)]
    pub fn get_public_key(&self) -> Result<PublicKey, CredentialError> {
        let sig_key = match self {
            Credential::Basic(b) => &b.signature_key,
        };

        PublicKey::from_uncompressed_bytes(sig_key, self.get_signature_scheme().into())
            .map_err(Into::into)
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
        self.get_public_key()?
            .verify(signature, data)
            .map_err(Into::into)
    }
}

pub(crate) trait CredentialConvertible {
    fn to_credential(&self) -> Credential;
}

#[derive(Clone, Debug, PartialEq, TlsDeserialize, TlsSerialize, TlsSize)]
pub struct BasicCredential {
    #[tls_codec(with = "crate::tls::ByteVec::<u32>")]
    pub identity: Vec<u8>,
    pub signature_scheme: SignatureScheme,
    #[tls_codec(with = "crate::tls::ByteVec::<u32>")]
    pub signature_key: Vec<u8>,
}

impl CredentialConvertible for BasicCredential {
    fn to_credential(&self) -> Credential {
        Credential::Basic(self.clone())
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

#[cfg(test)]
mod test {
    use super::*;
    use ferriscrypt::asym::ec_key::{generate_keypair, Curve, SecretKey};
    use ferriscrypt::rand::SecureRng;
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

            // Signature type
            let cred_sig_type = test_data.credential.get_signature_scheme();
            assert_eq!(cred_sig_type, one_scheme);

            // Signature key
            let cred_sig_key = test_data.credential.get_public_key().unwrap();
            assert_eq!(
                cred_sig_key.to_uncompressed_bytes().unwrap(),
                test_data.public.to_uncompressed_bytes().unwrap()
            )
        }
    }

    #[test]
    fn test_basic_credential_verify() {
        let test_signature_input = b"Don't Panic" as &[u8];

        for one_scheme in SignatureScheme::all() {
            println!(
                "Testing basic credential verify with signature scheme: {:?}",
                one_scheme
            );

            let test_data = get_test_basic_credential(vec![], one_scheme);

            let valid_signature = test_data.secret.sign(test_signature_input).unwrap();
            let invalid_signature_data = test_data.secret.sign(b"foo" as &[u8]).unwrap();
            let invalid_signature_key = SecretKey::generate(Curve::from(one_scheme))
                .unwrap()
                .sign(test_signature_input)
                .unwrap();

            assert!(test_data
                .credential
                .verify(&valid_signature, &test_signature_input)
                .unwrap());
            assert!(!test_data
                .credential
                .verify(&invalid_signature_data, &test_signature_input)
                .unwrap());
            assert!(!test_data
                .credential
                .verify(&invalid_signature_key, &test_signature_input)
                .unwrap());
        }
    }
}
