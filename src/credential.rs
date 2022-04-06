use crate::cipher_suite::SignatureScheme;
use crate::x509::{CertificateChain, X509Error};
use ferriscrypt::asym::ec_key::{EcKeyError, PublicKey};
use std::convert::TryInto;
use thiserror::Error;
use tls_codec_derive::{TlsDeserialize, TlsSerialize, TlsSize};

#[derive(Error, Debug)]
pub enum CredentialError {
    #[error(transparent)]
    EcKeyError(#[from] EcKeyError),
    #[error(transparent)]
    CertificateError(#[from] X509Error),
}

#[derive(Clone, Debug, TlsDeserialize, TlsSerialize, TlsSize, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum Credential {
    #[tls_codec(discriminant = 1)]
    Basic(BasicCredential),
    #[tls_codec(discriminant = 2)]
    Certificate(CertificateChain),
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

pub(crate) trait CredentialConvertible {
    fn into_credential(self) -> Credential;
    fn public_key(&self) -> Result<PublicKey, CredentialError>;
}

#[derive(Clone, Debug, PartialEq, TlsDeserialize, TlsSerialize, TlsSize, Eq, Hash)]
pub struct BasicCredential {
    #[tls_codec(with = "crate::tls::ByteVec")]
    pub identity: Vec<u8>,
    pub signature_scheme: SignatureScheme,
    #[tls_codec(with = "crate::tls::ByteVec")]
    pub(crate) signature_key: Vec<u8>,
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
            signature_scheme: signature_key.curve().try_into()?,
            signature_key: signature_key.to_uncompressed_bytes()?,
        })
    }
}

impl CredentialConvertible for CertificateChain {
    fn into_credential(self) -> Credential {
        Credential::Certificate(self)
    }

    fn public_key(&self) -> Result<PublicKey, CredentialError> {
        self.leaf()?.public_key().map_err(Into::into)
    }
}

#[cfg(test)]
pub mod test_utils {
    use super::*;
    use ferriscrypt::asym::ec_key::{generate_keypair, Curve, SecretKey};

    pub struct TestCredentialData {
        pub public: PublicKey,
        pub secret: SecretKey,
        pub credential: Credential,
    }

    pub fn get_test_basic_credential(
        identity: Vec<u8>,
        scheme: SignatureScheme,
    ) -> TestCredentialData {
        let (public, secret) = generate_keypair(Curve::from(scheme)).unwrap();
        let credential = Credential::Basic(BasicCredential::new(identity, public.clone()).unwrap());

        TestCredentialData {
            public,
            secret,
            credential,
        }
    }
}

#[cfg(test)]
mod test {
    use super::{test_utils::TestCredentialData, *};
    use crate::{
        credential::test_utils::get_test_basic_credential,
        x509::test_utils::{test_cert, test_key},
    };
    use ferriscrypt::{
        asym::ec_key::{Curve, SecretKey},
        rand::SecureRng,
    };

    #[cfg(target_arch = "wasm32")]
    use wasm_bindgen_test::wasm_bindgen_test as test;

    fn get_test_certificate_credential() -> TestCredentialData {
        let test_key = test_key(Curve::P256);

        let test_credential =
            CertificateChain::from(vec![test_cert(Curve::P256)]).into_credential();

        TestCredentialData {
            public: test_key.to_public().unwrap(),
            secret: test_key,
            credential: test_credential,
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
            );

            assert_eq!(
                test_data.secret.to_public().unwrap(),
                test_data.credential.public_key().unwrap()
            );
        }
    }

    #[test]
    fn test_certificate_credential_pub_key() {
        let test_data = get_test_certificate_credential();

        assert_eq!(test_data.public, test_data.credential.public_key().unwrap());

        assert_eq!(
            test_data.secret.to_public().unwrap(),
            test_data.credential.public_key().unwrap()
        );
    }
}
