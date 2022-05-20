use ferriscrypt::asym::ec_key::{EcKeyError, PublicKey};
use thiserror::Error;
use tls_codec_derive::{TlsDeserialize, TlsSerialize, TlsSize};

use crate::{
    cipher_suite::{CipherSuite, SignaturePublicKey},
    credential::Credential,
    signer::Signer,
    x509::X509Error,
};

#[derive(Debug, Error)]
pub enum SigningIdentityError {
    #[error(transparent)]
    EcKeyError(#[from] EcKeyError),
    #[error(transparent)]
    CertificateError(#[from] X509Error),
    #[error("internal signer error: {0:?}")]
    SignerError(Box<dyn std::error::Error>),
    #[error("certificate public key mismatch")]
    CertPublicKeyMismatch,
    #[error("invalid signature key data for cipher suite: {0:?}, underlying error: {1:?}")]
    InvalidSignatureKey(CipherSuite, EcKeyError),
    #[error("signing identity not valid for signer")]
    InvalidSignerPublicKey,
}

#[derive(
    Debug,
    Clone,
    Eq,
    Hash,
    PartialEq,
    TlsSize,
    TlsSerialize,
    TlsDeserialize,
    serde::Serialize,
    serde::Deserialize,
)]
#[non_exhaustive]
pub struct SigningIdentity {
    pub signature_key: SignaturePublicKey,
    pub credential: Credential,
}

impl SigningIdentity {
    pub fn new(credential: Credential, signature_key: SignaturePublicKey) -> SigningIdentity {
        SigningIdentity {
            credential,
            signature_key,
        }
    }

    pub(crate) fn public_key(
        &self,
        cipher_suite: CipherSuite,
    ) -> Result<PublicKey, SigningIdentityError> {
        PublicKey::from_uncompressed_bytes(&self.signature_key, cipher_suite.signature_key_curve())
            .map_err(|e| SigningIdentityError::InvalidSignatureKey(cipher_suite, e))
    }

    pub(crate) fn check_validity<S: Signer>(
        &self,
        signer: Option<&S>,
        cipher_suite: CipherSuite,
    ) -> Result<(), SigningIdentityError> {
        // Determine that the signature key is the right type based on the cipher suite
        let public_key = self.public_key(cipher_suite)?;

        // If the credential is X509, make sure that its public key matches the signature key
        // presented
        if let Credential::Certificate(ref cert) = self.credential {
            let cert_pk = cert.leaf()?.public_key()?;

            if cert_pk != public_key {
                return Err(SigningIdentityError::CertPublicKeyMismatch);
            }
        }

        if let Some(signer) = signer {
            let signer_public = signer
                .public_key()
                .map_err(|e| SigningIdentityError::SignerError(e.into()))?;

            if signer_public != public_key {
                return Err(SigningIdentityError::InvalidSignerPublicKey);
            }
        }

        Ok(())
    }
}

#[cfg(test)]
pub(crate) mod test_utils {
    use super::SigningIdentity;
    use crate::{
        cipher_suite::{CipherSuite, SignaturePublicKey},
        credential::test_utils::get_test_basic_credential,
    };
    use ferriscrypt::asym::ec_key::{generate_keypair, SecretKey};

    pub fn get_test_signing_identity(
        cipher_suite: CipherSuite,
        identity: Vec<u8>,
    ) -> (SigningIdentity, SecretKey) {
        let (signature_key, secret_key) =
            generate_keypair(cipher_suite.signature_key_curve()).unwrap();

        let signature_public_key = SignaturePublicKey::try_from(signature_key).unwrap();

        let basic = get_test_basic_credential(identity);

        (
            SigningIdentity::new(basic, signature_public_key),
            secret_key,
        )
    }
}

#[cfg(test)]
mod tests {
    use assert_matches::assert_matches;
    use ferriscrypt::asym::ec_key::{generate_keypair, SecretKey};

    use crate::{
        cipher_suite::{CipherSuite, SignaturePublicKey},
        credential::{
            test_utils::{get_test_basic_credential, get_test_certificate_credential},
            Credential,
        },
    };

    use super::{test_utils::get_test_signing_identity, *};

    #[test]
    fn test_signing_identity_creation() {
        let cipher_suite = CipherSuite::Curve25519Aes128;

        let (signature_key, _) = generate_keypair(cipher_suite.signature_key_curve()).unwrap();

        let signature_public_key = SignaturePublicKey::try_from(signature_key).unwrap();
        let basic = get_test_basic_credential(b"alice".to_vec());
        let signing_identity = SigningIdentity::new(basic, signature_public_key);

        assert_matches!(signing_identity.credential, Credential::Basic(id) if id == b"alice".to_vec());
    }

    #[test]
    fn test_signing_identity_public_key() {
        for cipher_suite in CipherSuite::all() {
            let (signing_identity, signer) =
                get_test_signing_identity(cipher_suite, b"alice".to_vec());

            let expected_public = signer.to_public().unwrap();

            assert_eq!(
                signing_identity.public_key(cipher_suite).unwrap(),
                expected_public
            );
        }
    }

    #[test]
    fn test_signing_identity_public_key_wrong_cipher_suite() {
        let cipher_suite = CipherSuite::Curve25519Aes128;
        let invalid_cipher_suite = CipherSuite::P256Aes128;

        let (signing_identity, _) = get_test_signing_identity(cipher_suite, b"alice".to_vec());

        let res = signing_identity.public_key(invalid_cipher_suite);

        assert_matches!(res, Err(SigningIdentityError::InvalidSignatureKey(cs, _)) if cs == invalid_cipher_suite);
    }

    #[test]
    fn test_signing_identity_validity() {
        for cipher_suite in CipherSuite::all() {
            let (signing_identity, signer) =
                get_test_signing_identity(cipher_suite, b"alice".to_vec());

            assert!(signing_identity
                .check_validity::<SecretKey>(None, cipher_suite)
                .is_ok());

            assert!(signing_identity
                .check_validity(Some(&signer), cipher_suite)
                .is_ok());
        }
    }

    #[test]
    fn test_signing_identity_invalid_wrong_cipher_suite() {
        let cipher_suite = CipherSuite::Curve25519Aes128;
        let invalid_cipher_suite = CipherSuite::P256Aes128;

        let (signing_identity, _) = get_test_signing_identity(cipher_suite, b"alice".to_vec());

        let res = signing_identity.check_validity::<SecretKey>(None, invalid_cipher_suite);

        assert_matches!(res, Err(SigningIdentityError::InvalidSignatureKey(cs, _)) if cs == invalid_cipher_suite);
    }

    #[test]
    fn test_signing_identity_invalid_signer() {
        let cipher_suite = CipherSuite::Curve25519Aes128;

        let (signing_identity, _) = get_test_signing_identity(cipher_suite, b"alice".to_vec());
        let invalid_signer = cipher_suite.generate_signing_key().unwrap();

        let res = signing_identity.check_validity(Some(&invalid_signer), cipher_suite);

        assert_matches!(res, Err(SigningIdentityError::InvalidSignerPublicKey));
    }

    #[test]
    fn test_signing_identity_x509_mismatch() {
        let cipher_suite = CipherSuite::Curve25519Aes128;
        let test_cert_credential = get_test_certificate_credential();
        let signature_key = cipher_suite.generate_signing_key().unwrap();

        let signing_identity = SigningIdentity::new(
            test_cert_credential,
            SignaturePublicKey::try_from(&signature_key).unwrap(),
        );

        let res = signing_identity.check_validity::<SecretKey>(None, cipher_suite);

        assert_matches!(res, Err(SigningIdentityError::CertPublicKeyMismatch));
    }
}
