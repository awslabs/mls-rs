use ferriscrypt::asym::ec_key::{EcKeyError, PublicKey};
use thiserror::Error;
use tls_codec_derive::{TlsDeserialize, TlsSerialize, TlsSize};

use crate::{
    cipher_suite::{CipherSuite, SignaturePublicKey},
    identity::Credential,
};

use super::{CredentialError, MlsCredential};

#[derive(Debug, Error)]
pub enum SigningIdentityError {
    #[error(transparent)]
    EcKeyError(#[from] EcKeyError),
    #[error(transparent)]
    CredentialError(#[from] CredentialError),
    #[error("internal signer error: {0:?}")]
    SignerError(Box<dyn std::error::Error + Send + Sync>),
    #[error("certificate public key mismatch")]
    CertPublicKeyMismatch,
    #[error("invalid signature key data for cipher suite: {0:?}, underlying error: {1:?}")]
    InvalidSignatureKey(CipherSuite, EcKeyError),
    #[error("signing identity not valid for signer")]
    InvalidSignerPublicKey,
    #[error("credential rejected by custom credential validator")]
    IdentityValidatorError(#[source] Box<dyn std::error::Error + Sync + Send>),
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
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
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

    pub fn credential<C: MlsCredential>(&self) -> Result<C, CredentialError> {
        C::from_credential(&self.credential)
    }

    pub fn public_key_bytes(&self) -> &[u8] {
        &self.signature_key
    }

    pub(crate) fn public_key(
        &self,
        cipher_suite: CipherSuite,
    ) -> Result<PublicKey, SigningIdentityError> {
        PublicKey::from_uncompressed_bytes(&self.signature_key, cipher_suite.signature_key_curve())
            .map_err(|e| SigningIdentityError::InvalidSignatureKey(cipher_suite, e))
    }
}

#[cfg(any(test, feature = "benchmark"))]
pub(crate) mod test_utils {
    use super::SigningIdentity;
    use crate::{
        cipher_suite::{CipherSuite, SignaturePublicKey},
        identity::test_utils::get_test_basic_credential,
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
    use ferriscrypt::asym::ec_key::generate_keypair;

    use crate::{
        cipher_suite::{CipherSuite, SignaturePublicKey},
        identity::test_utils::get_test_basic_credential,
    };

    use super::{test_utils::get_test_signing_identity, *};

    #[test]
    fn test_signing_identity_creation() {
        let cipher_suite = CipherSuite::Curve25519Aes128;

        let (signature_key, _) = generate_keypair(cipher_suite.signature_key_curve()).unwrap();

        let signature_public_key = SignaturePublicKey::try_from(signature_key).unwrap();
        let basic = get_test_basic_credential(b"alice".to_vec());
        let signing_identity = SigningIdentity::new(basic, signature_public_key);

        assert_eq!(
            signing_identity.credential,
            get_test_basic_credential(b"alice".to_vec())
        );
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
}