use std::ops::Deref;

use aws_mls_core::crypto::{CipherSuite, SignaturePublicKey, SignatureSecretKey};
use thiserror::Error;

use crate::ec::{
    generate_keypair, private_key_bytes_to_public, private_key_from_bytes,
    pub_key_from_uncompressed, sign_ed25519, sign_p256, verify_ed25519, verify_p256, Curve,
    EcError, EcPrivateKey, EcPublicKey,
};

#[derive(Debug, Error)]
pub enum EcSignerError {
    #[error("ec key is not a signature key")]
    EcKeyNotSignature,
    #[error(transparent)]
    EcError(#[from] EcError),
    #[error("invalid signature")]
    InvalidSignature,
}

#[derive(Clone, Debug, Copy, PartialEq, Eq)]
pub struct EcSigner(Curve);

impl Deref for EcSigner {
    type Target = Curve;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl EcSigner {
    pub fn new(cipher_suite: CipherSuite) -> Result<Self, EcSignerError> {
        Ok(Self(Curve::from_ciphersuite(cipher_suite, true)?))
    }

    pub fn new_from_curve(curve: Curve) -> Self {
        Self(curve)
    }

    pub fn signature_key_generate(
        &self,
    ) -> Result<(SignatureSecretKey, SignaturePublicKey), EcSignerError> {
        let key_pair = generate_keypair(self.0)?;
        Ok((key_pair.secret.into(), key_pair.public.into()))
    }

    pub fn signature_key_derive_public(
        &self,
        secret_key: &SignatureSecretKey,
    ) -> Result<SignaturePublicKey, EcSignerError> {
        Ok(private_key_bytes_to_public(secret_key, self.0)?.into())
    }

    pub fn sign(
        &self,
        secret_key: &SignatureSecretKey,
        data: &[u8],
    ) -> Result<Vec<u8>, EcSignerError> {
        let secret_key = private_key_from_bytes(secret_key, self.0)?;

        match secret_key {
            EcPrivateKey::X25519(_) => Err(EcSignerError::EcKeyNotSignature),
            EcPrivateKey::Ed25519(private_key) => Ok(sign_ed25519(&private_key, data)?),
            EcPrivateKey::P256(private_key) => Ok(sign_p256(&private_key, data)?),
        }
    }

    pub fn verify(
        &self,
        public_key: &SignaturePublicKey,
        signature: &[u8],
        data: &[u8],
    ) -> Result<(), EcSignerError> {
        let public_key = pub_key_from_uncompressed(public_key, self.0)?;

        let ver = match public_key {
            EcPublicKey::X25519(_) => Err(EcSignerError::EcKeyNotSignature),
            EcPublicKey::Ed25519(key) => Ok(verify_ed25519(&key, signature, data)?),
            EcPublicKey::P256(key) => Ok(verify_p256(&key, signature, data)?),
        }?;

        ver.then_some(()).ok_or(EcSignerError::InvalidSignature)
    }
}

#[cfg(test)]
mod test {
    use assert_matches::assert_matches;
    use aws_mls_core::crypto::CipherSuite;

    use crate::{
        ec::test_utils::{get_test_public_keys, get_test_secret_keys},
        ec_signer::{EcSigner, EcSignerError},
    };

    const TEST_INPUT: &[u8] = b"Hello World!";

    #[test]
    fn test_signatures() {
        [CipherSuite::CURVE25519_AES128, CipherSuite::P256_AES128]
            .into_iter()
            .for_each(test_signature);
    }

    fn test_signature(cipher_suite: CipherSuite) {
        println!("Testing signatures for cipher suite: {cipher_suite:?}");

        let public_key = get_test_public_keys().get_key(cipher_suite, true).into();
        let secret_key = get_test_secret_keys().get_key(cipher_suite, true);
        let ec_signer = EcSigner::new(cipher_suite).unwrap();

        assert_eq!(ec_signer.secret_key_size(), secret_key.len());

        let sig = ec_signer.sign(&secret_key.into(), TEST_INPUT).unwrap();

        ec_signer.verify(&public_key, &sig, TEST_INPUT).unwrap();

        let other_public_key = ec_signer.signature_key_generate().unwrap().1;

        assert_matches!(
            ec_signer.verify(&other_public_key, &sig, TEST_INPUT),
            Err(EcSignerError::InvalidSignature)
        );

        assert_matches!(
            ec_signer.verify(&public_key, &sig, &[TEST_INPUT, &[0]].concat()),
            Err(EcSignerError::InvalidSignature)
        );
    }
}
