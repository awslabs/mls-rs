use std::ops::Deref;

use aws_mls_core::crypto::{CipherSuite, SignaturePublicKey, SignatureSecretKey};
use openssl::{
    hash::MessageDigest,
    pkey::{PKey, Private, Public},
};
use thiserror::Error;

use crate::ec::{
    generate_keypair, private_key_bytes_to_public, private_key_from_bytes,
    pub_key_from_uncompressed, Curve, EcError,
};

#[derive(Debug, Error)]
pub enum EcSignerError {
    #[error(transparent)]
    OpensslError(#[from] openssl::error::ErrorStack),
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
    pub fn new(cipher_suite: CipherSuite) -> Self {
        Self(Curve::from_ciphersuite(cipher_suite, true))
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

    pub(crate) fn pkey_from_secret_key(
        &self,
        key: &SignatureSecretKey,
    ) -> Result<PKey<Private>, EcSignerError> {
        private_key_from_bytes(key, self.0).map_err(Into::into)
    }

    pub(crate) fn pkey_from_public_key(
        &self,
        key: &SignaturePublicKey,
    ) -> Result<PKey<Public>, EcSignerError> {
        pub_key_from_uncompressed(key, self.0).map_err(Into::into)
    }

    pub fn sign(
        &self,
        secret_key: &SignatureSecretKey,
        data: &[u8],
    ) -> Result<Vec<u8>, EcSignerError> {
        let secret_key = private_key_from_bytes(secret_key, self.0)?;

        let mut signer = match self.message_digest() {
            Some(md) => openssl::sign::Signer::new(md, &secret_key),
            None => openssl::sign::Signer::new_without_digest(&secret_key),
        }?;

        Ok(signer.sign_oneshot_to_vec(data)?)
    }

    pub fn verify(
        &self,
        public_key: &SignaturePublicKey,
        signature: &[u8],
        data: &[u8],
    ) -> Result<(), EcSignerError> {
        let public_key = pub_key_from_uncompressed(public_key, self.0)?;

        let mut verifier = match self.message_digest() {
            Some(md) => openssl::sign::Verifier::new(md, &public_key),
            None => openssl::sign::Verifier::new_without_digest(&public_key),
        }?;

        verifier
            .verify_oneshot(signature, data)?
            .then_some(())
            .ok_or(EcSignerError::InvalidSignature)
    }

    pub(crate) fn message_digest(&self) -> Option<MessageDigest> {
        match self.0 {
            Curve::P256 => Some(MessageDigest::sha256()),
            Curve::P384 => Some(MessageDigest::sha384()),
            Curve::P521 => Some(MessageDigest::sha512()),
            _ => None,
        }
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
        CipherSuite::all().for_each(test_signature);
    }

    fn test_signature(cipher_suite: CipherSuite) {
        println!("Testing signatures for cipher suite: {cipher_suite:?}");

        let public_key = get_test_public_keys().get_key(cipher_suite, true).into();
        let secret_key = get_test_secret_keys().get_key(cipher_suite, true);
        let ec_signer = EcSigner::new(cipher_suite);

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
