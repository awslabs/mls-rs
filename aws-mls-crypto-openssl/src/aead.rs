use std::ops::Deref;

use aws_mls_core::crypto::CipherSuite;
use openssl::symm::{decrypt_aead, encrypt_aead, Cipher};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum AeadError {
    #[error(transparent)]
    OpensslError(#[from] openssl::error::ErrorStack),
    #[error("AEAD ciphertext of length {0} is too short to fit the tag")]
    InvalidCipherLen(usize),
    #[error("encrypted message cannot be empty")]
    EmptyPlaintext,
}

pub const TAG_LEN: usize = 16;

#[derive(Clone)]
pub struct Aead(Cipher);

impl Deref for Aead {
    type Target = Cipher;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Aead {
    pub fn new(cipher_suite: CipherSuite) -> Self {
        let cipher = match cipher_suite {
            CipherSuite::P256Aes128 | CipherSuite::Curve25519Aes128 => Cipher::aes_128_gcm(),
            CipherSuite::Curve448Aes256 | CipherSuite::P384Aes256 | CipherSuite::P521Aes256 => {
                Cipher::aes_256_gcm()
            }
            CipherSuite::Curve25519ChaCha20 | CipherSuite::Curve448ChaCha20 => {
                Cipher::chacha20_poly1305()
            }
        };

        Self(cipher)
    }

    pub fn aead_seal(
        &self,
        key: &[u8],
        data: &[u8],
        aad: Option<&[u8]>,
        nonce: &[u8],
    ) -> Result<Vec<u8>, AeadError> {
        (!data.is_empty())
            .then_some(())
            .ok_or(AeadError::EmptyPlaintext)?;

        let mut tag = [0u8; TAG_LEN];
        let aad = aad.unwrap_or_default();

        let ciphertext = encrypt_aead(self.0, key, Some(nonce), aad, data, &mut tag)?;

        // Question Is this how this should be done? Or other encodings?
        Ok([&ciphertext, &tag as &[u8]].concat())
    }

    pub fn aead_open(
        &self,
        key: &[u8],
        ciphertext: &[u8],
        aad: Option<&[u8]>,
        nonce: &[u8],
    ) -> Result<Vec<u8>, AeadError> {
        (ciphertext.len() > TAG_LEN)
            .then_some(())
            .ok_or(AeadError::InvalidCipherLen(ciphertext.len()))?;

        let (data, tag) = ciphertext.split_at(ciphertext.len() - TAG_LEN);
        let aad = aad.unwrap_or_default();

        decrypt_aead(self.0, key, Some(nonce), aad, data, tag).map_err(Into::into)
    }

    pub fn aead_key_size(&self) -> usize {
        self.key_len()
    }

    pub fn aead_nonce_size(&self) -> usize {
        self.iv_len()
            .expect("The ciphersuite's AEAD algorithm must support nonce-based encryption.")
    }
}

#[cfg(test)]
mod test {
    use aws_mls_core::crypto::CipherSuite;

    use crate::aead::TAG_LEN;

    use super::{Aead, AeadError};

    use assert_matches::assert_matches;

    fn get_aeads() -> Vec<Aead> {
        [
            CipherSuite::Curve25519Aes128,
            CipherSuite::Curve25519ChaCha20,
            CipherSuite::Curve448Aes256,
        ]
        .into_iter()
        .map(Aead::new)
        .collect()
    }

    #[derive(serde::Deserialize)]
    struct TestCase {
        pub ciphersuite: CipherSuite,
        #[serde(with = "hex::serde")]
        pub key: Vec<u8>,
        #[serde(with = "hex::serde")]
        pub iv: Vec<u8>,
        #[serde(with = "hex::serde")]
        pub ct: Vec<u8>,
        #[serde(with = "hex::serde")]
        pub aad: Vec<u8>,
        #[serde(with = "hex::serde")]
        pub pt: Vec<u8>,
    }

    #[test]
    fn test_vectors() {
        let test_case_file = include_str!("../test_data/test_aead.json");
        let test_cases: Vec<TestCase> = serde_json::from_str(test_case_file).unwrap();

        for case in test_cases {
            let aead = Aead::new(case.ciphersuite);

            let ciphertext = aead
                .aead_seal(&case.key, &case.pt, Some(&case.aad), &case.iv)
                .unwrap();

            assert_eq!(ciphertext, case.ct);

            let plaintext = aead
                .aead_open(&case.key, &ciphertext, Some(&case.aad), &case.iv)
                .unwrap();

            assert_eq!(plaintext, case.pt);
        }
    }

    #[test]
    fn invalid_key() {
        for aead in get_aeads() {
            let nonce = vec![42u8; aead.aead_nonce_size()];
            let data = b"top secret";

            let too_short = vec![42u8; aead.aead_key_size() - 1];

            assert_matches!(
                aead.aead_seal(&too_short, data, None, &nonce),
                Err(AeadError::OpensslError(_))
            );

            let too_long = vec![42u8; aead.aead_key_size() + 1];

            assert_matches!(
                aead.aead_seal(&too_long, data, None, &nonce),
                Err(AeadError::OpensslError(_))
            );
        }
    }

    #[test]
    fn invalid_ciphertext() {
        for aead in get_aeads() {
            let key = vec![42u8; aead.aead_key_size()];
            let nonce = vec![42u8; aead.aead_nonce_size()];

            let too_short = [0u8; TAG_LEN];

            assert_matches!(
                aead.aead_open(&key, &too_short, None, &nonce),
                Err(AeadError::InvalidCipherLen(_))
            );
        }
    }

    #[test]
    fn aad_mismatch() {
        for aead in get_aeads() {
            let key = vec![42u8; aead.aead_key_size()];
            let nonce = vec![42u8; aead.aead_nonce_size()];

            let ciphertext = aead
                .aead_seal(&key, b"message", Some(b"foo"), &nonce)
                .unwrap();

            assert_matches!(
                aead.aead_open(&key, &ciphertext, Some(b"bar"), &nonce),
                Err(AeadError::OpensslError(_))
            );

            assert_matches!(
                aead.aead_open(&key, &ciphertext, None, &nonce),
                Err(AeadError::OpensslError(_))
            );
        }
    }
}
