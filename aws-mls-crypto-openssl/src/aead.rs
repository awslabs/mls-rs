use std::{fmt::Debug, ops::Deref};

use aws_mls_core::crypto::CipherSuite;
use aws_mls_crypto_traits::AeadType;
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
pub struct Aead {
    cipher: Cipher,
    aead_id: AeadId,
}

impl Debug for Aead {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_fmt(format_args!("Aead with aead_id {:?}", self.aead_id))
    }
}

/// Aead ID as specified in RFC 9180, Table 5.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u16)]
enum AeadId {
    /// AES-128-GCM: 16 byte key, 12 byte nonce, 16 byte tag
    Aes128Gcm = 0x0001,
    /// AES-256-GCM: 32 byte key, 12 byte nonce, 16 byte tag
    Aes256Gcm = 0x0002,
    /// ChaCha20-Poly1305: 32 byte key, 12 byte nonce, 16 byte tag
    Chacha20Poly1305 = 0x0003,
}

impl Deref for Aead {
    type Target = Cipher;

    fn deref(&self) -> &Self::Target {
        &self.cipher
    }
}

impl Aead {
    pub fn new(cipher_suite: CipherSuite) -> Self {
        let (cipher, aead_id) = match cipher_suite {
            CipherSuite::P256Aes128 | CipherSuite::Curve25519Aes128 => {
                (Cipher::aes_128_gcm(), AeadId::Aes128Gcm)
            }
            CipherSuite::Curve448Aes256 | CipherSuite::P384Aes256 | CipherSuite::P521Aes256 => {
                (Cipher::aes_256_gcm(), AeadId::Aes256Gcm)
            }
            CipherSuite::Curve25519ChaCha20 | CipherSuite::Curve448ChaCha20 => {
                (Cipher::chacha20_poly1305(), AeadId::Chacha20Poly1305)
            }
        };

        Self { cipher, aead_id }
    }
}

impl AeadType for Aead {
    type Error = AeadError;

    fn seal(
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

        let ciphertext = encrypt_aead(self.cipher, key, Some(nonce), aad, data, &mut tag)?;

        // Question Is this how this should be done? Or other encodings?
        Ok([&ciphertext, &tag as &[u8]].concat())
    }

    fn open(
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

        decrypt_aead(self.cipher, key, Some(nonce), aad, data, tag).map_err(Into::into)
    }

    fn key_size(&self) -> usize {
        self.key_len()
    }

    fn nonce_size(&self) -> usize {
        self.iv_len()
            .expect("The ciphersuite's AEAD algorithm must support nonce-based encryption.")
    }

    fn aead_id(&self) -> u16 {
        self.aead_id as u16
    }
}

#[cfg(test)]
mod test {
    use aws_mls_core::crypto::CipherSuite;
    use aws_mls_crypto_traits::AeadType;

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
                .seal(&case.key, &case.pt, Some(&case.aad), &case.iv)
                .unwrap();

            assert_eq!(ciphertext, case.ct);

            let plaintext = aead
                .open(&case.key, &ciphertext, Some(&case.aad), &case.iv)
                .unwrap();

            assert_eq!(plaintext, case.pt);
        }
    }

    #[test]
    fn invalid_key() {
        for aead in get_aeads() {
            let nonce = vec![42u8; aead.nonce_size()];
            let data = b"top secret";

            let too_short = vec![42u8; aead.key_size() - 1];

            assert_matches!(
                aead.seal(&too_short, data, None, &nonce),
                Err(AeadError::OpensslError(_))
            );

            let too_long = vec![42u8; aead.key_size() + 1];

            assert_matches!(
                aead.seal(&too_long, data, None, &nonce),
                Err(AeadError::OpensslError(_))
            );
        }
    }

    #[test]
    fn invalid_ciphertext() {
        for aead in get_aeads() {
            let key = vec![42u8; aead.key_size()];
            let nonce = vec![42u8; aead.nonce_size()];

            let too_short = [0u8; TAG_LEN];

            assert_matches!(
                aead.open(&key, &too_short, None, &nonce),
                Err(AeadError::InvalidCipherLen(_))
            );
        }
    }

    #[test]
    fn aad_mismatch() {
        for aead in get_aeads() {
            let key = vec![42u8; aead.key_size()];
            let nonce = vec![42u8; aead.nonce_size()];

            let ciphertext = aead.seal(&key, b"message", Some(b"foo"), &nonce).unwrap();

            assert_matches!(
                aead.open(&key, &ciphertext, Some(b"bar"), &nonce),
                Err(AeadError::OpensslError(_))
            );

            assert_matches!(
                aead.open(&key, &ciphertext, None, &nonce),
                Err(AeadError::OpensslError(_))
            );
        }
    }
}
