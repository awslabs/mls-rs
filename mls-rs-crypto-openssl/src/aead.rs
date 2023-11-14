// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// Copyright by contributors to this project.
// SPDX-License-Identifier: (Apache-2.0 OR MIT)

use std::{fmt::Debug, ops::Deref};

use mls_rs_core::{crypto::CipherSuite, error::IntoAnyError};
use mls_rs_crypto_traits::{AeadId, AeadType, AES_TAG_LEN};
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
    #[error("unsupported cipher suite")]
    UnsupportedCipherSuite,
}

impl IntoAnyError for AeadError {
    fn into_dyn_error(self) -> Result<Box<dyn std::error::Error + Send + Sync>, Self> {
        Ok(self.into())
    }
}

#[derive(Clone)]
pub struct Aead {
    cipher: Cipher,
    aead_id: AeadId,
}

impl Debug for Aead {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Aead with aead_id {:?}", self.aead_id)
    }
}

impl Deref for Aead {
    type Target = Cipher;

    fn deref(&self) -> &Self::Target {
        &self.cipher
    }
}

impl Aead {
    pub fn new(cipher_suite: CipherSuite) -> Option<Self> {
        let aead_id = AeadId::new(cipher_suite)?;

        let cipher = match aead_id {
            AeadId::Aes128Gcm => Some(Cipher::aes_128_gcm()),
            AeadId::Aes256Gcm => Some(Cipher::aes_256_gcm()),
            AeadId::Chacha20Poly1305 => Some(Cipher::chacha20_poly1305()),
            _ => None,
        };

        cipher.map(|cipher| Self { cipher, aead_id })
    }
}

#[cfg_attr(not(mls_build_async), maybe_async::must_be_sync)]
#[cfg_attr(all(target_arch = "wasm32", mls_build_async), maybe_async::must_be_async(?Send))]
#[cfg_attr(
    all(not(target_arch = "wasm32"), mls_build_async),
    maybe_async::must_be_async
)]
impl AeadType for Aead {
    type Error = AeadError;

    #[allow(clippy::needless_lifetimes)]
    async fn seal<'a>(
        &self,
        key: &[u8],
        data: &[u8],
        aad: Option<&'a [u8]>,
        nonce: &[u8],
    ) -> Result<Vec<u8>, AeadError> {
        (!data.is_empty())
            .then_some(())
            .ok_or(AeadError::EmptyPlaintext)?;

        let mut tag = [0u8; AES_TAG_LEN];
        let aad = aad.unwrap_or_default();

        let ciphertext = encrypt_aead(self.cipher, key, Some(nonce), aad, data, &mut tag)?;

        // Question Is this how this should be done? Or other encodings?
        Ok([&ciphertext, &tag as &[u8]].concat())
    }

    #[allow(clippy::needless_lifetimes)]
    async fn open<'a>(
        &self,
        key: &[u8],
        ciphertext: &[u8],
        aad: Option<&'a [u8]>,
        nonce: &[u8],
    ) -> Result<Vec<u8>, AeadError> {
        (ciphertext.len() > AES_TAG_LEN)
            .then_some(())
            .ok_or(AeadError::InvalidCipherLen(ciphertext.len()))?;

        let (data, tag) = ciphertext.split_at(ciphertext.len() - AES_TAG_LEN);
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

#[cfg(all(not(mls_build_async), test))]
mod test {
    use mls_rs_core::crypto::CipherSuite;
    use mls_rs_crypto_traits::{AeadType, AES_TAG_LEN};

    use super::{Aead, AeadError};

    use assert_matches::assert_matches;

    fn get_aeads() -> Vec<Aead> {
        [
            CipherSuite::CURVE25519_AES128,
            CipherSuite::CURVE25519_CHACHA,
            CipherSuite::CURVE448_AES256,
        ]
        .into_iter()
        .map(|v| Aead::new(v).unwrap())
        .collect()
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

            let too_short = [0u8; AES_TAG_LEN];

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
