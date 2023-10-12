// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// Copyright by contributors to this project.
// SPDX-License-Identifier: (Apache-2.0 OR MIT)

extern crate aead as rc_aead;

use core::fmt::Debug;

use aes_gcm::{Aes128Gcm, Aes256Gcm, KeyInit};
use aws_mls_core::{crypto::CipherSuite, error::IntoAnyError};
use aws_mls_crypto_traits::{AeadId, AeadType, AES_TAG_LEN};
use chacha20poly1305::ChaCha20Poly1305;
use rc_aead::{generic_array::GenericArray, Payload};

use alloc::vec::Vec;

#[derive(Debug)]
#[cfg_attr(feature = "std", derive(thiserror::Error))]
pub enum AeadError {
    #[cfg_attr(feature = "std", error("Rc AEAD Error"))]
    RcAeadError(rc_aead::Error),
    #[cfg_attr(
        feature = "std",
        error("AEAD ciphertext of length {0} is too short to fit the tag")
    )]
    InvalidCipherLen(usize),
    #[cfg_attr(feature = "std", error("encrypted message cannot be empty"))]
    EmptyPlaintext,
    #[cfg_attr(
        feature = "std",
        error("AEAD key of invalid length {0}. Expected length {1}")
    )]
    InvalidKeyLen(usize, usize),
    #[cfg_attr(feature = "std", error("unsupported cipher suite"))]
    UnsupportedCipherSuite,
}

impl From<rc_aead::Error> for AeadError {
    fn from(value: rc_aead::Error) -> Self {
        AeadError::RcAeadError(value)
    }
}

impl IntoAnyError for AeadError {
    #[cfg(feature = "std")]
    fn into_dyn_error(self) -> Result<Box<dyn std::error::Error + Send + Sync>, Self> {
        Ok(self.into())
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Aead(AeadId);

impl Aead {
    pub fn new(cipher_suite: CipherSuite) -> Option<Self> {
        AeadId::new(cipher_suite).map(Self)
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

        (key.len() == self.key_size())
            .then_some(())
            .ok_or_else(|| AeadError::InvalidKeyLen(key.len(), self.key_size()))?;

        match self.0 {
            AeadId::Aes128Gcm => {
                let cipher = Aes128Gcm::new(GenericArray::from_slice(key));
                encrypt_aead_trait(cipher, data, aad, nonce)
            }
            AeadId::Aes256Gcm => {
                let cipher = Aes256Gcm::new(GenericArray::from_slice(key));
                encrypt_aead_trait(cipher, data, aad, nonce)
            }
            AeadId::Chacha20Poly1305 => {
                let cipher = ChaCha20Poly1305::new(GenericArray::from_slice(key));
                encrypt_aead_trait(cipher, data, aad, nonce)
            }
            _ => Err(AeadError::UnsupportedCipherSuite),
        }
    }

    fn open(
        &self,
        key: &[u8],
        ciphertext: &[u8],
        aad: Option<&[u8]>,
        nonce: &[u8],
    ) -> Result<Vec<u8>, AeadError> {
        (ciphertext.len() > AES_TAG_LEN)
            .then_some(())
            .ok_or(AeadError::InvalidCipherLen(ciphertext.len()))?;

        (key.len() == self.key_size())
            .then_some(())
            .ok_or_else(|| AeadError::InvalidKeyLen(key.len(), self.key_size()))?;

        match self.0 {
            AeadId::Aes128Gcm => {
                let cipher = Aes128Gcm::new(GenericArray::from_slice(key));
                decrypt_aead_trait(cipher, ciphertext, aad, nonce)
            }
            AeadId::Aes256Gcm => {
                let cipher = Aes256Gcm::new(GenericArray::from_slice(key));
                decrypt_aead_trait(cipher, ciphertext, aad, nonce)
            }
            AeadId::Chacha20Poly1305 => {
                let cipher = ChaCha20Poly1305::new(GenericArray::from_slice(key));
                decrypt_aead_trait(cipher, ciphertext, aad, nonce)
            }
            _ => Err(AeadError::UnsupportedCipherSuite),
        }
    }

    #[inline(always)]
    fn key_size(&self) -> usize {
        self.0.key_size()
    }

    fn nonce_size(&self) -> usize {
        self.0.nonce_size()
    }

    fn aead_id(&self) -> u16 {
        self.0 as u16
    }
}

fn encrypt_aead_trait(
    cipher: impl rc_aead::Aead,
    data: &[u8],
    aad: Option<&[u8]>,
    nonce: &[u8],
) -> Result<Vec<u8>, AeadError> {
    let payload = Payload {
        msg: data,
        aad: aad.unwrap_or_default(),
    };

    Ok(cipher.encrypt(GenericArray::from_slice(nonce), payload)?)
}

fn decrypt_aead_trait(
    cipher: impl rc_aead::Aead,
    ciphertext: &[u8],
    aad: Option<&[u8]>,
    nonce: &[u8],
) -> Result<Vec<u8>, AeadError> {
    let payload = Payload {
        msg: ciphertext,
        aad: aad.unwrap_or_default(),
    };

    Ok(cipher.decrypt(GenericArray::from_slice(nonce), payload)?)
}

#[cfg(test)]
mod test {
    use aws_mls_core::crypto::CipherSuite;
    use aws_mls_crypto_traits::{AeadType, AES_TAG_LEN};

    use super::{Aead, AeadError};

    use assert_matches::assert_matches;

    use alloc::vec;
    use alloc::vec::Vec;

    fn get_aeads() -> Vec<Aead> {
        [
            CipherSuite::CURVE25519_AES128,
            CipherSuite::CURVE25519_CHACHA,
            CipherSuite::CURVE448_AES256,
        ]
        .into_iter()
        .map(|cs| Aead::new(cs).unwrap())
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
                Err(AeadError::InvalidKeyLen(_, _))
            );

            let too_long = vec![42u8; aead.key_size() + 1];

            assert_matches!(
                aead.seal(&too_long, data, None, &nonce),
                Err(AeadError::InvalidKeyLen(_, _))
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
                Err(AeadError::RcAeadError(_))
            );

            assert_matches!(
                aead.open(&key, &ciphertext, None, &nonce),
                Err(AeadError::RcAeadError(_))
            );
        }
    }
}
