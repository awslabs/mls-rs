// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// Copyright by contributors to this project.
// SPDX-License-Identifier: (Apache-2.0 OR MIT)

extern crate alloc;

use alloc::vec::Vec;
use core::fmt::Debug;

use mls_rs_core::{crypto::CipherSuite, error::IntoAnyError};
use mls_rs_crypto_traits::{AeadId, AeadType, AES_TAG_LEN};

#[derive(Debug)]
#[cfg_attr(feature = "std", derive(thiserror::Error))]
pub enum AeadError {
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
    #[cfg_attr(
        feature = "std",
        error("AEAD nonce of invalid length {0}. Expected length {1}")
    )]
    InvalidNonceLen(usize, usize),
    #[cfg_attr(feature = "std", error("unsupported cipher suite"))]
    UnsupportedCipherSuite,
    #[cfg_attr(feature = "std", error("CryptoKit error"))]
    CryptoKitError,
}

impl IntoAnyError for AeadError {
    #[cfg(feature = "std")]
    fn into_dyn_error(self) -> Result<Box<dyn std::error::Error + Send + Sync>, Self> {
        Ok(self.into())
    }
}

extern "C" {
    fn aead_seal(
        aead_id: u16,
        key_ptr: *const u8,
        key_len: u64,
        pt_ptr: *const u8,
        pt_len: u64,
        aad_ptr: *const u8,
        aad_len: u64,
        nonce_ptr: *const u8,
        nonce_len: u64,
        ct_ptr: *mut u8,
        ct_len: u64,
        tag_ptr: *mut u8,
        tag_len: u64,
    ) -> u64;

    fn aead_open(
        aead_id: u16,
        key_ptr: *const u8,
        key_len: u64,
        ct_ptr: *const u8,
        ct_len: u64,
        tag_ptr: *const u8,
        tag_len: u64,
        aad_ptr: *const u8,
        aad_len: u64,
        nonce_ptr: *const u8,
        nonce_len: u64,
        pt_ptr: *mut u8,
        pt_len: u64,
    ) -> u64;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Aead(AeadId);

impl Aead {
    pub fn new(cipher_suite: CipherSuite) -> Option<Self> {
        AeadId::new(cipher_suite).map(Self)
    }

    fn ensure_valid_ciphersuite(&self) -> Result<(), AeadError> {
        match self.0 {
            AeadId::Aes128Gcm => Ok(()),
            AeadId::Aes256Gcm => Ok(()),
            AeadId::Chacha20Poly1305 => Ok(()),
            _ => Err(AeadError::UnsupportedCipherSuite),
        }
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

        (key.len() == self.key_size())
            .then_some(())
            .ok_or_else(|| AeadError::InvalidKeyLen(key.len(), self.key_size()))?;

        (nonce.len() == self.nonce_size())
            .then_some(())
            .ok_or_else(|| AeadError::InvalidNonceLen(nonce.len(), self.nonce_size()))?;

        self.ensure_valid_ciphersuite()?;

        let aad = aad.unwrap_or(&[]);

        let ct_len = data.len();
        let out_len = data.len() + AES_TAG_LEN;
        let mut output = vec![0u8; out_len];
        let (ct, tag) = output.split_at_mut(ct_len);

        let rv = unsafe {
            aead_seal(
                self.0 as u16,
                key.as_ptr(),
                key.len() as u64,
                data.as_ptr(),
                data.len() as u64,
                aad.as_ptr(),
                aad.len() as u64,
                nonce.as_ptr(),
                nonce.len() as u64,
                ct.as_mut_ptr(),
                ct.len() as u64,
                tag.as_mut_ptr(),
                tag.len() as u64,
            )
        };

        if rv != 1 {
            return Err(AeadError::CryptoKitError);
        }

        Ok(output)
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

        (key.len() == self.key_size())
            .then_some(())
            .ok_or_else(|| AeadError::InvalidKeyLen(key.len(), self.key_size()))?;

        self.ensure_valid_ciphersuite()?;

        let aad = aad.unwrap_or(&[]);

        let pt_len = ciphertext.len() - AES_TAG_LEN;
        let (ct, tag) = ciphertext.split_at(pt_len);

        let mut pt = vec![0u8; pt_len];

        let rv = unsafe {
            aead_open(
                self.0 as u16,
                key.as_ptr(),
                key.len() as u64,
                ct.as_ptr(),
                ct.len() as u64,
                tag.as_ptr(),
                tag.len() as u64,
                aad.as_ptr(),
                aad.len() as u64,
                nonce.as_ptr(),
                nonce.len() as u64,
                pt.as_mut_ptr(),
                pt.len() as u64,
            )
        };

        if rv != 1 {
            return Err(AeadError::CryptoKitError);
        }

        Ok(pt)
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

#[cfg(all(not(mls_build_async), test))]
mod test {
    extern crate alloc;

    use mls_rs_core::crypto::CipherSuite;
    use mls_rs_crypto_traits::{AeadType, AES_TAG_LEN};

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
                Err(AeadError::CryptoKitError)
            );

            assert_matches!(
                aead.open(&key, &ciphertext, None, &nonce),
                Err(AeadError::CryptoKitError)
            );
        }
    }

    #[test]
    fn round_trip() {
        for aead in get_aeads() {
            let key = vec![42u8; aead.key_size()];
            let nonce = vec![42u8; aead.nonce_size()];

            let aad = Some(&b"foo"[..]);
            let original = b"message";
            let encrypted = aead.seal(&key, &original[..], aad, &nonce).unwrap();
            assert_ne!(original, encrypted.as_slice());
            assert_eq!(encrypted.len(), original.len() + AES_TAG_LEN);

            let decrypted = aead.open(&key, &encrypted, aad, &nonce).unwrap();
            assert_eq!(original, decrypted.as_slice());
        }
    }
}
