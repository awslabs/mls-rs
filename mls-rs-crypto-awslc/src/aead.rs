// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// Copyright by contributors to this project.
// SPDX-License-Identifier: (Apache-2.0 OR MIT)

use aws_lc_rs::aead::{self, UnboundKey, AES_128_GCM, AES_256_GCM, CHACHA20_POLY1305};
use mls_rs_core::crypto::CipherSuite;
use mls_rs_crypto_traits::AeadId;

use crate::AwsLcCryptoError;

#[derive(Clone, Copy)]
pub struct AwsLcAead(AeadId);

impl AwsLcAead {
    pub fn new(cipher_suite: CipherSuite) -> Option<Self> {
        AeadId::new(cipher_suite).map(Self)
    }

    fn unbound_key(&self, key: &[u8]) -> Result<UnboundKey, AwsLcCryptoError> {
        match self.0 {
            AeadId::Aes128Gcm => Ok(UnboundKey::new(&AES_128_GCM, key)?),
            AeadId::Aes256Gcm => Ok(UnboundKey::new(&AES_256_GCM, key)?),
            AeadId::Chacha20Poly1305 => Ok(UnboundKey::new(&CHACHA20_POLY1305, key)?),
            _ => Err(AwsLcCryptoError::UnsupportedCipherSuite),
        }
    }
}

#[cfg_attr(not(mls_build_async), maybe_async::must_be_sync)]
#[cfg_attr(all(target_arch = "wasm32", mls_build_async), maybe_async::must_be_async(?Send))]
#[cfg_attr(
    all(not(target_arch = "wasm32"), mls_build_async),
    maybe_async::must_be_async
)]
impl mls_rs_crypto_traits::AeadType for AwsLcAead {
    type Error = AwsLcCryptoError;

    fn aead_id(&self) -> u16 {
        self.0 as u16
    }

    #[allow(clippy::needless_lifetimes)]
    async fn seal<'a>(
        &self,
        key: &[u8],
        data: &[u8],
        aad: Option<&'a [u8]>,
        nonce: &[u8],
    ) -> Result<Vec<u8>, Self::Error> {
        let mut in_out_buffer = data.to_vec();

        let key = self.unbound_key(key)?;
        let nonce = aead::Nonce::try_assume_unique_for_key(nonce)?;

        let sealing_key = aead::LessSafeKey::new(key);

        let aad = aead::Aad::from(aad.unwrap_or_default());

        sealing_key.seal_in_place_append_tag(nonce, aad, &mut in_out_buffer)?;

        Ok(in_out_buffer)
    }

    #[allow(clippy::needless_lifetimes)]
    async fn open<'a>(
        &self,
        key: &[u8],
        ciphertext: &[u8],
        aad: Option<&'a [u8]>,
        nonce: &[u8],
    ) -> Result<Vec<u8>, Self::Error> {
        let mut in_out_buffer = ciphertext.to_vec();

        let key = self.unbound_key(key)?;
        let nonce = aead::Nonce::try_assume_unique_for_key(nonce)?;

        let opening_key = aead::LessSafeKey::new(key);

        let aad = aead::Aad::from(aad.unwrap_or_default());

        let len = opening_key
            .open_in_place(nonce, aad, &mut in_out_buffer)?
            .len();

        in_out_buffer.truncate(len);

        Ok(in_out_buffer)
    }

    fn key_size(&self) -> usize {
        self.0.key_size()
    }

    fn nonce_size(&self) -> usize {
        self.0.nonce_size()
    }
}
