// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// Copyright by contributors to this project.
// SPDX-License-Identifier: (Apache-2.0 OR MIT)

use js_sys::Uint8Array;
use mls_rs_core::crypto::CipherSuite;
use mls_rs_crypto_traits::{AeadId, AeadType};
use wasm_bindgen_futures::JsFuture;
use web_sys::AesGcmParams;

use crate::{get_crypto, key_type::KeyType, CryptoError};

#[derive(Clone)]
pub struct Aead {
    aead_id: AeadId,
}

impl Aead {
    pub fn new(cipher_suite: CipherSuite) -> Option<Self> {
        let aead_id = AeadId::new(cipher_suite)?;

        match aead_id {
            AeadId::Aes128Gcm | AeadId::Aes256Gcm => Some(Self { aead_id }),
            _ => None,
        }
    }
}

#[maybe_async::must_be_async(?Send)]
impl mls_rs_crypto_traits::AeadType for Aead {
    type Error = CryptoError;

    fn aead_id(&self) -> u16 {
        self.aead_id as u16
    }

    #[allow(clippy::needless_lifetimes)]
    async fn seal<'a>(
        &self,
        key: &[u8],
        data: &[u8],
        aad: Option<&'a [u8]>,
        nonce: &[u8],
    ) -> Result<Vec<u8>, Self::Error> {
        self.cipher(key, data, aad, nonce, KeyType::AesGcmEncrypt)
            .await
    }

    #[allow(clippy::needless_lifetimes)]
    async fn open<'a>(
        &self,
        key: &[u8],
        ciphertext: &[u8],
        aad: Option<&'a [u8]>,
        nonce: &[u8],
    ) -> Result<Vec<u8>, Self::Error> {
        self.cipher(key, ciphertext, aad, nonce, KeyType::AesGcmDecrypt)
            .await
    }

    fn key_size(&self) -> usize {
        self.aead_id.key_size()
    }

    fn nonce_size(&self) -> usize {
        self.aead_id.nonce_size()
    }
}

impl Aead {
    async fn cipher(
        &self,
        key: &[u8],
        data: &[u8],
        aad: Option<&[u8]>,
        nonce: &[u8],
        key_type: KeyType,
    ) -> Result<Vec<u8>, CryptoError> {
        let crypto = get_crypto()?;

        // Key length determines if AES128 or AES256 is used
        (key.len() == self.key_size())
            .then_some(())
            .ok_or(CryptoError::WrongKeyLength)?;

        let params = AesGcmParams::new(key_type.algorithm(), &Uint8Array::from(nonce));
        let aad = Uint8Array::from(aad.unwrap_or_default());
        params.set_additional_data(&aad);
        let key = key_type.import(&crypto, key).await?;

        let out = match key_type {
            KeyType::AesGcmDecrypt => {
                crypto.decrypt_with_object_and_u8_array(&params, &key, &mut data.to_vec())?
            }
            _ => crypto.encrypt_with_object_and_u8_array(&params, &key, &mut data.to_vec())?,
        };

        let out = JsFuture::from(out).await?;

        Ok(Uint8Array::new(&out).to_vec())
    }
}
