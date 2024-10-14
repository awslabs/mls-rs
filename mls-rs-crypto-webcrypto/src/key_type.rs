// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// Copyright by contributors to this project.
// SPDX-License-Identifier: (Apache-2.0 OR MIT)

use js_sys::{Array, Reflect, Uint8Array, Promise};
use wasm_bindgen::JsValue;
use wasm_bindgen_futures::JsFuture;
use web_sys::{CryptoKey, CryptoKeyPair, EcKeyImportParams, HmacImportParams, SubtleCrypto};

#[derive(Clone, Debug)]
pub(crate) enum KeyType {
    Hmac(&'static str),
    AesGcmEncrypt,
    AesGcmDecrypt,
    EcdhSecret(&'static str),
    EcdhPublic(&'static str),
    EcdsaSecret(&'static str),
    EcdsaPublic(&'static str),
}

impl KeyType {
    pub(crate) fn usage(&self) -> Option<&'static str> {
        match self {
            KeyType::Hmac(_) | KeyType::EcdsaSecret(_) => Some("sign"),
            KeyType::AesGcmEncrypt => Some("encrypt"),
            KeyType::AesGcmDecrypt => Some("decrypt"),
            KeyType::EcdhSecret(_) => Some("deriveBits"),
            KeyType::EcdsaPublic(_) => Some("verify"),
            KeyType::EcdhPublic(_) => None,
        }
    }

    pub(crate) fn algorithm(&self) -> &'static str {
        match self {
            KeyType::Hmac(_) => "HMAC",
            KeyType::AesGcmDecrypt | KeyType::AesGcmEncrypt => "AES-GCM",
            KeyType::EcdhPublic(_) | KeyType::EcdhSecret(_) => "ECDH",
            KeyType::EcdsaPublic(_) | KeyType::EcdsaSecret(_) => "ECDSA",
        }
    }

    pub(crate) fn format(&self) -> &'static str {
        match self {
            KeyType::EcdhSecret(_) | KeyType::EcdsaSecret(_) => "pkcs8",
            _ => "raw",
        }
    }

    pub(crate) fn export_label(&self) -> &'static str {
        match self {
            KeyType::EcdhSecret(_) | KeyType::EcdsaSecret(_) => "privateKey",
            KeyType::EcdhPublic(_) | KeyType::EcdsaPublic(_) => "publicKey",
            _ => "",
        }
    }

    #[cfg(not(feature = "node"))]
    async fn import_with_public_info(&self, crypto: &SubtleCrypto, key: &Uint8Array, params: &EcKeyImportParams, key_usages: &Array) -> Result<Promise, JsValue> {
        crypto.import_key_with_object(self.format(), &key, &params, true, &key_usages)
    }

    #[cfg(feature = "node")]
    async fn import_with_public_info(&self, crypto: &SubtleCrypto, bytes: &Uint8Array, params: &EcKeyImportParams, key_usages: &Array) -> Result<Promise, JsValue> {
        let crypto_key_promise = crypto.import_key_with_object(self.format(), bytes, params, true, key_usages)?;
        let crypto_key = JsFuture::from(crypto_key_promise).await?.into();
        // Export the key to jwk to force the generation of the public key.   
        let jwk_promise = crypto.export_key(&"jwk", &crypto_key)?;
        let jwk  = JsFuture::from(jwk_promise).await?;
        // Re-import into the original requested format with the same usages from jwk.
        crypto.import_key_with_object("jwk", &jwk.into(), params, true, &key_usages)
    }

    pub(crate) async fn import(
        &self,
        crypto: &SubtleCrypto,
        key: &[u8],
    ) -> Result<CryptoKey, JsValue> {
        let key = Uint8Array::from(key);

        let key_usages = match self.usage() {
            Some(usage) => {
                let usages = Array::new_with_length(1);
                usages.set(0, usage.into());
                usages
            }
            None => Array::new_with_length(0),
        };

        let key = match self {
            KeyType::Hmac(hash) => {
                let params = HmacImportParams::new(self.algorithm(), &(*hash).into());
                crypto.import_key_with_object(self.format(), &key, &params, false, &key_usages)?
            }
            KeyType::AesGcmDecrypt | KeyType::AesGcmEncrypt => crypto.import_key_with_str(
                self.format(),
                &key,
                self.algorithm(),
                false,
                &key_usages,
            )?,
            KeyType::EcdhPublic(curve)
            | KeyType::EcdhSecret(curve)
            | KeyType::EcdsaPublic(curve)
            | KeyType::EcdsaSecret(curve) => {
                let mut params = EcKeyImportParams::new(self.algorithm());
                params.set_named_curve(curve);
                self.import_with_public_info(&crypto, &key, &params, &key_usages).await?
            }
        };

        Ok(JsFuture::from(key).await?.into())
    }

    pub(crate) async fn export(
        &self,
        crypto: &SubtleCrypto,
        key_pair: &CryptoKeyPair,
    ) -> Result<Vec<u8>, JsValue> {
        let key: CryptoKey = Reflect::get(key_pair, &self.export_label().into())?.into();
        let key = crypto.export_key(self.format(), &key)?;
        let key = Uint8Array::new(&JsFuture::from(key).await?).to_vec();

        Ok(key)
    }
}
