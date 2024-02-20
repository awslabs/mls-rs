// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// Copyright by contributors to this project.
// SPDX-License-Identifier: (Apache-2.0 OR MIT)

#![cfg(all(mls_build_async, target_arch = "wasm32"))]

mod aead;
mod ec;
mod hkdf;
mod key_type;

use mls_rs_core::{
    crypto::{
        CipherSuite, CipherSuiteProvider, CryptoProvider, HpkeCiphertext, HpkePublicKey,
        HpkeSecretKey, SignaturePublicKey, SignatureSecretKey,
    },
    error::{AnyError, IntoAnyError},
};

use mls_rs_crypto_hpke::{
    context::{ContextR, ContextS},
    dhkem::DhKem,
    hpke::Hpke,
};

use mls_rs_crypto_traits::{AeadType, KdfType, KemId};

use wasm_bindgen::JsValue;
use web_sys::SubtleCrypto;
use zeroize::Zeroizing;

use crate::{
    aead::Aead,
    ec::{EcSigner, Ecdh},
    hkdf::Hkdf,
};

#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    #[error("Unsupported ciphersuite")]
    UnsupportedCipherSuite,
    #[error("JS error {0}")]
    JsValue(String),
    #[error("Key has wrong length for cipher suite")]
    WrongKeyLength,
    #[error("Window not found")]
    WindowNotFound,
    #[error("Invalid signature")]
    InvalidSignature,
    #[error("Der encoding error {0}")]
    DerError(String),
    #[error("Could not compute EC public key from seed")]
    CouldNotComputePublicKey,
    #[error(transparent)]
    HpkeError(AnyError),
}

impl From<JsValue> for CryptoError {
    fn from(e: JsValue) -> Self {
        Self::JsValue(format!("{e:?}"))
    }
}

#[inline]
pub(crate) fn get_crypto() -> Result<SubtleCrypto, CryptoError> {
    Ok(web_sys::window()
        .ok_or(CryptoError::WindowNotFound)?
        .crypto()?
        .subtle())
}

#[derive(Clone, Default, Debug)]
pub struct WebCryptoProvider;

impl WebCryptoProvider {
    pub fn new() -> Self {
        Self
    }

    pub fn all_supported_cipher_suites() -> Vec<CipherSuite> {
        vec![
            CipherSuite::P256_AES128,
            CipherSuite::P384_AES256,
            CipherSuite::P521_AES256,
        ]
    }
}

#[derive(Clone)]
pub struct WebCryptoCipherSuite {
    aead: Aead,
    hkdf: Hkdf,
    ec_signer: EcSigner,
    hpke: Hpke<DhKem<Ecdh, Hkdf>, Hkdf, Aead>,
    cipher_suite: CipherSuite,
}

impl WebCryptoCipherSuite {
    pub fn new(cipher_suite: CipherSuite) -> Option<Self> {
        let kem_id = KemId::new(cipher_suite)?;
        let hkdf = Hkdf::new(cipher_suite)?;
        let dh = Ecdh::new(cipher_suite)?;

        let dhkem = DhKem::new(dh, hkdf.clone(), kem_id as u16, kem_id.n_secret());
        let aead = Aead::new(cipher_suite)?;

        Some(Self {
            aead: aead.clone(),
            hkdf: hkdf.clone(),
            ec_signer: EcSigner::new(cipher_suite)?,
            hpke: Hpke::new(dhkem, hkdf, Some(aead)),
            cipher_suite,
        })
    }
}

impl CryptoProvider for WebCryptoProvider {
    type CipherSuiteProvider = WebCryptoCipherSuite;

    fn supported_cipher_suites(&self) -> Vec<CipherSuite> {
        Self::all_supported_cipher_suites()
    }

    fn cipher_suite_provider(&self, cipher_suite: CipherSuite) -> Option<WebCryptoCipherSuite> {
        WebCryptoCipherSuite::new(cipher_suite)
    }
}

impl IntoAnyError for CryptoError {}

#[maybe_async::must_be_async(?Send)]
impl CipherSuiteProvider for WebCryptoCipherSuite {
    type Error = CryptoError;

    type HpkeContextS = ContextS<Hkdf, Aead>;
    type HpkeContextR = ContextR<Hkdf, Aead>;

    fn cipher_suite(&self) -> mls_rs_core::crypto::CipherSuite {
        self.cipher_suite
    }

    async fn hash(&self, data: &[u8]) -> Result<Vec<u8>, Self::Error> {
        self.hkdf.hash(data).await
    }

    async fn mac(&self, key: &[u8], data: &[u8]) -> Result<Vec<u8>, Self::Error> {
        self.hkdf.hmac(key, data).await
    }

    async fn aead_seal(
        &self,
        key: &[u8],
        data: &[u8],
        aad: Option<&[u8]>,
        nonce: &[u8],
    ) -> Result<Vec<u8>, Self::Error> {
        self.aead.seal(key, data, aad, nonce).await
    }

    async fn aead_open(
        &self,
        key: &[u8],
        ciphertext: &[u8],
        aad: Option<&[u8]>,
        nonce: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, Self::Error> {
        self.aead
            .open(key, ciphertext, aad, nonce)
            .await
            .map(Zeroizing::new)
    }

    fn aead_key_size(&self) -> usize {
        self.aead.key_size()
    }

    fn aead_nonce_size(&self) -> usize {
        self.aead.nonce_size()
    }

    async fn kdf_extract(
        &self,
        salt: &[u8],
        ikm: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, Self::Error> {
        self.hkdf.extract(salt, ikm).await.map(Zeroizing::new)
    }

    async fn kdf_expand(
        &self,
        prk: &[u8],
        info: &[u8],
        len: usize,
    ) -> Result<Zeroizing<Vec<u8>>, Self::Error> {
        self.hkdf.expand(prk, info, len).await.map(Zeroizing::new)
    }

    fn kdf_extract_size(&self) -> usize {
        self.hkdf.extract_size()
    }

    async fn hpke_seal(
        &self,
        remote_key: &HpkePublicKey,
        info: &[u8],
        aad: Option<&[u8]>,
        pt: &[u8],
    ) -> Result<HpkeCiphertext, Self::Error> {
        self.hpke
            .seal(remote_key, info, None, aad, pt)
            .await
            .map_err(|e| CryptoError::HpkeError(e.into_any_error()))
    }

    async fn hpke_open(
        &self,
        ciphertext: &HpkeCiphertext,
        local_secret: &HpkeSecretKey,
        local_public: &HpkePublicKey,
        info: &[u8],
        aad: Option<&[u8]>,
    ) -> Result<Vec<u8>, Self::Error> {
        self.hpke
            .open(ciphertext, local_secret, local_public, info, None, aad)
            .await
            .map_err(|e| CryptoError::HpkeError(e.into_any_error()))
    }

    async fn hpke_setup_s(
        &self,
        remote_key: &HpkePublicKey,
        info: &[u8],
    ) -> Result<(Vec<u8>, Self::HpkeContextS), Self::Error> {
        self.hpke
            .setup_sender(remote_key, info, None)
            .await
            .map_err(|e| CryptoError::HpkeError(e.into_any_error()))
    }

    async fn hpke_setup_r(
        &self,
        kem_output: &[u8],
        local_secret: &HpkeSecretKey,
        local_public: &HpkePublicKey,
        info: &[u8],
    ) -> Result<Self::HpkeContextR, Self::Error> {
        self.hpke
            .setup_receiver(kem_output, local_secret, local_public, info, None)
            .await
            .map_err(|e| CryptoError::HpkeError(e.into_any_error()))
    }

    async fn kem_derive(&self, ikm: &[u8]) -> Result<(HpkeSecretKey, HpkePublicKey), Self::Error> {
        self.hpke
            .derive(ikm)
            .await
            .map_err(|e| CryptoError::HpkeError(e.into_any_error()))
    }

    async fn kem_generate(&self) -> Result<(HpkeSecretKey, HpkePublicKey), Self::Error> {
        self.hpke
            .generate()
            .await
            .map_err(|e| CryptoError::HpkeError(e.into_any_error()))
    }

    fn kem_public_key_validate(&self, key: &HpkePublicKey) -> Result<(), Self::Error> {
        self.hpke
            .public_key_validate(key)
            .map_err(|e| CryptoError::HpkeError(e.into_any_error()))
    }

    fn random_bytes(&self, out: &mut [u8]) -> Result<(), Self::Error> {
        web_sys::window()
            .ok_or(CryptoError::WindowNotFound)?
            .crypto()?
            .get_random_values_with_u8_array(out)?;

        Ok(())
    }

    async fn signature_key_generate(
        &self,
    ) -> Result<(SignatureSecretKey, SignaturePublicKey), Self::Error> {
        self.ec_signer.generate().await
    }

    async fn signature_key_derive_public(
        &self,
        secret_key: &SignatureSecretKey,
    ) -> Result<SignaturePublicKey, Self::Error> {
        self.ec_signer.derive_public(secret_key)
    }

    async fn sign(
        &self,
        secret_key: &SignatureSecretKey,
        data: &[u8],
    ) -> Result<Vec<u8>, Self::Error> {
        self.ec_signer.sign(secret_key, data).await
    }

    async fn verify(
        &self,
        public_key: &SignaturePublicKey,
        signature: &[u8],
        data: &[u8],
    ) -> Result<(), Self::Error> {
        self.ec_signer.verify(public_key, data, signature).await
    }
}

#[cfg(test)]
mod tests {
    wasm_bindgen_test::wasm_bindgen_test_configure!(run_in_browser);

    #[wasm_bindgen_test::wasm_bindgen_test]
    async fn mls_rs_core_test() {
        mls_rs_core::crypto::test_suite::verify_tests(&crate::WebCryptoProvider, false).await
    }
}
