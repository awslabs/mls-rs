// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// Copyright by contributors to this project.
// SPDX-License-Identifier: (Apache-2.0 OR MIT)

mod aead;
mod ec;
mod ecdsa;
mod kdf;

pub mod x509;

#[cfg(feature = "fips")]
use aws_lc_fips_sys as aws_lc_sys_impl;

#[cfg(not(feature = "fips"))]
use aws_lc_sys as aws_lc_sys_impl;

use std::{ffi::c_int, mem::MaybeUninit, num::TryFromIntError};

use aead::AwsLcAead;
use aws_lc_rs::{digest, error::Unspecified, hmac};

use crate::aws_lc_sys_impl::SHA256;
use mls_rs_core::{
    crypto::{
        CipherSuite, CipherSuiteProvider, CryptoProvider, HpkeCiphertext, HpkePublicKey,
        HpkeSecretKey, SignaturePublicKey, SignatureSecretKey,
    },
    error::IntoAnyError,
};

use ec::Ecdh;
use ecdsa::AwsLcEcdsa;
use kdf::AwsLcHkdf;
use mls_rs_crypto_hpke::{
    context::{ContextR, ContextS},
    dhkem::DhKem,
    hpke::{Hpke, HpkeError},
};
use mls_rs_crypto_traits::{AeadType, KdfType, KemId};
use thiserror::Error;
use zeroize::Zeroizing;

#[derive(Clone, Debug)]
pub struct AwsLcCryptoProvider {
    pub enabled_cipher_suites: Vec<CipherSuite>,
}

impl AwsLcCryptoProvider {
    pub fn new() -> Self {
        Self {
            enabled_cipher_suites: Self::all_supported_cipher_suites(),
        }
    }

    pub fn with_enabled_cipher_suites(enabled_cipher_suites: Vec<CipherSuite>) -> Self {
        Self {
            enabled_cipher_suites,
        }
    }

    pub fn all_supported_cipher_suites() -> Vec<CipherSuite> {
        vec![
            CipherSuite::CURVE25519_AES128,
            CipherSuite::CURVE25519_CHACHA,
            CipherSuite::P256_AES128,
            CipherSuite::P384_AES256,
            CipherSuite::P521_AES256,
        ]
    }
}

impl Default for AwsLcCryptoProvider {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone)]
pub struct AwsLcCipherSuite {
    cipher_suite: CipherSuite,
    signing: AwsLcEcdsa,
    aead: AwsLcAead,
    kdf: AwsLcHkdf,
    hpke: Hpke<DhKem<Ecdh, AwsLcHkdf>, AwsLcHkdf, AwsLcAead>,
    mac_algo: hmac::Algorithm,
}

impl AwsLcCipherSuite {
    pub fn new(cipher_suite: CipherSuite) -> Option<Self> {
        let kem_id = KemId::new(cipher_suite)?;
        let kdf = AwsLcHkdf::new(cipher_suite)?;
        let aead = AwsLcAead::new(cipher_suite)?;
        let dh = Ecdh::new(cipher_suite)?;
        let dh_kem = DhKem::new(dh, kdf.clone(), kem_id as u16, kem_id.n_secret());

        let mac_algo = match cipher_suite {
            CipherSuite::CURVE25519_AES128
            | CipherSuite::CURVE25519_CHACHA
            | CipherSuite::P256_AES128 => hmac::HMAC_SHA256,
            CipherSuite::P384_AES256 => hmac::HMAC_SHA384,
            CipherSuite::P521_AES256 => hmac::HMAC_SHA512,
            _ => return None,
        };

        Some(Self {
            cipher_suite,
            hpke: Hpke::new(dh_kem, kdf.clone(), Some(aead.clone())),
            aead,
            kdf,
            signing: AwsLcEcdsa::new(cipher_suite)?,
            mac_algo,
        })
    }

    pub fn import_ec_der_private_key(
        &self,
        bytes: &[u8],
    ) -> Result<SignatureSecretKey, AwsLcCryptoError> {
        self.signing.import_ec_der_private_key(bytes)
    }

    pub fn import_ec_der_public_key(
        &self,
        bytes: &[u8],
    ) -> Result<SignaturePublicKey, AwsLcCryptoError> {
        self.signing.import_ec_der_public_key(bytes)
    }
}

impl CryptoProvider for AwsLcCryptoProvider {
    type CipherSuiteProvider = AwsLcCipherSuite;

    fn supported_cipher_suites(&self) -> Vec<mls_rs_core::crypto::CipherSuite> {
        vec![
            CipherSuite::P521_AES256,
            CipherSuite::P256_AES128,
            CipherSuite::P384_AES256,
            CipherSuite::CURVE25519_AES128,
            CipherSuite::CURVE25519_CHACHA,
        ]
    }

    fn cipher_suite_provider(
        &self,
        cipher_suite: mls_rs_core::crypto::CipherSuite,
    ) -> Option<Self::CipherSuiteProvider> {
        self.enabled_cipher_suites
            .contains(&cipher_suite)
            .then(|| AwsLcCipherSuite::new(cipher_suite))
            .flatten()
    }
}

#[derive(Debug, Error)]
pub enum AwsLcCryptoError {
    #[error("Invalid key data")]
    InvalidKeyData,
    #[error("Underlying crypto error")]
    CryptoError,
    #[error("Invalid signature")]
    InvalidSignature,
    #[error(transparent)]
    HpkeError(#[from] HpkeError),
    #[error("Unsupported ciphersuite")]
    UnsupportedCipherSuite,
    #[error("Cert validation error: {0}")]
    CertValidationFailure(String),
    #[error(transparent)]
    TryFromIntError(#[from] TryFromIntError),
}

impl From<Unspecified> for AwsLcCryptoError {
    fn from(_value: Unspecified) -> Self {
        AwsLcCryptoError::CryptoError
    }
}

impl IntoAnyError for AwsLcCryptoError {}

#[cfg_attr(not(mls_build_async), maybe_async::must_be_sync)]
#[cfg_attr(all(target_arch = "wasm32", mls_build_async), maybe_async::must_be_async(?Send))]
#[cfg_attr(
    all(not(target_arch = "wasm32"), mls_build_async),
    maybe_async::must_be_async
)]
impl CipherSuiteProvider for AwsLcCipherSuite {
    type Error = AwsLcCryptoError;

    type HpkeContextS = ContextS<AwsLcHkdf, AwsLcAead>;
    type HpkeContextR = ContextR<AwsLcHkdf, AwsLcAead>;

    fn cipher_suite(&self) -> mls_rs_core::crypto::CipherSuite {
        self.cipher_suite
    }

    async fn hash(&self, data: &[u8]) -> Result<Vec<u8>, Self::Error> {
        Ok(digest::digest(self.mac_algo.digest_algorithm(), data)
            .as_ref()
            .to_vec())
    }

    async fn mac(&self, key: &[u8], data: &[u8]) -> Result<Vec<u8>, Self::Error> {
        let key = hmac::Key::new(self.mac_algo, key);
        Ok(hmac::sign(&key, data).as_ref().to_vec())
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
            .map(Into::into)
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
        self.kdf.extract(salt, ikm).await.map(Into::into)
    }

    async fn kdf_expand(
        &self,
        prk: &[u8],
        info: &[u8],
        len: usize,
    ) -> Result<Zeroizing<Vec<u8>>, Self::Error> {
        self.kdf.expand(prk, info, len).await.map(Into::into)
    }

    fn kdf_extract_size(&self) -> usize {
        self.kdf.extract_size()
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
            .map_err(Into::into)
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
            .map_err(Into::into)
    }

    async fn hpke_setup_s(
        &self,
        remote_key: &HpkePublicKey,
        info: &[u8],
    ) -> Result<(Vec<u8>, Self::HpkeContextS), Self::Error> {
        self.hpke
            .setup_sender(remote_key, info, None)
            .await
            .map_err(Into::into)
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
            .map_err(Into::into)
    }

    async fn kem_derive(&self, ikm: &[u8]) -> Result<(HpkeSecretKey, HpkePublicKey), Self::Error> {
        self.hpke.derive(ikm).await.map_err(Into::into)
    }

    async fn kem_generate(&self) -> Result<(HpkeSecretKey, HpkePublicKey), Self::Error> {
        self.hpke.generate().await.map_err(Into::into)
    }

    fn kem_public_key_validate(&self, key: &HpkePublicKey) -> Result<(), Self::Error> {
        self.hpke.public_key_validate(key).map_err(Into::into)
    }

    fn random_bytes(&self, out: &mut [u8]) -> Result<(), Self::Error> {
        unsafe {
            if 1 != crate::aws_lc_sys_impl::RAND_bytes(out.as_mut_ptr(), out.len()) {
                return Err(Unspecified.into());
            }
        }

        Ok(())
    }

    async fn signature_key_generate(
        &self,
    ) -> Result<(SignatureSecretKey, SignaturePublicKey), Self::Error> {
        self.signing.signature_key_generate()
    }

    async fn signature_key_derive_public(
        &self,
        secret_key: &SignatureSecretKey,
    ) -> Result<SignaturePublicKey, Self::Error> {
        self.signing.signature_key_derive_public(secret_key)
    }

    async fn sign(
        &self,
        secret_key: &SignatureSecretKey,
        data: &[u8],
    ) -> Result<Vec<u8>, Self::Error> {
        self.signing.sign(secret_key, data)
    }

    async fn verify(
        &self,
        public_key: &SignaturePublicKey,
        signature: &[u8],
        data: &[u8],
    ) -> Result<(), Self::Error> {
        self.signing.verify(public_key, signature, data)
    }
}

pub fn sha256(data: &[u8]) -> [u8; 32] {
    unsafe {
        let mut out = MaybeUninit::<[u8; 32]>::uninit();
        SHA256(data.as_ptr(), data.len(), out.as_mut_ptr() as *mut u8);
        out.assume_init()
    }
}

fn check_res(r: c_int) -> Result<(), AwsLcCryptoError> {
    check_int_return(r).map(|_| ())
}

fn check_int_return(r: c_int) -> Result<c_int, AwsLcCryptoError> {
    if r <= 0 {
        Err(AwsLcCryptoError::CryptoError)
    } else {
        Ok(r)
    }
}

fn check_non_null<T>(r: *mut T) -> Result<*mut T, AwsLcCryptoError> {
    if r.is_null() {
        return Err(AwsLcCryptoError::CryptoError);
    }

    Ok(r)
}

fn check_non_null_const<T>(r: *const T) -> Result<*const T, AwsLcCryptoError> {
    if r.is_null() {
        return Err(AwsLcCryptoError::CryptoError);
    }

    Ok(r)
}

#[cfg(not(mls_build_async))]
#[test]
fn mls_core_tests() {
    mls_rs_core::crypto::test_suite::verify_tests(&AwsLcCryptoProvider::new(), true);

    for cs in AwsLcCryptoProvider::new().supported_cipher_suites() {
        let mut hpke = AwsLcCryptoProvider::new()
            .cipher_suite_provider(cs)
            .unwrap()
            .hpke;

        mls_rs_core::crypto::test_suite::verify_hpke_context_tests(&hpke, cs);
        mls_rs_core::crypto::test_suite::verify_hpke_encap_tests(&mut hpke, cs);
    }
}
