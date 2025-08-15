// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// Copyright by contributors to this project.
// SPDX-License-Identifier: (Apache-2.0 OR MIT)

mod aead;
mod ec;
mod ecdsa;
mod hmac;
mod kdf;
mod kem;

pub mod x509;

#[cfg(feature = "fips")]
use aws_lc_fips_sys as aws_lc_sys_impl;

#[cfg(not(feature = "fips"))]
use aws_lc_sys as aws_lc_sys_impl;
pub use hmac::AwsLcHmac;

use std::{ffi::c_int, mem::MaybeUninit, num::TryFromIntError};

pub use aead::AwsLcAead;
use aws_lc_rs::error::{KeyRejected, Unspecified};

use crate::aws_lc_sys_impl::SHA256;
use mls_rs_core::{
    crypto::{
        CipherSuite, CipherSuiteProvider, CryptoProvider, HpkeCiphertext, HpkePublicKey,
        HpkeSecretKey, SignaturePublicKey, SignatureSecretKey,
    },
    error::{AnyError, IntoAnyError},
};

pub use ecdsa::AwsLcEcdsa;
pub use kdf::AwsLcHkdf;
use kem::ecdh::Ecdh;
use mls_rs_crypto_hpke::{
    context::{ContextR, ContextS},
    dhkem::DhKem,
    hpke::{Hpke, HpkeError},
};
use mls_rs_crypto_traits::{AeadId, AeadType, Curve, Hash, KdfId, KdfType, KemId};
use thiserror::Error;
use zeroize::Zeroizing;

#[cfg(feature = "post-quantum")]
use self::kdf::shake::AwsLcShake128;

#[cfg(feature = "post-quantum")]
use mls_rs_crypto_hpke::kem_combiner::{CombinedKem, XWingSharedSecretHashInput};

#[cfg(feature = "post-quantum")]
pub use self::kem::ml_kem::{MlKem, MlKemKem};

#[cfg(feature = "post-quantum")]
pub use self::kdf::Sha3;

pub use self::kdf::AwsLcHash;

#[derive(Clone)]
pub struct AwsLcCipherSuite {
    cipher_suite: CipherSuite,
    signing: AwsLcEcdsa,
    aead: AwsLcAead,
    kdf: AwsLcHkdf,
    hpke: AwsLcHpke,
    hmac: AwsLcHmac,
    hash: AwsLcHash,
}

pub type EcdhKem = DhKem<Ecdh, AwsLcHkdf>;

#[cfg(feature = "post-quantum")]
pub type CombinedEcdhMlKemKem =
    CombinedKem<MlKemKem, EcdhKem, AwsLcHash, AwsLcShake128, XWingSharedSecretHashInput>;

#[derive(Clone)]
#[non_exhaustive]
enum AwsLcHpke {
    Classical(Hpke<EcdhKem, AwsLcHkdf, AwsLcAead>),
    #[cfg(feature = "post-quantum")]
    PostQuantum(Hpke<MlKemKem, AwsLcHkdf, AwsLcAead>),
    #[cfg(feature = "post-quantum")]
    Combined(Hpke<CombinedEcdhMlKemKem, AwsLcHkdf, AwsLcAead>),
}

impl AwsLcCipherSuite {
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

#[derive(Clone, Debug)]
pub struct AwsLcCryptoProvider {
    pub enabled_cipher_suites: Vec<CipherSuite>,
}

impl Default for AwsLcCryptoProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl AwsLcCryptoProvider {
    pub fn new() -> Self {
        Self {
            enabled_cipher_suites: Self::all_supported_cipher_suites(),
        }
    }

    pub fn all_supported_cipher_suites() -> Vec<CipherSuite> {
        [
            Self::supported_classical_cipher_suites(),
            #[cfg(feature = "post-quantum")]
            Self::supported_pq_cipher_suites(),
        ]
        .concat()
    }

    pub fn supported_classical_cipher_suites() -> Vec<CipherSuite> {
        vec![
            CipherSuite::CURVE25519_AES128,
            CipherSuite::CURVE25519_CHACHA,
            CipherSuite::P256_AES128,
            CipherSuite::P384_AES256,
            CipherSuite::P521_AES256,
        ]
    }

    #[cfg(feature = "post-quantum")]
    pub fn supported_pq_cipher_suites() -> Vec<CipherSuite> {
        vec![
            CipherSuite::ML_KEM_512,
            CipherSuite::ML_KEM_768,
            CipherSuite::ML_KEM_1024,
            CipherSuite::ML_KEM_768_X25519,
        ]
    }
}

impl AwsLcCryptoProvider {
    pub fn with_enabled_cipher_suites(enabled_cipher_suites: Vec<CipherSuite>) -> Self {
        Self {
            enabled_cipher_suites,
        }
    }
}

#[derive(Clone, Default)]
pub struct AwsLcCipherSuiteBuilder {
    signing: Option<AwsLcEcdsa>,
    aead: Option<AwsLcAead>,
    kdf: Option<AwsLcHkdf>,
    hpke: Option<AwsLcHpke>,
    hmac: Option<AwsLcHmac>,
    hash: Option<AwsLcHash>,
    fallback_cipher_suite: Option<CipherSuite>,
}

impl AwsLcCipherSuiteBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn signing(self, signing: Curve) -> Self {
        Self {
            signing: Some(AwsLcEcdsa(signing)),
            ..self
        }
    }

    pub fn aead(self, aead: AeadId) -> Self {
        Self {
            aead: Some(AwsLcAead(aead)),
            ..self
        }
    }

    pub fn kdf(self, kdf: KdfId) -> Self {
        Self {
            kdf: Some(AwsLcHkdf(kdf)),
            ..self
        }
    }

    pub fn hmac(self, hmac: AwsLcHmac) -> Self {
        Self {
            hmac: Some(hmac),
            ..self
        }
    }

    pub fn hash(self, hash: AwsLcHash) -> Self {
        Self {
            hash: Some(hash),
            ..self
        }
    }

    pub fn hpke(self, cipher_suite: CipherSuite) -> Self {
        Self {
            hpke: classical_hpke(cipher_suite),
            ..self
        }
    }

    pub fn fallback_cipher_suite(self, cipher_suite: CipherSuite) -> Self {
        Self {
            fallback_cipher_suite: Some(cipher_suite),
            ..self
        }
    }

    #[cfg(feature = "post-quantum")]
    pub fn pq_hpke(self, ml_kem: MlKem, kdf: KdfId, aead: AeadId) -> Self {
        let ml_kem = MlKemKem {
            ml_kem,
            kdf: AwsLcHkdf(kdf),
        };

        Self {
            hpke: Some(AwsLcHpke::PostQuantum(Hpke::new(
                ml_kem,
                AwsLcHkdf(kdf),
                Some(AwsLcAead(aead)),
            ))),
            ..self
        }
    }

    #[cfg(feature = "post-quantum")]
    pub fn combined_hpke(
        self,
        classical_cipher_suite: CipherSuite,
        ml_kem: MlKem,
        kdf: KdfId,
        aead: AeadId,
        hash: AwsLcHash,
    ) -> Self {
        let ml_kem = MlKemKem {
            ml_kem,
            kdf: AwsLcHkdf(kdf),
        };

        let ecdh = dhkem(classical_cipher_suite);

        let hpke = ecdh.map(|ecdh| {
            let kem = CombinedKem::new_xwing(ml_kem, ecdh, hash, AwsLcShake128);

            AwsLcHpke::Combined(Hpke::new(kem, AwsLcHkdf(kdf), Some(AwsLcAead(aead))))
        });

        Self { hpke, ..self }
    }

    #[cfg(feature = "post-quantum")]
    pub fn ghp_combined_hpke(
        self,
        classical_cipher_suite: CipherSuite,
        ml_kem: MlKem,
        kdf: KdfId,
        aead: AeadId,
        hash: AwsLcHash,
    ) -> Self {
        let ml_kem = MlKemKem {
            ml_kem,
            kdf: AwsLcHkdf(kdf),
        };

        let ecdh = dhkem(classical_cipher_suite);

        let hpke = ecdh.map(|ecdh| {
            let kem = CombinedKem::new_xwing(ml_kem, ecdh, hash, AwsLcShake128);

            AwsLcHpke::Combined(Hpke::new(kem, AwsLcHkdf(kdf), Some(AwsLcAead(aead))))
        });

        Self { hpke, ..self }
    }

    pub fn build(self, cipher_suite: CipherSuite) -> Option<AwsLcCipherSuite> {
        let fallback_cs = self.fallback_cipher_suite.unwrap_or(cipher_suite);
        let hpke = self.hpke.or_else(|| classical_hpke(fallback_cs))?;
        let kdf = self.kdf.or_else(|| AwsLcHkdf::new(fallback_cs))?;
        let aead = self.aead.or_else(|| AwsLcAead::new(fallback_cs))?;
        let signing = self.signing.or_else(|| AwsLcEcdsa::new(fallback_cs))?;
        let hmac = self.hmac.or_else(|| AwsLcHmac::new(fallback_cs))?;
        let hash = self.hash.or_else(|| AwsLcHash::new(fallback_cs))?;

        Some(AwsLcCipherSuite {
            cipher_suite,
            hpke,
            aead,
            kdf,
            signing,
            hmac,
            hash,
        })
    }
}

fn classical_hpke(cipher_suite: CipherSuite) -> Option<AwsLcHpke> {
    Some(AwsLcHpke::Classical(Hpke::new(
        dhkem(cipher_suite)?,
        AwsLcHkdf::new(cipher_suite)?,
        Some(AwsLcAead::new(cipher_suite)?),
    )))
}

impl CryptoProvider for AwsLcCryptoProvider {
    type CipherSuiteProvider = AwsLcCipherSuite;

    fn supported_cipher_suites(&self) -> Vec<CipherSuite> {
        self.enabled_cipher_suites.clone()
    }

    fn cipher_suite_provider(
        &self,
        cipher_suite: CipherSuite,
    ) -> Option<Self::CipherSuiteProvider> {
        let classical_cs = match cipher_suite {
            #[cfg(feature = "post-quantum")]
            CipherSuite::ML_KEM_1024 => CipherSuite::P384_AES256,
            #[cfg(feature = "post-quantum")]
            CipherSuite::ML_KEM_512 | CipherSuite::ML_KEM_768 | CipherSuite::ML_KEM_768_X25519 => {
                CipherSuite::CURVE25519_AES128
            }
            _ => cipher_suite,
        };

        let kdf = AwsLcHkdf::new(classical_cs)?;
        let aead = AwsLcAead::new(classical_cs)?;
        let hmac = AwsLcHmac::new(classical_cs)?;

        let hpke = match cipher_suite {
            #[cfg(feature = "post-quantum")]
            CipherSuite::ML_KEM_512 | CipherSuite::ML_KEM_768 | CipherSuite::ML_KEM_1024 => {
                AwsLcHpke::PostQuantum(Hpke::new(MlKemKem::new(cipher_suite)?, kdf, Some(aead)))
            }
            #[cfg(feature = "post-quantum")]
            CipherSuite::ML_KEM_768_X25519 => {
                let kem = CombinedKem::new_xwing(
                    MlKemKem::new(CipherSuite::ML_KEM_768)?,
                    dhkem(classical_cs)?,
                    AwsLcHash::new_sha3(Sha3::SHA3_256)?,
                    AwsLcShake128,
                );

                AwsLcHpke::Combined(Hpke::new(kem, kdf, Some(aead)))
            }
            _ => AwsLcHpke::Classical(Hpke::new(dhkem(cipher_suite)?, kdf, Some(aead))),
        };

        Some(AwsLcCipherSuite {
            cipher_suite,
            hpke,
            aead,
            kdf,
            signing: AwsLcEcdsa::new(classical_cs)?,
            hmac,
            hash: AwsLcHash::new(classical_cs)?,
        })
    }
}

pub fn dhkem(cipher_suite: CipherSuite) -> Option<DhKem<Ecdh, AwsLcHkdf>> {
    let kem_id = KemId::new(cipher_suite)?;
    let dh = Ecdh::new(cipher_suite)?;
    let kdf = AwsLcHkdf::new(cipher_suite)?;

    Some(DhKem::new(dh, kdf, kem_id as u16, kem_id.n_secret()))
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
    #[error(transparent)]
    KeyRejected(#[from] KeyRejected),
    #[error(transparent)]
    CombinedKemError(AnyError),
    #[error(transparent)]
    MlsCodecError(#[from] mls_rs_core::mls_rs_codec::Error),
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
        self.hash.hash(data)
    }

    async fn mac(&self, key: &[u8], data: &[u8]) -> Result<Vec<u8>, Self::Error> {
        self.hmac.hmac(key, data)
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
        match &self.hpke {
            AwsLcHpke::Classical(hpke) => hpke.seal(remote_key, info, None, aad, pt),
            #[cfg(feature = "post-quantum")]
            AwsLcHpke::PostQuantum(hpke) => hpke.seal(remote_key, info, None, aad, pt),
            #[cfg(feature = "post-quantum")]
            AwsLcHpke::Combined(hpke) => hpke.seal(remote_key, info, None, aad, pt),
        }
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
        match &self.hpke {
            AwsLcHpke::Classical(hpke) => {
                hpke.open(ciphertext, local_secret, local_public, info, None, aad)
            }
            #[cfg(feature = "post-quantum")]
            AwsLcHpke::PostQuantum(hpke) => {
                hpke.open(ciphertext, local_secret, local_public, info, None, aad)
            }
            #[cfg(feature = "post-quantum")]
            AwsLcHpke::Combined(hpke) => {
                hpke.open(ciphertext, local_secret, local_public, info, None, aad)
            }
        }
        .await
        .map_err(Into::into)
    }

    async fn hpke_setup_s(
        &self,
        remote_key: &HpkePublicKey,
        info: &[u8],
    ) -> Result<(Vec<u8>, Self::HpkeContextS), Self::Error> {
        match &self.hpke {
            AwsLcHpke::Classical(hpke) => hpke.setup_sender(remote_key, info, None),
            #[cfg(feature = "post-quantum")]
            AwsLcHpke::PostQuantum(hpke) => hpke.setup_sender(remote_key, info, None),
            #[cfg(feature = "post-quantum")]
            AwsLcHpke::Combined(hpke) => hpke.setup_sender(remote_key, info, None),
        }
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
        match &self.hpke {
            AwsLcHpke::Classical(hpke) => {
                hpke.setup_receiver(kem_output, local_secret, local_public, info, None)
            }
            #[cfg(feature = "post-quantum")]
            AwsLcHpke::PostQuantum(hpke) => {
                hpke.setup_receiver(kem_output, local_secret, local_public, info, None)
            }
            #[cfg(feature = "post-quantum")]
            AwsLcHpke::Combined(hpke) => {
                hpke.setup_receiver(kem_output, local_secret, local_public, info, None)
            }
        }
        .await
        .map_err(Into::into)
    }

    async fn kem_derive(&self, ikm: &[u8]) -> Result<(HpkeSecretKey, HpkePublicKey), Self::Error> {
        match &self.hpke {
            AwsLcHpke::Classical(hpke) => hpke.derive(ikm),
            #[cfg(feature = "post-quantum")]
            AwsLcHpke::PostQuantum(hpke) => hpke.derive(ikm),
            #[cfg(feature = "post-quantum")]
            AwsLcHpke::Combined(hpke) => hpke.derive(ikm),
        }
        .await
        .map_err(Into::into)
    }

    async fn kem_generate(&self) -> Result<(HpkeSecretKey, HpkePublicKey), Self::Error> {
        match &self.hpke {
            AwsLcHpke::Classical(hpke) => hpke.generate(),
            #[cfg(feature = "post-quantum")]
            AwsLcHpke::PostQuantum(hpke) => hpke.generate(),
            #[cfg(feature = "post-quantum")]
            AwsLcHpke::Combined(hpke) => hpke.generate(),
        }
        .await
        .map_err(Into::into)
    }

    fn kem_public_key_validate(&self, key: &HpkePublicKey) -> Result<(), Self::Error> {
        match &self.hpke {
            AwsLcHpke::Classical(hpke) => hpke.public_key_validate(key),
            #[cfg(feature = "post-quantum")]
            AwsLcHpke::PostQuantum(hpke) => hpke.public_key_validate(key),
            #[cfg(feature = "post-quantum")]
            AwsLcHpke::Combined(hpke) => hpke.public_key_validate(key),
        }
        .map_err(Into::into)
    }

    fn random_bytes(&self, out: &mut [u8]) -> Result<(), Self::Error> {
        Ok(aws_lc_rs::rand::fill(out)?)
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

    for cs in AwsLcCryptoProvider::supported_classical_cipher_suites() {
        let mut hpke = Hpke::new(
            dhkem(cs).unwrap(),
            AwsLcHkdf::new(cs).unwrap(),
            AwsLcAead::new(cs),
        );

        mls_rs_core::crypto::test_suite::verify_hpke_context_tests(&hpke, cs);
        mls_rs_core::crypto::test_suite::verify_hpke_encap_tests(&mut hpke, cs);
    }
}

#[cfg(all(not(mls_build_async), feature = "post-quantum", not(feature = "fips")))]
#[test]
fn pq_cipher_suite_test() {
    for cs in AwsLcCryptoProvider::supported_pq_cipher_suites() {
        let cs = AwsLcCryptoProvider::new()
            .cipher_suite_provider(cs)
            .unwrap();

        let (sk, pk) = cs.kem_derive(&[0u8; 64]).unwrap();
        let ct = cs.hpke_seal(&pk, b"info", None, b"very secret").unwrap();
        let pt = cs.hpke_open(&ct, &sk, &pk, b"info", None).unwrap();
        assert_eq!(pt, b"very secret");
    }
}
