#![cfg(any(target_os = "macos", target_os = "ios"))]

pub mod aead;
pub mod kdf;
pub mod kem;
#[cfg(feature = "post-quantum")]
pub mod ml_kem;
pub mod random;
pub mod sig;

use aead::{Aead, AeadError};
use kdf::{Kdf, KdfError};
use kem::{Kem, KemError};
use sig::{Signature, SignatureError};

use mls_rs_core::{
    crypto::{
        CipherSuite, CipherSuiteProvider, CryptoProvider, HpkeCiphertext, HpkeContextR,
        HpkeContextS, HpkePsk, HpkePublicKey, HpkeSecretKey, SignaturePublicKey,
        SignatureSecretKey,
    },
    error::IntoAnyError,
};
use mls_rs_crypto_traits::{AeadType, KdfType};
use zeroize::Zeroizing;

#[derive(Debug)]
#[cfg_attr(feature = "std", derive(thiserror::Error))]
pub enum CryptoKitError {
    #[cfg_attr(feature = "std", error(transparent))]
    AeadError(AeadError),
    #[cfg_attr(feature = "std", error(transparent))]
    KdfError(KdfError),
    #[cfg_attr(feature = "std", error(transparent))]
    KemError(KemError),
    #[cfg_attr(feature = "std", error("randomness error"))]
    RandError,
    #[cfg_attr(feature = "std", error(transparent))]
    SignatureError(SignatureError),
}

impl From<AeadError> for CryptoKitError {
    fn from(e: AeadError) -> Self {
        CryptoKitError::AeadError(e)
    }
}

impl From<KdfError> for CryptoKitError {
    fn from(e: KdfError) -> Self {
        CryptoKitError::KdfError(e)
    }
}

impl From<KemError> for CryptoKitError {
    fn from(e: KemError) -> Self {
        CryptoKitError::KemError(e)
    }
}

impl From<SignatureError> for CryptoKitError {
    fn from(e: SignatureError) -> Self {
        CryptoKitError::SignatureError(e)
    }
}

#[cfg(feature = "post-quantum")]
impl From<mls_rs_crypto_hpke::hpke::HpkeError> for CryptoKitError {
    fn from(e: mls_rs_crypto_hpke::hpke::HpkeError) -> Self {
        use mls_rs_crypto_hpke::hpke::HpkeError;
        match e {
            HpkeError::KemError(_) => CryptoKitError::KemError(KemError::CryptoKitError),
            HpkeError::AeadError(_) => CryptoKitError::AeadError(AeadError::CryptoKitError),
            HpkeError::KdfError(_) => CryptoKitError::KdfError(KdfError::CryptoKitError),
            _ => CryptoKitError::KemError(KemError::CryptoKitError),
        }
    }
}

impl IntoAnyError for CryptoKitError {
    #[cfg(feature = "std")]
    fn into_dyn_error(self) -> Result<Box<dyn std::error::Error + Send + Sync>, Self> {
        Ok(self.into())
    }
}

#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct CryptoKitProvider {
    pub enabled_cipher_suites: Vec<CipherSuite>,
}

impl CryptoKitProvider {
    const ALL_SUPPORTED_CIPHER_SUITES: [CipherSuite; 5] = [
        CipherSuite::P256_AES128,
        CipherSuite::P384_AES256,
        CipherSuite::P521_AES256,
        CipherSuite::CURVE25519_AES128,
        CipherSuite::CURVE25519_CHACHA,
    ];

    pub fn with_enabled_cipher_suites(enabled_cipher_suites: Vec<CipherSuite>) -> Self {
        let supported = enabled_cipher_suites
            .iter()
            .filter(|cs| Self::ALL_SUPPORTED_CIPHER_SUITES.contains(cs))
            .cloned()
            .collect();
        Self {
            enabled_cipher_suites: supported,
        }
    }

    pub fn all_supported_cipher_suites() -> Vec<CipherSuite> {
        Self::ALL_SUPPORTED_CIPHER_SUITES.to_vec()
    }
}

impl Default for CryptoKitProvider {
    fn default() -> Self {
        Self {
            enabled_cipher_suites: Self::all_supported_cipher_suites(),
        }
    }
}

impl CryptoProvider for CryptoKitProvider {
    type CipherSuiteProvider = CryptoKitCipherSuite;

    fn supported_cipher_suites(&self) -> Vec<CipherSuite> {
        self.enabled_cipher_suites.clone()
    }

    fn cipher_suite_provider(
        &self,
        cipher_suite: CipherSuite,
    ) -> Option<Self::CipherSuiteProvider> {
        if !self.enabled_cipher_suites.contains(&cipher_suite) {
            return None;
        }

        CryptoKitCipherSuite::new(cipher_suite)
    }
}

#[derive(Clone)]
pub struct CryptoKitCipherSuite {
    cipher_suite: CipherSuite,
    aead: Aead,
    kdf: Kdf,
    kem: Kem,
    sig: Signature,
}

impl CryptoKitCipherSuite {
    pub fn new(cipher_suite: CipherSuite) -> Option<Self> {
        Some(Self {
            cipher_suite,
            kdf: Kdf::new(cipher_suite)?,
            aead: Aead::new(cipher_suite)?,
            kem: Kem::new(cipher_suite)?,
            sig: Signature::new(cipher_suite)?,
        })
    }

    pub fn random_bytes(&self, out: &mut [u8]) -> Result<(), CryptoKitError> {
        random::fill(out)
            .then_some(())
            .ok_or(CryptoKitError::RandError)
    }
}

impl CipherSuiteProvider for CryptoKitCipherSuite {
    type Error = CryptoKitError;
    type HpkeContextR = kem::HpkeContextR;
    type HpkeContextS = kem::HpkeContextS;

    fn hash(&self, data: &[u8]) -> Result<Vec<u8>, Self::Error> {
        self.kdf.hash(data).map_err(|e| e.into())
    }

    fn mac(&self, key: &[u8], data: &[u8]) -> Result<Vec<u8>, Self::Error> {
        self.kdf.mac(key, data).map_err(|e| e.into())
    }

    fn aead_seal(
        &self,
        key: &[u8],
        data: &[u8],
        aad: Option<&[u8]>,
        nonce: &[u8],
    ) -> Result<Vec<u8>, Self::Error> {
        self.aead.seal(key, data, aad, nonce).map_err(|e| e.into())
    }

    fn aead_open(
        &self,
        key: &[u8],
        cipher_text: &[u8],
        aad: Option<&[u8]>,
        nonce: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, Self::Error> {
        self.aead
            .open(key, cipher_text, aad, nonce)
            .map(Zeroizing::new)
            .map_err(|e| e.into())
    }

    fn aead_key_size(&self) -> usize {
        self.aead.key_size()
    }

    fn aead_nonce_size(&self) -> usize {
        self.aead.nonce_size()
    }

    fn kdf_expand(
        &self,
        prk: &[u8],
        info: &[u8],
        len: usize,
    ) -> Result<Zeroizing<Vec<u8>>, Self::Error> {
        self.kdf
            .expand(prk, info, len)
            .map(Zeroizing::new)
            .map_err(|e| e.into())
    }

    fn kdf_extract(&self, salt: &[u8], ikm: &[u8]) -> Result<Zeroizing<Vec<u8>>, Self::Error> {
        self.kdf
            .extract(salt, ikm)
            .map(Zeroizing::new)
            .map_err(|e| e.into())
    }

    fn kdf_extract_size(&self) -> usize {
        self.kdf.extract_size()
    }

    fn kem_generate(&self) -> Result<(HpkeSecretKey, HpkePublicKey), Self::Error> {
        self.kem.generate().map_err(|e| e.into())
    }

    fn kem_derive(&self, ikm: &[u8]) -> Result<(HpkeSecretKey, HpkePublicKey), Self::Error> {
        self.kem.derive(ikm).map_err(|e| e.into())
    }

    fn kem_public_key_validate(&self, key: &HpkePublicKey) -> Result<(), Self::Error> {
        self.kem.public_key_validate(key).map_err(|e| e.into())
    }

    fn hpke_setup_s(
        &self,
        remote_key: &HpkePublicKey,
        info: &[u8],
    ) -> Result<(Vec<u8>, Self::HpkeContextS), Self::Error> {
        self.kem
            .hpke_setup_s(remote_key, info)
            .map_err(|e| e.into())
    }

    fn hpke_setup_r(
        &self,
        enc: &[u8],
        local_secret: &HpkeSecretKey,
        local_public: &HpkePublicKey,
        info: &[u8],
    ) -> Result<Self::HpkeContextR, Self::Error> {
        self.kem
            .hpke_setup_r(enc, local_secret, local_public, info)
            .map_err(|e| e.into())
    }

    fn hpke_seal(
        &self,
        remote_key: &HpkePublicKey,
        info: &[u8],
        aad: Option<&[u8]>,
        pt: &[u8],
    ) -> Result<HpkeCiphertext, Self::Error> {
        let (kem_output, mut ctx) = self.hpke_setup_s(remote_key, info)?;
        let ciphertext = ctx
            .seal(aad, pt)
            .map_err(<KemError as Into<CryptoKitError>>::into)?;
        Ok(HpkeCiphertext {
            kem_output,
            ciphertext,
        })
    }

    fn hpke_seal_psk(
        &self,
        remote_key: &HpkePublicKey,
        info: &[u8],
        aad: Option<&[u8]>,
        pt: &[u8],
        psk: HpkePsk<'_>,
    ) -> Result<HpkeCiphertext, Self::Error> {
        let (kem_output, mut ctx) = self
            .kem
            .hpke_setup_s_psk(remote_key, info, psk.value, psk.id)?;
        let ciphertext = ctx
            .seal(aad, pt)
            .map_err(<KemError as Into<CryptoKitError>>::into)?;
        Ok(HpkeCiphertext {
            kem_output,
            ciphertext,
        })
    }

    fn hpke_open(
        &self,
        ciphertext: &HpkeCiphertext,
        local_secret: &HpkeSecretKey,
        local_public: &HpkePublicKey,
        info: &[u8],
        aad: Option<&[u8]>,
    ) -> Result<Zeroizing<Vec<u8>>, Self::Error> {
        let mut ctx =
            self.hpke_setup_r(&ciphertext.kem_output, local_secret, local_public, info)?;
        ctx.open(aad, &ciphertext.ciphertext)
            .map_err(<KemError as Into<CryptoKitError>>::into)
    }

    fn hpke_open_psk(
        &self,
        ciphertext: &HpkeCiphertext,
        local_secret: &HpkeSecretKey,
        local_public: &HpkePublicKey,
        info: &[u8],
        aad: Option<&[u8]>,
        psk: HpkePsk<'_>,
    ) -> Result<Zeroizing<Vec<u8>>, Self::Error> {
        let mut ctx = self.kem.hpke_setup_r_psk(
            &ciphertext.kem_output,
            local_secret,
            local_public,
            info,
            psk.value,
            psk.id,
        )?;
        ctx.open(aad, &ciphertext.ciphertext)
            .map_err(<KemError as Into<CryptoKitError>>::into)
    }

    fn random_bytes(&self, out: &mut [u8]) -> Result<(), Self::Error> {
        random::fill(out)
            .then_some(())
            .ok_or(CryptoKitError::RandError)
    }

    fn cipher_suite(&self) -> CipherSuite {
        self.cipher_suite
    }

    fn signature_key_generate(
        &self,
    ) -> Result<(SignatureSecretKey, SignaturePublicKey), Self::Error> {
        self.sig.generate().map_err(|e| e.into())
    }

    fn signature_key_derive_public(
        &self,
        secret_key: &SignatureSecretKey,
    ) -> Result<SignaturePublicKey, Self::Error> {
        self.sig.derive_public(secret_key).map_err(|e| e.into())
    }

    fn sign(&self, secret_key: &SignatureSecretKey, data: &[u8]) -> Result<Vec<u8>, Self::Error> {
        self.sig.sign(secret_key, data).map_err(|e| e.into())
    }

    fn verify(
        &self,
        public_key: &SignaturePublicKey,
        signature: &[u8],
        data: &[u8],
    ) -> Result<(), Self::Error> {
        self.sig
            .verify(public_key, signature, data)
            .map_err(|e| e.into())
    }
}

#[test]
fn mls_core_tests() {
    let provider = CryptoKitProvider::default();
    mls_rs_core::crypto::test_suite::verify_tests(&provider, true);
}

#[cfg(feature = "post-quantum")]
#[test]
fn ml_kem_hpke_seal_open_roundtrip() {
    use mls_rs_core::crypto::{CipherSuiteProvider, CryptoProvider};
    let provider = CryptoKitMlKemProvider;
    let cs = provider.cipher_suite_provider(CS::ML_KEM_768).unwrap();
    let (sk, pk) = cs.kem_generate().unwrap();
    let ct = cs
        .hpke_seal(&pk, b"test-info", None, b"hello world")
        .unwrap();
    let pt = cs.hpke_open(&ct, &sk, &pk, b"test-info", None).unwrap();
    assert_eq!(&*pt, b"hello world");
}

#[cfg(feature = "post-quantum")]
#[test]
fn ml_kem_hpke_seal_open_with_aad() {
    use mls_rs_core::crypto::{CipherSuiteProvider, CryptoProvider};
    let provider = CryptoKitMlKemProvider;
    let cs = provider.cipher_suite_provider(CS::ML_KEM_768).unwrap();
    let (sk, pk) = cs.kem_generate().unwrap();
    let ct = cs
        .hpke_seal(&pk, b"info", Some(b"aad"), b"payload")
        .unwrap();
    let pt = cs.hpke_open(&ct, &sk, &pk, b"info", Some(b"aad")).unwrap();
    assert_eq!(&*pt, b"payload");
    // wrong AAD must fail
    assert!(cs
        .hpke_open(&ct, &sk, &pk, b"info", Some(b"wrong-aad"))
        .is_err());
}

#[cfg(feature = "post-quantum")]
#[test]
fn ml_kem_kem_derive_returns_not_supported() {
    use crate::kem::KemError;
    use mls_rs_core::crypto::{CipherSuiteProvider, CryptoProvider};
    let provider = CryptoKitMlKemProvider;
    let cs = provider.cipher_suite_provider(CS::ML_KEM_768).unwrap();
    let err = cs.kem_derive(b"some-ikm").unwrap_err();
    assert!(matches!(
        err,
        CryptoKitError::KemError(KemError::NotSupported)
    ));
}

// Verify HPKE wire interop between CryptoKit and AWS-LC ML-KEM-768 providers.
// Both use mls-rs-crypto-hpke::Hpke with HKDF-SHA256 + AES-128-GCM, so encap/decap
// ciphertexts (1088 bytes) and public keys (1184 bytes) are compatible across providers.
// Private key formats are NOT interchangeable: CryptoKit stores 96 bytes
// (integrityCheckedRepresentation), AWS-LC stores 2400 bytes (FIPS 203 expanded).
#[cfg(feature = "awslc-interop")]
#[test]
fn ml_kem_768_wire_interop_cryptokit_encap_awslc_decap() {
    use mls_rs_core::crypto::{CipherSuiteProvider, CryptoProvider};
    use mls_rs_crypto_awslc::AwsLcCryptoProvider;

    let ck_provider = CryptoKitMlKemProvider;
    let ck_cs = ck_provider.cipher_suite_provider(CS::ML_KEM_768).unwrap();

    let awslc_provider = AwsLcCryptoProvider::new();
    let awslc_cs = awslc_provider
        .cipher_suite_provider(CS::ML_KEM_768)
        .unwrap();

    // AWS-LC generates the key pair; CryptoKit encrypts to it.
    let (awslc_sk, awslc_pk) = awslc_cs.kem_generate().unwrap();
    let ct = ck_cs
        .hpke_seal(&awslc_pk, b"interop-info", None, b"cryptokit->awslc")
        .unwrap();
    let pt = awslc_cs
        .hpke_open(&ct, &awslc_sk, &awslc_pk, b"interop-info", None)
        .unwrap();
    assert_eq!(&*pt, b"cryptokit->awslc");
}

#[cfg(feature = "awslc-interop")]
#[test]
fn ml_kem_768_wire_interop_awslc_encap_cryptokit_decap() {
    use mls_rs_core::crypto::{CipherSuiteProvider, CryptoProvider};
    use mls_rs_crypto_awslc::AwsLcCryptoProvider;

    let ck_provider = CryptoKitMlKemProvider;
    let ck_cs = ck_provider.cipher_suite_provider(CS::ML_KEM_768).unwrap();

    let awslc_provider = AwsLcCryptoProvider::new();
    let awslc_cs = awslc_provider
        .cipher_suite_provider(CS::ML_KEM_768)
        .unwrap();

    // CryptoKit generates the key pair; AWS-LC encrypts to it.
    let (ck_sk, ck_pk) = ck_cs.kem_generate().unwrap();
    let ct = awslc_cs
        .hpke_seal(&ck_pk, b"interop-info", None, b"awslc->cryptokit")
        .unwrap();
    let pt = ck_cs
        .hpke_open(&ct, &ck_sk, &ck_pk, b"interop-info", None)
        .unwrap();
    assert_eq!(&*pt, b"awslc->cryptokit");
}

#[cfg(feature = "post-quantum")]
use ml_kem::MlKem768Kem;
#[cfg(feature = "post-quantum")]
use mls_rs_core::crypto::CipherSuite as CS;
#[cfg(feature = "post-quantum")]
use mls_rs_crypto_hpke::{
    context::{ContextR, ContextS},
    hpke::Hpke,
};

/// A `CipherSuiteProvider` for ML-KEM-768 (0xFDEA) backed by CryptoKit ML-KEM
/// + CryptoKit HKDF-SHA256/AES-128-GCM + CryptoKit Ed25519 signing.
#[cfg(feature = "post-quantum")]
#[derive(Clone)]
pub struct CryptoKitMlKemCipherSuite {
    hpke: Hpke<MlKem768Kem, Kdf, Aead>,
    kdf: Kdf,
    aead: Aead,
    sig: Signature,
}

#[cfg(feature = "post-quantum")]
impl CryptoKitMlKemCipherSuite {
    fn new() -> Self {
        // ML-KEM-768 = MLS_128_ML_KEM_768_AES128GCM_SHA256_Ed25519:
        // KDF = HKDF-SHA256, AEAD = AES-128-GCM, Sig = Ed25519
        // CURVE25519_AES128 shares these primitives, so we borrow its providers.
        let kdf = Kdf::new(CS::CURVE25519_AES128).expect("HKDF-SHA256 is always available");
        let aead = Aead::new(CS::CURVE25519_AES128).expect("AES-128-GCM is always available");
        let sig = Signature::new(CS::CURVE25519_AES128).expect("Ed25519 is always available");
        let hpke = Hpke::new(MlKem768Kem::new(), kdf, Some(aead));
        Self {
            hpke,
            kdf,
            aead,
            sig,
        }
    }
}

#[cfg(feature = "post-quantum")]
impl CipherSuiteProvider for CryptoKitMlKemCipherSuite {
    type Error = CryptoKitError;
    type HpkeContextS = ContextS<Kdf, Aead>;
    type HpkeContextR = ContextR<Kdf, Aead>;

    fn cipher_suite(&self) -> CipherSuite {
        CS::ML_KEM_768
    }

    fn hash(&self, data: &[u8]) -> Result<Vec<u8>, Self::Error> {
        self.kdf.hash(data).map_err(|e| e.into())
    }

    fn mac(&self, key: &[u8], data: &[u8]) -> Result<Vec<u8>, Self::Error> {
        self.kdf.mac(key, data).map_err(|e| e.into())
    }

    fn aead_seal(
        &self,
        key: &[u8],
        data: &[u8],
        aad: Option<&[u8]>,
        nonce: &[u8],
    ) -> Result<Vec<u8>, Self::Error> {
        self.aead.seal(key, data, aad, nonce).map_err(|e| e.into())
    }

    fn aead_open(
        &self,
        key: &[u8],
        cipher_text: &[u8],
        aad: Option<&[u8]>,
        nonce: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, Self::Error> {
        self.aead
            .open(key, cipher_text, aad, nonce)
            .map(Zeroizing::new)
            .map_err(|e| e.into())
    }

    fn aead_key_size(&self) -> usize {
        self.aead.key_size()
    }

    fn aead_nonce_size(&self) -> usize {
        self.aead.nonce_size()
    }

    fn kdf_expand(
        &self,
        prk: &[u8],
        info: &[u8],
        len: usize,
    ) -> Result<Zeroizing<Vec<u8>>, Self::Error> {
        self.kdf
            .expand(prk, info, len)
            .map(Zeroizing::new)
            .map_err(|e| e.into())
    }

    fn kdf_extract(&self, salt: &[u8], ikm: &[u8]) -> Result<Zeroizing<Vec<u8>>, Self::Error> {
        self.kdf
            .extract(salt, ikm)
            .map(Zeroizing::new)
            .map_err(|e| e.into())
    }

    fn kdf_extract_size(&self) -> usize {
        self.kdf.extract_size()
    }

    fn kem_generate(&self) -> Result<(HpkeSecretKey, HpkePublicKey), Self::Error> {
        self.hpke.generate().map_err(|e| e.into())
    }

    fn kem_derive(&self, _ikm: &[u8]) -> Result<(HpkeSecretKey, HpkePublicKey), Self::Error> {
        // CryptoKit's MLKEM768 has no seed-based key generation API; derive is not supported.
        Err(CryptoKitError::KemError(KemError::NotSupported))
    }

    fn kem_public_key_validate(&self, _key: &HpkePublicKey) -> Result<(), Self::Error> {
        Ok(())
    }

    fn hpke_setup_s(
        &self,
        remote_key: &HpkePublicKey,
        info: &[u8],
    ) -> Result<(Vec<u8>, Self::HpkeContextS), Self::Error> {
        self.hpke
            .setup_sender(remote_key, info, None)
            .map_err(|e| e.into())
    }

    fn hpke_setup_r(
        &self,
        enc: &[u8],
        local_secret: &HpkeSecretKey,
        local_public: &HpkePublicKey,
        info: &[u8],
    ) -> Result<Self::HpkeContextR, Self::Error> {
        self.hpke
            .setup_receiver(enc, local_secret, local_public, info, None)
            .map_err(|e| e.into())
    }

    fn hpke_seal(
        &self,
        remote_key: &HpkePublicKey,
        info: &[u8],
        aad: Option<&[u8]>,
        pt: &[u8],
    ) -> Result<HpkeCiphertext, Self::Error> {
        self.hpke
            .seal(remote_key, info, None, aad, pt)
            .map_err(|e| e.into())
    }

    fn hpke_seal_psk(
        &self,
        remote_key: &HpkePublicKey,
        info: &[u8],
        aad: Option<&[u8]>,
        pt: &[u8],
        psk: HpkePsk<'_>,
    ) -> Result<HpkeCiphertext, Self::Error> {
        self.hpke
            .seal(remote_key, info, Some(psk), aad, pt)
            .map_err(|e| e.into())
    }

    fn hpke_open(
        &self,
        ciphertext: &HpkeCiphertext,
        local_secret: &HpkeSecretKey,
        local_public: &HpkePublicKey,
        info: &[u8],
        aad: Option<&[u8]>,
    ) -> Result<Zeroizing<Vec<u8>>, Self::Error> {
        self.hpke
            .open(ciphertext, local_secret, local_public, info, None, aad)
            .map_err(|e| e.into())
    }

    fn hpke_open_psk(
        &self,
        ciphertext: &HpkeCiphertext,
        local_secret: &HpkeSecretKey,
        local_public: &HpkePublicKey,
        info: &[u8],
        aad: Option<&[u8]>,
        psk: HpkePsk<'_>,
    ) -> Result<Zeroizing<Vec<u8>>, Self::Error> {
        self.hpke
            .open(ciphertext, local_secret, local_public, info, Some(psk), aad)
            .map_err(|e| e.into())
    }

    fn random_bytes(&self, out: &mut [u8]) -> Result<(), Self::Error> {
        random::fill(out)
            .then_some(())
            .ok_or(CryptoKitError::RandError)
    }

    fn signature_key_generate(
        &self,
    ) -> Result<(SignatureSecretKey, SignaturePublicKey), Self::Error> {
        self.sig.generate().map_err(|e| e.into())
    }

    fn signature_key_derive_public(
        &self,
        secret_key: &SignatureSecretKey,
    ) -> Result<SignaturePublicKey, Self::Error> {
        self.sig.derive_public(secret_key).map_err(|e| e.into())
    }

    fn sign(&self, secret_key: &SignatureSecretKey, data: &[u8]) -> Result<Vec<u8>, Self::Error> {
        self.sig.sign(secret_key, data).map_err(|e| e.into())
    }

    fn verify(
        &self,
        public_key: &SignaturePublicKey,
        signature: &[u8],
        data: &[u8],
    ) -> Result<(), Self::Error> {
        self.sig
            .verify(public_key, signature, data)
            .map_err(|e| e.into())
    }
}

/// A `CryptoProvider` that supports only ML-KEM-768 (0xFDEA).
/// Requires iOS 26 / macOS 26 or later for the CryptoKit ML-KEM primitives.
/// Pair with `CryptoKitProvider` (classical) in `two-mls-pq` for a full session.
#[cfg(feature = "post-quantum")]
#[derive(Debug, Clone)]
pub struct CryptoKitMlKemProvider;

#[cfg(feature = "post-quantum")]
impl CryptoProvider for CryptoKitMlKemProvider {
    type CipherSuiteProvider = CryptoKitMlKemCipherSuite;

    fn supported_cipher_suites(&self) -> Vec<CipherSuite> {
        vec![CS::ML_KEM_768]
    }

    fn cipher_suite_provider(
        &self,
        cipher_suite: CipherSuite,
    ) -> Option<Self::CipherSuiteProvider> {
        if cipher_suite == CS::ML_KEM_768 {
            Some(CryptoKitMlKemCipherSuite::new())
        } else {
            None
        }
    }
}
