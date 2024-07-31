#![cfg(any(target_os = "macos", target_os = "ios"))]

pub mod aead;
pub mod kdf;
pub mod kem;
pub mod random;
pub mod sig;

use aead::{Aead, AeadError};
use kdf::{Kdf, KdfError};
use kem::{Kem, KemError};
use sig::{Signature, SignatureError};

use mls_rs_core::{
    crypto::{
        CipherSuite, CipherSuiteProvider, CryptoProvider, HpkeCiphertext, HpkeContextR,
        HpkeContextS, HpkePublicKey, HpkeSecretKey, SignaturePublicKey, SignatureSecretKey,
    },
    error::IntoAnyError,
};
use mls_rs_crypto_traits::{AeadType, KdfType};
use zeroize::Zeroizing;

#[derive(Debug, thiserror::Error)]
pub enum CryptoKitError {
    #[error(transparent)]
    AeadError(AeadError),
    #[error(transparent)]
    KdfError(KdfError),
    #[error(transparent)]
    KemError(KemError),
    #[error("randomness error")]
    RandError,
    #[error(transparent)]
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

impl IntoAnyError for CryptoKitError {
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

    fn hpke_open(
        &self,
        ciphertext: &HpkeCiphertext,
        local_secret: &HpkeSecretKey,
        local_public: &HpkePublicKey,
        info: &[u8],
        aad: Option<&[u8]>,
    ) -> Result<Vec<u8>, Self::Error> {
        let mut ctx =
            self.hpke_setup_r(&ciphertext.kem_output, local_secret, local_public, info)?;
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
