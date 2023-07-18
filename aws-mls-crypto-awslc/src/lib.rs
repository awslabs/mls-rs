mod aead;
mod ec;
mod ecdsa;
mod kdf;

use std::mem::MaybeUninit;

use aead::AwsLcAead;
use aws_lc_rs::{digest, error::Unspecified, hmac};

use aws_lc_sys::SHA256;
use aws_mls_core::{
    crypto::{
        CipherSuite, CipherSuiteProvider, CryptoProvider, HpkeCiphertext, HpkePublicKey,
        HpkeSecretKey, SignaturePublicKey, SignatureSecretKey,
    },
    error::IntoAnyError,
};

use aws_mls_crypto_hpke::{
    context::{ContextR, ContextS},
    dhkem::DhKem,
    hpke::{Hpke, HpkeError},
};
use aws_mls_crypto_traits::{AeadType, KdfType, KemId};
use ec::Ecdh;
use ecdsa::AwsLcEcdsa;
use kdf::AwsLcHkdf;
use thiserror::Error;
use zeroize::Zeroizing;

#[derive(Clone, Default, Debug)]
pub struct AwsLcCryptoProvider;

impl AwsLcCryptoProvider {
    pub fn new() -> Self {
        Self
    }
}

#[derive(Clone)]
pub struct AwsLcCipherSuite {
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
}

impl CryptoProvider for AwsLcCryptoProvider {
    type CipherSuiteProvider = AwsLcCipherSuite;

    fn supported_cipher_suites(&self) -> Vec<aws_mls_core::crypto::CipherSuite> {
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
        cipher_suite: aws_mls_core::crypto::CipherSuite,
    ) -> Option<Self::CipherSuiteProvider> {
        AwsLcCipherSuite::new(cipher_suite)
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
}

impl From<Unspecified> for AwsLcCryptoError {
    fn from(_value: Unspecified) -> Self {
        AwsLcCryptoError::CryptoError
    }
}

impl IntoAnyError for AwsLcCryptoError {}

impl CipherSuiteProvider for AwsLcCipherSuite {
    type Error = AwsLcCryptoError;

    type HpkeContextS = ContextS<AwsLcHkdf, AwsLcAead>;
    type HpkeContextR = ContextR<AwsLcHkdf, AwsLcAead>;

    fn cipher_suite(&self) -> aws_mls_core::crypto::CipherSuite {
        CipherSuite::P521_AES256
    }

    fn hash(&self, data: &[u8]) -> Result<Vec<u8>, Self::Error> {
        Ok(digest::digest(&digest::SHA512, data).as_ref().to_vec())
    }

    fn mac(&self, key: &[u8], data: &[u8]) -> Result<Vec<u8>, Self::Error> {
        let key = hmac::Key::new(self.mac_algo, key);
        Ok(hmac::sign(&key, data).as_ref().to_vec())
    }

    fn aead_seal(
        &self,
        key: &[u8],
        data: &[u8],
        aad: Option<&[u8]>,
        nonce: &[u8],
    ) -> Result<Vec<u8>, Self::Error> {
        self.aead.seal(key, data, aad, nonce)
    }

    fn aead_open(
        &self,
        key: &[u8],
        ciphertext: &[u8],
        aad: Option<&[u8]>,
        nonce: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, Self::Error> {
        self.aead.open(key, ciphertext, aad, nonce).map(Into::into)
    }

    fn aead_key_size(&self) -> usize {
        self.aead.key_size()
    }

    fn aead_nonce_size(&self) -> usize {
        self.aead.nonce_size()
    }

    fn kdf_extract(&self, salt: &[u8], ikm: &[u8]) -> Result<Zeroizing<Vec<u8>>, Self::Error> {
        self.kdf.extract(salt, ikm).map(Into::into)
    }

    fn kdf_expand(
        &self,
        prk: &[u8],
        info: &[u8],
        len: usize,
    ) -> Result<Zeroizing<Vec<u8>>, Self::Error> {
        self.kdf.expand(prk, info, len).map(Into::into)
    }

    fn kdf_extract_size(&self) -> usize {
        self.kdf.extract_size()
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
            .map_err(Into::into)
    }

    fn hpke_open(
        &self,
        ciphertext: &HpkeCiphertext,
        local_secret: &HpkeSecretKey,
        local_public: &HpkePublicKey,
        info: &[u8],
        aad: Option<&[u8]>,
    ) -> Result<Vec<u8>, Self::Error> {
        self.hpke
            .open(ciphertext, local_secret, local_public, info, None, aad)
            .map_err(Into::into)
    }

    fn hpke_setup_s(
        &self,
        remote_key: &HpkePublicKey,
        info: &[u8],
    ) -> Result<(Vec<u8>, Self::HpkeContextS), Self::Error> {
        self.hpke
            .setup_sender(remote_key, info, None)
            .map_err(Into::into)
    }

    fn hpke_setup_r(
        &self,
        kem_output: &[u8],
        local_secret: &HpkeSecretKey,
        local_public: &HpkePublicKey,

        info: &[u8],
    ) -> Result<Self::HpkeContextR, Self::Error> {
        self.hpke
            .setup_receiver(kem_output, local_secret, local_public, info, None)
            .map_err(Into::into)
    }

    fn kem_derive(&self, ikm: &[u8]) -> Result<(HpkeSecretKey, HpkePublicKey), Self::Error> {
        self.hpke.derive(ikm).map_err(Into::into)
    }

    fn kem_generate(&self) -> Result<(HpkeSecretKey, HpkePublicKey), Self::Error> {
        self.hpke.generate().map_err(Into::into)
    }

    fn kem_public_key_validate(&self, key: &HpkePublicKey) -> Result<(), Self::Error> {
        self.hpke.public_key_validate(key).map_err(Into::into)
    }

    fn random_bytes(&self, out: &mut [u8]) -> Result<(), Self::Error> {
        unsafe {
            if 1 != aws_lc_sys::RAND_bytes(out.as_mut_ptr(), out.len()) {
                return Err(Unspecified.into());
            }
        }

        Ok(())
    }

    fn signature_key_generate(
        &self,
    ) -> Result<(SignatureSecretKey, SignaturePublicKey), Self::Error> {
        self.signing.signature_key_generate()
    }

    fn signature_key_derive_public(
        &self,
        secret_key: &SignatureSecretKey,
    ) -> Result<SignaturePublicKey, Self::Error> {
        self.signing.signature_key_derive_public(secret_key)
    }

    fn sign(&self, secret_key: &SignatureSecretKey, data: &[u8]) -> Result<Vec<u8>, Self::Error> {
        self.signing.sign(secret_key, data)
    }

    fn verify(
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

#[cfg(test)]
mod tests {
    #[test]
    fn cipher_suite_standard_conformance() {
        aws_mls_core::crypto::test_suite::verify_tests(&crate::AwsLcCryptoProvider)
    }
}
