pub use openssl;

mod aead;
mod hpke;
mod kdf;
mod mac;

#[cfg(feature = "x509")]
pub mod x509;

use aead::{Aead, AeadError};
use hpke::{HpkeError, OpensslHpkeContext};
use kdf::{Kdf, KdfError};
use mac::{Hash, HashError};
use thiserror::Error;

use aws_mls_core::crypto::{
    CipherSuite, CipherSuiteProvider, CryptoProvider, HpkeCiphertext, HpkePublicKey, HpkeSecretKey,
    SignaturePublicKey, SignatureSecretKey,
};

#[derive(Debug, Error)]
pub enum OpensslCryptoError {
    #[error(transparent)]
    AeadError(#[from] AeadError),
    #[error(transparent)]
    HpkeError(#[from] HpkeError),
    #[error(transparent)]
    KdfError(#[from] KdfError),
    #[error(transparent)]
    HashError(#[from] HashError),
}

#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub struct OpensslCryptoProvider {
    pub enabled_cipher_suites: Vec<CipherSuite>,
}

impl OpensslCryptoProvider {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_enabled_cipher_suites(enabled_cipher_suites: Vec<CipherSuite>) -> Self {
        Self {
            enabled_cipher_suites,
        }
    }
}

impl CryptoProvider for OpensslCryptoProvider {
    type CipherSuiteProvider = OpensslCipherSuite;

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

        Some(OpensslCipherSuite::new(cipher_suite))
    }
}

// TODO consider wrapping aead to implement debug
#[derive(Clone)]
pub struct OpensslCipherSuite {
    cipher_suite: CipherSuite,
    aead: Aead,
    kdf: Kdf,
    hash: Hash,
}

impl OpensslCipherSuite {
    pub fn new(cipher_suite: CipherSuite) -> Self {
        Self {
            cipher_suite,
            aead: Aead::new(cipher_suite),
            kdf: Kdf::new(cipher_suite),
            hash: Hash::new(cipher_suite),
        }
    }

    pub fn kem_derive(
        &self,
        _ikm: &[u8],
    ) -> Result<(HpkeSecretKey, HpkePublicKey), OpensslCryptoError> {
        Ok((vec![].into(), vec![].into()))
    }

    pub fn kem_generate(&self) -> Result<(HpkeSecretKey, HpkePublicKey), OpensslCryptoError> {
        Ok((vec![].into(), vec![].into()))
    }

    pub fn kem_public_key_validate(&self, _key: &HpkePublicKey) -> Result<(), OpensslCryptoError> {
        Ok(())
    }

    pub fn random_bytes(&self, _out: &mut [u8]) -> Result<(), OpensslCryptoError> {
        Ok(())
    }

    pub fn signature_key_generate(
        &self,
    ) -> Result<(SignatureSecretKey, SignaturePublicKey), OpensslCryptoError> {
        Ok((vec![].into(), vec![].into()))
    }

    pub fn signature_key_derive_public(
        &self,
        _secret_key: &SignatureSecretKey,
    ) -> Result<SignaturePublicKey, OpensslCryptoError> {
        Ok(vec![].into())
    }

    pub fn sign(
        &self,
        _secret_key: &SignatureSecretKey,
        _data: &[u8],
    ) -> Result<Vec<u8>, OpensslCryptoError> {
        Ok(vec![])
    }

    pub fn verify(
        &self,
        _public_key: &SignaturePublicKey,
        _signature: &[u8],
        _data: &[u8],
    ) -> Result<(), OpensslCryptoError> {
        Ok(())
    }
}

impl CipherSuiteProvider for OpensslCipherSuite {
    type Error = OpensslCryptoError;
    // TODO exporter_secret in this struct is not zeroized
    type HpkeContext = OpensslHpkeContext;

    fn hash(&self, data: &[u8]) -> Result<Vec<u8>, Self::Error> {
        Ok(self.hash.hash(data)?)
    }

    fn mac(&self, key: &[u8], data: &[u8]) -> Result<Vec<u8>, Self::Error> {
        Ok(self.hash.mac(key, data)?)
    }

    fn aead_seal(
        &self,
        key: &[u8],
        data: &[u8],
        aad: Option<&[u8]>,
        nonce: &[u8],
    ) -> Result<Vec<u8>, Self::Error> {
        Ok(self.aead.aead_seal(key, data, aad, nonce)?)
    }

    fn aead_open(
        &self,
        key: &[u8],
        cipher_text: &[u8],
        aad: Option<&[u8]>,
        nonce: &[u8],
    ) -> Result<Vec<u8>, Self::Error> {
        Ok(self.aead.aead_open(key, cipher_text, aad, nonce)?)
    }

    fn aead_key_size(&self) -> usize {
        self.aead.aead_key_size()
    }

    fn aead_nonce_size(&self) -> usize {
        self.aead.aead_nonce_size()
    }

    fn kdf_expand(&self, prk: &[u8], info: &[u8], len: usize) -> Result<Vec<u8>, Self::Error> {
        Ok(self.kdf.kdf_expand(prk, info, len)?)
    }

    fn kdf_extract(&self, salt: &[u8], ikm: &[u8]) -> Result<Vec<u8>, Self::Error> {
        Ok(self.kdf.kdf_extract(salt, ikm)?)
    }

    fn kdf_extract_size(&self) -> usize {
        self.kdf.kdf_extract_size()
    }

    fn hpke_seal(
        &self,
        remote_key: &HpkePublicKey,
        info: &[u8],
        aad: Option<&[u8]>,
        pt: &[u8],
    ) -> Result<HpkeCiphertext, Self::Error> {
        Ok(self.hpke_seal(remote_key, info, aad, pt)?)
    }

    fn hpke_open(
        &self,
        ciphertext: &HpkeCiphertext,
        local_secret: &HpkeSecretKey,
        info: &[u8],
        aad: Option<&[u8]>,
    ) -> Result<Vec<u8>, Self::Error> {
        Ok(self.hpke_open(ciphertext, local_secret, info, aad)?)
    }

    fn hpke_setup_r(
        &self,
        enc: &[u8],
        local_secret: &HpkeSecretKey,
        info: &[u8],
    ) -> Result<Self::HpkeContext, Self::Error> {
        Ok(self.hpke_setup_r(enc, local_secret, info)?)
    }

    fn hpke_setup_s(
        &self,
        remote_key: &HpkePublicKey,
        info: &[u8],
    ) -> Result<(Vec<u8>, Self::HpkeContext), Self::Error> {
        Ok(self.hpke_setup_s(remote_key, info)?)
    }

    fn kem_derive(&self, ikm: &[u8]) -> Result<(HpkeSecretKey, HpkePublicKey), Self::Error> {
        self.kem_derive(ikm)
    }

    fn kem_generate(&self) -> Result<(HpkeSecretKey, HpkePublicKey), Self::Error> {
        self.kem_generate()
    }

    fn random_bytes(&self, out: &mut [u8]) -> Result<(), Self::Error> {
        self.random_bytes(out)
    }

    fn cipher_suite(&self) -> CipherSuite {
        self.cipher_suite
    }

    fn sign(&self, secret_key: &SignatureSecretKey, data: &[u8]) -> Result<Vec<u8>, Self::Error> {
        self.sign(secret_key, data)
    }

    fn verify(
        &self,
        public_key: &SignaturePublicKey,
        signature: &[u8],
        data: &[u8],
    ) -> Result<(), Self::Error> {
        self.verify(public_key, signature, data)
    }

    fn signature_key_generate(
        &self,
    ) -> Result<(SignatureSecretKey, SignaturePublicKey), Self::Error> {
        self.signature_key_generate()
    }

    fn signature_key_derive_public(
        &self,
        secret_key: &SignatureSecretKey,
    ) -> Result<SignaturePublicKey, Self::Error> {
        self.signature_key_derive_public(secret_key)
    }

    fn kem_public_key_validate(&self, key: &HpkePublicKey) -> Result<(), Self::Error> {
        self.kem_public_key_validate(key)
    }
}
