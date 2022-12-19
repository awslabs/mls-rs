use ferriscrypt::{
    cipher::{
        aead::{self, Aead, AeadError, AeadNonce},
        NonceError,
    },
    digest::HashFunction,
    hmac::HMacError,
    hpke::{
        kem::{Kem, KemType},
        AeadId, Hpke, HpkeError, KdfId, KemId,
    },
    kdf::{hkdf::Hkdf, KdfError},
    rand::{SecureRng, SecureRngError},
};

use thiserror::Error;

use crate::cipher_suite::CipherSuite;

use super::{CryptoProvider, HpkeCiphertext, HpkePublicKey, HpkeSecretKey};

#[derive(Debug, Error)]
pub enum FerriscryptCryptoError {
    #[error(transparent)]
    HMacError(#[from] HMacError),
    #[error(transparent)]
    AeadError(#[from] AeadError),
    #[error(transparent)]
    NonceError(#[from] NonceError),
    #[error(transparent)]
    KdfError(#[from] KdfError),
    #[error(transparent)]
    HpkeError(#[from] HpkeError),
    #[error(transparent)]
    SecureRngError(#[from] SecureRngError),
}

#[derive(Debug, Clone, Default)]
pub struct FerriscryptCryptoProvider;

impl FerriscryptCryptoProvider {
    pub fn hash(
        &self,
        cipher_suite: CipherSuite,
        data: &[u8],
    ) -> Result<Vec<u8>, FerriscryptCryptoError> {
        Ok(self.hash_function(cipher_suite).digest(data))
    }

    pub fn mac(
        &self,
        cipher_suite: CipherSuite,
        key: &[u8],
        data: &[u8],
    ) -> Result<Vec<u8>, FerriscryptCryptoError> {
        let hmac_key = ferriscrypt::hmac::Key::new(key, self.hash_function(cipher_suite))?;

        hmac_key
            .generate_tag(data)
            .map(|t| t.to_vec())
            .map_err(Into::into)
    }

    pub fn aead_seal(
        &self,
        cipher_suite: CipherSuite,
        key: &[u8],
        data: &[u8],
        aad: Option<&[u8]>,
        nonce: &[u8],
    ) -> Result<Vec<u8>, FerriscryptCryptoError> {
        let key = aead::Key::new(self.aead_type(cipher_suite), key.to_vec())?;

        key.encrypt_to_vec(data, aad, AeadNonce::new(nonce)?)
            .map_err(Into::into)
    }

    pub fn aead_open(
        &self,
        cipher_suite: CipherSuite,
        key: &[u8],
        cipher_text: &[u8],
        aad: Option<&[u8]>,
        nonce: &[u8],
    ) -> Result<Vec<u8>, FerriscryptCryptoError> {
        let key = aead::Key::new(self.aead_type(cipher_suite), key.to_vec())?;

        key.decrypt_from_vec(cipher_text, aad, AeadNonce::new(nonce)?)
            .map_err(Into::into)
    }

    pub fn kdf_expand(
        &self,
        cipher_suite: CipherSuite,
        prk: &[u8],
        info: &[u8],
        len: usize,
    ) -> Result<Vec<u8>, FerriscryptCryptoError> {
        let mut out = vec![0u8; len];

        Hkdf::new(self.hash_function(cipher_suite))
            .expand(prk, info, &mut out)
            .map(|_| out)
            .map_err(Into::into)
    }

    pub fn kdf_extract(
        &self,
        cipher_suite: CipherSuite,
        salt: &[u8],
        ikm: &[u8],
    ) -> Result<Vec<u8>, FerriscryptCryptoError> {
        Hkdf::new(self.hash_function(cipher_suite))
            .extract(ikm, salt)
            .map_err(Into::into)
    }

    pub fn hpke_seal(
        &self,
        cipher_suite: CipherSuite,
        remote_key: &HpkePublicKey,
        info: &[u8],
        aad: Option<&[u8]>,
        pt: &[u8],
    ) -> Result<HpkeCiphertext, FerriscryptCryptoError> {
        let hpke = self.hpke(cipher_suite);

        let remote_key = ferriscrypt::hpke::kem::HpkePublicKey::from(remote_key.0.to_vec());

        hpke.seal(&remote_key, info, None, aad, pt)
            .map(Into::into)
            .map_err(Into::into)
    }

    pub fn hpke_open(
        &self,
        cipher_suite: CipherSuite,
        ciphertext: &HpkeCiphertext,
        local_secret: &HpkeSecretKey,
        info: &[u8],
        aad: Option<&[u8]>,
    ) -> Result<Vec<u8>, FerriscryptCryptoError> {
        let hpke = self.hpke(cipher_suite);
        let ciphertext = ferriscrypt::hpke::HpkeCiphertext::from(ciphertext.clone());
        let local_secret = ferriscrypt::hpke::kem::HpkeSecretKey::from(local_secret.0.to_vec());

        hpke.open(&ciphertext, &local_secret, info, None, aad)
            .map_err(Into::into)
    }

    pub fn kem_derive(
        &self,
        cipher_suite: CipherSuite,
        ikm: &[u8],
    ) -> Result<(HpkeSecretKey, HpkePublicKey), FerriscryptCryptoError> {
        Kem::new(self.kem_type(cipher_suite))
            .derive(ikm)
            .map(|(sk, pk)| (HpkeSecretKey::from(sk), HpkePublicKey::from(pk)))
            .map_err(Into::into)
    }

    pub fn random_bytes(&self, out: &mut [u8]) -> Result<(), FerriscryptCryptoError> {
        SecureRng::fill(out).map_err(Into::into)
    }

    #[inline(always)]
    fn hash_function(&self, cipher_suite: CipherSuite) -> HashFunction {
        match cipher_suite {
            CipherSuite::Curve25519Aes128 => HashFunction::Sha256,
            CipherSuite::P256Aes128 => HashFunction::Sha256,
            CipherSuite::Curve25519ChaCha20 => HashFunction::Sha256,
            #[cfg(feature = "openssl_engine")]
            CipherSuite::Curve448Aes256 => HashFunction::Sha512,
            #[cfg(feature = "openssl_engine")]
            CipherSuite::P521Aes256 => HashFunction::Sha512,
            #[cfg(feature = "openssl_engine")]
            CipherSuite::Curve448ChaCha20 => HashFunction::Sha512,
            #[cfg(feature = "openssl_engine")]
            CipherSuite::P384Aes256 => HashFunction::Sha384,
        }
    }

    #[inline(always)]
    fn aead_type(&self, cipher_suite: CipherSuite) -> Aead {
        match cipher_suite {
            CipherSuite::Curve25519Aes128 => Aead::Aes128Gcm,
            CipherSuite::P256Aes128 => Aead::Aes128Gcm,
            CipherSuite::Curve25519ChaCha20 => Aead::Chacha20Poly1305,
            #[cfg(feature = "openssl_engine")]
            CipherSuite::Curve448Aes256 => Aead::Aes256Gcm,
            #[cfg(feature = "openssl_engine")]
            CipherSuite::P521Aes256 => Aead::Aes256Gcm,
            #[cfg(feature = "openssl_engine")]
            CipherSuite::Curve448ChaCha20 => Aead::Chacha20Poly1305,
            #[cfg(feature = "openssl_engine")]
            CipherSuite::P384Aes256 => Aead::Aes256Gcm,
        }
    }

    #[inline(always)]
    fn kem_type(&self, cipher_suite: CipherSuite) -> KemId {
        match cipher_suite {
            CipherSuite::Curve25519Aes128 => KemId::X25519HkdfSha256,
            CipherSuite::P256Aes128 => KemId::P256HkdfSha256,
            CipherSuite::Curve25519ChaCha20 => KemId::X25519HkdfSha256,
            #[cfg(feature = "openssl_engine")]
            CipherSuite::Curve448Aes256 => KemId::X448HkdfSha512,
            #[cfg(feature = "openssl_engine")]
            CipherSuite::P521Aes256 => KemId::P521HkdfSha512,
            #[cfg(feature = "openssl_engine")]
            CipherSuite::Curve448ChaCha20 => KemId::X448HkdfSha512,
            #[cfg(feature = "openssl_engine")]
            CipherSuite::P384Aes256 => KemId::P384HkdfSha384,
        }
    }

    #[inline(always)]
    fn kdf_type(&self, cipher_suite: CipherSuite) -> KdfId {
        self.kem_type(cipher_suite).kdf()
    }

    #[inline(always)]
    fn hpke(&self, cipher_suite: CipherSuite) -> Hpke {
        Hpke::new(
            self.kem_type(cipher_suite),
            self.kdf_type(cipher_suite),
            AeadId::from(self.aead_type(cipher_suite)),
        )
    }
}

impl CryptoProvider for FerriscryptCryptoProvider {
    type Error = FerriscryptCryptoError;

    fn hash(&self, cipher_suite: CipherSuite, data: &[u8]) -> Result<Vec<u8>, Self::Error> {
        self.hash(cipher_suite, data)
    }

    fn mac(
        &self,
        cipher_suite: CipherSuite,
        key: &[u8],
        data: &[u8],
    ) -> Result<Vec<u8>, Self::Error> {
        self.mac(cipher_suite, key, data)
    }

    fn aead_seal(
        &self,
        cipher_suite: CipherSuite,
        key: &[u8],
        data: &[u8],
        aad: Option<&[u8]>,
        nonce: &[u8],
    ) -> Result<Vec<u8>, Self::Error> {
        self.aead_seal(cipher_suite, key, data, aad, nonce)
    }

    fn aead_open(
        &self,
        cipher_suite: CipherSuite,
        key: &[u8],
        cipher_text: &[u8],
        aad: Option<&[u8]>,
        nonce: &[u8],
    ) -> Result<Vec<u8>, Self::Error> {
        self.aead_open(cipher_suite, key, cipher_text, aad, nonce)
    }

    fn kdf_expand(
        &self,
        cipher_suite: CipherSuite,
        prk: &[u8],
        info: &[u8],
        len: usize,
    ) -> Result<Vec<u8>, Self::Error> {
        self.kdf_expand(cipher_suite, prk, info, len)
    }

    fn kdf_extract(
        &self,
        cipher_suite: CipherSuite,
        salt: &[u8],
        ikm: &[u8],
    ) -> Result<Vec<u8>, Self::Error> {
        self.kdf_extract(cipher_suite, salt, ikm)
    }

    fn hpke_seal(
        &self,
        cipher_suite: CipherSuite,
        remote_key: &HpkePublicKey,
        info: &[u8],
        aad: Option<&[u8]>,
        pt: &[u8],
    ) -> Result<HpkeCiphertext, Self::Error> {
        self.hpke_seal(cipher_suite, remote_key, info, aad, pt)
    }

    fn hpke_open(
        &self,
        cipher_suite: CipherSuite,
        ciphertext: &HpkeCiphertext,
        local_secret: &HpkeSecretKey,
        info: &[u8],
        aad: Option<&[u8]>,
    ) -> Result<Vec<u8>, Self::Error> {
        self.hpke_open(cipher_suite, ciphertext, local_secret, info, aad)
    }

    fn kem_derive(
        &self,
        cipher_suite: CipherSuite,
        ikm: &[u8],
    ) -> Result<(HpkeSecretKey, HpkePublicKey), Self::Error> {
        self.kem_derive(cipher_suite, ikm)
    }

    fn random_bytes(&self, out: &mut [u8]) -> Result<(), Self::Error> {
        self.random_bytes(out)
    }
}

impl From<ferriscrypt::hpke::HpkeCiphertext> for HpkeCiphertext {
    fn from(ciphertext: ferriscrypt::hpke::HpkeCiphertext) -> Self {
        Self {
            kem_output: ciphertext.enc,
            ciphertext: ciphertext.ciphertext,
        }
    }
}

impl From<HpkeCiphertext> for ferriscrypt::hpke::HpkeCiphertext {
    fn from(ciphertext: HpkeCiphertext) -> Self {
        Self {
            enc: ciphertext.kem_output,
            ciphertext: ciphertext.ciphertext,
        }
    }
}

impl From<ferriscrypt::hpke::kem::HpkePublicKey> for HpkePublicKey {
    fn from(key: ferriscrypt::hpke::kem::HpkePublicKey) -> Self {
        HpkePublicKey(key.to_vec())
    }
}

impl From<HpkePublicKey> for ferriscrypt::hpke::kem::HpkePublicKey {
    fn from(key: HpkePublicKey) -> Self {
        ferriscrypt::hpke::kem::HpkePublicKey::from(key.0)
    }
}

impl From<ferriscrypt::hpke::kem::HpkeSecretKey> for HpkeSecretKey {
    fn from(key: ferriscrypt::hpke::kem::HpkeSecretKey) -> Self {
        HpkeSecretKey(key.to_vec())
    }
}

impl From<HpkeSecretKey> for ferriscrypt::hpke::kem::HpkeSecretKey {
    fn from(key: HpkeSecretKey) -> Self {
        ferriscrypt::hpke::kem::HpkeSecretKey::from(key.0)
    }
}
