use std::ops::Deref;

pub use ferriscrypt;

use ferriscrypt::{
    asym::ec_key::{generate_keypair, Curve, EcKeyError, PublicKey, SecretKey},
    cipher::{
        aead::{self, Aead, AeadError, AeadNonce},
        NonceError,
    },
    digest::HashFunction,
    hmac::HMacError,
    hpke::{
        self,
        kem::{Kem, KemType},
        Hpke, HpkeError, KemId,
    },
    kdf::{hkdf::Hkdf, KdfError},
    rand::{SecureRng, SecureRngError},
};

use thiserror::Error;

use aws_mls_core::crypto::{
    CipherSuite, CipherSuiteProvider, CryptoProvider, HpkeCiphertext, HpkeContext, HpkePublicKey,
    HpkeSecretKey, SignaturePublicKey, SignatureSecretKey,
};

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
    #[error(transparent)]
    EcKeyError(#[from] EcKeyError),
    #[error("invalid signature")]
    InvalidSignature,
}

#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub struct FerriscryptCryptoProvider {
    // Note: This is a temporary pattern since Ferriscrypt will eventually be deleted in favor of a
    // direct OpenSSL / Rust Crypto provider. We will build enabled cipher suites vs specifically
    // disabling them in that version
    pub disabled_cipher_suites: Vec<CipherSuite>,
}

impl FerriscryptCryptoProvider {
    pub fn new() -> FerriscryptCryptoProvider {
        FerriscryptCryptoProvider::default()
    }

    pub fn with_disabled_cipher_suites(disabled_cipher_suites: Vec<CipherSuite>) -> Self {
        Self {
            disabled_cipher_suites,
        }
    }
}

impl CryptoProvider for FerriscryptCryptoProvider {
    type CipherSuiteProvider = FerriscryptCipherSuite;

    fn supported_cipher_suites(&self) -> Vec<CipherSuite> {
        CipherSuite::all()
            .filter(|v| !self.disabled_cipher_suites.contains(v))
            .collect()
    }

    fn cipher_suite_provider(
        &self,
        cipher_suite: CipherSuite,
    ) -> Option<Self::CipherSuiteProvider> {
        if !self.supported_cipher_suites().contains(&cipher_suite) {
            return None;
        }

        Some(FerriscryptCipherSuite::new(cipher_suite))
    }
}

#[derive(Debug, Clone)]
pub struct FerriscryptCipherSuite {
    cipher_suite: CipherSuite,
    aead: Aead,
    hash: HashFunction,
    kem: KemId,
    signature_key_curve: Curve,
}

impl FerriscryptCipherSuite {
    pub fn new(cipher_suite: CipherSuite) -> Self {
        let aead = match cipher_suite {
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
        };

        let hash = match cipher_suite {
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
        };

        let kem_id = match cipher_suite {
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
        };

        let signature_key_curve = match cipher_suite {
            CipherSuite::Curve25519Aes128 => Curve::Ed25519,
            CipherSuite::P256Aes128 => Curve::P256,
            CipherSuite::Curve25519ChaCha20 => Curve::Ed25519,
            #[cfg(feature = "openssl_engine")]
            CipherSuite::Curve448Aes256 => Curve::Ed448,
            #[cfg(feature = "openssl_engine")]
            CipherSuite::P521Aes256 => Curve::P521,
            #[cfg(feature = "openssl_engine")]
            CipherSuite::Curve448ChaCha20 => Curve::Ed448,
            #[cfg(feature = "openssl_engine")]
            CipherSuite::P384Aes256 => Curve::P384,
        };

        Self {
            cipher_suite,
            aead,
            hash,
            kem: kem_id,
            signature_key_curve,
        }
    }

    pub fn hash(&self, data: &[u8]) -> Result<Vec<u8>, FerriscryptCryptoError> {
        Ok(self.hash.digest(data))
    }

    pub fn mac(&self, key: &[u8], data: &[u8]) -> Result<Vec<u8>, FerriscryptCryptoError> {
        let hmac_key = ferriscrypt::hmac::Key::new(key, self.hash)?;

        hmac_key
            .generate_tag(data)
            .map(|t| t.to_vec())
            .map_err(Into::into)
    }

    pub fn aead_seal(
        &self,
        key: &[u8],
        data: &[u8],
        aad: Option<&[u8]>,
        nonce: &[u8],
    ) -> Result<Vec<u8>, FerriscryptCryptoError> {
        let key = aead::Key::new(self.aead, key.to_vec())?;

        key.encrypt_to_vec(data, aad, AeadNonce::new(nonce)?)
            .map_err(Into::into)
    }

    pub fn aead_open(
        &self,
        key: &[u8],
        cipher_text: &[u8],
        aad: Option<&[u8]>,
        nonce: &[u8],
    ) -> Result<Vec<u8>, FerriscryptCryptoError> {
        let key = aead::Key::new(self.aead, key.to_vec())?;

        key.decrypt_from_vec(cipher_text, aad, AeadNonce::new(nonce)?)
            .map_err(Into::into)
    }

    fn aead_key_size(&self) -> usize {
        self.aead.key_size()
    }

    fn aead_nonce_size(&self) -> usize {
        self.aead.nonce_size()
    }

    pub fn kdf_expand(
        &self,
        prk: &[u8],
        info: &[u8],
        len: usize,
    ) -> Result<Vec<u8>, FerriscryptCryptoError> {
        let mut out = vec![0u8; len];

        Hkdf::new(self.hash)
            .expand(prk, info, &mut out)
            .map(|_| out)
            .map_err(Into::into)
    }

    pub fn kdf_extract(&self, salt: &[u8], ikm: &[u8]) -> Result<Vec<u8>, FerriscryptCryptoError> {
        Hkdf::new(self.hash).extract(ikm, salt).map_err(Into::into)
    }

    pub fn kdf_extract_size(&self) -> usize {
        Hkdf::new(self.hash).extract_size()
    }

    #[inline(always)]
    fn hpke(&self) -> Hpke {
        Hpke::new(self.kem, self.kem.kdf(), self.aead.into())
    }

    pub fn hpke_seal(
        &self,
        remote_key: &HpkePublicKey,
        info: &[u8],
        aad: Option<&[u8]>,
        pt: &[u8],
    ) -> Result<HpkeCiphertext, FerriscryptCryptoError> {
        let remote_key = ferriscrypt::hpke::kem::HpkePublicKey::from(remote_key.to_vec());

        self.hpke()
            .seal(&remote_key, info, None, aad, pt)
            .map(|ciphertext| HpkeCiphertext {
                kem_output: ciphertext.enc,
                ciphertext: ciphertext.ciphertext,
            })
            .map_err(Into::into)
    }

    pub fn hpke_open(
        &self,
        ciphertext: &HpkeCiphertext,
        local_secret: &HpkeSecretKey,
        info: &[u8],
        aad: Option<&[u8]>,
    ) -> Result<Vec<u8>, FerriscryptCryptoError> {
        let ciphertext = ferriscrypt::hpke::HpkeCiphertext {
            enc: ciphertext.kem_output.clone(),
            ciphertext: ciphertext.ciphertext.clone(),
        };

        let local_secret = ferriscrypt::hpke::kem::HpkeSecretKey::from(local_secret.to_vec());

        self.hpke()
            .open(&ciphertext, &local_secret, info, None, aad)
            .map_err(Into::into)
    }

    fn hpke_setup_r(
        &self,
        enc: &[u8],
        local_secret: &HpkeSecretKey,
        info: &[u8],
    ) -> Result<hpke::Context, FerriscryptCryptoError> {
        let local_secret = ferriscrypt::hpke::kem::HpkeSecretKey::from(local_secret.to_vec());

        self.hpke()
            .setup_receiver(enc, &local_secret, info, None)
            .map_err(Into::into)
    }

    fn hpke_setup_s(
        &self,
        remote_key: &HpkePublicKey,
        info: &[u8],
    ) -> Result<(Vec<u8>, hpke::Context), FerriscryptCryptoError> {
        let remote_key = ferriscrypt::hpke::kem::HpkePublicKey::from(remote_key.to_vec());
        Ok(self.hpke().setup_sender(&remote_key, info, None)?)
    }

    pub fn kem_derive(
        &self,
        ikm: &[u8],
    ) -> Result<(HpkeSecretKey, HpkePublicKey), FerriscryptCryptoError> {
        Kem::new(self.kem)
            .derive(ikm)
            .map(|(sk, pk)| {
                (
                    HpkeSecretKey::from(sk.to_vec()),
                    HpkePublicKey::from(pk.to_vec()),
                )
            })
            .map_err(Into::into)
    }

    pub fn kem_generate(&self) -> Result<(HpkeSecretKey, HpkePublicKey), FerriscryptCryptoError> {
        let (pk, sk) = generate_keypair(self.kem.curve())?;
        Ok((sk.to_bytes()?.into(), pk.to_uncompressed_bytes()?.into()))
    }

    pub fn kem_public_key_validate(
        &self,
        key: &HpkePublicKey,
    ) -> Result<(), FerriscryptCryptoError> {
        PublicKey::from_uncompressed_bytes(key, self.kem.curve())
            .map(|_| ())
            .map_err(Into::into)
    }

    pub fn random_bytes(&self, out: &mut [u8]) -> Result<(), FerriscryptCryptoError> {
        SecureRng::fill(out).map_err(Into::into)
    }

    pub fn signature_key_generate(
        &self,
    ) -> Result<(SignatureSecretKey, SignaturePublicKey), FerriscryptCryptoError> {
        let (pk, sk) = generate_keypair(self.signature_key_curve)?;
        Ok((sk.to_bytes()?.into(), pk.to_uncompressed_bytes()?.into()))
    }

    pub fn signature_key_derive_public(
        &self,
        secret_key: &SignatureSecretKey,
    ) -> Result<SignaturePublicKey, FerriscryptCryptoError> {
        SecretKey::from_bytes(secret_key, self.signature_key_curve)?
            .to_public()?
            .to_uncompressed_bytes()
            .map(SignaturePublicKey::from)
            .map_err(Into::into)
    }

    pub fn sign(
        &self,
        secret_key: &SignatureSecretKey,
        data: &[u8],
    ) -> Result<Vec<u8>, FerriscryptCryptoError> {
        let secret_key = SecretKey::from_bytes(secret_key, self.signature_key_curve)?;

        secret_key.sign(data).map_err(Into::into)
    }

    pub fn verify(
        &self,
        public_key: &SignaturePublicKey,
        signature: &[u8],
        data: &[u8],
    ) -> Result<(), FerriscryptCryptoError> {
        let public_key = PublicKey::from_uncompressed_bytes(public_key, self.signature_key_curve)?;

        public_key
            .verify(signature, data)?
            .then_some(())
            .ok_or(FerriscryptCryptoError::InvalidSignature)
    }
}

impl CipherSuiteProvider for FerriscryptCipherSuite {
    type Error = FerriscryptCryptoError;
    // TODO exporter_secret in this struct is not zeroized
    type HpkeContext = FerriscryptHpkeContext;

    fn hash(&self, data: &[u8]) -> Result<Vec<u8>, Self::Error> {
        self.hash(data)
    }

    fn mac(&self, key: &[u8], data: &[u8]) -> Result<Vec<u8>, Self::Error> {
        self.mac(key, data)
    }

    fn aead_seal(
        &self,
        key: &[u8],
        data: &[u8],
        aad: Option<&[u8]>,
        nonce: &[u8],
    ) -> Result<Vec<u8>, Self::Error> {
        self.aead_seal(key, data, aad, nonce)
    }

    fn aead_open(
        &self,
        key: &[u8],
        cipher_text: &[u8],
        aad: Option<&[u8]>,
        nonce: &[u8],
    ) -> Result<Vec<u8>, Self::Error> {
        self.aead_open(key, cipher_text, aad, nonce)
    }

    fn aead_key_size(&self) -> usize {
        self.aead_key_size()
    }

    fn aead_nonce_size(&self) -> usize {
        self.aead_nonce_size()
    }

    fn kdf_expand(&self, prk: &[u8], info: &[u8], len: usize) -> Result<Vec<u8>, Self::Error> {
        self.kdf_expand(prk, info, len)
    }

    fn kdf_extract(&self, salt: &[u8], ikm: &[u8]) -> Result<Vec<u8>, Self::Error> {
        self.kdf_extract(salt, ikm)
    }

    fn kdf_extract_size(&self) -> usize {
        self.kdf_extract_size()
    }

    fn hpke_seal(
        &self,
        remote_key: &HpkePublicKey,
        info: &[u8],
        aad: Option<&[u8]>,
        pt: &[u8],
    ) -> Result<HpkeCiphertext, Self::Error> {
        self.hpke_seal(remote_key, info, aad, pt)
    }

    fn hpke_open(
        &self,
        ciphertext: &HpkeCiphertext,
        local_secret: &HpkeSecretKey,
        info: &[u8],
        aad: Option<&[u8]>,
    ) -> Result<Vec<u8>, Self::Error> {
        self.hpke_open(ciphertext, local_secret, info, aad)
    }

    fn hpke_setup_r(
        &self,
        enc: &[u8],
        local_secret: &HpkeSecretKey,
        info: &[u8],
    ) -> Result<Self::HpkeContext, Self::Error> {
        self.hpke_setup_r(enc, local_secret, info)
            .map(FerriscryptHpkeContext)
    }

    fn hpke_setup_s(
        &self,
        remote_key: &HpkePublicKey,
        info: &[u8],
    ) -> Result<(Vec<u8>, Self::HpkeContext), Self::Error> {
        self.hpke_setup_s(remote_key, info)
            .map(|(v, c)| (v, FerriscryptHpkeContext(c)))
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

pub struct FerriscryptHpkeContext(hpke::Context);

impl Deref for FerriscryptHpkeContext {
    type Target = hpke::Context;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl HpkeContext for FerriscryptHpkeContext {
    type Error = HpkeError;

    fn open(&mut self, aad: Option<&[u8]>, ciphertext: &[u8]) -> Result<Vec<u8>, Self::Error> {
        self.0.open(aad, ciphertext)
    }

    fn seal(&mut self, aad: Option<&[u8]>, data: &[u8]) -> Result<Vec<u8>, Self::Error> {
        self.0.seal(aad, data)
    }

    fn export(&self, exporter_context: &[u8], len: usize) -> Result<Vec<u8>, Self::Error> {
        let mut buf = vec![0; len];
        self.0.export(exporter_context, &mut buf)?;
        Ok(buf)
    }
}
