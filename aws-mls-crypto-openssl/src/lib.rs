pub mod aead;
mod ec;
pub mod ec_signer;
pub mod ecdh;
pub mod kdf;
pub mod mac;

#[cfg(feature = "x509")]
pub mod x509;

use aead::Aead;
use aws_mls_crypto_hpke::{
    context::Context,
    dhkem::DhKem,
    hpke::{Hpke, HpkeError},
};
use aws_mls_crypto_traits::{AeadType, KdfType, KemType};
use ec_signer::{EcSigner, EcSignerError};
use ecdh::{Ecdh, KemId};
use kdf::Kdf;
use mac::{Hash, HashError};
use openssl::error::ErrorStack;
use thiserror::Error;

use aws_mls_core::crypto::{
    CipherSuite, CipherSuiteProvider, CryptoProvider, HpkeCiphertext, HpkePublicKey, HpkeSecretKey,
    SignaturePublicKey, SignatureSecretKey,
};

#[derive(Debug, Error)]
pub enum OpensslCryptoError {
    #[error(transparent)]
    AeadError(Box<dyn std::error::Error + Send + Sync + 'static>),
    #[error(transparent)]
    HpkeError(#[from] HpkeError),
    #[error(transparent)]
    KdfError(Box<dyn std::error::Error + Send + Sync + 'static>),
    #[error(transparent)]
    HashError(#[from] HashError),
    #[error(transparent)]
    EcSignerError(#[from] EcSignerError),
    #[error(transparent)]
    OpensslError(#[from] ErrorStack),
}

#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct OpensslCryptoProvider {
    pub enabled_cipher_suites: Vec<CipherSuite>,
}

impl OpensslCryptoProvider {
    pub fn new() -> Self {
        Default::default()
    }

    pub fn with_enabled_cipher_suites(enabled_cipher_suites: Vec<CipherSuite>) -> Self {
        Self {
            enabled_cipher_suites,
        }
    }

    pub fn all_supported_cipher_suites() -> Vec<CipherSuite> {
        CipherSuite::all().collect()
    }
}

impl Default for OpensslCryptoProvider {
    fn default() -> Self {
        Self {
            enabled_cipher_suites: Self::all_supported_cipher_suites(),
        }
    }
}

impl CryptoProvider for OpensslCryptoProvider {
    type CipherSuiteProvider = OpensslCipherSuite<DhKem<Ecdh, Kdf>, Kdf, Aead>;

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

        let kdf = Kdf::new(cipher_suite);
        let ecdh = Ecdh::new(cipher_suite);
        let kem_id = KemId::new(cipher_suite);
        let kem = DhKem::new(ecdh, kdf.clone(), kem_id as u16, kem_id.n_secret());
        let aead = Aead::new(cipher_suite);

        Some(OpensslCipherSuite::new(cipher_suite, kem, kdf, aead))
    }
}

#[derive(Clone)]
pub struct OpensslCipherSuite<KEM, KDF, AEAD>
where
    KEM: KemType + Clone,
    KDF: KdfType + Clone,
    AEAD: AeadType + Clone,
{
    cipher_suite: CipherSuite,
    aead: AEAD,
    kdf: KDF,
    hash: Hash,
    hpke: Hpke<KEM, KDF, AEAD>,
    ec_signer: EcSigner,
}

impl<KEM, KDF, AEAD> OpensslCipherSuite<KEM, KDF, AEAD>
where
    KEM: KemType + Clone,
    KDF: KdfType + Clone,
    AEAD: AeadType + Clone,
{
    pub fn new(cipher_suite: CipherSuite, kem: KEM, kdf: KDF, aead: AEAD) -> Self {
        let hpke = Hpke::new(kem, kdf.clone(), Some(aead.clone()));

        Self {
            cipher_suite,
            kdf,
            aead,
            hash: Hash::new(cipher_suite),
            hpke,
            ec_signer: EcSigner::new(cipher_suite),
        }
    }

    pub fn random_bytes(&self, out: &mut [u8]) -> Result<(), OpensslCryptoError> {
        Ok(openssl::rand::rand_bytes(out)?)
    }
}

impl<KEM, KDF, AEAD> CipherSuiteProvider for OpensslCipherSuite<KEM, KDF, AEAD>
where
    KEM: KemType + Clone + Send + Sync,
    KDF: KdfType + Clone + Send + Sync,
    AEAD: AeadType + Clone + Send + Sync,
{
    type Error = OpensslCryptoError;
    // TODO exporter_secret in this struct is not zeroized
    type HpkeContext = Context<KDF, AEAD>;

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
        self.aead
            .seal(key, data, aad, nonce)
            .map_err(|e| OpensslCryptoError::AeadError(e.into()))
    }

    fn aead_open(
        &self,
        key: &[u8],
        cipher_text: &[u8],
        aad: Option<&[u8]>,
        nonce: &[u8],
    ) -> Result<Vec<u8>, Self::Error> {
        self.aead
            .open(key, cipher_text, aad, nonce)
            .map_err(|e| OpensslCryptoError::AeadError(e.into()))
    }

    fn aead_key_size(&self) -> usize {
        self.aead.key_size()
    }

    fn aead_nonce_size(&self) -> usize {
        self.aead.nonce_size()
    }

    fn kdf_expand(&self, prk: &[u8], info: &[u8], len: usize) -> Result<Vec<u8>, Self::Error> {
        self.kdf
            .expand(prk, info, len)
            .map_err(|e| OpensslCryptoError::KdfError(e.into()))
    }

    fn kdf_extract(&self, salt: &[u8], ikm: &[u8]) -> Result<Vec<u8>, Self::Error> {
        self.kdf
            .extract(salt, ikm)
            .map_err(|e| OpensslCryptoError::KdfError(e.into()))
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
        Ok(self.hpke.seal(remote_key, info, None, aad, pt)?)
    }

    fn hpke_open(
        &self,
        ciphertext: &HpkeCiphertext,
        local_secret: &HpkeSecretKey,
        info: &[u8],
        aad: Option<&[u8]>,
    ) -> Result<Vec<u8>, Self::Error> {
        Ok(self.hpke.open(ciphertext, local_secret, info, None, aad)?)
    }

    fn hpke_setup_r(
        &self,
        enc: &[u8],
        local_secret: &HpkeSecretKey,
        info: &[u8],
    ) -> Result<Self::HpkeContext, Self::Error> {
        Ok(self.hpke.setup_receiver(enc, local_secret, info, None)?)
    }

    fn hpke_setup_s(
        &self,
        remote_key: &HpkePublicKey,
        info: &[u8],
    ) -> Result<(Vec<u8>, Self::HpkeContext), Self::Error> {
        Ok(self.hpke.setup_sender(remote_key, info, None)?)
    }

    fn kem_derive(&self, ikm: &[u8]) -> Result<(HpkeSecretKey, HpkePublicKey), Self::Error> {
        Ok(self.hpke.derive(ikm)?)
    }

    fn kem_generate(&self) -> Result<(HpkeSecretKey, HpkePublicKey), Self::Error> {
        Ok(self.hpke.generate()?)
    }

    fn kem_public_key_validate(&self, key: &HpkePublicKey) -> Result<(), Self::Error> {
        Ok(self.hpke.public_key_validate(key)?)
    }

    fn random_bytes(&self, out: &mut [u8]) -> Result<(), Self::Error> {
        self.random_bytes(out)
    }

    fn cipher_suite(&self) -> CipherSuite {
        self.cipher_suite
    }

    fn sign(&self, secret_key: &SignatureSecretKey, data: &[u8]) -> Result<Vec<u8>, Self::Error> {
        Ok(self.ec_signer.sign(secret_key, data)?)
    }

    fn verify(
        &self,
        public_key: &SignaturePublicKey,
        signature: &[u8],
        data: &[u8],
    ) -> Result<(), Self::Error> {
        Ok(self.ec_signer.verify(public_key, signature, data)?)
    }

    fn signature_key_generate(
        &self,
    ) -> Result<(SignatureSecretKey, SignaturePublicKey), Self::Error> {
        Ok(self.ec_signer.signature_key_generate()?)
    }

    fn signature_key_derive_public(
        &self,
        secret_key: &SignatureSecretKey,
    ) -> Result<SignaturePublicKey, Self::Error> {
        Ok(self.ec_signer.signature_key_derive_public(secret_key)?)
    }
}
