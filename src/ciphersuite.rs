use crate::crypto::aead::{aes, chacha20, Cipher, CipherError};
use crate::crypto::asym::AsymmetricKey;
use crate::crypto::asym::{AsymmetricKeyError, PublicKey, SecretKey};
use crate::crypto::hash;
use crate::crypto::hash::{HashError, HashFunction, Mac};
use crate::crypto::hpke;
use crate::crypto::hpke::{HPKECiphertext, HPKEError, Hpke};
use crate::crypto::kdf;
use crate::crypto::kdf::Kdf;
use crate::crypto::kem::Kem;
use crate::crypto::rand::SecureRng;
use crate::crypto::signature;
use crate::crypto::signature::{SignatureError, SignatureScheme};
use crate::key_schedule::KeyScheduleKdf;
use crate::protocol_version::ProtocolVersion;
use num_enum::{IntoPrimitive, TryFromPrimitive};
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(IntoPrimitive, TryFromPrimitive, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[repr(u16)]
#[serde(into = "u16", try_from = "u16")]
pub enum CipherSuite {
    Mls10128Dhkemx25519Aes128gcmSha256Ed25519 = 0x0001,
    Mls10128Dhkemp256Aes128gcmSha256P256 = 0x0002,
    Mls10128Dhkemx25519Chacha20poly1305Sha256Ed25519 = 0x0003,
    //MLS10_256_DHKEMX448_AES256GCM_SHA512_Ed448 = 0x0004, // Unsupported
    Mls10256Dhkemp521Aes256gcmSha512P521 = 0x0005,
    //MLS10_256_DHKEMX448_CHACHA20POLY1305_SHA512_Ed448 = 0x0006, // Unsupported
}

#[derive(Error, Debug)]
pub enum CipherSuiteError {
    #[error(transparent)]
    SignatureError(#[from] SignatureError),
    #[error(transparent)]
    AsymmetricKeyError(#[from] AsymmetricKeyError),
    #[error(transparent)]
    RngError(#[from] rand_core::Error),
    #[error(transparent)]
    KdfError(#[from] kdf::KdfError),
    #[error(transparent)]
    HpkeError(#[from] HPKEError),
    #[error(transparent)]
    HashError(#[from] HashError),
    #[error(transparent)]
    CipherError(#[from] CipherError),
}

pub trait CipherSuiteType {
    type HPKE: Hpke;
    type KDF: KeyScheduleKdf;
    type AEAD: Cipher;
    type H: HashFunction;
    type SS: SignatureScheme;

    const SUITE_ID: u16;
    const PROTOCOL_VERSION: ProtocolVersion;

    fn generate_kem_key_pair<RNG: SecureRng + 'static>(
        rng: &mut RNG,
    ) -> Result<KemKeyPair, CipherSuiteError> {
        let (pk, sk) = <<Self::HPKE as Hpke>::KEM as Kem>::generate_kem_key_pair(rng)?;
        Ok(KemKeyPair {
            public_key: pk.to_bytes()?,
            secret_key: sk.to_bytes()?,
        })
    }

    fn derive_kem_key_pair(ikm: &[u8]) -> Result<KemKeyPair, CipherSuiteError> {
        let (pk, sk) = <<Self::HPKE as Hpke>::KEM as Kem>::derive_key_pair(ikm)?;
        Ok(KemKeyPair {
            public_key: pk.to_bytes()?,
            secret_key: sk.to_bytes()?,
        })
    }

    fn get_protocol_version() -> ProtocolVersion {
        Self::PROTOCOL_VERSION
    }

    fn extract_size() -> u16 {
        Self::KDF::EXTRACT_SIZE
    }

    fn hmac(key: &[u8], message: &[u8]) -> Result<Mac, CipherSuiteError> {
        Self::H::hmac(key, message).map_err(|e| e.into())
    }

    fn hash(value: &[u8]) -> Result<Vec<u8>, CipherSuiteError> {
        Self::H::hash(value).map_err(|e| e.into())
    }

    fn generate_leaf_secret<RNG: SecureRng + 'static>(
        rng: &mut RNG,
    ) -> Result<Vec<u8>, CipherSuiteError> {
        let mut ret = vec![0u8; <<Self::HPKE as Hpke>::KEM as Kem>::N_SECRET as usize];
        rng.try_fill_bytes(&mut ret)?;
        Ok(ret)
    }

    fn generate_init_secret<RNG: SecureRng + 'static>(
        rng: &mut RNG,
    ) -> Result<Vec<u8>, CipherSuiteError> {
        let mut ret = vec![0u8; Self::KDF::EXTRACT_SIZE as usize];
        rng.try_fill_bytes(&mut ret)?;
        Ok(ret)
    }

    fn extract(salt: &[u8], key: &[u8]) -> Result<Vec<u8>, CipherSuiteError> {
        Self::KDF::extract(salt, key).map_err(|e| e.into())
    }

    fn expand(secret: &[u8], info: &[u8], e_type: ExpandType) -> Result<Vec<u8>, CipherSuiteError> {
        let len = match e_type {
            ExpandType::Secret => Self::KDF::EXTRACT_SIZE,
            ExpandType::AeadKey => Self::AEAD::KEY_LEN,
            ExpandType::AeadNonce => Self::AEAD::NONCE_LEN,
        };

        Self::KDF::expand(secret, info, len).map_err(|e| e.into())
    }

    fn expand_with_label(
        secret: &[u8],
        label: &str,
        context: &[u8],
        e_type: ExpandType,
    ) -> Result<Vec<u8>, CipherSuiteError> {
        let len = match e_type {
            ExpandType::Secret => Self::KDF::EXTRACT_SIZE,
            ExpandType::AeadKey => Self::AEAD::KEY_LEN,
            ExpandType::AeadNonce => Self::AEAD::NONCE_LEN,
        };

        Self::KDF::expand_with_label(secret, label, context, len).map_err(|e| e.into())
    }

    fn derive_secret(secret: &[u8], label: &str) -> Result<Vec<u8>, CipherSuiteError> {
        Self::KDF::derive_secret(secret, label).map_err(|e| e.into())
    }

    fn derive_tree_secret(
        secret: &[u8],
        label: &str,
        node: u32,
        generation: u32,
        e_type: ExpandType,
    ) -> Result<Vec<u8>, CipherSuiteError> {
        let len = match e_type {
            ExpandType::Secret => Self::KDF::EXTRACT_SIZE,
            ExpandType::AeadKey => Self::AEAD::KEY_LEN,
            ExpandType::AeadNonce => Self::AEAD::NONCE_LEN,
        };
        Self::KDF::derive_tree_secret(secret, label, node, generation, len).map_err(|e| e.into())
    }

    fn import_pub_key<PK>(data: &[u8]) -> Result<PK, CipherSuiteError>
    where
        PK: PublicKey,
    {
        PK::from_bytes(data).map_err(|e| e.into())
    }

    fn import_secret_key<SK>(data: &[u8]) -> Result<SK, CipherSuiteError>
    where
        SK: SecretKey,
    {
        SK::from_bytes(data).map_err(|e| e.into())
    }

    fn hpke_seal<RNG: SecureRng + 'static>(
        rng: &mut RNG,
        public_key: &[u8],
        aad: &[u8],
        pt: &[u8],
    ) -> Result<HPKECiphertext, CipherSuiteError> {
        let pub_key = Self::import_pub_key(public_key)?;
        Self::HPKE::seal_basic(rng, &pub_key, &[], aad, pt).map_err(|e| e.into())
    }

    fn hpke_open(
        ct: &HPKECiphertext,
        secret_key: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, CipherSuiteError> {
        let secret_key = Self::import_secret_key(secret_key)?;
        Self::HPKE::open_basic(ct, &secret_key, &[], aad).map_err(|e| e.into())
    }

    fn aead_encrypt(
        key: Vec<u8>,
        plaintext: &[u8],
        aad: &[u8],
        nonce: &[u8],
    ) -> Result<Vec<u8>, CipherSuiteError> {
        let aead = Self::AEAD::new(key)?;
        aead.encrypt(plaintext, aad, nonce).map_err(|e| e.into())
    }

    fn aead_decrypt(
        key: Vec<u8>,
        ciphertext: &[u8],
        aad: &[u8],
        nonce: &[u8],
    ) -> Result<Vec<u8>, CipherSuiteError> {
        let aead = Self::AEAD::new(key)?;
        aead.decrypt(nonce, ciphertext, aad).map_err(|e| e.into())
    }
}

#[derive(Clone, PartialEq, Debug)]
pub struct KemKeyPair {
    pub public_key: Vec<u8>,
    pub secret_key: Vec<u8>,
}

#[derive(Clone, Copy, PartialEq, Debug)]
pub enum ExpandType {
    Secret,
    AeadKey,
    AeadNonce,
}

impl CipherSuite {
    pub fn generate_leaf_secret<RNG: SecureRng + 'static>(
        &self,
        rng: &mut RNG,
    ) -> Result<Vec<u8>, CipherSuiteError> {
        match self {
            CipherSuite::Mls10128Dhkemx25519Aes128gcmSha256Ed25519 => {
                Mls10DhKem25519Aes128GcmSha256Ed25519::generate_leaf_secret(rng)
            }
            CipherSuite::Mls10128Dhkemp256Aes128gcmSha256P256 => {
                Mls10DhKemP256Aes128GcmSha256P256::generate_leaf_secret(rng)
            }
            CipherSuite::Mls10128Dhkemx25519Chacha20poly1305Sha256Ed25519 => {
                Mls10DhKem25519ChaChaPoly1305Sha256Ed25519::generate_leaf_secret(rng)
            }
            CipherSuite::Mls10256Dhkemp521Aes256gcmSha512P521 => {
                Mls10DhKemP521Aes256GcmSha512P521::generate_leaf_secret(rng)
            }
        }
    }

    pub fn extract_size(&self) -> u16 {
        match self {
            CipherSuite::Mls10128Dhkemx25519Aes128gcmSha256Ed25519 => {
                Mls10DhKem25519Aes128GcmSha256Ed25519::extract_size()
            }
            CipherSuite::Mls10128Dhkemp256Aes128gcmSha256P256 => {
                Mls10DhKemP256Aes128GcmSha256P256::extract_size()
            }
            CipherSuite::Mls10128Dhkemx25519Chacha20poly1305Sha256Ed25519 => {
                Mls10DhKem25519ChaChaPoly1305Sha256Ed25519::extract_size()
            }
            CipherSuite::Mls10256Dhkemp521Aes256gcmSha512P521 => {
                Mls10DhKemP521Aes256GcmSha512P521::extract_size()
            }
        }
    }

    pub fn hmac(&self, key: &[u8], message: &[u8]) -> Result<Mac, CipherSuiteError> {
        match self {
            CipherSuite::Mls10128Dhkemx25519Aes128gcmSha256Ed25519 => {
                Mls10DhKem25519Aes128GcmSha256Ed25519::hmac(key, message)
            }
            CipherSuite::Mls10128Dhkemp256Aes128gcmSha256P256 => {
                Mls10DhKemP256Aes128GcmSha256P256::hmac(key, message)
            }
            CipherSuite::Mls10128Dhkemx25519Chacha20poly1305Sha256Ed25519 => {
                Mls10DhKem25519ChaChaPoly1305Sha256Ed25519::hmac(key, message)
            }
            CipherSuite::Mls10256Dhkemp521Aes256gcmSha512P521 => {
                Mls10DhKemP521Aes256GcmSha512P521::hmac(key, message)
            }
        }
    }

    pub fn hash(&self, value: &[u8]) -> Result<Vec<u8>, CipherSuiteError> {
        match self {
            CipherSuite::Mls10128Dhkemx25519Aes128gcmSha256Ed25519 => {
                Mls10DhKem25519Aes128GcmSha256Ed25519::hash(value)
            }
            CipherSuite::Mls10128Dhkemp256Aes128gcmSha256P256 => {
                Mls10DhKemP256Aes128GcmSha256P256::hash(value)
            }
            CipherSuite::Mls10128Dhkemx25519Chacha20poly1305Sha256Ed25519 => {
                Mls10DhKem25519ChaChaPoly1305Sha256Ed25519::hash(value)
            }
            CipherSuite::Mls10256Dhkemp521Aes256gcmSha512P521 => {
                Mls10DhKemP521Aes256GcmSha512P521::hash(value)
            }
        }
    }

    pub fn generate_init_secret<RNG: SecureRng + 'static>(
        &self,
        rng: &mut RNG,
    ) -> Result<Vec<u8>, CipherSuiteError> {
        match self {
            CipherSuite::Mls10128Dhkemx25519Aes128gcmSha256Ed25519 => {
                Mls10DhKem25519Aes128GcmSha256Ed25519::generate_init_secret(rng)
            }
            CipherSuite::Mls10128Dhkemp256Aes128gcmSha256P256 => {
                Mls10DhKemP256Aes128GcmSha256P256::generate_init_secret(rng)
            }
            CipherSuite::Mls10128Dhkemx25519Chacha20poly1305Sha256Ed25519 => {
                Mls10DhKem25519ChaChaPoly1305Sha256Ed25519::generate_init_secret(rng)
            }
            CipherSuite::Mls10256Dhkemp521Aes256gcmSha512P521 => {
                Mls10DhKemP521Aes256GcmSha512P521::generate_init_secret(rng)
            }
        }
    }

    pub fn generate_kem_key_pair<RNG: SecureRng + 'static>(
        &self,
        rng: &mut RNG,
    ) -> Result<KemKeyPair, CipherSuiteError> {
        match self {
            CipherSuite::Mls10128Dhkemx25519Aes128gcmSha256Ed25519 => {
                Mls10DhKem25519Aes128GcmSha256Ed25519::generate_kem_key_pair(rng)
            }
            CipherSuite::Mls10128Dhkemp256Aes128gcmSha256P256 => {
                Mls10DhKemP256Aes128GcmSha256P256::generate_kem_key_pair(rng)
            }
            CipherSuite::Mls10128Dhkemx25519Chacha20poly1305Sha256Ed25519 => {
                Mls10DhKem25519ChaChaPoly1305Sha256Ed25519::generate_kem_key_pair(rng)
            }
            CipherSuite::Mls10256Dhkemp521Aes256gcmSha512P521 => {
                Mls10DhKemP521Aes256GcmSha512P521::generate_kem_key_pair(rng)
            }
        }
    }

    pub fn derive_kem_key_pair(&self, ikm: &[u8]) -> Result<KemKeyPair, CipherSuiteError> {
        match self {
            CipherSuite::Mls10128Dhkemx25519Aes128gcmSha256Ed25519 => {
                Mls10DhKem25519Aes128GcmSha256Ed25519::derive_kem_key_pair(ikm)
            }
            CipherSuite::Mls10128Dhkemp256Aes128gcmSha256P256 => {
                Mls10DhKemP256Aes128GcmSha256P256::derive_kem_key_pair(ikm)
            }
            CipherSuite::Mls10128Dhkemx25519Chacha20poly1305Sha256Ed25519 => {
                Mls10DhKem25519ChaChaPoly1305Sha256Ed25519::derive_kem_key_pair(ikm)
            }
            CipherSuite::Mls10256Dhkemp521Aes256gcmSha512P521 => {
                Mls10DhKemP521Aes256GcmSha512P521::derive_kem_key_pair(ikm)
            }
        }
    }

    pub fn get_protocol_version(&self) -> ProtocolVersion {
        match self {
            CipherSuite::Mls10128Dhkemx25519Aes128gcmSha256Ed25519 => {
                Mls10DhKem25519Aes128GcmSha256Ed25519::get_protocol_version()
            }
            CipherSuite::Mls10128Dhkemp256Aes128gcmSha256P256 => {
                Mls10DhKemP256Aes128GcmSha256P256::get_protocol_version()
            }
            CipherSuite::Mls10128Dhkemx25519Chacha20poly1305Sha256Ed25519 => {
                Mls10DhKem25519ChaChaPoly1305Sha256Ed25519::get_protocol_version()
            }
            CipherSuite::Mls10256Dhkemp521Aes256gcmSha512P521 => {
                Mls10DhKemP521Aes256GcmSha512P521::get_protocol_version()
            }
        }
    }

    pub fn derive_secret(&self, secret: &[u8], label: &str) -> Result<Vec<u8>, CipherSuiteError> {
        match self {
            CipherSuite::Mls10128Dhkemx25519Aes128gcmSha256Ed25519 => {
                Mls10DhKem25519Aes128GcmSha256Ed25519::derive_secret(secret, label)
            }
            CipherSuite::Mls10128Dhkemp256Aes128gcmSha256P256 => {
                Mls10DhKemP256Aes128GcmSha256P256::derive_secret(secret, label)
            }
            CipherSuite::Mls10128Dhkemx25519Chacha20poly1305Sha256Ed25519 => {
                Mls10DhKem25519ChaChaPoly1305Sha256Ed25519::derive_secret(secret, label)
            }
            CipherSuite::Mls10256Dhkemp521Aes256gcmSha512P521 => {
                Mls10DhKemP521Aes256GcmSha512P521::derive_secret(secret, label)
            }
        }
    }

    pub fn extract(&self, salt: &[u8], key: &[u8]) -> Result<Vec<u8>, CipherSuiteError> {
        match self {
            CipherSuite::Mls10128Dhkemx25519Aes128gcmSha256Ed25519 => {
                Mls10DhKem25519Aes128GcmSha256Ed25519::extract(salt, key)
            }
            CipherSuite::Mls10128Dhkemp256Aes128gcmSha256P256 => {
                Mls10DhKemP256Aes128GcmSha256P256::extract(salt, key)
            }
            CipherSuite::Mls10128Dhkemx25519Chacha20poly1305Sha256Ed25519 => {
                Mls10DhKem25519ChaChaPoly1305Sha256Ed25519::extract(salt, key)
            }
            CipherSuite::Mls10256Dhkemp521Aes256gcmSha512P521 => {
                Mls10DhKemP521Aes256GcmSha512P521::extract(salt, key)
            }
        }
    }

    pub fn expand(
        &self,
        secret: &[u8],
        info: &[u8],
        e_type: ExpandType,
    ) -> Result<Vec<u8>, CipherSuiteError> {
        match self {
            CipherSuite::Mls10128Dhkemx25519Aes128gcmSha256Ed25519 => {
                Mls10DhKem25519Aes128GcmSha256Ed25519::expand(secret, info, e_type)
            }
            CipherSuite::Mls10128Dhkemp256Aes128gcmSha256P256 => {
                Mls10DhKemP256Aes128GcmSha256P256::expand(secret, info, e_type)
            }
            CipherSuite::Mls10128Dhkemx25519Chacha20poly1305Sha256Ed25519 => {
                Mls10DhKem25519ChaChaPoly1305Sha256Ed25519::expand(secret, info, e_type)
            }
            CipherSuite::Mls10256Dhkemp521Aes256gcmSha512P521 => {
                Mls10DhKemP521Aes256GcmSha512P521::expand(secret, info, e_type)
            }
        }
    }

    pub fn expand_with_label(
        &self,
        secret: &[u8],
        label: &str,
        context: &[u8],
        e_type: ExpandType,
    ) -> Result<Vec<u8>, CipherSuiteError> {
        match self {
            CipherSuite::Mls10128Dhkemx25519Aes128gcmSha256Ed25519 => {
                Mls10DhKem25519Aes128GcmSha256Ed25519::expand_with_label(
                    secret, label, context, e_type,
                )
            }
            CipherSuite::Mls10128Dhkemp256Aes128gcmSha256P256 => {
                Mls10DhKemP256Aes128GcmSha256P256::expand_with_label(secret, label, context, e_type)
            }
            CipherSuite::Mls10128Dhkemx25519Chacha20poly1305Sha256Ed25519 => {
                Mls10DhKem25519ChaChaPoly1305Sha256Ed25519::expand_with_label(
                    secret, label, context, e_type,
                )
            }
            CipherSuite::Mls10256Dhkemp521Aes256gcmSha512P521 => {
                Mls10DhKemP521Aes256GcmSha512P521::expand_with_label(secret, label, context, e_type)
            }
        }
    }

    pub fn derive_tree_secret(
        &self,
        secret: &[u8],
        label: &str,
        node: u32,
        generation: u32,
        e_type: ExpandType,
    ) -> Result<Vec<u8>, CipherSuiteError> {
        match self {
            CipherSuite::Mls10128Dhkemx25519Aes128gcmSha256Ed25519 => {
                Mls10DhKem25519Aes128GcmSha256Ed25519::derive_tree_secret(
                    secret, label, node, generation, e_type,
                )
            }
            CipherSuite::Mls10128Dhkemp256Aes128gcmSha256P256 => {
                Mls10DhKemP256Aes128GcmSha256P256::derive_tree_secret(
                    secret, label, node, generation, e_type,
                )
            }
            CipherSuite::Mls10128Dhkemx25519Chacha20poly1305Sha256Ed25519 => {
                Mls10DhKem25519ChaChaPoly1305Sha256Ed25519::derive_tree_secret(
                    secret, label, node, generation, e_type,
                )
            }
            CipherSuite::Mls10256Dhkemp521Aes256gcmSha512P521 => {
                Mls10DhKemP521Aes256GcmSha512P521::derive_tree_secret(
                    secret, label, node, generation, e_type,
                )
            }
        }
    }

    pub fn hpke_seal<RNG: SecureRng + 'static>(
        &self,
        rng: &mut RNG,
        public_key: &[u8],
        aad: &[u8],
        pt: &[u8],
    ) -> Result<HPKECiphertext, CipherSuiteError> {
        match self {
            CipherSuite::Mls10128Dhkemx25519Aes128gcmSha256Ed25519 => {
                Mls10DhKem25519Aes128GcmSha256Ed25519::hpke_seal(rng, public_key, aad, pt)
            }
            CipherSuite::Mls10128Dhkemp256Aes128gcmSha256P256 => {
                Mls10DhKemP256Aes128GcmSha256P256::hpke_seal(rng, public_key, aad, pt)
            }
            CipherSuite::Mls10128Dhkemx25519Chacha20poly1305Sha256Ed25519 => {
                Mls10DhKem25519ChaChaPoly1305Sha256Ed25519::hpke_seal(rng, public_key, aad, pt)
            }
            CipherSuite::Mls10256Dhkemp521Aes256gcmSha512P521 => {
                Mls10DhKemP521Aes256GcmSha512P521::hpke_seal(rng, public_key, aad, pt)
            }
        }
    }

    pub fn hpke_open(
        &self,
        ct: &HPKECiphertext,
        secret_key: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, CipherSuiteError> {
        match self {
            CipherSuite::Mls10128Dhkemx25519Aes128gcmSha256Ed25519 => {
                Mls10DhKem25519Aes128GcmSha256Ed25519::hpke_open(ct, secret_key, aad)
            }
            CipherSuite::Mls10128Dhkemp256Aes128gcmSha256P256 => {
                Mls10DhKemP256Aes128GcmSha256P256::hpke_open(ct, secret_key, aad)
            }
            CipherSuite::Mls10128Dhkemx25519Chacha20poly1305Sha256Ed25519 => {
                Mls10DhKem25519ChaChaPoly1305Sha256Ed25519::hpke_open(ct, secret_key, aad)
            }
            CipherSuite::Mls10256Dhkemp521Aes256gcmSha512P521 => {
                Mls10DhKemP521Aes256GcmSha512P521::hpke_open(ct, secret_key, aad)
            }
        }
    }

    pub fn aead_encrypt(
        &self,
        key: Vec<u8>,
        data: &[u8],
        aad: &[u8],
        nonce: &[u8],
    ) -> Result<Vec<u8>, CipherSuiteError> {
        match self {
            CipherSuite::Mls10128Dhkemx25519Aes128gcmSha256Ed25519 => {
                Mls10DhKem25519Aes128GcmSha256Ed25519::aead_encrypt(key, data, aad, nonce)
            }
            CipherSuite::Mls10128Dhkemp256Aes128gcmSha256P256 => {
                Mls10DhKemP256Aes128GcmSha256P256::aead_encrypt(key, data, aad, nonce)
            }
            CipherSuite::Mls10128Dhkemx25519Chacha20poly1305Sha256Ed25519 => {
                Mls10DhKem25519ChaChaPoly1305Sha256Ed25519::aead_encrypt(key, data, aad, nonce)
            }
            CipherSuite::Mls10256Dhkemp521Aes256gcmSha512P521 => {
                Mls10DhKemP521Aes256GcmSha512P521::aead_encrypt(key, data, aad, nonce)
            }
        }
    }

    pub fn aead_decrypt(
        &self,
        key: Vec<u8>,
        data: &[u8],
        aad: &[u8],
        nonce: &[u8],
    ) -> Result<Vec<u8>, CipherSuiteError> {
        match self {
            CipherSuite::Mls10128Dhkemx25519Aes128gcmSha256Ed25519 => {
                Mls10DhKem25519Aes128GcmSha256Ed25519::aead_decrypt(key, data, aad, nonce)
            }
            CipherSuite::Mls10128Dhkemp256Aes128gcmSha256P256 => {
                Mls10DhKemP256Aes128GcmSha256P256::aead_decrypt(key, data, aad, nonce)
            }
            CipherSuite::Mls10128Dhkemx25519Chacha20poly1305Sha256Ed25519 => {
                Mls10DhKem25519ChaChaPoly1305Sha256Ed25519::aead_decrypt(key, data, aad, nonce)
            }
            CipherSuite::Mls10256Dhkemp521Aes256gcmSha512P521 => {
                Mls10DhKemP521Aes256GcmSha512P521::aead_decrypt(key, data, aad, nonce)
            }
        }
    }
}

macro_rules! impl_cipher_suite_type {
    ($name:ident, $hpke:ty, $kdf:ty, $aead:ty, $hash:ty, $signature_scheme:ty, $suite_id:expr, $protocol_version:expr) => {
        #[derive(Clone, PartialEq, Debug)]
        pub struct $name;

        impl CipherSuiteType for $name {
            type HPKE = $hpke;
            type KDF = $kdf;
            type AEAD = $aead;
            type H = $hash;
            type SS = $signature_scheme;
            const SUITE_ID: u16 = $suite_id;
            const PROTOCOL_VERSION: ProtocolVersion = $protocol_version;
        }
    };
}

impl_cipher_suite_type!(
    Mls10DhKem25519Aes128GcmSha256Ed25519,
    hpke::X25519HkdfSha256Aes128Gcm,
    kdf::HkdfSha256,
    aes::Gcm128,
    hash::Sha256,
    signature::ed25519::EdDsa25519,
    CipherSuite::Mls10128Dhkemx25519Aes128gcmSha256Ed25519 as u16,
    ProtocolVersion::Mls10
);
impl_cipher_suite_type!(
    Mls10DhKemP256Aes128GcmSha256P256,
    hpke::P256HkdfSha256Aes128Gcm,
    kdf::HkdfSha256,
    aes::Gcm128,
    hash::Sha256,
    signature::p256::EcDsaP256,
    CipherSuite::Mls10128Dhkemp256Aes128gcmSha256P256 as u16,
    ProtocolVersion::Mls10
);
impl_cipher_suite_type!(
    Mls10DhKem25519ChaChaPoly1305Sha256Ed25519,
    hpke::X25519HkdfSha256ChaCha20,
    kdf::HkdfSha256,
    chacha20::Poly1305,
    hash::Sha256,
    signature::ed25519::EdDsa25519,
    CipherSuite::Mls10128Dhkemx25519Chacha20poly1305Sha256Ed25519 as u16,
    ProtocolVersion::Mls10
);
impl_cipher_suite_type!(
    Mls10DhKemP521Aes256GcmSha512P521,
    hpke::P521HkdfSha512Aes256Gcm,
    kdf::HkdfSha512,
    aes::Gcm256,
    hash::Sha512,
    signature::p521::EcDsaP521,
    CipherSuite::Mls10256Dhkemp521Aes256gcmSha512P521 as u16,
    ProtocolVersion::Mls10
);

#[cfg(test)]
mod test {
    use super::test_util;
    use crate::ciphersuite::{
        CipherSuite, CipherSuiteType, ExpandType, Mls10DhKem25519Aes128GcmSha256Ed25519,
        Mls10DhKem25519ChaChaPoly1305Sha256Ed25519, Mls10DhKemP256Aes128GcmSha256P256,
        Mls10DhKemP521Aes256GcmSha512P521,
    };
    use crate::crypto::asym::test_util::MockPublicKey;
    use crate::crypto::asym::test_util::MockSecretKey;
    use crate::crypto::kem::test_util::MockTestKem;
    use crate::crypto::rand::test_rng::{RepeatRng, ZerosRng};
    use crate::key_schedule::test_util::MockTestKeyScheduleKdf;

    #[test]
    fn test_protocol_version() {
        assert_eq!(
            CipherSuite::Mls10128Dhkemx25519Aes128gcmSha256Ed25519.get_protocol_version(),
            Mls10DhKem25519Aes128GcmSha256Ed25519::PROTOCOL_VERSION
        );

        assert_eq!(
            CipherSuite::Mls10128Dhkemp256Aes128gcmSha256P256.get_protocol_version(),
            Mls10DhKemP256Aes128GcmSha256P256::PROTOCOL_VERSION
        );

        assert_eq!(
            CipherSuite::Mls10128Dhkemx25519Chacha20poly1305Sha256Ed25519.get_protocol_version(),
            Mls10DhKem25519ChaChaPoly1305Sha256Ed25519::PROTOCOL_VERSION
        );

        assert_eq!(
            CipherSuite::Mls10256Dhkemp521Aes256gcmSha512P521.get_protocol_version(),
            Mls10DhKemP521Aes256GcmSha512P521::PROTOCOL_VERSION
        );
    }

    #[test]
    fn test_generate_kem_keypair_trait() {
        let mock_kem = MockTestKem::generate_kem_key_pair_context();
        mock_kem.expect().returning(|_: &mut ZerosRng| {
            let mut mock_pub = MockPublicKey::new();
            mock_pub
                .expect_to_bytes()
                .returning_st(move || Ok(vec![0; 4]));
            let mut mock_pri = MockSecretKey::new();
            mock_pri
                .expect_to_bytes()
                .returning_st(move || Ok(vec![0; 2]));
            Ok((mock_pub, mock_pri))
        });

        let res = test_util::MockTestCipherSuiteType::generate_kem_key_pair(&mut ZerosRng)
            .expect("failed key pair gen");
        assert_eq!(res.public_key, vec![0; 4]);
        assert_eq!(res.secret_key, vec![0; 2]);
    }

    #[test]
    fn test_generate_kem_keypair() {
        assert_eq!(
            CipherSuite::Mls10128Dhkemx25519Aes128gcmSha256Ed25519
                .generate_kem_key_pair(&mut ZerosRng)
                .unwrap(),
            Mls10DhKem25519Aes128GcmSha256Ed25519::generate_kem_key_pair(&mut ZerosRng).unwrap()
        );

        assert_eq!(
            CipherSuite::Mls10128Dhkemp256Aes128gcmSha256P256
                .generate_kem_key_pair(&mut ZerosRng)
                .unwrap(),
            Mls10DhKemP256Aes128GcmSha256P256::generate_kem_key_pair(&mut ZerosRng).unwrap()
        );

        assert_eq!(
            CipherSuite::Mls10128Dhkemx25519Chacha20poly1305Sha256Ed25519
                .generate_kem_key_pair(&mut ZerosRng)
                .unwrap(),
            Mls10DhKem25519ChaChaPoly1305Sha256Ed25519::generate_kem_key_pair(&mut ZerosRng)
                .unwrap()
        );

        assert_eq!(
            CipherSuite::Mls10256Dhkemp521Aes256gcmSha512P521
                .generate_kem_key_pair(&mut ZerosRng)
                .unwrap(),
            Mls10DhKemP521Aes256GcmSha512P521::generate_kem_key_pair(&mut ZerosRng).unwrap()
        );
    }

    #[test]
    fn test_derive_kem_keypair_trait() {
        let mock_kem = MockTestKem::derive_key_pair_context();
        mock_kem.expect().returning(|ikm| {
            let public = ikm.to_vec();
            let private = vec![0u8; ikm.len()];
            let mut mock_pub = MockPublicKey::new();
            mock_pub
                .expect_to_bytes()
                .returning_st(move || Ok(public.clone()));
            let mut mock_pri = MockSecretKey::new();
            mock_pri
                .expect_to_bytes()
                .returning_st(move || Ok(private.clone()));
            Ok((mock_pub, mock_pri))
        });

        let expected_public = vec![42u8; 10];
        let expected_secret = vec![0u8; 10];

        let res = test_util::MockTestCipherSuiteType::derive_kem_key_pair(&expected_public)
            .expect("failed key pair gen");

        assert_eq!(res.public_key, expected_public);
        assert_eq!(res.secret_key, expected_secret);
    }

    #[test]
    fn test_derive_kem_keypair() {
        let ikm = vec![0u8; 32];

        assert_eq!(
            CipherSuite::Mls10128Dhkemx25519Aes128gcmSha256Ed25519
                .derive_kem_key_pair(&ikm)
                .unwrap(),
            Mls10DhKem25519Aes128GcmSha256Ed25519::derive_kem_key_pair(&ikm).unwrap()
        );

        assert_eq!(
            CipherSuite::Mls10128Dhkemp256Aes128gcmSha256P256
                .derive_kem_key_pair(&ikm)
                .unwrap(),
            Mls10DhKemP256Aes128GcmSha256P256::derive_kem_key_pair(&ikm).unwrap()
        );

        assert_eq!(
            CipherSuite::Mls10128Dhkemx25519Chacha20poly1305Sha256Ed25519
                .derive_kem_key_pair(&ikm)
                .unwrap(),
            Mls10DhKem25519ChaChaPoly1305Sha256Ed25519::derive_kem_key_pair(&ikm).unwrap()
        );

        assert_eq!(
            CipherSuite::Mls10256Dhkemp521Aes256gcmSha512P521
                .derive_kem_key_pair(&ikm)
                .unwrap(),
            Mls10DhKemP521Aes256GcmSha512P521::derive_kem_key_pair(&ikm).unwrap()
        );
    }

    #[test]
    fn test_generate_leaf_secret_trait() {
        let mut rng = RepeatRng { num: 42 };
        let expected = vec![42u8; 42];
        let res =
            test_util::MockTestCipherSuiteType::generate_leaf_secret(&mut rng).expect("failed gen");
        assert_eq!(expected, res)
    }

    #[test]
    fn test_generate_leaf_secret() {
        let mut rng = RepeatRng { num: 42 };

        assert_eq!(
            CipherSuite::Mls10128Dhkemx25519Aes128gcmSha256Ed25519
                .generate_leaf_secret(&mut rng)
                .unwrap(),
            Mls10DhKem25519Aes128GcmSha256Ed25519::generate_leaf_secret(&mut rng).unwrap()
        );

        assert_eq!(
            CipherSuite::Mls10128Dhkemp256Aes128gcmSha256P256
                .generate_leaf_secret(&mut rng)
                .unwrap(),
            Mls10DhKemP256Aes128GcmSha256P256::generate_leaf_secret(&mut rng).unwrap()
        );

        assert_eq!(
            CipherSuite::Mls10128Dhkemx25519Chacha20poly1305Sha256Ed25519
                .generate_leaf_secret(&mut rng)
                .unwrap(),
            Mls10DhKem25519ChaChaPoly1305Sha256Ed25519::generate_leaf_secret(&mut rng).unwrap()
        );

        assert_eq!(
            CipherSuite::Mls10256Dhkemp521Aes256gcmSha512P521
                .generate_leaf_secret(&mut rng)
                .unwrap(),
            Mls10DhKemP521Aes256GcmSha512P521::generate_leaf_secret(&mut rng).unwrap()
        );
    }

    #[test]
    fn test_generate_init_secret() {
        let mut rng = RepeatRng { num: 42 };

        assert_eq!(
            CipherSuite::Mls10128Dhkemx25519Aes128gcmSha256Ed25519
                .generate_init_secret(&mut rng)
                .unwrap(),
            Mls10DhKem25519Aes128GcmSha256Ed25519::generate_init_secret(&mut rng).unwrap()
        );

        assert_eq!(
            CipherSuite::Mls10128Dhkemp256Aes128gcmSha256P256
                .generate_init_secret(&mut rng)
                .unwrap(),
            Mls10DhKemP256Aes128GcmSha256P256::generate_init_secret(&mut rng).unwrap()
        );

        assert_eq!(
            CipherSuite::Mls10128Dhkemx25519Chacha20poly1305Sha256Ed25519
                .generate_init_secret(&mut rng)
                .unwrap(),
            Mls10DhKem25519ChaChaPoly1305Sha256Ed25519::generate_init_secret(&mut rng).unwrap()
        );

        assert_eq!(
            CipherSuite::Mls10256Dhkemp521Aes256gcmSha512P521
                .generate_init_secret(&mut rng)
                .unwrap(),
            Mls10DhKemP521Aes256GcmSha512P521::generate_init_secret(&mut rng).unwrap()
        );
    }

    #[test]
    fn test_derive_secret_trait() {
        let mock_kdf = MockTestKeyScheduleKdf::derive_secret_context();
        mock_kdf
            .expect()
            .returning(|secret, label| Ok([secret, label.as_bytes()].concat()));

        let secret = vec![0u8; 42];
        let label = "foo";

        let res = test_util::MockTestCipherSuiteType::derive_secret(&secret, label)
            .expect("failed derive");

        assert_eq!(res, [secret, label.as_bytes().to_vec()].concat());
    }

    #[test]
    fn test_generate_derive_secret() {
        let secret = vec![0u8; 42];
        let label = "foo";

        assert_eq!(
            CipherSuite::Mls10128Dhkemx25519Aes128gcmSha256Ed25519
                .derive_secret(&secret, label)
                .unwrap(),
            Mls10DhKem25519Aes128GcmSha256Ed25519::derive_secret(&secret, label).unwrap()
        );

        assert_eq!(
            CipherSuite::Mls10128Dhkemp256Aes128gcmSha256P256
                .derive_secret(&secret, label)
                .unwrap(),
            Mls10DhKemP256Aes128GcmSha256P256::derive_secret(&secret, label).unwrap()
        );

        assert_eq!(
            CipherSuite::Mls10128Dhkemx25519Chacha20poly1305Sha256Ed25519
                .derive_secret(&secret, label)
                .unwrap(),
            Mls10DhKem25519ChaChaPoly1305Sha256Ed25519::derive_secret(&secret, label).unwrap()
        );

        assert_eq!(
            CipherSuite::Mls10256Dhkemp521Aes256gcmSha512P521
                .derive_secret(&secret, label)
                .unwrap(),
            Mls10DhKemP521Aes256GcmSha512P521::derive_secret(&secret, label).unwrap()
        );
    }

    #[test]
    fn test_derive_tree_secret() {
        let secret = vec![0u8; 42];
        let label = "foo";
        let node = 0;
        let generation = 0;
        let expand_type = ExpandType::AeadKey;

        assert_eq!(
            CipherSuite::Mls10128Dhkemx25519Aes128gcmSha256Ed25519
                .derive_tree_secret(&secret, label, node, generation, expand_type)
                .unwrap(),
            Mls10DhKem25519Aes128GcmSha256Ed25519::derive_tree_secret(
                &secret,
                label,
                node,
                generation,
                expand_type
            )
            .unwrap()
        );

        assert_eq!(
            CipherSuite::Mls10128Dhkemp256Aes128gcmSha256P256
                .derive_tree_secret(&secret, label, node, generation, expand_type)
                .unwrap(),
            Mls10DhKemP256Aes128GcmSha256P256::derive_tree_secret(
                &secret,
                label,
                node,
                generation,
                expand_type
            )
            .unwrap()
        );

        assert_eq!(
            CipherSuite::Mls10128Dhkemx25519Chacha20poly1305Sha256Ed25519
                .derive_tree_secret(&secret, label, node, generation, expand_type)
                .unwrap(),
            Mls10DhKem25519ChaChaPoly1305Sha256Ed25519::derive_tree_secret(
                &secret,
                label,
                node,
                generation,
                expand_type
            )
            .unwrap()
        );

        assert_eq!(
            CipherSuite::Mls10256Dhkemp521Aes256gcmSha512P521
                .derive_tree_secret(&secret, label, node, generation, expand_type)
                .unwrap(),
            Mls10DhKemP521Aes256GcmSha512P521::derive_tree_secret(
                &secret,
                label,
                node,
                generation,
                expand_type
            )
            .unwrap()
        );
    }

    #[test]
    fn test_extract() {
        let salt = vec![0u8; 42];
        let key = b"foo".to_vec();

        assert_eq!(
            CipherSuite::Mls10128Dhkemx25519Aes128gcmSha256Ed25519
                .extract(&salt, &key)
                .unwrap(),
            Mls10DhKem25519Aes128GcmSha256Ed25519::extract(&salt, &key).unwrap()
        );

        assert_eq!(
            CipherSuite::Mls10128Dhkemp256Aes128gcmSha256P256
                .extract(&salt, &key)
                .unwrap(),
            Mls10DhKemP256Aes128GcmSha256P256::extract(&salt, &key).unwrap()
        );

        assert_eq!(
            CipherSuite::Mls10128Dhkemx25519Chacha20poly1305Sha256Ed25519
                .extract(&salt, &key)
                .unwrap(),
            Mls10DhKem25519ChaChaPoly1305Sha256Ed25519::extract(&salt, &key).unwrap()
        );

        assert_eq!(
            CipherSuite::Mls10256Dhkemp521Aes256gcmSha512P521
                .extract(&salt, &key)
                .unwrap(),
            Mls10DhKemP521Aes256GcmSha512P521::extract(&salt, &key).unwrap()
        );
    }

    #[test]
    fn test_expand() {
        let secret = vec![0u8; 42];
        let info = b"foo".to_vec();
        let e_type = ExpandType::AeadNonce;

        assert_eq!(
            CipherSuite::Mls10128Dhkemx25519Aes128gcmSha256Ed25519
                .expand(&secret, &info, e_type)
                .unwrap(),
            Mls10DhKem25519Aes128GcmSha256Ed25519::expand(&secret, &info, e_type).unwrap()
        );

        assert_eq!(
            CipherSuite::Mls10128Dhkemp256Aes128gcmSha256P256
                .expand(&secret, &info, e_type)
                .unwrap(),
            Mls10DhKemP256Aes128GcmSha256P256::expand(&secret, &info, e_type).unwrap()
        );

        assert_eq!(
            CipherSuite::Mls10128Dhkemx25519Chacha20poly1305Sha256Ed25519
                .expand(&secret, &info, e_type)
                .unwrap(),
            Mls10DhKem25519ChaChaPoly1305Sha256Ed25519::expand(&secret, &info, e_type).unwrap()
        );

        assert_eq!(
            CipherSuite::Mls10256Dhkemp521Aes256gcmSha512P521
                .expand(&secret, &info, e_type)
                .unwrap(),
            Mls10DhKemP521Aes256GcmSha512P521::expand(&secret, &info, e_type).unwrap()
        );
    }

    #[test]
    fn test_hmac() {
        let key = b"foo".to_vec();
        let msg = vec![0u8; 42];

        assert_eq!(
            CipherSuite::Mls10128Dhkemx25519Aes128gcmSha256Ed25519
                .hmac(&key, &msg)
                .unwrap(),
            Mls10DhKem25519Aes128GcmSha256Ed25519::hmac(&key, &msg).unwrap()
        );

        assert_eq!(
            CipherSuite::Mls10128Dhkemp256Aes128gcmSha256P256
                .hmac(&key, &msg)
                .unwrap(),
            Mls10DhKemP256Aes128GcmSha256P256::hmac(&key, &msg).unwrap()
        );

        assert_eq!(
            CipherSuite::Mls10128Dhkemx25519Chacha20poly1305Sha256Ed25519
                .hmac(&key, &msg)
                .unwrap(),
            Mls10DhKem25519ChaChaPoly1305Sha256Ed25519::hmac(&key, &msg).unwrap()
        );

        assert_eq!(
            CipherSuite::Mls10256Dhkemp521Aes256gcmSha512P521
                .hmac(&key, &msg)
                .unwrap(),
            Mls10DhKemP521Aes256GcmSha512P521::hmac(&key, &msg).unwrap()
        );
    }

    #[test]
    fn test_hash() {
        let msg = vec![0u8; 42];

        assert_eq!(
            CipherSuite::Mls10128Dhkemx25519Aes128gcmSha256Ed25519
                .hash(&msg)
                .unwrap(),
            Mls10DhKem25519Aes128GcmSha256Ed25519::hash(&msg).unwrap()
        );

        assert_eq!(
            CipherSuite::Mls10128Dhkemp256Aes128gcmSha256P256
                .hash(&msg)
                .unwrap(),
            Mls10DhKemP256Aes128GcmSha256P256::hash(&msg).unwrap()
        );

        assert_eq!(
            CipherSuite::Mls10128Dhkemx25519Chacha20poly1305Sha256Ed25519
                .hash(&msg)
                .unwrap(),
            Mls10DhKem25519ChaChaPoly1305Sha256Ed25519::hash(&msg).unwrap()
        );

        assert_eq!(
            CipherSuite::Mls10256Dhkemp521Aes256gcmSha512P521
                .hash(&msg)
                .unwrap(),
            Mls10DhKemP521Aes256GcmSha512P521::hash(&msg).unwrap()
        );
    }

    #[test]
    fn test_expand_with_label() {
        let secret = b"foo".to_vec();
        let label = "bar";
        let context = b"baz".to_vec();
        let e_type = ExpandType::AeadKey;

        assert_eq!(
            CipherSuite::Mls10128Dhkemx25519Aes128gcmSha256Ed25519
                .expand_with_label(&secret, label, &context, e_type)
                .unwrap(),
            Mls10DhKem25519Aes128GcmSha256Ed25519::expand_with_label(
                &secret, label, &context, e_type
            )
            .unwrap()
        );

        assert_eq!(
            CipherSuite::Mls10128Dhkemp256Aes128gcmSha256P256
                .expand_with_label(&secret, label, &context, e_type)
                .unwrap(),
            Mls10DhKemP256Aes128GcmSha256P256::expand_with_label(&secret, label, &context, e_type)
                .unwrap()
        );

        assert_eq!(
            CipherSuite::Mls10128Dhkemx25519Chacha20poly1305Sha256Ed25519
                .expand_with_label(&secret, label, &context, e_type)
                .unwrap(),
            Mls10DhKem25519ChaChaPoly1305Sha256Ed25519::expand_with_label(
                &secret, label, &context, e_type
            )
            .unwrap()
        );

        assert_eq!(
            CipherSuite::Mls10256Dhkemp521Aes256gcmSha512P521
                .expand_with_label(&secret, label, &context, e_type)
                .unwrap(),
            Mls10DhKemP521Aes256GcmSha512P521::expand_with_label(&secret, label, &context, e_type)
                .unwrap()
        );
    }
}

#[cfg(test)]
pub mod test_util {
    use super::hash::test_util::MockTestHashFunction;
    use super::hpke::test_util::MockTestHpke;
    use super::signature::test_utils::MockTestSignatureScheme;
    use super::CipherSuiteType;
    use super::ExpandType;
    use crate::ciphersuite::{CipherSuiteError, KemKeyPair};
    use crate::crypto::aead::test_util::MockTestCipher;
    use crate::crypto::hash::Mac;
    use crate::crypto::hpke::HPKECiphertext;
    use crate::crypto::rand::SecureRng;
    use crate::key_schedule::test_util::MockTestKeyScheduleKdf;
    use crate::protocol_version::ProtocolVersion;
    use mockall::mock;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    use std::fmt;
    use std::fmt::Debug;
    // This is a test cipher suite that will mock out methods for testing purposes

    mock! {
        pub CipherSuite {
            pub fn generate_kem_key_pair<RNG: SecureRng + 'static>(&self, mut rng: &RNG) -> Result<KemKeyPair, CipherSuiteError>;
            pub fn derive_kem_key_pair(&self, ikm: &[u8]) -> Result<KemKeyPair, CipherSuiteError>;
            pub fn get_protocol_version(&self) -> ProtocolVersion;
            pub fn get_id(&self) -> u16;
            pub fn extract_size(&self) -> u16;
            pub fn hmac(&self, key: &[u8], message: &[u8]) -> Result<Mac, CipherSuiteError>;
            pub fn hash(&self, value: &[u8]) -> Result<Vec<u8>, CipherSuiteError>;
            pub fn extract(&self, salt: &[u8], key: &[u8]) -> Result<Vec<u8>, CipherSuiteError>;
            pub fn expand(&self, secret: &[u8], info: &[u8], e_type: ExpandType) -> Result<Vec<u8>, CipherSuiteError>;
            pub fn expand_with_label(&self, secret: &[u8], label: &str, context: &[u8], e_type: ExpandType) -> Result<Vec<u8>, CipherSuiteError>;
            pub fn derive_tree_secret(&self, secret: &[u8], label: &str, node: u32, generation: u32, e_type: ExpandType) -> Result<Vec<u8>, CipherSuiteError>;
            pub fn derive_secret(&self, secret: &[u8], label: &str) -> Result<Vec<u8>, CipherSuiteError>;
            pub fn generate_leaf_secret<RNG: SecureRng + 'static>(&self, rng: &RNG) -> Result<Vec<u8>, CipherSuiteError>;
            pub fn generate_init_secret<RNG: SecureRng + 'static>(&self, rng: &mut RNG) -> Result<Vec<u8>, CipherSuiteError>;
            pub fn hpke_seal<RNG: SecureRng + 'static>(&self, rng: &mut RNG, public_key: &[u8],aad: &[u8], pt: &[u8]) -> Result<HPKECiphertext, CipherSuiteError>;
            pub fn hpke_open(&self, ct: &HPKECiphertext, secret_key: &[u8],aad: &[u8]) -> Result<Vec<u8>, CipherSuiteError>;
            pub fn aead_encrypt(&self, key: Vec<u8>, data: &[u8], aad: &[u8], nonce: &[u8]) -> Result<Vec<u8>, CipherSuiteError>;
            pub fn aead_decrypt(&self, key: Vec<u8>, data: &[u8], aad: &[u8], nonce: &[u8]) -> Result<Vec<u8>, CipherSuiteError>;
        }

        impl Clone for CipherSuite {
            fn clone(&self) -> Self;
        }
    }

    impl PartialEq for MockCipherSuite {
        fn eq(&self, other: &Self) -> bool {
            self.get_id() == other.get_id()
        }
    }

    impl Debug for MockCipherSuite {
        fn fmt(&self, _f: &mut fmt::Formatter<'_>) -> fmt::Result {
            Ok(())
        }
    }

    // A cipher suite is actually an enum with u16 value so we can mock that easily
    impl Serialize for MockCipherSuite {
        fn serialize<S>(
            &self,
            serializer: S,
        ) -> Result<<S as Serializer>::Ok, <S as Serializer>::Error>
        where
            S: Serializer,
        {
            serializer.serialize_u16(self.get_id())
        }
    }

    impl<'de> Deserialize<'de> for MockCipherSuite {
        fn deserialize<D>(deserializer: D) -> Result<Self, <D as Deserializer<'de>>::Error>
        where
            D: Deserializer<'de>,
        {
            let val = u16::deserialize(deserializer)?;
            let mut mock = MockCipherSuite::new();
            mock.expect_get_id().return_const(val);
            Ok(mock)
        }
    }

    // Mock the cipher suite trait type for internal testing
    mock! {
        pub TestCipherSuiteType {}
        impl CipherSuiteType for TestCipherSuiteType {
            type HPKE = MockTestHpke;
            type KDF = MockTestKeyScheduleKdf;
            type AEAD = MockTestCipher;
            type H = MockTestHashFunction;
            type SS = MockTestSignatureScheme;
            const SUITE_ID: u16 = 0xFFFF;
            const PROTOCOL_VERSION: ProtocolVersion = ProtocolVersion::Test;
        }
    }
}
