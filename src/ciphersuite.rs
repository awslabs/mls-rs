use crate::aead;
use crate::asym::{AsymmetricKeyError, AsymmetricKeyEngine, PublicKey, SecretKey};
use crate::hash;
use crate::hash::HashFunction;
use crate::kem;
use crate::hpke;
use crate::kdf;
use crate::kem::Kem;
use crate::protocol_version::ProtocolVersion;
use crate::signature;
use crate::signature::{SignatureError, SignatureScheme};
use rand_core::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use crate::asym::AsymmetricKey;
use num_enum::{IntoPrimitive, TryFromPrimitive};
use crate::kdf::{Kdf, KdfError, KdfId};
use crate::key_schedule::KeyScheduleKdf;
use crate::hpke::{Hpke, HPKEError, HPKECiphertext};
use crate::aead::Cipher;

#[derive(IntoPrimitive, TryFromPrimitive, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[repr(u16)]
#[serde(into = "u16", try_from = "u16")]
pub enum CipherSuite {
    MLS10_128_DHKEMX25519_AES128GCM_SHA256_Ed25519 = 0x0001,
    MLS10_128_DHKEMP256_AES128GCM_SHA256_P256 = 0x0002,
    MLS10_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519 = 0x0003,
    //MLS10_256_DHKEMX448_AES256GCM_SHA512_Ed448 = 0x0004, // Unsupported
    MLS10_256_DHKEMP521_AES256GCM_SHA512_P521 = 0x0005,
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
    HpkeError(#[from] HPKEError)
}

pub trait CipherSuiteType {
    type HPKE: Hpke;
    type KDF: KeyScheduleKdf;
    type AEAD: aead::Cipher;
    type H: HashFunction;
    type SS: SignatureScheme;

    const SUITE_ID: u16;
    const PROTOCOL_VERSION: ProtocolVersion;

    fn generate_kem_key_pair<RNG: CryptoRng + RngCore + 'static>(rng: &mut RNG) -> Result<KemKeyPair, CipherSuiteError> {
        let (pk, sk) = <<Self::HPKE as Hpke>::KEM as Kem>::generate_kem_key_pair(rng)?;
        Ok(KemKeyPair {
            public_key: pk.to_bytes()?,
            secret_key: sk.to_bytes()?
        })
    }

    fn derive_kem_key_pair(ikm: &[u8]) -> Result<KemKeyPair, CipherSuiteError> {
        let (pk, sk) = <<Self::HPKE as Hpke>::KEM as Kem>::derive_key_pair(ikm)?;
        Ok(KemKeyPair {
            public_key: pk.to_bytes()?,
            secret_key: sk.to_bytes()?
        })
    }

    fn get_protocol_version() -> ProtocolVersion {
        Self::PROTOCOL_VERSION
    }

    fn generate_leaf_secret<RNG: CryptoRng + RngCore + 'static>
        (rng: &mut RNG) -> Result<Vec<u8>, CipherSuiteError> {
        let mut ret = vec![0u8; <<Self::HPKE as Hpke>::KEM as Kem>::N_SECRET as usize];
        rng.try_fill_bytes(&mut ret)?;
        Ok(ret)
    }

    fn extract(salt: &[u8], key: &[u8]) -> Result<Vec<u8>, CipherSuiteError> {
        Self::KDF::extract(salt, key).map_err(|e| e.into())
    }

    fn expand_with_label(secret: &[u8], label: &str, context: &[u8], e_type: ExpandType) -> Result<Vec<u8>, CipherSuiteError> {
        let len = match e_type {
            ExpandType::Secret => Self::KDF::EXTRACT_SIZE,
            ExpandType::Aead => Self::AEAD::KEY_LEN
        };

        Self::KDF::expand_with_label(secret, label, context, len)
            .map_err(|e| e.into())
    }

    fn derive_secret(secret: &[u8], label: &str) -> Result<Vec<u8>, CipherSuiteError> {
        Self::KDF::derive_secret(secret, label).map_err(|e| e.into())
    }

    fn derive_tree_secret(secret: &[u8], label: &str, node: u32, generation: u32, e_type: ExpandType) -> Result<Vec<u8>, CipherSuiteError> {
        let len = match e_type {
            ExpandType::Secret => Self::KDF::EXTRACT_SIZE,
            ExpandType::Aead => Self::AEAD::KEY_LEN
        };
        Self::KDF::derive_tree_secret(secret, label, node, generation, len)
            .map_err(|e| e.into())
    }

    fn import_pub_key<PK>(data: &[u8]) -> Result<PK, CipherSuiteError> where PK: PublicKey {
        PK::from_bytes(data).map_err(|e| e.into())
    }

    fn import_secret_key<SK>(data: &[u8]) -> Result<SK, CipherSuiteError> where SK: SecretKey {
        SK::from_bytes(data).map_err(|e| e.into())
    }

    fn hpke_seal<RNG: CryptoRng + RngCore + 'static>(
        rng: &mut RNG, public_key: &[u8],
        aad: &[u8], pt: &[u8]
    ) -> Result<HPKECiphertext, CipherSuiteError> {
        let pub_key = Self::import_pub_key(public_key)?;
        Self::HPKE::seal_basic(rng, &pub_key, &[], aad, pt)
            .map_err(|e| e.into())
    }

    fn hpke_open(
        ct: &HPKECiphertext, secret_key: &[u8],
        aad: &[u8]
    ) -> Result<Vec<u8>, CipherSuiteError> {
        let secret_key = Self::import_secret_key(&secret_key)?;
        Self::HPKE::open_basic(ct, &secret_key, &[], aad)
            .map_err(|e| e.into())
    }
}

#[derive(Clone, PartialEq, Debug)]
pub struct KemKeyPair {
    pub public_key: Vec<u8>,
    pub secret_key: Vec<u8>
}

#[derive(Clone, PartialEq, Debug)]
pub enum ExpandType {
    Secret,
    Aead
}

impl CipherSuite {

    pub fn generate_leaf_secret<RNG: CryptoRng + RngCore + 'static>(&self, rng: &mut RNG) -> Result<Vec<u8>, CipherSuiteError> {
        match self {
            CipherSuite::MLS10_128_DHKEMX25519_AES128GCM_SHA256_Ed25519 => {
                Mls10DhKem25519Aes128GcmSha256Ed25519::generate_leaf_secret(rng)
            }
            CipherSuite::MLS10_128_DHKEMP256_AES128GCM_SHA256_P256 => {
                Mls10DhKemP256Aes128GcmSha256P256::generate_leaf_secret(rng)
            }
            CipherSuite::MLS10_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519 => {
                Mls10DhKem25519ChaChaPoly1305Sha256Ed25519::generate_leaf_secret(rng)
            }
            CipherSuite::MLS10_256_DHKEMP521_AES256GCM_SHA512_P521 => {
                Mls10DhKemP521Aes256GcmSha512P521::generate_leaf_secret(rng)
            }
        }
    }

    pub fn generate_kem_key_pair<RNG: CryptoRng + RngCore + 'static>(&self, rng: &mut RNG) -> Result<KemKeyPair, CipherSuiteError> {
        match self {
            CipherSuite::MLS10_128_DHKEMX25519_AES128GCM_SHA256_Ed25519 => {
                Mls10DhKem25519Aes128GcmSha256Ed25519::generate_kem_key_pair(rng)
            }
            CipherSuite::MLS10_128_DHKEMP256_AES128GCM_SHA256_P256 => {
                Mls10DhKemP256Aes128GcmSha256P256::generate_kem_key_pair(rng)
            }
            CipherSuite::MLS10_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519 => {
                Mls10DhKem25519ChaChaPoly1305Sha256Ed25519::generate_kem_key_pair(rng)
            }
            CipherSuite::MLS10_256_DHKEMP521_AES256GCM_SHA512_P521 => {
                Mls10DhKemP521Aes256GcmSha512P521::generate_kem_key_pair(rng)
            }
        }
    }

    pub fn derive_kem_key_pair(&self, ikm: &[u8]) -> Result<KemKeyPair, CipherSuiteError> {
        match self {
            CipherSuite::MLS10_128_DHKEMX25519_AES128GCM_SHA256_Ed25519 => {
                Mls10DhKem25519Aes128GcmSha256Ed25519::derive_kem_key_pair(ikm)
            }
            CipherSuite::MLS10_128_DHKEMP256_AES128GCM_SHA256_P256 => {
                Mls10DhKemP256Aes128GcmSha256P256::derive_kem_key_pair(ikm)
            }
            CipherSuite::MLS10_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519 => {
                Mls10DhKem25519ChaChaPoly1305Sha256Ed25519::derive_kem_key_pair(ikm)
            }
            CipherSuite::MLS10_256_DHKEMP521_AES256GCM_SHA512_P521 => {
                Mls10DhKemP521Aes256GcmSha512P521::derive_kem_key_pair(ikm)
            }
        }
    }

    pub fn get_protocol_version(&self) -> ProtocolVersion {
        match self {
            CipherSuite::MLS10_128_DHKEMX25519_AES128GCM_SHA256_Ed25519 => {
                Mls10DhKem25519Aes128GcmSha256Ed25519::get_protocol_version()
            }
            CipherSuite::MLS10_128_DHKEMP256_AES128GCM_SHA256_P256 => {
                Mls10DhKemP256Aes128GcmSha256P256::get_protocol_version()
            }
            CipherSuite::MLS10_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519 => {
                Mls10DhKem25519ChaChaPoly1305Sha256Ed25519::get_protocol_version()
            }
            CipherSuite::MLS10_256_DHKEMP521_AES256GCM_SHA512_P521 => {
                Mls10DhKemP521Aes256GcmSha512P521::get_protocol_version()
            }
        }
    }

    pub fn derive_secret(&self, secret: &[u8], label: &str) -> Result<Vec<u8>, CipherSuiteError> {
        match self {
            CipherSuite::MLS10_128_DHKEMX25519_AES128GCM_SHA256_Ed25519 => {
                Mls10DhKem25519Aes128GcmSha256Ed25519::derive_secret(secret, label)
            }
            CipherSuite::MLS10_128_DHKEMP256_AES128GCM_SHA256_P256 => {
                Mls10DhKemP256Aes128GcmSha256P256::derive_secret(secret, label)
            }
            CipherSuite::MLS10_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519 => {
                Mls10DhKem25519ChaChaPoly1305Sha256Ed25519::derive_secret(secret, label)
            }
            CipherSuite::MLS10_256_DHKEMP521_AES256GCM_SHA512_P521 => {
                Mls10DhKemP521Aes256GcmSha512P521::derive_secret(secret, label)
            }
        }
    }

    pub fn extract(&self, salt: &[u8], key: &[u8]) -> Result<Vec<u8>, CipherSuiteError> {
        match self {
            CipherSuite::MLS10_128_DHKEMX25519_AES128GCM_SHA256_Ed25519 => {
                Mls10DhKem25519Aes128GcmSha256Ed25519::extract(salt, key)
            }
            CipherSuite::MLS10_128_DHKEMP256_AES128GCM_SHA256_P256 => {
                Mls10DhKemP256Aes128GcmSha256P256::extract(salt, key)
            }
            CipherSuite::MLS10_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519 => {
                Mls10DhKem25519ChaChaPoly1305Sha256Ed25519::extract(salt, key)
            }
            CipherSuite::MLS10_256_DHKEMP521_AES256GCM_SHA512_P521 => {
                Mls10DhKemP521Aes256GcmSha512P521::extract(salt, key)
            }
        }
    }

    pub fn expand_with_label(&self, secret: &[u8], label: &str, context: &[u8], e_type: ExpandType) -> Result<Vec<u8>, CipherSuiteError> {

        match self {
            CipherSuite::MLS10_128_DHKEMX25519_AES128GCM_SHA256_Ed25519 => {
                Mls10DhKem25519Aes128GcmSha256Ed25519::expand_with_label(secret, label, context, e_type)
            }
            CipherSuite::MLS10_128_DHKEMP256_AES128GCM_SHA256_P256 => {
                Mls10DhKemP256Aes128GcmSha256P256::expand_with_label(secret, label, context, e_type)
            }
            CipherSuite::MLS10_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519 => {
                Mls10DhKem25519ChaChaPoly1305Sha256Ed25519::expand_with_label(secret, label, context, e_type)
            }
            CipherSuite::MLS10_256_DHKEMP521_AES256GCM_SHA512_P521 => {
                Mls10DhKemP521Aes256GcmSha512P521::expand_with_label(secret, label, context, e_type)
            }
        }
    }

    pub fn derive_tree_secret(&self, secret: &[u8], label: &str, node: u32, generation: u32, e_type: ExpandType) -> Result<Vec<u8>, CipherSuiteError> {
        match self {
            CipherSuite::MLS10_128_DHKEMX25519_AES128GCM_SHA256_Ed25519 => {
                Mls10DhKem25519Aes128GcmSha256Ed25519::derive_tree_secret(secret, label, node, generation, e_type)
            }
            CipherSuite::MLS10_128_DHKEMP256_AES128GCM_SHA256_P256 => {
                Mls10DhKemP256Aes128GcmSha256P256::derive_tree_secret(secret, label, node, generation, e_type)
            }
            CipherSuite::MLS10_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519 => {
                Mls10DhKem25519ChaChaPoly1305Sha256Ed25519::derive_tree_secret(secret, label, node, generation, e_type)
            }
            CipherSuite::MLS10_256_DHKEMP521_AES256GCM_SHA512_P521 => {
                Mls10DhKemP521Aes256GcmSha512P521::derive_tree_secret(secret, label, node, generation, e_type)
            }
        }
    }

    pub fn hpke_seal<RNG: CryptoRng + RngCore + 'static>(
        &self, rng: &mut RNG, public_key: &[u8],
        aad: &[u8], pt: &[u8]
    ) -> Result<HPKECiphertext, CipherSuiteError> {
        match self {
            CipherSuite::MLS10_128_DHKEMX25519_AES128GCM_SHA256_Ed25519 => {
                Mls10DhKem25519Aes128GcmSha256Ed25519::hpke_seal(rng, public_key, aad, pt)
            }
            CipherSuite::MLS10_128_DHKEMP256_AES128GCM_SHA256_P256 => {
                Mls10DhKemP256Aes128GcmSha256P256::hpke_seal(rng, public_key, aad, pt)
            }
            CipherSuite::MLS10_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519 => {
                Mls10DhKem25519ChaChaPoly1305Sha256Ed25519::hpke_seal(rng, public_key, aad, pt)
            }
            CipherSuite::MLS10_256_DHKEMP521_AES256GCM_SHA512_P521 => {
                Mls10DhKemP521Aes256GcmSha512P521::hpke_seal(rng, public_key, aad, pt)
            }
        }
    }

    pub fn hpke_open(
        &self, ct: &HPKECiphertext, secret_key: &[u8],
        aad: &[u8]
    ) -> Result<Vec<u8>, CipherSuiteError> {
        match self {
            CipherSuite::MLS10_128_DHKEMX25519_AES128GCM_SHA256_Ed25519 => {
                Mls10DhKem25519Aes128GcmSha256Ed25519::hpke_open(ct, secret_key, aad)
            }
            CipherSuite::MLS10_128_DHKEMP256_AES128GCM_SHA256_P256 => {
                Mls10DhKemP256Aes128GcmSha256P256::hpke_open(ct, secret_key, aad)
            }
            CipherSuite::MLS10_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519 => {
                Mls10DhKem25519ChaChaPoly1305Sha256Ed25519::hpke_open(ct, secret_key, aad)
            }
            CipherSuite::MLS10_256_DHKEMP521_AES256GCM_SHA512_P521 => {
                Mls10DhKemP521Aes256GcmSha512P521::hpke_open(ct, secret_key, aad)
            }
        }
    }
}

macro_rules! impl_cipher_suite_type {
    ($name:ident, $hpke:ty, $kdf:ty, $aead:ty, $hash:ty, $signature_scheme:ty, $suite_id:expr, $protocol_version:expr) => {
        #[derive(Clone, PartialEq, Debug)]
        pub struct $name;

        impl CipherSuiteType for $name
        {
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

impl_cipher_suite_type!(Mls10DhKem25519Aes128GcmSha256Ed25519, hpke::X25519HkdfSha256Aes128Gcm, kdf::HkdfSha256, aead::aes::Gcm128, hash::Sha256, signature::ed25519::EdDsa25519, CipherSuite::MLS10_128_DHKEMX25519_AES128GCM_SHA256_Ed25519 as u16, ProtocolVersion::Mls10);
impl_cipher_suite_type!(Mls10DhKemP256Aes128GcmSha256P256, hpke::P256HkdfSha256Aes128Gcm, kdf::HkdfSha256, aead::aes::Gcm128, hash::Sha256, signature::p256::EcDsaP256, CipherSuite::MLS10_128_DHKEMP256_AES128GCM_SHA256_P256 as u16, ProtocolVersion::Mls10);
impl_cipher_suite_type!(Mls10DhKem25519ChaChaPoly1305Sha256Ed25519, hpke::X25519HkdfSha256ChaCha20, kdf::HkdfSha256, aead::chacha20::Poly1305, hash::Sha256, signature::ed25519::EdDsa25519, CipherSuite::MLS10_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519 as u16, ProtocolVersion::Mls10);
impl_cipher_suite_type!(Mls10DhKemP521Aes256GcmSha512P521, hpke::P521HkdfSha512Aes256Gcm, kdf::HkdfSha512, aead::aes::Gcm256, hash::Sha512, signature::p521::EcDsaP521, CipherSuite::MLS10_256_DHKEMP521_AES256GCM_SHA512_P521 as u16, ProtocolVersion::Mls10);

#[cfg(test)]
mod test {
    use crate::ciphersuite::{
        CipherSuite,
        Mls10DhKem25519Aes128GcmSha256Ed25519,
        CipherSuiteType,
        Mls10DhKemP256Aes128GcmSha256P256,
        Mls10DhKem25519ChaChaPoly1305Sha256Ed25519,
        Mls10DhKemP521Aes256GcmSha512P521
    };
    use crate::rand::test_rng::{ZerosRng, RepeatRng};
    use super::test_util;
    use crate::kem::test_util::MockTestKem;
    use crate::asym::test_util::MockPublicKey;
    use crate::asym::test_util::MockSecretKey;
    use crate::key_schedule::test_util::MockTestKeyScheduleKdf;

    #[test]
    fn test_protocol_version() {
        assert_eq!(CipherSuite::MLS10_128_DHKEMX25519_AES128GCM_SHA256_Ed25519
                       .get_protocol_version(),
                   Mls10DhKem25519Aes128GcmSha256Ed25519::PROTOCOL_VERSION);

        assert_eq!(CipherSuite::MLS10_128_DHKEMP256_AES128GCM_SHA256_P256
                       .get_protocol_version(),
                   Mls10DhKemP256Aes128GcmSha256P256::PROTOCOL_VERSION);

        assert_eq!(CipherSuite::MLS10_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519
                       .get_protocol_version(),
                   Mls10DhKem25519ChaChaPoly1305Sha256Ed25519::PROTOCOL_VERSION);

        assert_eq!(CipherSuite::MLS10_256_DHKEMP521_AES256GCM_SHA512_P521
                       .get_protocol_version(),
                   Mls10DhKemP521Aes256GcmSha512P521::PROTOCOL_VERSION);
    }

    #[test]
    fn test_generate_kem_keypair_trait() {
        let mock_kem = MockTestKem::generate_kem_key_pair_context();
        mock_kem.expect().returning(|_: &mut ZerosRng| {
            let mut mock_pub = MockPublicKey::new();
            mock_pub.expect_to_bytes().returning_st(move || Ok(vec![0; 4]));
            let mut mock_pri = MockSecretKey::new();
            mock_pri.expect_to_bytes().returning_st(move || Ok(vec![0; 2]));
            Ok((mock_pub, mock_pri))
        });

        let res = test_util::MockTestCipherSuiteType::generate_kem_key_pair(&mut ZerosRng).expect("failed key pair gen");
        assert_eq!(res.public_key, vec![0;4]);
        assert_eq!(res.secret_key, vec![0;2]);
    }

    #[test]
    fn test_generate_kem_keypair() {

        assert_eq!(CipherSuite::MLS10_128_DHKEMX25519_AES128GCM_SHA256_Ed25519
                       .generate_kem_key_pair(&mut ZerosRng)
                       .expect("failed keypair generation"),
                   Mls10DhKem25519Aes128GcmSha256Ed25519::generate_kem_key_pair(&mut ZerosRng)
                       .expect("failed keypair generation"));

        assert_eq!(CipherSuite::MLS10_128_DHKEMP256_AES128GCM_SHA256_P256
                       .generate_kem_key_pair(&mut ZerosRng)
                       .expect("failed keypair generation"),
                   Mls10DhKemP256Aes128GcmSha256P256::generate_kem_key_pair(&mut ZerosRng)
                       .expect("failed keypair generation"));

        assert_eq!(CipherSuite::MLS10_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519
                       .generate_kem_key_pair(&mut ZerosRng)
                       .expect("failed keypair generation"),
                   Mls10DhKem25519ChaChaPoly1305Sha256Ed25519::generate_kem_key_pair(&mut ZerosRng)
                       .expect("failed keypair generation"));

        assert_eq!(CipherSuite::MLS10_256_DHKEMP521_AES256GCM_SHA512_P521
                       .generate_kem_key_pair(&mut ZerosRng)
                       .expect("failed keypair generation"),
                   Mls10DhKemP521Aes256GcmSha512P521::generate_kem_key_pair(&mut ZerosRng)
                       .expect("failed keypair generation"));
    }

    #[test]
    fn test_derive_kem_keypair_trait() {
        let mock_kem = MockTestKem::derive_key_pair_context();
        mock_kem.expect().returning(|ikm| {
            let public = ikm.to_vec();
            let private = vec![0u8; ikm.len()];
            let mut mock_pub = MockPublicKey::new();
            mock_pub.expect_to_bytes().returning_st(move || Ok(public.clone()));
            let mut mock_pri = MockSecretKey::new();
            mock_pri.expect_to_bytes().returning_st(move || Ok(private.clone()));
            Ok((mock_pub, mock_pri))
        });

        let expected_public = vec![42u8; 10];
        let expected_secret = vec![0u8; 10];

        let res = test_util::MockTestCipherSuiteType::derive_kem_key_pair(&expected_public.clone())
            .expect("failed key pair gen");

        assert_eq!(res.public_key, expected_public);
        assert_eq!(res.secret_key, expected_secret);
    }

    #[test]
    fn test_derive_kem_keypair() {
        let ikm = vec![0u8; 32];

        assert_eq!(CipherSuite::MLS10_128_DHKEMX25519_AES128GCM_SHA256_Ed25519
                       .derive_kem_key_pair(&ikm)
                       .expect("failed keypair generation"),
                   Mls10DhKem25519Aes128GcmSha256Ed25519::derive_kem_key_pair(&ikm)
                       .expect("failed keypair generation"));

        assert_eq!(CipherSuite::MLS10_128_DHKEMP256_AES128GCM_SHA256_P256
                       .derive_kem_key_pair(&ikm)
                       .expect("failed keypair generation"),
                   Mls10DhKemP256Aes128GcmSha256P256::derive_kem_key_pair(&ikm)
                       .expect("failed keypair generation"));

        assert_eq!(CipherSuite::MLS10_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519
                       .derive_kem_key_pair(&ikm)
                       .expect("failed keypair generation"),
                   Mls10DhKem25519ChaChaPoly1305Sha256Ed25519::derive_kem_key_pair(&ikm)
                       .expect("failed keypair generation"));

        assert_eq!(CipherSuite::MLS10_256_DHKEMP521_AES256GCM_SHA512_P521
                       .derive_kem_key_pair(&ikm)
                       .expect("failed keypair generation"),
                   Mls10DhKemP521Aes256GcmSha512P521::derive_kem_key_pair(&ikm)
                       .expect("failed keypair generation"));
    }

    #[test]
    fn test_generate_leaf_secret_trait() {
        let mut rng = RepeatRng { num: 42 };
        let expected = vec![42u8; 42];
        let res = test_util::MockTestCipherSuiteType::generate_leaf_secret(&mut rng)
            .expect("failed gen");
        assert_eq!(expected, res)
    }

    #[test]
    fn test_generate_leaf_secret() {
        let mut rng = RepeatRng { num: 42 };

        assert_eq!(CipherSuite::MLS10_128_DHKEMX25519_AES128GCM_SHA256_Ed25519
                       .generate_leaf_secret(&mut rng)
                       .expect("failed keypair generation"),
                   Mls10DhKem25519Aes128GcmSha256Ed25519::generate_leaf_secret(&mut rng)
                       .expect("failed keypair generation"));

        assert_eq!(CipherSuite::MLS10_128_DHKEMP256_AES128GCM_SHA256_P256
                       .generate_leaf_secret(&mut rng)
                       .expect("failed keypair generation"),
                   Mls10DhKemP256Aes128GcmSha256P256::generate_leaf_secret(&mut rng)
                       .expect("failed keypair generation"));

        assert_eq!(CipherSuite::MLS10_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519
                       .generate_leaf_secret(&mut rng)
                       .expect("failed keypair generation"),
                   Mls10DhKem25519ChaChaPoly1305Sha256Ed25519::generate_leaf_secret(&mut rng)
                       .expect("failed keypair generation"));

        assert_eq!(CipherSuite::MLS10_256_DHKEMP521_AES256GCM_SHA512_P521
                       .generate_leaf_secret(&mut rng)
                       .expect("failed keypair generation"),
                   Mls10DhKemP521Aes256GcmSha512P521::generate_leaf_secret(&mut rng)
                       .expect("failed keypair generation"));
    }

    #[test]
    fn test_derive_secret_trait() {
        let mock_kdf = MockTestKeyScheduleKdf::derive_secret_context();
        mock_kdf.expect().returning(|secret, label| {
            Ok([secret, label.as_bytes()].concat())
        });

        let secret = vec![0u8;42];
        let label = "foo";

        let res = test_util::MockTestCipherSuiteType::derive_secret(&secret, label)
            .expect("failed derive");

        assert_eq!(res, [secret, label.as_bytes().to_vec()].concat());
    }

    #[test]
    fn test_generate_derive_secret() {
        let secret = vec![0u8;42];
        let label = "foo";

        assert_eq!(CipherSuite::MLS10_128_DHKEMX25519_AES128GCM_SHA256_Ed25519
                       .derive_secret(&secret, label)
                       .expect("failed keypair generation"),
                   Mls10DhKem25519Aes128GcmSha256Ed25519::derive_secret(&secret, label)
                       .expect("failed keypair generation"));

        assert_eq!(CipherSuite::MLS10_128_DHKEMP256_AES128GCM_SHA256_P256
                       .derive_secret(&secret, label)
                       .expect("failed keypair generation"),
                   Mls10DhKemP256Aes128GcmSha256P256::derive_secret(&secret, label)
                       .expect("failed keypair generation"));

        assert_eq!(CipherSuite::MLS10_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519
                       .derive_secret(&secret, label)
                       .expect("failed keypair generation"),
                   Mls10DhKem25519ChaChaPoly1305Sha256Ed25519::derive_secret(&secret, label)
                       .expect("failed keypair generation"));

        assert_eq!(CipherSuite::MLS10_256_DHKEMP521_AES256GCM_SHA512_P521
                       .derive_secret(&secret, label)
                       .expect("failed keypair generation"),
                   Mls10DhKemP521Aes256GcmSha512P521::derive_secret(&secret, label)
                       .expect("failed keypair generation"));
    }
}



#[cfg(test)]
pub mod test_util {
    use mockall::mock;
    use serde::{Serialize, Deserialize, Serializer, Deserializer};
    use rand_core::{CryptoRng, RngCore};
    use crate::ciphersuite::{KemKeyPair, CipherSuiteError};
    use crate::protocol_version::ProtocolVersion;
    use std::fmt::{Debug};
    use std::fmt;
    use super::CipherSuiteType;
    use super::ExpandType;
    use super::hpke::test_util::MockTestHpke;
    use crate::key_schedule::test_util::MockTestKeyScheduleKdf;
    use super::aead::test_util::MockTestCipher;
    use super::hash::test_util::MockTestHashFunction;
    use super::signature::test_utils::MockTestSignatureScheme;
    use crate::hpke::HPKECiphertext;
    // This is a test cipher suite that will mock out methods for testing purposes

    mock! {
        pub CipherSuite {
            pub fn generate_kem_key_pair<RNG: CryptoRng + RngCore + 'static>(&self, mut rng: &RNG) -> Result<KemKeyPair, CipherSuiteError>;
            pub fn derive_kem_key_pair(&self, ikm: &[u8]) -> Result<KemKeyPair, CipherSuiteError>;
            pub fn get_protocol_version(&self) -> ProtocolVersion;
            pub fn get_id(&self) -> u16;
            pub fn extract(&self, salt: &[u8], key: &[u8]) -> Result<Vec<u8>, CipherSuiteError>;
            pub fn expand_with_label(&self, secret: &[u8], label: &str, context: &[u8], e_type: ExpandType) -> Result<Vec<u8>, CipherSuiteError>;
            pub fn derive_tree_secret(&self, secret: &[u8], label: &str, node: u32, generation: u32, e_type: ExpandType) -> Result<Vec<u8>, CipherSuiteError>;
            pub fn derive_secret(&self, secret: &[u8], label: &str) -> Result<Vec<u8>, CipherSuiteError>;
            pub fn generate_leaf_secret<RNG: CryptoRng + RngCore + 'static>(&self, rng: &RNG) -> Result<Vec<u8>, CipherSuiteError>;
            pub fn hpke_seal<RNG: CryptoRng + RngCore + 'static>(&self, rng: &mut RNG, public_key: &[u8],aad: &[u8], pt: &[u8]) -> Result<HPKECiphertext, CipherSuiteError>;
            pub fn hpke_open(&self, ct: &HPKECiphertext, secret_key: &[u8],aad: &[u8]) -> Result<Vec<u8>, CipherSuiteError>;
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
        fn serialize<S>(&self, serializer: S) -> Result<<S as Serializer>::Ok, <S as Serializer>::Error> where
            S: Serializer {
            serializer.serialize_u16(self.get_id())
        }
    }

    impl <'de> Deserialize<'de> for MockCipherSuite {
        fn deserialize<D>(deserializer: D) -> Result<Self, <D as Deserializer<'de>>::Error> where
            D: Deserializer<'de> {
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