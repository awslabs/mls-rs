use crate::aead;
use crate::asym::{AsymmetricKeyError};
use crate::hash;
use crate::hash::HashFunction;
use crate::kem;
use crate::kem::Kem;
use crate::protocol_version::ProtocolVersion;
use crate::signature;
use crate::signature::{SignatureError, SignatureScheme};
use rand_core::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use crate::asym::AsymmetricKey;
use num_enum::{IntoPrimitive, TryFromPrimitive};

#[derive(IntoPrimitive, TryFromPrimitive, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[repr(u16)]
#[serde(into = "u16", try_from = "u16")]
pub enum CipherSuite {
    MLS10_128_DHKEMX25519_AES128GCM_SHA256_Ed25519 = 0x0001,
    MLS10_128_DHKEMP256_AES128GCM_SHA256_P256 = 0x0002,
    MLS10_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519 = 0x0003,
    //MLS10_256_DHKEMX448_AES256GCM_SHA512_Ed448 = 0x0004, // Unsupported
    MLS10_256_DHKEMP521_AES256GCM_SHA512_P521 = 0x0004,
    #[cfg(test)]
    MLS10_TEST = 0x0000,
    //MLS10_256_DHKEMX448_CHACHA20POLY1305_SHA512_Ed448 = 0x0006, // Unsupported
}

#[derive(Error, Debug)]
pub enum CipherSuiteError {
    #[error(transparent)]
    SignatureError(#[from] SignatureError),
    #[error(transparent)]
    AsymmetricKeyError(#[from] AsymmetricKeyError)
}

pub trait CipherSuiteType {
    type KEM: Kem;
    type AEAD: aead::Cipher;
    type H: HashFunction;
    type SS: SignatureScheme;

    const SUITE_ID: u16;
    const PROTOCOL_VERSION: ProtocolVersion;

    fn generate_kem_key_pair<RNG: CryptoRng + RngCore>(rng: RNG) -> Result<KemKeyPair, CipherSuiteError> {
        let (pk, sk) = Self::KEM::generate_kem_key_pair(rng)?;
        Ok(KemKeyPair {
            public_key: pk.to_bytes()?,
            secret_key: sk.to_bytes()?
        })
    }

    fn get_protocol_version() -> ProtocolVersion {
        Self::PROTOCOL_VERSION
    }
}

#[derive(Clone, PartialEq, Debug)]
pub struct KemKeyPair {
    pub public_key: Vec<u8>,
    pub secret_key: Vec<u8>
}

impl CipherSuite {
    pub fn generate_kem_key_pair<RNG: CryptoRng + RngCore>(&self, mut rng: RNG) -> Result<KemKeyPair, CipherSuiteError> {
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
            #[cfg(test)]
            // For testing we use the rng to directly make up a key pair
            CipherSuite::MLS10_TEST => {
                let mut pub_bytes = vec![255u8; 4];
                let mut sec_bytes = vec![255u8; 4];

                rng.fill_bytes(&mut pub_bytes);
                rng.fill_bytes(&mut sec_bytes);

                Ok(KemKeyPair {
                    public_key: pub_bytes.to_vec(),
                    secret_key: sec_bytes.to_vec()
                })
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
            #[cfg(test)]
            CipherSuite::MLS10_TEST => {
                ProtocolVersion::Test
            }
        }
    }
}

macro_rules! impl_cipher_suite_type {
    ($name:ident, $kem:ty, $aead:ty, $hash:ty, $signature_scheme:ty, $suite_id:expr, $protocol_version:expr) => {
        #[derive(Clone, PartialEq, Debug)]
        pub struct $name;

        impl CipherSuiteType for $name
        {
            type KEM = $kem;
            type AEAD = $aead;
            type H = $hash;
            type SS = $signature_scheme;
            const SUITE_ID: u16 = $suite_id;
            const PROTOCOL_VERSION: ProtocolVersion = $protocol_version;
        }
    };
}

impl_cipher_suite_type!(Mls10DhKem25519Aes128GcmSha256Ed25519, kem::X25519HkdfSha256, aead::aes::Gcm128, hash::Sha256, signature::ed25519::EdDsa25519, 0x0001, ProtocolVersion::Mls10);
impl_cipher_suite_type!(Mls10DhKemP256Aes128GcmSha256P256, kem::P256HkdfSha256, aead::aes::Gcm128, hash::Sha256, signature::p256::EcDsaP256, 0x0002, ProtocolVersion::Mls10);
impl_cipher_suite_type!(Mls10DhKem25519ChaChaPoly1305Sha256Ed25519, kem::X25519HkdfSha256, aead::chacha20::Poly1305, hash::Sha256, signature::ed25519::EdDsa25519, 0x0003, ProtocolVersion::Mls10);
impl_cipher_suite_type!(Mls10DhKemP521Aes256GcmSha512P521, kem::P521HkdfSha512, aead::aes::Gcm256, hash::Sha512, signature::p521::EcDsaP521, 0x0005, ProtocolVersion::Mls10);

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
    use crate::rand::test_rng::ZerosRng;

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
    fn test_generate_kem_keypair() {
        assert_eq!(CipherSuite::MLS10_128_DHKEMX25519_AES128GCM_SHA256_Ed25519
                       .generate_kem_key_pair(ZerosRng {})
                       .expect("failed keypair generation"),
                   Mls10DhKem25519Aes128GcmSha256Ed25519::generate_kem_key_pair(ZerosRng {})
                       .expect("failed keypair generation"));

        assert_eq!(CipherSuite::MLS10_128_DHKEMP256_AES128GCM_SHA256_P256
                       .generate_kem_key_pair(ZerosRng {})
                       .expect("failed keypair generation"),
                   Mls10DhKemP256Aes128GcmSha256P256::generate_kem_key_pair(ZerosRng {})
                       .expect("failed keypair generation"));

        assert_eq!(CipherSuite::MLS10_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519
                       .generate_kem_key_pair(ZerosRng {})
                       .expect("failed keypair generation"),
                   Mls10DhKem25519ChaChaPoly1305Sha256Ed25519::generate_kem_key_pair(ZerosRng {})
                       .expect("failed keypair generation"));

        assert_eq!(CipherSuite::MLS10_256_DHKEMP521_AES256GCM_SHA512_P521
                       .generate_kem_key_pair(ZerosRng {})
                       .expect("failed keypair generation"),
                   Mls10DhKemP521Aes256GcmSha512P521::generate_kem_key_pair(ZerosRng {})
                       .expect("failed keypair generation"));
    }
}