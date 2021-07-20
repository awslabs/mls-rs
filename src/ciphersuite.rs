use crate::protocol_version::ProtocolVersion;
use ferriscrypt::asym::ec_key::{Curve, EcKeyError};
use ferriscrypt::cipher::Aead;
use ferriscrypt::digest::HashFunction;
use ferriscrypt::hpke::kem::Kem;
use ferriscrypt::hpke::{AeadId, HPKECiphertext, Hpke, KdfId, KemId};
use serde::{Deserialize, Serialize};
use serde_repr::{Deserialize_repr, Serialize_repr};
use std::convert::TryInto;

#[derive(Deserialize_repr, Serialize_repr, Clone, Copy, Debug, PartialEq)]
#[repr(u16)]
pub enum SignatureScheme {
    EcdsaSecp256r1Sha256 = 0x0403,
    EcdsaSecp521r1Sha512 = 0x0603,
    Ed25519 = 0x0703,
    Ed448 = 0x0808,
}

impl TryInto<SignatureScheme> for Curve {
    type Error = EcKeyError;

    fn try_into(self) -> Result<SignatureScheme, Self::Error> {
        match self {
            Curve::P256 => Ok(SignatureScheme::EcdsaSecp256r1Sha256),
            Curve::P384 => Err(EcKeyError::UnsupportedCurveType(self as i32)),
            Curve::P521 => Ok(SignatureScheme::EcdsaSecp521r1Sha512),
            Curve::X25519 => Err(EcKeyError::NotSigningKey(self)),
            Curve::Ed25519 => Ok(SignatureScheme::Ed25519),
            Curve::X448 => Err(EcKeyError::NotSigningKey(self)),
            Curve::Ed448 => Ok(SignatureScheme::Ed448),
        }
    }
}

#[cfg(test)]
impl SignatureScheme {
    pub(crate) fn all() -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::Ed25519,
            SignatureScheme::Ed448,
            SignatureScheme::EcdsaSecp256r1Sha256,
            SignatureScheme::EcdsaSecp521r1Sha512,
        ]
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct HpkeCiphertext {
    kem_output: Vec<u8>,
    ciphertext: Vec<u8>,
}

//TODO: Naming is crazy here, needs to be fixed in ferriscrypt too
impl From<HPKECiphertext> for HpkeCiphertext {
    fn from(ciphertext: HPKECiphertext) -> Self {
        Self {
            kem_output: ciphertext.enc,
            ciphertext: ciphertext.ciphertext,
        }
    }
}

impl From<HpkeCiphertext> for HPKECiphertext {
    fn from(ciphertext: HpkeCiphertext) -> Self {
        Self {
            enc: ciphertext.kem_output,
            ciphertext: ciphertext.ciphertext,
        }
    }
}

#[derive(Serialize_repr, Deserialize_repr, Debug, Copy, Clone, PartialEq)]
#[repr(u16)]
#[serde(into = "u16", try_from = "u16")]
pub enum CipherSuite {
    Mls10128Dhkemx25519Aes128gcmSha256Ed25519 = 0x0001,
    Mls10128Dhkemp256Aes128gcmSha256P256 = 0x0002,
    Mls10128Dhkemx25519Chacha20poly1305Sha256Ed25519 = 0x0003,
    Mls10256Dhkemx448Aes256gcmSha512Ed448 = 0x0004,
    Mls10256Dhkemp521Aes256gcmSha512P521 = 0x0005,
    Mls10256Dhkemx448Chacha20poly1305Sha512Ed448 = 0x0006,
}

impl CipherSuite {
    #[cfg(test)]
    pub fn all() -> Vec<CipherSuite> {
        vec![
            CipherSuite::Mls10128Dhkemx25519Aes128gcmSha256Ed25519,
            CipherSuite::Mls10128Dhkemp256Aes128gcmSha256P256,
            CipherSuite::Mls10128Dhkemx25519Chacha20poly1305Sha256Ed25519,
            CipherSuite::Mls10256Dhkemx448Aes256gcmSha512Ed448,
            CipherSuite::Mls10256Dhkemp521Aes256gcmSha512P521,
            CipherSuite::Mls10256Dhkemx448Chacha20poly1305Sha512Ed448,
        ]
    }

    #[inline(always)]
    pub fn protocol_version(&self) -> ProtocolVersion {
        ProtocolVersion::Mls10
    }

    #[inline(always)]
    pub fn aead_type(&self) -> Aead {
        match self {
            CipherSuite::Mls10128Dhkemx25519Aes128gcmSha256Ed25519 => Aead::Aes128Gcm,
            CipherSuite::Mls10128Dhkemp256Aes128gcmSha256P256 => Aead::Aes128Gcm,
            CipherSuite::Mls10128Dhkemx25519Chacha20poly1305Sha256Ed25519 => Aead::Chacha20Poly1305,
            CipherSuite::Mls10256Dhkemx448Aes256gcmSha512Ed448 => Aead::Aes256Gcm,
            CipherSuite::Mls10256Dhkemp521Aes256gcmSha512P521 => Aead::Aes256Gcm,
            CipherSuite::Mls10256Dhkemx448Chacha20poly1305Sha512Ed448 => Aead::Chacha20Poly1305,
        }
    }

    #[inline(always)]
    pub fn kem_type(&self) -> KemId {
        match self {
            CipherSuite::Mls10128Dhkemx25519Aes128gcmSha256Ed25519 => KemId::X25519HkdfSha256,
            CipherSuite::Mls10128Dhkemp256Aes128gcmSha256P256 => KemId::P256HkdfSha256,
            CipherSuite::Mls10128Dhkemx25519Chacha20poly1305Sha256Ed25519 => {
                KemId::X25519HkdfSha256
            }
            CipherSuite::Mls10256Dhkemx448Aes256gcmSha512Ed448 => KemId::X448HkdfSha512,
            CipherSuite::Mls10256Dhkemp521Aes256gcmSha512P521 => KemId::P521HkdfSha512,
            CipherSuite::Mls10256Dhkemx448Chacha20poly1305Sha512Ed448 => KemId::X448HkdfSha512,
        }
    }

    #[inline(always)]
    pub fn hash_function(&self) -> HashFunction {
        match self {
            CipherSuite::Mls10128Dhkemx25519Aes128gcmSha256Ed25519 => HashFunction::Sha256,
            CipherSuite::Mls10128Dhkemp256Aes128gcmSha256P256 => HashFunction::Sha256,
            CipherSuite::Mls10128Dhkemx25519Chacha20poly1305Sha256Ed25519 => HashFunction::Sha256,
            CipherSuite::Mls10256Dhkemx448Aes256gcmSha512Ed448 => HashFunction::Sha512,
            CipherSuite::Mls10256Dhkemp521Aes256gcmSha512P521 => HashFunction::Sha512,
            CipherSuite::Mls10256Dhkemx448Chacha20poly1305Sha512Ed448 => HashFunction::Sha512,
        }
    }

    #[inline(always)]
    pub fn signature_scheme(&self) -> SignatureScheme {
        match self {
            CipherSuite::Mls10128Dhkemx25519Aes128gcmSha256Ed25519 => SignatureScheme::Ed25519,
            CipherSuite::Mls10128Dhkemp256Aes128gcmSha256P256 => {
                SignatureScheme::EcdsaSecp256r1Sha256
            }
            CipherSuite::Mls10128Dhkemx25519Chacha20poly1305Sha256Ed25519 => {
                SignatureScheme::Ed25519
            }
            CipherSuite::Mls10256Dhkemx448Aes256gcmSha512Ed448 => SignatureScheme::Ed448,
            CipherSuite::Mls10256Dhkemp521Aes256gcmSha512P521 => {
                SignatureScheme::EcdsaSecp521r1Sha512
            }
            CipherSuite::Mls10256Dhkemx448Chacha20poly1305Sha512Ed448 => SignatureScheme::Ed448,
        }
    }

    #[inline(always)]
    pub fn kdf_type(&self) -> KdfId {
        self.kem_type().kdf()
    }

    #[inline(always)]
    pub fn hpke(&self) -> Hpke {
        Hpke::new(
            self.kem_type(),
            self.kdf_type(),
            AeadId::from(self.aead_type()),
        )
    }

    pub fn kem(&self) -> Kem {
        Kem::new(self.kem_type())
    }
}

impl From<SignatureScheme> for Curve {
    fn from(scheme: SignatureScheme) -> Self {
        match scheme {
            SignatureScheme::EcdsaSecp256r1Sha256 => Curve::P256,
            SignatureScheme::EcdsaSecp521r1Sha512 => Curve::P521,
            SignatureScheme::Ed25519 => Curve::Ed25519,
            SignatureScheme::Ed448 => Curve::Ed448,
        }
    }
}
