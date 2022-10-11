use crate::maybe::MaybeEnum;
use crate::serde_utils::vec_u8_as_base64::VecAsBase64;
use ferriscrypt::asym::ec_key::{Curve, EcKeyError, PublicKey, SecretKey};
use ferriscrypt::cipher::aead::Aead;
use ferriscrypt::digest::HashFunction;
use ferriscrypt::hpke::kem::Kem;
use ferriscrypt::hpke::{AeadId, Hpke, KdfId, KemId};
use num_enum::{IntoPrimitive, TryFromPrimitive};
use serde_with::serde_as;
use std::ops::Deref;
use tls_codec_derive::{TlsDeserialize, TlsSerialize, TlsSize};

#[serde_as]
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    Hash,
    TlsDeserialize,
    TlsSerialize,
    TlsSize,
    serde::Deserialize,
    serde::Serialize,
)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct SignaturePublicKey(
    #[tls_codec(with = "crate::tls::ByteVec")]
    #[serde_as(as = "VecAsBase64")]
    Vec<u8>,
);

impl Deref for SignaturePublicKey {
    type Target = Vec<u8>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl From<Vec<u8>> for SignaturePublicKey {
    fn from(data: Vec<u8>) -> Self {
        SignaturePublicKey(data)
    }
}

impl TryFrom<PublicKey> for SignaturePublicKey {
    type Error = EcKeyError;

    fn try_from(pk: PublicKey) -> Result<Self, Self::Error> {
        Ok(SignaturePublicKey::from(pk.to_uncompressed_bytes()?))
    }
}

impl TryFrom<&SecretKey> for SignaturePublicKey {
    type Error = EcKeyError;

    fn try_from(value: &SecretKey) -> Result<Self, Self::Error> {
        SignaturePublicKey::try_from(value.to_public()?)
    }
}

#[derive(
    Debug,
    Copy,
    Clone,
    Eq,
    enum_iterator::Sequence,
    PartialEq,
    TlsDeserialize,
    TlsSerialize,
    TlsSize,
    serde::Deserialize,
    serde::Serialize,
    TryFromPrimitive,
    IntoPrimitive,
)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[repr(u16)]
pub enum CipherSuite {
    Curve25519Aes128 = 0x0001,
    P256Aes128 = 0x0002,
    Curve25519ChaCha20 = 0x0003,
    #[cfg(feature = "openssl_engine")]
    Curve448Aes256 = 0x0004,
    #[cfg(feature = "openssl_engine")]
    P521Aes256 = 0x0005,
    #[cfg(feature = "openssl_engine")]
    Curve448ChaCha20 = 0x0006,
    #[cfg(feature = "openssl_engine")]
    P384Aes256 = 0x0007,
}

impl ToString for CipherSuite {
    fn to_string(&self) -> String {
        match self {
            CipherSuite::Curve25519Aes128 => "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519",
            CipherSuite::P256Aes128 => "MLS_128_DHKEMP256_AES128GCM_SHA256_P256",
            CipherSuite::Curve25519ChaCha20 => {
                "MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519"
            }
            #[cfg(feature = "openssl_engine")]
            CipherSuite::Curve448Aes256 => "MLS_256_DHKEMX448_AES256GCM_SHA512_Ed448",
            #[cfg(feature = "openssl_engine")]
            CipherSuite::P521Aes256 => "MLS_256_DHKEMP521_AES256GCM_SHA512_P521",
            #[cfg(feature = "openssl_engine")]
            CipherSuite::Curve448ChaCha20 => "MLS_256_DHKEMX448_CHACHA20POLY1305_SHA512_Ed448",
            #[cfg(feature = "openssl_engine")]
            CipherSuite::P384Aes256 => "MLS_256_DHKEMP384_AES256GCM_SHA384_P384",
        }
        .to_string()
    }
}

impl CipherSuite {
    pub fn all() -> impl Iterator<Item = CipherSuite> {
        enum_iterator::all()
    }

    #[inline(always)]
    pub fn aead_type(&self) -> Aead {
        match self {
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
    pub(crate) fn kem_type(&self) -> KemId {
        match self {
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
    pub fn hash_function(&self) -> HashFunction {
        match self {
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
    pub(crate) fn kdf_type(&self) -> KdfId {
        self.kem_type().kdf()
    }

    #[inline(always)]
    pub(crate) fn hpke(&self) -> Hpke {
        Hpke::new(
            self.kem_type(),
            self.kdf_type(),
            AeadId::from(self.aead_type()),
        )
    }

    pub(crate) fn kem(&self) -> Kem {
        Kem::new(self.kem_type())
    }

    pub fn signature_key_curve(&self) -> Curve {
        match self {
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
        }
    }

    pub fn generate_signing_key(&self) -> Result<SecretKey, EcKeyError> {
        SecretKey::generate(self.signature_key_curve())
    }
}

pub type MaybeCipherSuite = MaybeEnum<CipherSuite>;
