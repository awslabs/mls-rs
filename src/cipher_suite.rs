use enum_iterator::IntoEnumIterator;
use ferriscrypt::asym::ec_key::{Curve, EcKeyError, SecretKey};
use ferriscrypt::cipher::aead::Aead;
use ferriscrypt::digest::HashFunction;
use ferriscrypt::hpke::kem::Kem;
use ferriscrypt::hpke::{AeadId, HPKECiphertext, Hpke, KdfId, KemId};
use std::convert::TryInto;
use tls_codec_derive::{TlsDeserialize, TlsSerialize, TlsSize};

#[derive(
    Clone, Copy, Debug, IntoEnumIterator, PartialEq, TlsDeserialize, TlsSerialize, TlsSize, Eq, Hash,
)]
#[repr(u16)]
pub enum SignatureScheme {
    EcdsaSecp256r1Sha256 = 0x0403,
    #[cfg(feature = "openssl_engine")]
    EcdsaSecp384r1Sha384 = 0x0503,
    #[cfg(feature = "openssl_engine")]
    EcdsaSecp521r1Sha512 = 0x0603,
    Ed25519 = 0x0703,
    #[cfg(feature = "openssl_engine")]
    Ed448 = 0x0808,
}

impl TryInto<SignatureScheme> for Curve {
    type Error = EcKeyError;

    fn try_into(self) -> Result<SignatureScheme, Self::Error> {
        match self {
            Curve::P256 => Ok(SignatureScheme::EcdsaSecp256r1Sha256),
            #[cfg(feature = "openssl_engine")]
            Curve::P384 => Ok(SignatureScheme::EcdsaSecp384r1Sha384),
            #[cfg(feature = "openssl_engine")]
            Curve::P521 => Ok(SignatureScheme::EcdsaSecp521r1Sha512),
            Curve::X25519 => Err(EcKeyError::NotSigningKey(self)),
            Curve::Ed25519 => Ok(SignatureScheme::Ed25519),
            #[cfg(feature = "openssl_engine")]
            Curve::X448 => Err(EcKeyError::NotSigningKey(self)),
            #[cfg(feature = "openssl_engine")]
            Curve::Ed448 => Ok(SignatureScheme::Ed448),
        }
    }
}

impl SignatureScheme {
    pub fn all() -> impl Iterator<Item = SignatureScheme> {
        Self::into_enum_iter()
    }
}

#[derive(Clone, Debug, PartialEq, TlsDeserialize, TlsSerialize, TlsSize)]
pub struct HpkeCiphertext {
    #[tls_codec(with = "crate::tls::ByteVec::<u32>")]
    kem_output: Vec<u8>,
    #[tls_codec(with = "crate::tls::ByteVec::<u32>")]
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

#[derive(
    Debug, Copy, Clone, Eq, IntoEnumIterator, PartialEq, TlsDeserialize, TlsSerialize, TlsSize,
)]
#[repr(u16)]
pub enum CipherSuite {
    Curve25519Aes128V1 = 0x0001,
    P256Aes128V1 = 0x0002,
    Curve25519ChaCha20V1 = 0x0003,
    #[cfg(feature = "openssl_engine")]
    Curve448Aes256V1 = 0x0004,
    #[cfg(feature = "openssl_engine")]
    P521Aes256V1 = 0x0005,
    #[cfg(feature = "openssl_engine")]
    Curve448ChaCha20V1 = 0x0006,
    #[cfg(feature = "openssl_engine")]
    P384Aes256V1 = 0x0007,
}

impl ToString for CipherSuite {
    fn to_string(&self) -> String {
        match self {
            CipherSuite::Curve25519Aes128V1 => "MLS10_128_DHKEMX25519_AES128GCM_SHA256_Ed25519",
            CipherSuite::P256Aes128V1 => "MLS10_128_DHKEMP256_AES128GCM_SHA256_P256",
            CipherSuite::Curve25519ChaCha20V1 => {
                "MLS10_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519"
            }
            #[cfg(feature = "openssl_engine")]
            CipherSuite::Curve448Aes256V1 => "MLS10_256_DHKEMX448_AES256GCM_SHA512_Ed448",
            #[cfg(feature = "openssl_engine")]
            CipherSuite::P521Aes256V1 => "MLS10_256_DHKEMP521_AES256GCM_SHA512_P521",
            #[cfg(feature = "openssl_engine")]
            CipherSuite::Curve448ChaCha20V1 => "MLS10_256_DHKEMX448_CHACHA20POLY1305_SHA512_Ed448",
            #[cfg(feature = "openssl_engine")]
            CipherSuite::P384Aes256V1 => "MLS10_256_DHKEMP384_AES256GCM_SHA384_P384",
        }
        .to_string()
    }
}

impl CipherSuite {
    #[inline(always)]
    pub fn from_raw(raw: u16) -> Option<Self> {
        match raw {
            1 => Some(CipherSuite::Curve25519Aes128V1),
            2 => Some(CipherSuite::P256Aes128V1),
            3 => Some(CipherSuite::Curve25519ChaCha20V1),
            #[cfg(feature = "openssl_engine")]
            4 => Some(CipherSuite::Curve448Aes256V1),
            #[cfg(feature = "openssl_engine")]
            5 => Some(CipherSuite::P521Aes256V1),
            #[cfg(feature = "openssl_engine")]
            6 => Some(CipherSuite::Curve448ChaCha20V1),
            #[cfg(feature = "openssl_engine")]
            7 => Some(CipherSuite::P384Aes256V1),
            _ => None,
        }
    }

    pub fn all() -> impl Iterator<Item = CipherSuite> {
        Self::into_enum_iter()
    }

    #[inline(always)]
    pub fn aead_type(&self) -> Aead {
        match self {
            CipherSuite::Curve25519Aes128V1 => Aead::Aes128Gcm,
            CipherSuite::P256Aes128V1 => Aead::Aes128Gcm,
            CipherSuite::Curve25519ChaCha20V1 => Aead::Chacha20Poly1305,
            #[cfg(feature = "openssl_engine")]
            CipherSuite::Curve448Aes256V1 => Aead::Aes256Gcm,
            #[cfg(feature = "openssl_engine")]
            CipherSuite::P521Aes256V1 => Aead::Aes256Gcm,
            #[cfg(feature = "openssl_engine")]
            CipherSuite::Curve448ChaCha20V1 => Aead::Chacha20Poly1305,
            #[cfg(feature = "openssl_engine")]
            CipherSuite::P384Aes256V1 => Aead::Aes256Gcm,
        }
    }

    #[inline(always)]
    pub(crate) fn kem_type(&self) -> KemId {
        match self {
            CipherSuite::Curve25519Aes128V1 => KemId::X25519HkdfSha256,
            CipherSuite::P256Aes128V1 => KemId::P256HkdfSha256,
            CipherSuite::Curve25519ChaCha20V1 => KemId::X25519HkdfSha256,
            #[cfg(feature = "openssl_engine")]
            CipherSuite::Curve448Aes256V1 => KemId::X448HkdfSha512,
            #[cfg(feature = "openssl_engine")]
            CipherSuite::P521Aes256V1 => KemId::P521HkdfSha512,
            #[cfg(feature = "openssl_engine")]
            CipherSuite::Curve448ChaCha20V1 => KemId::X448HkdfSha512,
            #[cfg(feature = "openssl_engine")]
            CipherSuite::P384Aes256V1 => KemId::P384HkdfSha384,
        }
    }

    #[inline(always)]
    pub fn hash_function(&self) -> HashFunction {
        match self {
            CipherSuite::Curve25519Aes128V1 => HashFunction::Sha256,
            CipherSuite::P256Aes128V1 => HashFunction::Sha256,
            CipherSuite::Curve25519ChaCha20V1 => HashFunction::Sha256,
            #[cfg(feature = "openssl_engine")]
            CipherSuite::Curve448Aes256V1 => HashFunction::Sha512,
            #[cfg(feature = "openssl_engine")]
            CipherSuite::P521Aes256V1 => HashFunction::Sha512,
            #[cfg(feature = "openssl_engine")]
            CipherSuite::Curve448ChaCha20V1 => HashFunction::Sha512,
            #[cfg(feature = "openssl_engine")]
            CipherSuite::P384Aes256V1 => HashFunction::Sha384,
        }
    }

    #[inline(always)]
    pub fn signature_scheme(&self) -> SignatureScheme {
        match self {
            CipherSuite::Curve25519Aes128V1 => SignatureScheme::Ed25519,
            CipherSuite::P256Aes128V1 => SignatureScheme::EcdsaSecp256r1Sha256,
            CipherSuite::Curve25519ChaCha20V1 => SignatureScheme::Ed25519,
            #[cfg(feature = "openssl_engine")]
            CipherSuite::Curve448Aes256V1 => SignatureScheme::Ed448,
            #[cfg(feature = "openssl_engine")]
            CipherSuite::P521Aes256V1 => SignatureScheme::EcdsaSecp521r1Sha512,
            #[cfg(feature = "openssl_engine")]
            CipherSuite::Curve448ChaCha20V1 => SignatureScheme::Ed448,
            #[cfg(feature = "openssl_engine")]
            CipherSuite::P384Aes256V1 => SignatureScheme::EcdsaSecp384r1Sha384,
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

    pub fn generate_secret_key(&self) -> Result<SecretKey, EcKeyError> {
        SecretKey::generate(Curve::from(self.signature_scheme()))
    }
}

impl From<SignatureScheme> for Curve {
    fn from(scheme: SignatureScheme) -> Self {
        match scheme {
            SignatureScheme::EcdsaSecp256r1Sha256 => Curve::P256,
            #[cfg(feature = "openssl_engine")]
            SignatureScheme::EcdsaSecp521r1Sha512 => Curve::P521,
            SignatureScheme::Ed25519 => Curve::Ed25519,
            #[cfg(feature = "openssl_engine")]
            SignatureScheme::Ed448 => Curve::Ed448,
            #[cfg(feature = "openssl_engine")]
            SignatureScheme::EcdsaSecp384r1Sha384 => Curve::P384,
        }
    }
}
