use enum_iterator::IntoEnumIterator;
use ferriscrypt::asym::ec_key::{Curve, EcKeyError, SecretKey};
use ferriscrypt::cipher::aead::Aead;
use ferriscrypt::digest::HashFunction;
use ferriscrypt::hpke::kem::Kem;
use ferriscrypt::hpke::{AeadId, Hpke, KdfId, KemId};
use std::io::{Read, Write};
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

impl TryFrom<Curve> for SignatureScheme {
    type Error = EcKeyError;

    fn try_from(curve: Curve) -> Result<SignatureScheme, Self::Error> {
        match curve {
            Curve::P256 => Ok(SignatureScheme::EcdsaSecp256r1Sha256),
            #[cfg(feature = "openssl_engine")]
            Curve::P384 => Ok(SignatureScheme::EcdsaSecp384r1Sha384),
            #[cfg(feature = "openssl_engine")]
            Curve::P521 => Ok(SignatureScheme::EcdsaSecp521r1Sha512),
            Curve::X25519 => Err(EcKeyError::NotSigningKey(curve)),
            Curve::Ed25519 => Ok(SignatureScheme::Ed25519),
            #[cfg(feature = "openssl_engine")]
            Curve::X448 => Err(EcKeyError::NotSigningKey(curve)),
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
    #[tls_codec(with = "crate::tls::ByteVec")]
    kem_output: Vec<u8>,
    #[tls_codec(with = "crate::tls::ByteVec")]
    ciphertext: Vec<u8>,
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

#[derive(Clone, Debug, Copy, PartialEq)]
pub enum MaybeCipherSuite {
    CipherSuite(CipherSuite),
    Unsupported(u16),
}

impl From<CipherSuite> for MaybeCipherSuite {
    fn from(cs: CipherSuite) -> Self {
        MaybeCipherSuite::CipherSuite(cs)
    }
}

impl From<u16> for MaybeCipherSuite {
    fn from(val: u16) -> Self {
        Self::from_raw_value(val)
    }
}

impl MaybeCipherSuite {
    pub fn raw_value(&self) -> u16 {
        match self {
            MaybeCipherSuite::CipherSuite(cipher_suite) => *cipher_suite as u16,
            MaybeCipherSuite::Unsupported(value) => *value,
        }
    }

    pub fn from_raw_value(value: u16) -> Self {
        CipherSuite::from_raw(value)
            .map(MaybeCipherSuite::CipherSuite)
            .unwrap_or_else(|| MaybeCipherSuite::Unsupported(value))
    }
}

impl tls_codec::Size for MaybeCipherSuite {
    fn tls_serialized_len(&self) -> usize {
        self.raw_value().tls_serialized_len()
    }
}

impl tls_codec::Serialize for MaybeCipherSuite {
    fn tls_serialize<W: Write>(&self, writer: &mut W) -> Result<usize, tls_codec::Error> {
        self.raw_value().tls_serialize(writer)
    }
}

impl tls_codec::Deserialize for MaybeCipherSuite {
    fn tls_deserialize<R: Read>(bytes: &mut R) -> Result<Self, tls_codec::Error>
    where
        Self: Sized,
    {
        let raw_value = u16::tls_deserialize(bytes)?;
        Ok(MaybeCipherSuite::from_raw_value(raw_value))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use assert_matches::assert_matches;
    use tls_codec::Serialize;

    #[cfg(target_arch = "wasm32")]
    use wasm_bindgen_test::wasm_bindgen_test as test;

    #[test]
    fn test_maybe_cipher_suite() {
        for cipher_suite in CipherSuite::all() {
            let maybe = MaybeCipherSuite::from_raw_value(cipher_suite as u16);
            assert_matches!(maybe, MaybeCipherSuite::CipherSuite(cs) if cs == cipher_suite);
        }

        let test_val = CipherSuite::all().map(|cs| cs as u16).max().unwrap() + 1;
        let other = MaybeCipherSuite::from_raw_value(test_val);
        assert_eq!(other, MaybeCipherSuite::Unsupported(test_val));
    }

    #[test]
    fn test_maybe_cipher_suite_serialize() {
        let supported = MaybeCipherSuite::CipherSuite(CipherSuite::Curve25519Aes128V1);
        assert_eq!(
            CipherSuite::Curve25519Aes128V1
                .tls_serialize_detached()
                .unwrap(),
            supported.tls_serialize_detached().unwrap()
        );

        let not_supported = MaybeCipherSuite::Unsupported(32);
        assert_eq!(
            32u16.tls_serialize_detached().unwrap(),
            not_supported.tls_serialize_detached().unwrap()
        );
    }

    #[test]
    fn test_maybe_cipher_suite_from() {
        let supported = MaybeCipherSuite::CipherSuite(CipherSuite::Curve25519Aes128V1);

        assert_eq!(
            MaybeCipherSuite::from(CipherSuite::Curve25519Aes128V1),
            supported
        );

        let unsupported = MaybeCipherSuite::Unsupported(32);
        assert_eq!(MaybeCipherSuite::from(32u16), unsupported);
    }
}
