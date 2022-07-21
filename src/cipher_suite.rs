use enum_iterator::IntoEnumIterator;
use ferriscrypt::asym::ec_key::{Curve, EcKeyError, PublicKey, SecretKey};
use ferriscrypt::cipher::aead::Aead;
use ferriscrypt::digest::HashFunction;
use ferriscrypt::hpke::kem::Kem;
use ferriscrypt::hpke::{AeadId, Hpke, KdfId, KemId};
use std::io::{Read, Write};
use std::ops::Deref;
use tls_codec_derive::{TlsDeserialize, TlsSerialize, TlsSize};

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
pub struct SignaturePublicKey(#[tls_codec(with = "crate::tls::ByteVec")] Vec<u8>);

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

#[derive(Clone, Debug, PartialEq, TlsDeserialize, TlsSerialize, TlsSize)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
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
    Debug,
    Copy,
    Clone,
    Eq,
    IntoEnumIterator,
    PartialEq,
    TlsDeserialize,
    TlsSerialize,
    TlsSize,
    serde::Deserialize,
    serde::Serialize,
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
    #[inline(always)]
    pub fn from_raw(raw: u16) -> Option<Self> {
        match raw {
            1 => Some(CipherSuite::Curve25519Aes128),
            2 => Some(CipherSuite::P256Aes128),
            3 => Some(CipherSuite::Curve25519ChaCha20),
            #[cfg(feature = "openssl_engine")]
            4 => Some(CipherSuite::Curve448Aes256),
            #[cfg(feature = "openssl_engine")]
            5 => Some(CipherSuite::P521Aes256),
            #[cfg(feature = "openssl_engine")]
            6 => Some(CipherSuite::Curve448ChaCha20),
            #[cfg(feature = "openssl_engine")]
            7 => Some(CipherSuite::P384Aes256),
            _ => None,
        }
    }

    pub fn all() -> impl Iterator<Item = CipherSuite> {
        Self::into_enum_iter()
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

    pub(crate) fn signature_key_curve(&self) -> Curve {
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

#[derive(Clone, Debug, Copy, PartialEq, serde::Deserialize, serde::Serialize)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
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
        let supported = MaybeCipherSuite::CipherSuite(CipherSuite::Curve25519Aes128);
        assert_eq!(
            CipherSuite::Curve25519Aes128
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
        let supported = MaybeCipherSuite::CipherSuite(CipherSuite::Curve25519Aes128);

        assert_eq!(
            MaybeCipherSuite::from(CipherSuite::Curve25519Aes128),
            supported
        );

        let unsupported = MaybeCipherSuite::Unsupported(32);
        assert_eq!(MaybeCipherSuite::from(32u16), unsupported);
    }
}
