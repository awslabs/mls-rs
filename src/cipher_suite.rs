use crate::maybe::MaybeEnum;
use ferriscrypt::asym::ec_key::Curve;
use num_enum::{IntoPrimitive, TryFromPrimitive};
use tls_codec_derive::{TlsDeserialize, TlsSerialize, TlsSize};

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
}

pub type MaybeCipherSuite = MaybeEnum<CipherSuite>;
