use crate::maybe::MaybeEnum;
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

impl CipherSuite {
    pub fn all() -> impl Iterator<Item = CipherSuite> {
        enum_iterator::all()
    }
}

pub type MaybeCipherSuite = MaybeEnum<CipherSuite>;
