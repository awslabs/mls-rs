use std::ops::Deref;

use tls_codec_derive::{TlsDeserialize, TlsSerialize, TlsSize};

#[derive(
    Debug,
    Copy,
    Clone,
    Eq,
    PartialEq,
    TlsDeserialize,
    TlsSerialize,
    TlsSize,
    serde::Deserialize,
    serde::Serialize,
    PartialOrd,
    Ord,
)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct CipherSuite(u16);

impl From<u16> for CipherSuite {
    fn from(value: u16) -> Self {
        CipherSuite(value)
    }
}

impl From<CipherSuite> for u16 {
    fn from(val: CipherSuite) -> Self {
        val.0
    }
}

impl Deref for CipherSuite {
    type Target = u16;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

pub const CURVE25519_AES128: CipherSuite = CipherSuite(1);
pub const P256_AES128: CipherSuite = CipherSuite(2);
pub const CURVE25519_CHACHA: CipherSuite = CipherSuite(3);
pub const CURVE448_AES256: CipherSuite = CipherSuite(4);
pub const P521_AES256: CipherSuite = CipherSuite(5);
pub const CURVE448_CHACHA: CipherSuite = CipherSuite(6);
pub const P384_AES256: CipherSuite = CipherSuite(7);

impl CipherSuite {
    pub fn all() -> impl Iterator<Item = CipherSuite> {
        (1..=7).map(CipherSuite)
    }
}
