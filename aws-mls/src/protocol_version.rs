use std::ops::Deref;

use tls_codec_derive::{TlsDeserialize, TlsSerialize, TlsSize};

#[derive(
    Debug,
    Clone,
    Copy,
    Eq,
    Hash,
    Ord,
    PartialEq,
    PartialOrd,
    TlsDeserialize,
    TlsSerialize,
    TlsSize,
    serde::Deserialize,
    serde::Serialize,
)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct ProtocolVersion(u16);

impl From<u16> for ProtocolVersion {
    fn from(value: u16) -> Self {
        ProtocolVersion(value)
    }
}

impl From<ProtocolVersion> for u16 {
    fn from(value: ProtocolVersion) -> Self {
        value.0
    }
}

impl Deref for ProtocolVersion {
    type Target = u16;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

pub const MLS_10: ProtocolVersion = ProtocolVersion(1);

impl ProtocolVersion {
    pub fn all() -> impl Iterator<Item = ProtocolVersion> {
        [MLS_10].into_iter()
    }
}
