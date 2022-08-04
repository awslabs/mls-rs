use enum_iterator::IntoEnumIterator;
use tls_codec_derive::{TlsDeserialize, TlsSerialize, TlsSize};

#[derive(
    Debug,
    Clone,
    Copy,
    Eq,
    Hash,
    IntoEnumIterator,
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
#[repr(u8)]
pub enum ProtocolVersion {
    /// todo: If a new version is added, please add a test to check that incoming messages with a
    /// version different from the group version are rejected.
    Mls10 = 0x01,
}

impl ProtocolVersion {
    pub fn all() -> impl Iterator<Item = ProtocolVersion> {
        ProtocolVersion::into_enum_iter()
    }
}
