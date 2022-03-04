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
)]
#[repr(u8)]
pub enum ProtocolVersion {
    Mls10 = 0x01,
}

impl ProtocolVersion {
    pub fn all() -> impl Iterator<Item = ProtocolVersion> {
        ProtocolVersion::into_enum_iter()
    }
}
