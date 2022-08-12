use crate::maybe::MaybeEnum;
use enum_iterator::IntoEnumIterator;
use num_enum::{IntoPrimitive, TryFromPrimitive};
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
    TryFromPrimitive,
    IntoPrimitive,
)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[repr(u8)]
pub enum ProtocolVersion {
    #[cfg(test)]
    Reserved = 0,
    Mls10 = 1,
}

impl ProtocolVersion {
    pub fn all() -> impl Iterator<Item = ProtocolVersion> {
        cfg_if::cfg_if! {
            if #[cfg(test)] {
                ProtocolVersion::into_enum_iter().filter(|&p| p != ProtocolVersion::Reserved)
            } else {
                ProtocolVersion::into_enum_iter()
            }
        }
    }
}

pub type MaybeProtocolVersion = MaybeEnum<ProtocolVersion, u8>;
