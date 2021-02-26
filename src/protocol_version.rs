use serde::{Deserialize, Serialize};
use num_enum::{IntoPrimitive, TryFromPrimitive};

#[derive(IntoPrimitive, TryFromPrimitive, Serialize, Deserialize, Debug, Clone, PartialEq)]
#[repr(u8)]
#[serde(into = "u8", try_from = "u8")]
pub enum ProtocolVersion {
    Mls10 = 0x01,
    #[cfg(test)]
    Test = 0xff
}