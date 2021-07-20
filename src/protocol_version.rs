use serde_repr::{Deserialize_repr, Serialize_repr};

#[derive(Serialize_repr, Deserialize_repr, Debug, Clone, Copy, PartialEq)]
#[repr(u8)]
pub enum ProtocolVersion {
    Mls10 = 0x01,
}
