use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub enum ProtocolVersion {
    Reserved = 0x00,
    Mls10 = 0x01,
}