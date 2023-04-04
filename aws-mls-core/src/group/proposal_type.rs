use std::fmt::Debug;
use std::ops::Deref;

use aws_mls_codec::{MlsDecode, MlsEncode, MlsSize};

#[derive(
    Clone,
    Copy,
    Eq,
    Hash,
    PartialEq,
    MlsSize,
    MlsEncode,
    MlsDecode,
    serde::Deserialize,
    serde::Serialize,
)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
/// Wrapper type representing a proposal type identifier along with default
/// values defined by the MLS RFC.
pub struct ProposalType(u16);

impl ProposalType {
    pub const fn new(value: u16) -> ProposalType {
        ProposalType(value)
    }

    pub const fn raw_value(&self) -> u16 {
        self.0
    }
}

impl From<ProposalType> for u16 {
    fn from(value: ProposalType) -> Self {
        value.0
    }
}

impl From<u16> for ProposalType {
    fn from(value: u16) -> Self {
        ProposalType(value)
    }
}

impl Deref for ProposalType {
    type Target = u16;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl ProposalType {
    pub const ADD: ProposalType = ProposalType(1);
    pub const UPDATE: ProposalType = ProposalType(2);
    pub const REMOVE: ProposalType = ProposalType(3);
    pub const PSK: ProposalType = ProposalType(4);
    pub const RE_INIT: ProposalType = ProposalType(5);
    pub const EXTERNAL_INIT: ProposalType = ProposalType(6);
    pub const GROUP_CONTEXT_EXTENSIONS: ProposalType = ProposalType(7);
}

impl Debug for ProposalType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match *self {
            Self::ADD => f.write_str("Add"),
            Self::UPDATE => f.write_str("Update"),
            Self::REMOVE => f.write_str("Remove"),
            Self::PSK => f.write_str("Psk"),
            Self::RE_INIT => f.write_str("ReInit"),
            Self::EXTERNAL_INIT => f.write_str("ExternalInit"),
            Self::GROUP_CONTEXT_EXTENSIONS => f.write_str("GroupContextExtensions"),
            _ => write!(f, "ProposalType({})", self.0),
        }
    }
}
