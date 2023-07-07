use core::fmt::Debug;
use core::ops::Deref;

use aws_mls_codec::{MlsDecode, MlsEncode, MlsSize};

/// Wrapper type representing a proposal type identifier along with default
/// values defined by the MLS RFC.
#[derive(
    Clone, Copy, Eq, Hash, PartialOrd, Ord, PartialEq, MlsSize, MlsEncode, MlsDecode, Debug,
)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[cfg_attr(feature = "ffi", safer_ffi_gen::ffi_type(clone))]
#[repr(transparent)]
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
    #[cfg(feature = "external_commit")]
    pub const EXTERNAL_INIT: ProposalType = ProposalType(6);
    pub const GROUP_CONTEXT_EXTENSIONS: ProposalType = ProposalType(7);
}
