use super::*;
use crate::{psk::PreSharedKeyID, tree_kem::leaf_node::LeafNode};
use std::fmt::{self, Debug};

#[derive(
    Clone,
    Debug,
    PartialEq,
    TlsDeserialize,
    TlsSerialize,
    TlsSize,
    serde::Deserialize,
    serde::Serialize,
)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct AddProposal {
    pub key_package: KeyPackage,
}

#[derive(
    Clone,
    Debug,
    PartialEq,
    TlsDeserialize,
    TlsSerialize,
    TlsSize,
    serde::Deserialize,
    serde::Serialize,
)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct UpdateProposal {
    pub leaf_node: LeafNode,
}

#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    TlsDeserialize,
    TlsSerialize,
    TlsSize,
    serde::Deserialize,
    serde::Serialize,
)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct RemoveProposal {
    pub to_remove: LeafIndex,
}

#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    TlsDeserialize,
    TlsSerialize,
    TlsSize,
    serde::Deserialize,
    serde::Serialize,
)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct PreSharedKey {
    pub psk: PreSharedKeyID,
}

#[derive(
    Clone,
    Debug,
    PartialEq,
    TlsDeserialize,
    TlsSerialize,
    TlsSize,
    serde::Deserialize,
    serde::Serialize,
)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct ReInit {
    #[tls_codec(with = "crate::tls::ByteVec")]
    pub group_id: Vec<u8>,
    pub version: ProtocolVersion,
    pub cipher_suite: CipherSuite,
    pub extensions: ExtensionList,
}

#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    TlsDeserialize,
    TlsSerialize,
    TlsSize,
    serde::Deserialize,
    serde::Serialize,
)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct ExternalInit {
    #[tls_codec(with = "crate::tls::ByteVec")]
    pub kem_output: Vec<u8>,
}

#[derive(
    Clone,
    Copy,
    Eq,
    Hash,
    PartialEq,
    TlsDeserialize,
    TlsSerialize,
    TlsSize,
    serde::Deserialize,
    serde::Serialize,
)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct ProposalType(pub u16);

impl ProposalType {
    pub const ADD: ProposalType = ProposalType(1);
    pub const UPDATE: ProposalType = ProposalType(2);
    pub const REMOVE: ProposalType = ProposalType(3);
    pub const PSK: ProposalType = ProposalType(4);
    pub const RE_INIT: ProposalType = ProposalType(5);
    pub const EXTERNAL_INIT: ProposalType = ProposalType(6);
    pub const GROUP_CONTEXT_EXTENSIONS: ProposalType = ProposalType(7);
}

impl From<u16> for ProposalType {
    fn from(n: u16) -> Self {
        Self(n)
    }
}

impl Debug for ProposalType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
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

#[derive(
    Clone,
    Debug,
    PartialEq,
    TlsDeserialize,
    TlsSerialize,
    TlsSize,
    serde::Deserialize,
    serde::Serialize,
)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[repr(u16)]
pub enum Proposal {
    #[tls_codec(discriminant = 1)]
    Add(AddProposal),
    Update(UpdateProposal),
    Remove(RemoveProposal),
    Psk(PreSharedKey),
    ReInit(ReInit),
    ExternalInit(ExternalInit),
    GroupContextExtensions(ExtensionList),
}

impl Proposal {
    pub fn proposal_type(&self) -> ProposalType {
        match self {
            Proposal::Add(_) => ProposalType::ADD,
            Proposal::Update(_) => ProposalType::UPDATE,
            Proposal::Remove(_) => ProposalType::REMOVE,
            Proposal::Psk(_) => ProposalType::PSK,
            Proposal::ReInit(_) => ProposalType::RE_INIT,
            Proposal::ExternalInit(_) => ProposalType::EXTERNAL_INIT,
            Proposal::GroupContextExtensions(_) => ProposalType::GROUP_CONTEXT_EXTENSIONS,
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub enum BorrowedProposal<'a> {
    Add(&'a AddProposal),
    Update(&'a UpdateProposal),
    Remove(&'a RemoveProposal),
    Psk(&'a PreSharedKey),
    ReInit(&'a ReInit),
    ExternalInit(&'a ExternalInit),
    GroupContextExtensions(&'a ExtensionList),
}

impl<'a> From<&'a Proposal> for BorrowedProposal<'a> {
    fn from(p: &'a Proposal) -> Self {
        match p {
            Proposal::Add(p) => BorrowedProposal::Add(p),
            Proposal::Update(p) => BorrowedProposal::Update(p),
            Proposal::Remove(p) => BorrowedProposal::Remove(p),
            Proposal::Psk(p) => BorrowedProposal::Psk(p),
            Proposal::ReInit(p) => BorrowedProposal::ReInit(p),
            Proposal::ExternalInit(p) => BorrowedProposal::ExternalInit(p),
            Proposal::GroupContextExtensions(p) => BorrowedProposal::GroupContextExtensions(p),
        }
    }
}

impl<'a> From<&'a AddProposal> for BorrowedProposal<'a> {
    fn from(p: &'a AddProposal) -> Self {
        Self::Add(p)
    }
}

impl<'a> From<&'a UpdateProposal> for BorrowedProposal<'a> {
    fn from(p: &'a UpdateProposal) -> Self {
        Self::Update(p)
    }
}

impl<'a> From<&'a RemoveProposal> for BorrowedProposal<'a> {
    fn from(p: &'a RemoveProposal) -> Self {
        Self::Remove(p)
    }
}

impl<'a> From<&'a PreSharedKey> for BorrowedProposal<'a> {
    fn from(p: &'a PreSharedKey) -> Self {
        Self::Psk(p)
    }
}

impl<'a> From<&'a ReInit> for BorrowedProposal<'a> {
    fn from(p: &'a ReInit) -> Self {
        Self::ReInit(p)
    }
}

impl<'a> From<&'a ExternalInit> for BorrowedProposal<'a> {
    fn from(p: &'a ExternalInit) -> Self {
        Self::ExternalInit(p)
    }
}

impl<'a> From<&'a ExtensionList> for BorrowedProposal<'a> {
    fn from(p: &'a ExtensionList) -> Self {
        Self::GroupContextExtensions(p)
    }
}

#[derive(Clone, Debug, PartialEq, TlsDeserialize, TlsSerialize, TlsSize)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[repr(u8)]
#[allow(clippy::large_enum_variant)]
pub enum ProposalOrRef {
    #[tls_codec(discriminant = 1)]
    Proposal(Proposal),
    Reference(ProposalRef),
}

impl From<Proposal> for ProposalOrRef {
    fn from(proposal: Proposal) -> Self {
        Self::Proposal(proposal)
    }
}

impl From<ProposalRef> for ProposalOrRef {
    fn from(r: ProposalRef) -> Self {
        Self::Reference(r)
    }
}
