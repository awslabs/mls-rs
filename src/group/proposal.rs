use crate::key_package::KeyPackage;
use crate::tree_kem::node::LeafIndex;
use tls_codec_derive::{TlsDeserialize, TlsSerialize, TlsSize};

#[derive(Clone, Debug, PartialEq, TlsDeserialize, TlsSerialize, TlsSize)]
#[repr(u8)]
pub enum ProposalType {
    Reserved = 0,
    Add,
    Update,
    Remove,
    //TODO: Psk,
    //TODO: ReInit,
    //TODO: ExternalInit,
}

#[derive(Clone, Debug, PartialEq, TlsDeserialize, TlsSerialize, TlsSize)]
pub struct AddProposal {
    pub key_package: KeyPackage,
}

#[derive(Clone, Debug, PartialEq, TlsDeserialize, TlsSerialize, TlsSize)]
pub struct UpdateProposal {
    pub key_package: KeyPackage,
}

#[derive(Clone, Debug, PartialEq, TlsDeserialize, TlsSerialize, TlsSize)]
pub struct RemoveProposal {
    pub to_remove: u32,
}

#[derive(Clone, Debug, PartialEq, TlsDeserialize, TlsSerialize, TlsSize)]
#[repr(u16)]
pub enum Proposal {
    #[tls_codec(discriminant = 1)]
    Add(AddProposal),
    Update(UpdateProposal),
    Remove(RemoveProposal),
    //TODO: PSK
    //TODO: Psk,
    //TODO: ReInit,
    //TODO: ExternalInit,
}

impl Proposal {
    pub fn is_add(&self) -> bool {
        matches!(self, Self::Add(_))
    }

    pub fn as_add(&self) -> Option<&AddProposal> {
        match self {
            Proposal::Add(add) => Some(add),
            _ => None,
        }
    }

    pub fn is_update(&self) -> bool {
        matches!(self, Self::Update(_))
    }

    pub fn as_update(&self) -> Option<&UpdateProposal> {
        match self {
            Proposal::Update(update) => Some(update),
            _ => None,
        }
    }

    pub fn is_remove(&self) -> bool {
        matches!(self, Self::Remove(_))
    }

    pub fn as_remove(&self) -> Option<&RemoveProposal> {
        match self {
            Proposal::Remove(removal) => Some(removal),
            _ => None,
        }
    }
}

impl From<AddProposal> for Proposal {
    fn from(ap: AddProposal) -> Self {
        Proposal::Add(ap)
    }
}

impl From<Proposal> for ProposalType {
    fn from(p: Proposal) -> Self {
        match p {
            Proposal::Add(_) => ProposalType::Add,
            Proposal::Update(_) => ProposalType::Update,
            Proposal::Remove(_) => ProposalType::Remove,
        }
    }
}

#[derive(Clone, Debug, PartialEq, TlsDeserialize, TlsSerialize, TlsSize)]
#[repr(u8)]
pub enum ProposalOrRefType {
    Reserved = 0,
    Proposal,
    Reference,
}

#[derive(Clone, Debug, PartialEq, TlsDeserialize, TlsSerialize, TlsSize)]
#[repr(u8)]
pub enum ProposalOrRef {
    #[tls_codec(discriminant = 1)]
    Proposal(Proposal),
    Reference(#[tls_codec(with = "crate::tls::ByteVec::<u32>")] Vec<u8>),
}

impl From<Proposal> for ProposalOrRef {
    fn from(proposal: Proposal) -> Self {
        Self::Proposal(proposal)
    }
}

impl From<Vec<u8>> for ProposalOrRef {
    fn from(v: Vec<u8>) -> Self {
        Self::Reference(v)
    }
}

#[derive(Clone, Debug, PartialEq, TlsDeserialize, TlsSerialize, TlsSize)]
pub struct PendingProposal {
    pub proposal: Proposal,
    pub sender: LeafIndex,
}
