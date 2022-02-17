use super::*;
use crate::psk::PreSharedKeyID;

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
    pub to_remove: KeyPackageRef,
}

#[derive(Clone, Debug, PartialEq, TlsDeserialize, TlsSerialize, TlsSize)]
pub struct PreSharedKey {
    pub psk: PreSharedKeyID,
}

#[derive(Clone, Debug, PartialEq, TlsDeserialize, TlsSerialize, TlsSize)]
pub struct ReInit {
    #[tls_codec(with = "crate::tls::ByteVec::<u8>")]
    pub group_id: Vec<u8>,
    pub version: ProtocolVersion,
    pub cipher_suite: CipherSuite,
    pub extensions: ExtensionList,
}

pub type ProposalType = u16;

#[derive(Clone, Debug, PartialEq, TlsDeserialize, TlsSerialize, TlsSize)]
#[repr(u16)]
pub enum Proposal {
    #[tls_codec(discriminant = 1)]
    Add(AddProposal),
    Update(UpdateProposal),
    Remove(RemoveProposal),
    Psk(PreSharedKey),
    ReInit(ReInit),
    //TODO: ExternalInit,
    //TODO: AppAck,
    #[tls_codec(discriminant = 8)]
    GroupContextExtensions(ExtensionList),
}

#[derive(Clone, Debug, PartialEq, TlsDeserialize, TlsSerialize, TlsSize)]
#[repr(u8)]
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
