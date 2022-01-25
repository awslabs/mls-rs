use super::*;

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

pub type ProposalType = u16;

#[derive(Clone, Debug, PartialEq, TlsDeserialize, TlsSerialize, TlsSize)]
#[repr(u16)]
pub enum Proposal {
    #[tls_codec(discriminant = 1)]
    Add(AddProposal),
    Update(UpdateProposal),
    Remove(RemoveProposal),
    //TODO: Psk,
    //TODO: ReInit,
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
