use crate::{
    group::{
        proposal_filter::{ProposalBundle, ProposalFilter, ProposalFilterError},
        ReInit,
    },
    ProtocolVersion,
};

#[derive(Debug)]
pub struct ReInitProposalFilter {
    protocol_version: ProtocolVersion,
}

impl ReInitProposalFilter {
    pub fn new(protocol_version: ProtocolVersion) -> Self {
        Self { protocol_version }
    }

    fn validate_proposal(&self, proposal: &ReInit) -> Result<(), ProposalFilterError> {
        (proposal.version >= self.protocol_version)
            .then(|| ())
            .ok_or(ProposalFilterError::InvalidProtocolVersionInReInit {
                proposed: proposal.version,
                original: self.protocol_version,
            })?;

        Ok(())
    }
}

impl ProposalFilter for ReInitProposalFilter {
    type Error = ProposalFilterError;

    fn validate(&self, proposals: &ProposalBundle) -> Result<(), Self::Error> {
        proposals
            .by_type()
            .try_for_each(|p| self.validate_proposal(&p.proposal))
    }

    fn filter(&self, mut proposals: ProposalBundle) -> Result<ProposalBundle, Self::Error> {
        proposals.retain_by_type(|p| self.validate_proposal(&p.proposal).is_ok());
        Ok(proposals)
    }
}
