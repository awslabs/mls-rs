use crate::group::proposal_filter::{ProposalBundle, ProposalFilter, ProposalFilterError};

#[derive(Debug)]
pub struct RemoveProposalFilter;

impl RemoveProposalFilter {
    pub fn new() -> Self {
        Self
    }
}

impl ProposalFilter for RemoveProposalFilter {
    type Error = ProposalFilterError;

    fn validate(&self, _: &ProposalBundle) -> Result<(), Self::Error> {
        // todo: Implement when remove proposals are adapted to use indexes
        Ok(())
    }

    fn filter(&self, proposals: ProposalBundle) -> Result<ProposalBundle, Self::Error> {
        // todo: Implement when remove proposals are adapted to use indexes
        Ok(proposals)
    }
}
