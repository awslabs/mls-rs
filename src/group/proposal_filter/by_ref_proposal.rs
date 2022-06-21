use crate::group::{
    proposal_filter::{ProposalBundle, ProposalFilter, ProposalFilterError, ProposalInfo},
    Sender,
};

#[derive(Debug)]
pub struct ByRefProposalFilter {
    committer: Sender,
}

impl ByRefProposalFilter {
    pub fn new(committer: Sender) -> Self {
        Self { committer }
    }

    fn validate_proposal<T>(&self, proposal: &ProposalInfo<T>) -> Result<(), ProposalFilterError> {
        match (&self.committer, &proposal.proposal_ref) {
            (_, None) | (Sender::Member(_), _) => Ok(()),
            _ => Err(ProposalFilterError::OnlyMembersCanCommitProposalsByRef),
        }
    }
}

impl ProposalFilter for ByRefProposalFilter {
    type Error = ProposalFilterError;

    fn validate(&self, proposals: &ProposalBundle) -> Result<(), Self::Error> {
        proposals
            .iter_proposals()
            .try_for_each(|p| self.validate_proposal(&p))
    }

    fn filter(&self, proposals: ProposalBundle) -> Result<ProposalBundle, Self::Error> {
        self.validate(&proposals).map(|_| proposals)
    }
}
