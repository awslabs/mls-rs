use crate::{
    extension::ExtensionList,
    group::proposal_filter::{ProposalBundle, ProposalFilter, ProposalFilterError},
};

#[derive(Debug)]
pub struct GroupContextExtensionsProposalFilter;

impl ProposalFilter for GroupContextExtensionsProposalFilter {
    type Error = ProposalFilterError;

    fn validate(&self, proposals: &ProposalBundle) -> Result<(), Self::Error> {
        (proposals.by_type::<ExtensionList>().count() <= 1)
            .then(|| ())
            .ok_or(ProposalFilterError::MoreThanOneGroupContextExtensionsProposal)
    }

    fn filter(&self, mut proposals: ProposalBundle) -> Result<ProposalBundle, Self::Error> {
        let mut found = false;
        proposals.retain_by_type::<ExtensionList, _>(|_| !std::mem::replace(&mut found, true));
        Ok(proposals)
    }
}
