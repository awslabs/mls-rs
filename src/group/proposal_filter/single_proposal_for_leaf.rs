use crate::{
    cipher_suite::CipherSuite,
    group::{
        proposal_filter::{ProposalBundle, ProposalFilter, ProposalFilterError},
        AddProposal, RemoveProposal, Sender, UpdateProposal,
    },
};
use std::collections::HashSet;

#[derive(Debug)]
pub struct SingleProposalForLeaf {
    cipher_suite: CipherSuite,
}

impl SingleProposalForLeaf {
    pub fn new(cipher_suite: CipherSuite) -> Self {
        Self { cipher_suite }
    }
}

impl ProposalFilter for SingleProposalForLeaf {
    type Error = ProposalFilterError;

    fn validate(&self, proposals: &ProposalBundle) -> Result<(), Self::Error> {
        proposals
            .by_type::<RemoveProposal>()
            .map(|p| p.proposal.to_remove.clone())
            .chain(
                proposals
                    .by_type::<UpdateProposal>()
                    .filter_map(|p| match &p.sender {
                        Sender::Member(leaf) => Some(leaf.clone()),
                        _ => None,
                    }),
            )
            .map(Ok)
            .chain(proposals.by_type::<AddProposal>().map(|p| {
                p.proposal
                    .key_package
                    .leaf_node
                    .to_reference(self.cipher_suite)
            }))
            .try_fold(HashSet::new(), |mut leaves, leaf| {
                let leaf = leaf?;
                leaves
                    .insert(leaf.clone())
                    .then(|| leaves)
                    .ok_or(ProposalFilterError::MoreThanOneProposalForLeaf(leaf))
            })
            .map(|_| ())
    }

    fn filter(&self, mut proposals: ProposalBundle) -> Result<ProposalBundle, Self::Error> {
        let mut leaves = HashSet::new();

        proposals
            .retain_by_type::<RemoveProposal, _>(|p| leaves.insert(p.proposal.to_remove.clone()));

        proposals.retain_by_type::<UpdateProposal, _>(|p| match &p.sender {
            Sender::Member(leaf) => leaves.insert(leaf.clone()),
            _ => true,
        });

        let mut res = Ok(());

        proposals.retain_by_type::<AddProposal, _>(|p| {
            match p
                .proposal
                .key_package
                .leaf_node
                .to_reference(self.cipher_suite)
            {
                Ok(leaf) => leaves.insert(leaf),
                Err(e) => {
                    if res.is_ok() {
                        res = Err(e);
                    }
                    false
                }
            }
        });

        res?;
        Ok(proposals)
    }
}
