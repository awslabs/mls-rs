use crate::{
    group::{
        proposal_filter::{ProposalBundle, ProposalFilter, ProposalFilterError, ProposalInfo},
        AddProposal, ProposalType, Sender, UpdateProposal,
    },
    tree_kem::TreeKemPublic,
};

#[derive(Debug)]
pub struct UniqueKeysInTree<'a> {
    tree: &'a TreeKemPublic,
}

impl<'a> UniqueKeysInTree<'a> {
    pub fn new(tree: &'a TreeKemPublic) -> Self {
        Self { tree }
    }
}

impl<'a> ProposalFilter for UniqueKeysInTree<'a> {
    type Error = ProposalFilterError;

    fn validate(&self, proposals: &ProposalBundle) -> Result<(), Self::Error> {
        let mut tree = proposals
            .by_type::<UpdateProposal>()
            .try_fold(self.tree.clone(), |mut tree, proposal| {
                apply_update(&mut tree, proposal).map(|_| tree)
            })?;

        let additions = proposals
            .by_type::<AddProposal>()
            .map(|proposal| proposal.proposal.key_package.leaf_node.clone())
            .collect();

        tree.add_leaves(additions)?;
        Ok(())
    }

    fn filter(&self, mut proposals: ProposalBundle) -> Result<ProposalBundle, Self::Error> {
        let mut tree = self.tree.clone();
        proposals.retain_by_type(|proposal| apply_update(&mut tree, proposal).is_ok());

        proposals.retain_by_type::<AddProposal, _>(|proposal| {
            let leaf = proposal.proposal.key_package.leaf_node.clone();
            tree.add_leaves(vec![leaf]).is_ok()
        });

        Ok(proposals)
    }
}

fn apply_update(
    tree: &mut TreeKemPublic,
    proposal: &ProposalInfo<UpdateProposal>,
) -> Result<(), ProposalFilterError> {
    match &proposal.sender {
        Sender::Member(leaf_index) => {
            let leaf = proposal.proposal.leaf_node.clone();
            tree.update_leaf(*leaf_index, leaf)?;
            Ok(())
        }
        _ => Err(ProposalFilterError::InvalidProposalTypeForProposer(
            ProposalType::UPDATE,
            proposal.sender.clone(),
        )),
    }
}
