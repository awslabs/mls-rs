use crate::{
    group::{
        framing::Sender,
        proposal_filter::{
            ignore_invalid_by_ref_proposal, ProposalBundle, ProposalFilter, ProposalFilterError,
        },
    },
    tree_kem::TreeKemPublic,
    RemoveProposal,
};

#[derive(Debug)]
pub struct RemoveProposalFilter<'a> {
    tree: &'a TreeKemPublic,
}

impl<'a> RemoveProposalFilter<'a> {
    pub fn new(tree: &'a TreeKemPublic) -> Self {
        Self { tree }
    }

    pub fn validate_proposal(
        &self,
        proposal: &RemoveProposal,
        sender: &Sender,
    ) -> Result<(), ProposalFilterError> {
        if matches!(sender, Sender::Member(sender_index) if sender_index == &proposal.to_remove) {
            return Err(ProposalFilterError::CommitterSelfRemoval);
        }

        self.tree
            .get_leaf_node(proposal.to_remove)
            .map(|_| ())
            .map_err(Into::into)
    }
}

impl<'a> ProposalFilter for RemoveProposalFilter<'a> {
    type Error = ProposalFilterError;

    fn validate(&self, proposals: &ProposalBundle) -> Result<(), Self::Error> {
        proposals
            .by_type()
            .try_for_each(|p| self.validate_proposal(&p.proposal, &p.sender))
    }

    fn filter(&self, mut proposals: ProposalBundle) -> Result<ProposalBundle, Self::Error> {
        proposals.retain_by_type(ignore_invalid_by_ref_proposal(|p| {
            self.validate_proposal(&p.proposal, &p.sender)
        }))?;
        Ok(proposals)
    }
}

#[cfg(test)]
mod tests {
    use assert_matches::assert_matches;

    use crate::{
        cipher_suite::CipherSuite,
        group::{
            framing::Sender,
            proposal_filter::{ProposalBundle, ProposalFilter, ProposalFilterError},
        },
        tree_kem::{
            node::LeafIndex,
            test_utils::{get_test_leaf_nodes, get_test_tree},
            RatchetTreeError, TreeKemPublic,
        },
        Proposal, RemoveProposal,
    };

    use super::RemoveProposalFilter;

    const TEST_CIPHER_SUITE: CipherSuite = CipherSuite::Curve25519Aes128;

    fn get_test_public_tree() -> TreeKemPublic {
        let mut test_tree = get_test_tree(TEST_CIPHER_SUITE);

        let test_leaves = get_test_leaf_nodes(TEST_CIPHER_SUITE);
        test_tree.public.add_leaves(test_leaves).unwrap();

        test_tree.public
    }

    fn get_test_removal(to_remove: LeafIndex, sender: LeafIndex) -> ProposalBundle {
        let mut bundle = ProposalBundle::default();
        bundle.add(
            Proposal::Remove(RemoveProposal { to_remove }),
            Sender::Member(sender),
            None,
        );
        bundle
    }

    #[test]
    fn test_valid_removal() {
        let test_tree = get_test_public_tree();
        let test_bundle = get_test_removal(LeafIndex(1), LeafIndex(0));
        let test_filter = RemoveProposalFilter::new(&test_tree);

        assert!(test_filter.validate(&test_bundle).is_ok());

        assert_eq!(
            test_filter
                .filter(test_bundle.clone())
                .unwrap()
                .by_type::<RemoveProposal>()
                .cloned()
                .map(|info| info.proposal)
                .collect::<Vec<_>>(),
            test_bundle
                .by_type::<RemoveProposal>()
                .cloned()
                .map(|info| info.proposal)
                .collect::<Vec<_>>()
        )
    }

    #[test]
    fn test_committer_self_removal() {
        let test_tree = get_test_public_tree();
        let test_bundle = get_test_removal(LeafIndex(1), LeafIndex(1));
        let test_filter = RemoveProposalFilter::new(&test_tree);

        assert_matches!(
            test_filter.validate(&test_bundle),
            Err(ProposalFilterError::CommitterSelfRemoval)
        );

        assert_matches!(
            test_filter.filter(test_bundle),
            Err(ProposalFilterError::CommitterSelfRemoval)
        );
    }

    #[test]
    fn test_invalid_leaf_index() {
        let test_tree = get_test_public_tree();
        let test_bundle = get_test_removal(LeafIndex(128), LeafIndex(1));
        let test_filter = RemoveProposalFilter::new(&test_tree);

        assert_matches!(
            test_filter.validate(&test_bundle),
            Err(ProposalFilterError::RatchetTreeError(
                RatchetTreeError::NodeVecError(_)
            ))
        );

        assert_matches!(
            test_filter.filter(test_bundle),
            Err(ProposalFilterError::RatchetTreeError(
                RatchetTreeError::NodeVecError(_)
            ))
        )
    }
}
