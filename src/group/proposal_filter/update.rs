use crate::{
    cipher_suite::CipherSuite,
    client_config::CredentialValidator,
    extension::RequiredCapabilitiesExt,
    group::{
        proposal_filter::{ProposalBundle, ProposalFilter, ProposalFilterError, ProposalInfo},
        ProposalType, Sender, UpdateProposal,
    },
    tree_kem::{
        leaf_node_validator::{LeafNodeValidator, ValidationContext},
        TreeKemPublic,
    },
};

#[derive(Debug)]
pub struct UpdateProposalFilter<'a, C> {
    committer: Sender,
    group_id: Vec<u8>,
    cipher_suite: CipherSuite,
    required_capabilities: Option<RequiredCapabilitiesExt>,
    credential_validator: C,
    tree: &'a TreeKemPublic,
}

impl<'a, C> UpdateProposalFilter<'a, C>
where
    C: CredentialValidator,
{
    pub fn new(
        committer: Sender,
        group_id: Vec<u8>,
        cipher_suite: CipherSuite,
        required_capabilities: Option<RequiredCapabilitiesExt>,
        credential_validator: C,
        tree: &'a TreeKemPublic,
    ) -> Self {
        Self {
            committer,
            group_id,
            cipher_suite,
            required_capabilities,
            credential_validator,
            tree,
        }
    }

    fn validate_proposal(
        &self,
        proposal: &ProposalInfo<UpdateProposal>,
        required_capabilities: Option<&RequiredCapabilitiesExt>,
    ) -> Result<(), ProposalFilterError> {
        let proposer = match &proposal.sender {
            Sender::Member(r) => Ok(r),
            _ => Err(ProposalFilterError::InvalidProposalTypeForProposer(
                ProposalType::UPDATE,
                proposal.sender.clone(),
            )),
        }?;

        let validator = LeafNodeValidator::new(
            self.cipher_suite,
            required_capabilities,
            &self.credential_validator,
        );

        validator.check_if_valid(
            &proposal.proposal.leaf_node,
            ValidationContext::Update(&self.group_id),
        )?;

        self.tree
            .can_update_leaf(*proposer, &proposal.proposal.leaf_node)?;

        (proposal.sender != self.committer)
            .then(|| ())
            .ok_or(ProposalFilterError::InvalidCommitSelfUpdate)
    }
}

impl<C> ProposalFilter for UpdateProposalFilter<'_, C>
where
    C: CredentialValidator,
{
    type Error = ProposalFilterError;

    fn validate(&self, proposals: &ProposalBundle) -> Result<(), Self::Error> {
        let required_capabilities =
            proposals.effective_required_capabilities(self.required_capabilities.clone());

        proposals
            .by_type()
            .try_for_each(|p| self.validate_proposal(p, required_capabilities.as_ref()))
    }

    fn filter(&self, mut proposals: ProposalBundle) -> Result<ProposalBundle, Self::Error> {
        let required_capabilities =
            proposals.effective_required_capabilities(self.required_capabilities.clone());

        proposals.retain_by_type(|p| {
            self.validate_proposal(p, required_capabilities.as_ref())
                .is_ok()
        });

        Ok(proposals)
    }
}
