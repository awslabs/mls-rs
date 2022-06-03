use crate::{
    cipher_suite::CipherSuite,
    client_config::CredentialValidator,
    extension::RequiredCapabilitiesExt,
    group::proposal_filter::{ProposalBundle, ProposalFilter, ProposalFilterError},
    key_package::KeyPackageValidator,
    tree_kem::TreeKemPublic,
    AddProposal, ProtocolVersion,
};

#[derive(Debug)]
pub struct AddProposalFilter<'a, C> {
    protocol_version: ProtocolVersion,
    cipher_suite: CipherSuite,
    required_capabilities: Option<RequiredCapabilitiesExt>,
    credential_validator: C,
    tree: &'a TreeKemPublic,
}

impl<'a, C> AddProposalFilter<'a, C>
where
    C: CredentialValidator,
{
    pub fn new(
        protocol_version: ProtocolVersion,
        cipher_suite: CipherSuite,
        required_capabilities: Option<RequiredCapabilitiesExt>,
        credential_validator: C,
        tree: &'a TreeKemPublic,
    ) -> Self {
        Self {
            protocol_version,
            cipher_suite,
            required_capabilities,
            credential_validator,
            tree,
        }
    }

    fn validate_proposal(
        &self,
        proposal: &AddProposal,
        required_capabilities: Option<&RequiredCapabilitiesExt>,
    ) -> Result<(), ProposalFilterError> {
        let validator = KeyPackageValidator::new(
            self.protocol_version,
            self.cipher_suite,
            required_capabilities,
            &self.credential_validator,
        );

        validator.check_if_valid(&proposal.key_package, Default::default())?;
        self.tree.can_add_leaf(&proposal.key_package.leaf_node)?;
        Ok(())
    }
}

impl<C> ProposalFilter for AddProposalFilter<'_, C>
where
    C: CredentialValidator,
{
    type Error = ProposalFilterError;

    fn validate(&self, proposals: &ProposalBundle) -> Result<(), Self::Error> {
        let required_capabilities =
            proposals.effective_required_capabilities(self.required_capabilities.clone());

        proposals
            .by_type()
            .try_for_each(|p| self.validate_proposal(&p.proposal, required_capabilities.as_ref()))
    }

    fn filter(&self, mut proposals: ProposalBundle) -> Result<ProposalBundle, Self::Error> {
        let required_capabilities =
            proposals.effective_required_capabilities(self.required_capabilities.clone());

        proposals.retain_by_type(|p| {
            self.validate_proposal(&p.proposal, required_capabilities.as_ref())
                .is_ok()
        });

        Ok(proposals)
    }
}
