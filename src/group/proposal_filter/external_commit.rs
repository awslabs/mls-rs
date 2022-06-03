use crate::{
    cipher_suite::CipherSuite,
    client_config::CredentialValidator,
    extension::RequiredCapabilitiesExt,
    group::{
        proposal_filter::{ProposalBundle, ProposalFilter, ProposalFilterError, ProposalInfo},
        ExternalInit, ProposalType, RemoveProposal, Sender,
    },
    tree_kem::{
        leaf_node::LeafNode,
        leaf_node_validator::{LeafNodeValidator, ValidationContext},
        TreeKemPublic, UpdatePath,
    },
};

#[derive(Debug)]
pub struct ExternalCommitFilter<'a, C> {
    cipher_suite: CipherSuite,
    group_id: Vec<u8>,
    committer: Sender,
    update_path: Option<&'a UpdatePath>,
    tree: &'a TreeKemPublic,
    required_capabilities: Option<RequiredCapabilitiesExt>,
    credential_validator: C,
}

impl<'a, C> ExternalCommitFilter<'a, C>
where
    C: CredentialValidator,
{
    pub fn new(
        cipher_suite: CipherSuite,
        group_id: Vec<u8>,
        committer: Sender,
        update_path: Option<&'a UpdatePath>,
        tree: &'a TreeKemPublic,
        required_capabilities: Option<RequiredCapabilitiesExt>,
        credential_validator: C,
    ) -> Self {
        Self {
            cipher_suite,
            group_id,
            committer,
            update_path,
            tree,
            required_capabilities,
            credential_validator,
        }
    }

    fn validate_custom<F>(
        &self,
        proposals: &ProposalBundle,
        validate_removal: F,
    ) -> Result<(), ProposalFilterError>
    where
        F: FnOnce(&RemoveProposal, &LeafNode) -> Result<(), ProposalFilterError>,
    {
        let _ = match at_most_one_external_init_proposal(&self.committer, proposals)? {
            Some(p) => p,
            None => return Ok(()),
        };

        let unsupported_kind = proposals.proposal_types().find(|ty| {
            ![
                ProposalType::EXTERNAL_INIT,
                ProposalType::REMOVE,
                ProposalType::PSK,
            ]
            .contains(ty)
        });

        match unsupported_kind {
            Some(kind) => Err(ProposalFilterError::InvalidProposalTypeInExternalCommit(
                kind,
            )),
            None => Ok(()),
        }?;

        let leaf_node = &self
            .update_path
            .ok_or(ProposalFilterError::MissingUpdatePathInExternalCommit)?
            .leaf_node;

        let required_capabilities =
            proposals.effective_required_capabilities(self.required_capabilities.clone());

        let validator = LeafNodeValidator::new(
            self.cipher_suite,
            required_capabilities.as_ref(),
            &self.credential_validator,
        );

        validator.check_if_valid(leaf_node, ValidationContext::Commit(&self.group_id))?;
        self.tree.can_add_leaf(leaf_node)?;

        at_most_one_remove_proposal(proposals, leaf_node, validate_removal)?;
        Ok(())
    }

    fn verify_remove_proposal(
        &self,
        proposal: &RemoveProposal,
        update_path_leaf: &LeafNode,
    ) -> Result<(), ProposalFilterError> {
        let credential = &self
            .tree
            .get_leaf_node(proposal.to_remove)?
            .signing_identity
            .credential;

        self.credential_validator
            .is_equal_identity(&update_path_leaf.signing_identity.credential, credential)
            .then(|| ())
            .ok_or(ProposalFilterError::ExternalCommitRemovesOtherIdentity)
    }
}

impl<'a, C> ProposalFilter for ExternalCommitFilter<'a, C>
where
    C: CredentialValidator,
{
    type Error = ProposalFilterError;

    fn validate(&self, proposals: &ProposalBundle) -> Result<(), Self::Error> {
        self.validate_custom(proposals, |p, leaf| self.verify_remove_proposal(p, leaf))
    }

    fn filter(&self, mut proposals: ProposalBundle) -> Result<ProposalBundle, Self::Error> {
        match &self.committer {
            Sender::Member(_) => proposals.retain_by_type::<ExternalInit, _>(|_| false),
            _ => self.validate_custom(&proposals, |_, _| Ok(()))?,
        }
        Ok(proposals)
    }
}

fn at_most_one_remove_proposal<F>(
    proposals: &ProposalBundle,
    update_path_leaf: &LeafNode,
    validate: F,
) -> Result<(), ProposalFilterError>
where
    F: FnOnce(&RemoveProposal, &LeafNode) -> Result<(), ProposalFilterError>,
{
    let mut removals = proposals.by_type::<RemoveProposal>();

    match (removals.next(), removals.next()) {
        (None, _) => Ok(()),
        (Some(removal), None) => validate(&removal.proposal, update_path_leaf),
        (Some(_), Some(_)) => Err(ProposalFilterError::ExternalCommitWithMoreThanOneRemove),
    }
}

fn at_most_one_external_init_proposal<'a>(
    committer: &Sender,
    proposals: &'a ProposalBundle,
) -> Result<Option<&'a ProposalInfo<ExternalInit>>, ProposalFilterError> {
    let mut external_inits = proposals.by_type::<ExternalInit>();

    match (committer, external_inits.next(), external_inits.next()) {
        (Sender::NewMember, Some(p), None) => (*committer == p.sender)
            .then(|| Some(p))
            .ok_or(ProposalFilterError::ExternalInitMustBeCommittedByNewMember),
        (Sender::NewMember, ..) => {
            Err(ProposalFilterError::ExternalCommitMustHaveExactlyOneExternalInit)
        }
        (_, None, _) => Ok(None),
        (_, Some(_), _) => Err(ProposalFilterError::ExternalInitMustBeCommittedByNewMember),
    }
}
