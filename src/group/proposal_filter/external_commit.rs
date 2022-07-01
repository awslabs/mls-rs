use crate::{
    client_config::CredentialValidator,
    group::{
        proposal_filter::{
            ignore_invalid_by_ref_proposal, ProposalBundle, ProposalFilter, ProposalFilterError,
            ProposalInfo,
        },
        ExternalInit, ProposalType, RemoveProposal, Sender,
    },
    tree_kem::{leaf_node::LeafNode, TreeKemPublic},
};

#[derive(Debug)]
pub struct ExternalCommitFilter<'a, C> {
    committer: Sender,
    new_leaf: Option<&'a LeafNode>,
    tree: &'a TreeKemPublic,
    credential_validator: C,
}

impl<'a, C> ExternalCommitFilter<'a, C>
where
    C: CredentialValidator,
{
    pub fn new(
        committer: Sender,
        new_leaf: Option<&'a LeafNode>,
        tree: &'a TreeKemPublic,
        credential_validator: C,
    ) -> Self {
        Self {
            committer,
            new_leaf,
            tree,
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

        match self.new_leaf {
            Some(leaf) => at_most_one_remove_proposal(proposals, leaf, validate_removal),
            None => Err(ProposalFilterError::ExternalCommitMustHaveNewLeaf),
        }
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
            Sender::Member(_) => {
                proposals.retain_by_type::<ExternalInit, _, _>(ignore_invalid_by_ref_proposal(
                    |_| Err(ProposalFilterError::ExternalInitMustBeCommittedByNewMember),
                ))?;
            }
            _ => self.validate_custom(&proposals, |_, _| Ok(()))?,
        }
        Ok(proposals)
    }
}

fn at_most_one_remove_proposal<F>(
    proposals: &ProposalBundle,
    new_leaf: &LeafNode,
    validate: F,
) -> Result<(), ProposalFilterError>
where
    F: FnOnce(&RemoveProposal, &LeafNode) -> Result<(), ProposalFilterError>,
{
    let mut removals = proposals.by_type::<RemoveProposal>();

    match (removals.next(), removals.next()) {
        (None, _) => Ok(()),
        (Some(removal), None) => validate(&removal.proposal, new_leaf),
        (Some(_), Some(_)) => Err(ProposalFilterError::ExternalCommitWithMoreThanOneRemove),
    }
}

fn at_most_one_external_init_proposal<'a>(
    committer: &Sender,
    proposals: &'a ProposalBundle,
) -> Result<Option<&'a ProposalInfo<ExternalInit>>, ProposalFilterError> {
    let mut external_inits = proposals.by_type::<ExternalInit>();

    match (committer, external_inits.next(), external_inits.next()) {
        (Sender::NewMemberCommit, Some(p), None) => (*committer == p.sender)
            .then(|| Some(p))
            .ok_or(ProposalFilterError::ExternalInitMustBeCommittedByNewMember),
        (Sender::NewMemberCommit, ..) => {
            Err(ProposalFilterError::ExternalCommitMustHaveExactlyOneExternalInit)
        }
        (_, None, _) => Ok(None),
        (_, Some(_), _) => Err(ProposalFilterError::ExternalInitMustBeCommittedByNewMember),
    }
}
