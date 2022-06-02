use crate::{
    client_config::CredentialValidator,
    group::{
        proposal_filter::{ProposalBundle, ProposalFilter, ProposalFilterError, ProposalInfo},
        ExternalInit, ProposalType, RemoveProposal, Sender,
    },
    tree_kem::{TreeKemPublic, UpdatePath},
};

#[derive(Debug)]
pub struct ExternalCommitFilter<'a, C> {
    committer: Sender,
    update_path: Option<&'a UpdatePath>,
    tree: &'a TreeKemPublic,
    credential_validator: C,
}

impl<'a, C> ExternalCommitFilter<'a, C>
where
    C: CredentialValidator,
{
    pub fn new(
        committer: Sender,
        update_path: Option<&'a UpdatePath>,
        tree: &'a TreeKemPublic,
        credential_validator: C,
    ) -> Self {
        Self {
            committer,
            update_path,
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
        F: FnOnce(&RemoveProposal) -> Result<(), ProposalFilterError>,
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

        at_most_one_remove_proposal(proposals, validate_removal)?;
        Ok(())
    }

    fn verify_remove_proposal(&self, proposal: &RemoveProposal) -> Result<(), ProposalFilterError> {
        let credential = &self
            .tree
            .get_leaf_node(&proposal.to_remove)?
            .signing_identity
            .credential;

        self.credential_validator
            .is_equal_identity(
                &self
                    .update_path
                    .ok_or(ProposalFilterError::MissingUpdatePathInExternalCommit)?
                    .leaf_node
                    .signing_identity
                    .credential,
                credential,
            )
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
        self.validate_custom(proposals, |p| self.verify_remove_proposal(p))
    }

    fn filter(&self, mut proposals: ProposalBundle) -> Result<ProposalBundle, Self::Error> {
        match &self.committer {
            Sender::Member(_) => proposals.retain_by_type::<ExternalInit, _>(|_| false),
            _ => self.validate_custom(&proposals, |_| Ok(()))?,
        }
        Ok(proposals)
    }
}

fn at_most_one_remove_proposal<F>(
    proposals: &ProposalBundle,
    validate: F,
) -> Result<(), ProposalFilterError>
where
    F: FnOnce(&RemoveProposal) -> Result<(), ProposalFilterError>,
{
    let mut removals = proposals.by_type::<RemoveProposal>();

    match (removals.next(), removals.next()) {
        (None, _) => Ok(()),
        (Some(removal), None) => validate(&removal.proposal),
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
