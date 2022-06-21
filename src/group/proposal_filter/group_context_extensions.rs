use crate::{
    cipher_suite::CipherSuite,
    client_config::CredentialValidator,
    extension::{ExtensionList, ExternalSendersExt},
    group::proposal_filter::{
        ignore_invalid_by_ref_proposal, ProposalBundle, ProposalFilter, ProposalFilterError,
    },
};

use super::ProposalInfo;

#[derive(Debug)]
pub struct GroupContextExtensionsProposalFilter<'a, C>
where
    C: CredentialValidator,
{
    credential_validator: &'a C,
    cipher_suite: CipherSuite,
}

impl<'a, C> GroupContextExtensionsProposalFilter<'a, C>
where
    C: CredentialValidator,
{
    pub fn new(credential_validator: &'a C, cipher_suite: CipherSuite) -> Self {
        Self {
            credential_validator,
            cipher_suite,
        }
    }

    fn check_external_senders_ext(
        &self,
        proposal_info: &ProposalInfo<ExtensionList>,
    ) -> Result<(), ProposalFilterError> {
        if let Some(ext_senders) = proposal_info
            .proposal
            .get_extension::<ExternalSendersExt>()?
        {
            ext_senders.verify_all(self.credential_validator, self.cipher_suite)?;
        }

        Ok(())
    }
}

impl<'a, C> ProposalFilter for GroupContextExtensionsProposalFilter<'a, C>
where
    C: CredentialValidator,
{
    type Error = ProposalFilterError;

    fn validate(&self, proposals: &ProposalBundle) -> Result<(), Self::Error> {
        let mut group_context_proposals = proposals.by_type::<ExtensionList>();

        if let Some(first_gcp) = group_context_proposals.next() {
            self.check_external_senders_ext(first_gcp)?;
        }

        if group_context_proposals.next().is_some() {
            Err(ProposalFilterError::MoreThanOneGroupContextExtensionsProposal)
        } else {
            Ok(())
        }
    }

    fn filter(&self, mut proposals: ProposalBundle) -> Result<ProposalBundle, Self::Error> {
        let mut found = false;
        proposals.retain_by_type::<ExtensionList, _, _>(ignore_invalid_by_ref_proposal(
            |proposal| {
                (!std::mem::replace(&mut found, true))
                    .then(|| ())
                    .ok_or(ProposalFilterError::MoreThanOneGroupContextExtensionsProposal)?;

                self.check_external_senders_ext(proposal)
            },
        ))?;
        Ok(proposals)
    }
}

#[cfg(test)]
mod tests {
    use assert_matches::assert_matches;

    use crate::{
        cipher_suite::CipherSuite,
        client_config::{CredentialValidator, PassthroughCredentialValidator},
        extension::{ExtensionList, ExternalSendersExt},
        group::{
            framing::Sender, proposal_filter::ProposalFilterError,
            proposal_ref::test_utils::plaintext_from_proposal, ProposalRef,
        },
        signing_identity::{test_utils::get_test_signing_identity, SigningIdentityError},
        tree_kem::{leaf_node_validator::test_utils::FailureCredentialValidator, node::LeafIndex},
        Proposal, ProposalBundle, ProposalFilter,
    };

    use super::GroupContextExtensionsProposalFilter;

    fn test_bundle(cipher_suite: CipherSuite, extensions: Vec<ExtensionList>) -> ProposalBundle {
        let mut bundle = ProposalBundle::default();

        extensions.into_iter().for_each(|ext| {
            let proposal = Proposal::GroupContextExtensions(ext);

            let proposal_ref = ProposalRef::from_plaintext(
                cipher_suite,
                &plaintext_from_proposal(proposal.clone(), LeafIndex(0)),
                false,
            )
            .unwrap();

            bundle.add(proposal, Sender::Member(LeafIndex(0)), Some(proposal_ref))
        });

        bundle
    }

    #[test]
    fn test_valid_group_context_extensions() {
        let bundle = test_bundle(CipherSuite::Curve25519Aes128, vec![ExtensionList::new()]);
        let credential_validator = PassthroughCredentialValidator::new();

        let filter = GroupContextExtensionsProposalFilter::new(
            &credential_validator,
            crate::cipher_suite::CipherSuite::Curve25519Aes128,
        );

        filter.validate(&bundle).unwrap();

        assert_eq!(
            filter
                .filter(bundle)
                .unwrap()
                .by_type::<ExtensionList>()
                .count(),
            1
        );
    }

    #[test]
    fn test_more_than_one_group_context_extension() {
        let bundle = test_bundle(
            CipherSuite::Curve25519Aes128,
            vec![ExtensionList::new(), ExtensionList::new()],
        );

        let credential_validator = PassthroughCredentialValidator::new();

        let filter = GroupContextExtensionsProposalFilter::new(
            &credential_validator,
            crate::cipher_suite::CipherSuite::Curve25519Aes128,
        );

        assert_matches!(
            filter.validate(&bundle),
            Err(ProposalFilterError::MoreThanOneGroupContextExtensionsProposal)
        );

        assert_eq!(
            filter
                .filter(bundle)
                .unwrap()
                .by_type::<ExtensionList>()
                .count(),
            1
        );
    }

    fn test_filter_external_sender<C: CredentialValidator>(
        credential_validator: &C,
    ) -> (GroupContextExtensionsProposalFilter<C>, ProposalBundle) {
        let cipher_suite = CipherSuite::Curve25519Aes128;

        let (external_sender, _) = get_test_signing_identity(cipher_suite, b"foo".to_vec());
        let mut extensions = ExtensionList::new();

        extensions
            .set_extension(ExternalSendersExt::new(vec![external_sender]))
            .unwrap();

        let bundle = test_bundle(cipher_suite, vec![extensions]);

        (
            GroupContextExtensionsProposalFilter::new(credential_validator, cipher_suite),
            bundle,
        )
    }

    #[test]
    fn test_valid_external_sender() {
        let success_validator = PassthroughCredentialValidator::new();
        let (filter, bundle) = test_filter_external_sender(&success_validator);

        filter.validate(&bundle).unwrap();

        assert_eq!(
            filter
                .filter(bundle)
                .unwrap()
                .by_type::<ExtensionList>()
                .count(),
            1
        )
    }

    #[test]
    fn test_invalid_external_sender() {
        let failure_validator = FailureCredentialValidator::new().pass_validation(false);
        let (filter, bundle) = test_filter_external_sender(&failure_validator);

        assert_matches!(
            filter.validate(&bundle),
            Err(ProposalFilterError::SigningIdentityError(
                SigningIdentityError::CredentialValidatorError(_)
            ))
        );

        assert_eq!(
            filter
                .filter(bundle)
                .unwrap()
                .by_type::<ExtensionList>()
                .count(),
            0
        );
    }
}
