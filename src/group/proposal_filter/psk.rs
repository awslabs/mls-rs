use crate::{
    cipher_suite::CipherSuite,
    group::{
        proposal_filter::{ProposalBundle, ProposalFilter, ProposalFilterError},
        JustPreSharedKeyID, KeyScheduleKdf, PreSharedKey,
    },
};
use std::collections::HashSet;

#[derive(Debug)]
pub struct PskProposalFilter {
    cipher_suite: CipherSuite,
}

impl PskProposalFilter {
    pub fn new(cipher_suite: CipherSuite) -> Self {
        Self { cipher_suite }
    }

    fn validate_proposal(&self, proposal: &PreSharedKey) -> Result<(), ProposalFilterError> {
        matches!(proposal.psk.key_id, JustPreSharedKeyID::External(_))
            .then(|| ())
            .ok_or(ProposalFilterError::PskTypeMustBeExternalInPreSharedKeyProposal)?;

        let kdf_extract_size = KeyScheduleKdf::new(self.cipher_suite.kdf_type()).extract_size();

        (proposal.psk.psk_nonce.0.len() == kdf_extract_size)
            .then(|| ())
            .ok_or(ProposalFilterError::InvalidPskNonceLength {
                found: proposal.psk.psk_nonce.0.len(),
                expected: kdf_extract_size,
            })?;

        Ok(())
    }
}

impl ProposalFilter for PskProposalFilter {
    type Error = ProposalFilterError;

    fn validate(&self, proposals: &ProposalBundle) -> Result<(), Self::Error> {
        proposals
            .by_type()
            .try_fold(HashSet::new(), |mut ids, p| {
                self.validate_proposal(&p.proposal)?;
                ids.insert(&p.proposal.psk)
                    .then(|| ids)
                    .ok_or(ProposalFilterError::DuplicatePskIds)
            })
            .map(|_| ())
    }

    fn filter(&self, mut proposals: ProposalBundle) -> Result<ProposalBundle, Self::Error> {
        let mut ids = HashSet::new();

        proposals.retain_by_type(|p| {
            self.validate_proposal(&p.proposal).is_ok() && ids.insert(p.proposal.psk.clone())
        });

        Ok(proposals)
    }
}
