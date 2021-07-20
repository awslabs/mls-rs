use crate::epoch::EpochKeySchedule;
use crate::transcript_hash::ConfirmedTranscriptHash;
use ferriscrypt::hmac::{HMacError, Key, Tag};
use ferriscrypt::Signer;
use serde::{Deserialize, Serialize};
use std::ops::Deref;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ConfirmationTagError {
    #[error(transparent)]
    HMacError(#[from] HMacError),
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ConfirmationTag(Tag);

impl Deref for ConfirmationTag {
    type Target = Tag;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl ConfirmationTag {
    pub(crate) fn create(
        key_schedule: &EpochKeySchedule,
        confirmed_transcript_hash: &ConfirmedTranscriptHash,
    ) -> Result<Self, ConfirmationTagError> {
        let hmac_key = Key::new(
            &key_schedule.confirmation_key,
            key_schedule.cipher_suite.hash_function(),
        )?;
        let mac = hmac_key.sign(confirmed_transcript_hash)?;
        Ok(ConfirmationTag(mac))
    }

    pub(crate) fn matches(
        &self,
        key_schedule: &EpochKeySchedule,
        confirmed_transcript_hash: &ConfirmedTranscriptHash,
    ) -> Result<bool, ConfirmationTagError> {
        let tag = ConfirmationTag::create(key_schedule, confirmed_transcript_hash)?;
        Ok(&tag == self)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::ciphersuite::CipherSuite;
    use crate::epoch::test_utils::get_test_epoch_key_schedule;

    #[test]
    fn test_confirmation_tag_matching() {
        for cipher_suite in CipherSuite::all() {
            println!("Running confirmation tag tests for {:?}", cipher_suite);

            let confirmed_hash_a = ConfirmedTranscriptHash::from(b"foo_a".to_vec());

            let epoch_a = get_test_epoch_key_schedule(cipher_suite, vec![], b"bar_a".to_vec());

            let confirmed_hash_b = ConfirmedTranscriptHash::from(b"foo_b".to_vec());

            let epoch_b = get_test_epoch_key_schedule(cipher_suite, vec![], b"bar_b".to_vec());

            let confirmation_tag = ConfirmationTag::create(&epoch_a, &confirmed_hash_a).unwrap();

            assert!(confirmation_tag
                .matches(&epoch_a, &confirmed_hash_a)
                .unwrap());

            assert!(!confirmation_tag
                .matches(&epoch_b, &confirmed_hash_a)
                .unwrap());

            assert!(!confirmation_tag
                .matches(&epoch_a, &confirmed_hash_b)
                .unwrap());
        }
    }
}
