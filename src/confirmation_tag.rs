use crate::ciphersuite::CipherSuiteError;
use crate::crypto::hash::Mac;
use crate::epoch::EpochKeySchedule;
use crate::transcript_hash::ConfirmedTranscriptHash;
use serde::{Deserialize, Serialize};
use std::ops::Deref;

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ConfirmationTag(Mac);

impl Deref for ConfirmationTag {
    type Target = Mac;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl ConfirmationTag {
    pub(crate) fn create(
        key_schedule: &EpochKeySchedule,
        confirmed_transcript_hash: &ConfirmedTranscriptHash,
    ) -> Result<Self, CipherSuiteError> {
        let mac = key_schedule
            .cipher_suite
            .hmac(&key_schedule.confirmation_key, confirmed_transcript_hash)?;

        Ok(Self(mac))
    }

    pub(crate) fn matches(
        &self,
        key_schedule: &EpochKeySchedule,
        confirmed_transcript_hash: &ConfirmedTranscriptHash,
    ) -> Result<bool, CipherSuiteError> {
        let tag = ConfirmationTag::create(key_schedule, confirmed_transcript_hash)?;
        Ok(&tag == self) //FIXME: Constant time equals
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::ciphersuite::test_util::MockCipherSuite as CipherSuite;
    use crate::crypto::hash::{HashFunction, Sha256};
    use crate::epoch::test_utils::get_test_epoch_key_schedule;

    // Mock cipher suite that just takes a SHA256 of the key and message
    fn get_mock_cipher_suite() -> CipherSuite {
        let mut cipher_suite = CipherSuite::new();
        cipher_suite
            .expect_hmac()
            .returning_st(move |key, message| {
                let data = [key.to_vec(), message.to_vec()].concat();
                Ok(Mac::from(Sha256::hash(&data).unwrap()))
            });
        cipher_suite
            .expect_clone()
            .returning_st(get_mock_cipher_suite);
        cipher_suite
    }

    #[test]
    fn test_confirmation_tag_value() {
        let confirmed_hash = ConfirmedTranscriptHash::from(b"foo".to_vec());

        let epoch = get_test_epoch_key_schedule(get_mock_cipher_suite(), vec![], b"bar".to_vec());

        let confirmation_tag = ConfirmationTag::create(&epoch, &confirmed_hash).unwrap();

        assert_eq!(
            hex::encode(&confirmation_tag.mac_value),
            "88ecde925da3c6f8ec3d140683da9d2a422f26c1ae1d9212da1e5a53416dcc88"
        );
    }

    #[test]
    fn test_confirmation_tag_matching() {
        let confirmed_hash_a = ConfirmedTranscriptHash::from(b"foo_a".to_vec());

        let epoch_a =
            get_test_epoch_key_schedule(get_mock_cipher_suite(), vec![], b"bar_a".to_vec());

        let confirmed_hash_b = ConfirmedTranscriptHash::from(b"foo_b".to_vec());

        let epoch_b =
            get_test_epoch_key_schedule(get_mock_cipher_suite(), vec![], b"bar_b".to_vec());

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
