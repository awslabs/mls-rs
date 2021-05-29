use crate::ciphersuite::CipherSuiteError;
use crate::confirmation_tag::ConfirmationTag;
use crate::epoch::EpochKeySchedule;
use crate::framing::MLSPlaintext;
use crate::group::GroupContext;
use crate::hash::Mac;
use crate::message_signature::{MLSPlaintextTBS, MessageSignature};
use serde::{Deserialize, Serialize};
use std::ops::Deref;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum MembershipTagError {
    #[error(transparent)]
    CipherSuiteError(#[from] CipherSuiteError),
    #[error(transparent)]
    SerializationError(#[from] bincode::Error),
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
struct MLSPlaintextTBM {
    tbs: MLSPlaintextTBS,
    signature: MessageSignature,
    confirmation_tag: Option<ConfirmationTag>,
}

impl MLSPlaintextTBM {
    pub fn from_plaintext(
        plaintext: &MLSPlaintext,
        group_context: &GroupContext,
    ) -> MLSPlaintextTBM {
        MLSPlaintextTBM {
            tbs: MLSPlaintextTBS::from_plaintext(plaintext, group_context),
            signature: plaintext.signature.clone(),
            confirmation_tag: plaintext.confirmation_tag.clone(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct MembershipTag(Mac);

impl Deref for MembershipTag {
    type Target = Mac;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl From<Mac> for MembershipTag {
    fn from(m: Mac) -> Self {
        Self(m)
    }
}

impl MembershipTag {
    pub(crate) fn create(
        plaintext: &MLSPlaintext,
        group_context: &GroupContext,
        key_schedule: &EpochKeySchedule,
    ) -> Result<Self, MembershipTagError> {
        let plaintext_tbm = MLSPlaintextTBM::from_plaintext(plaintext, group_context);
        let serialized_tbm = bincode::serialize(&plaintext_tbm)?;
        let tag = key_schedule
            .cipher_suite
            .hmac(&key_schedule.membership_key, &serialized_tbm)?;
        Ok(MembershipTag(tag))
    }

    pub(crate) fn matches(
        &self,
        plaintext: &MLSPlaintext,
        group_context: &GroupContext,
        key_schedule: &EpochKeySchedule,
    ) -> Result<bool, MembershipTagError> {
        let local = MembershipTag::create(plaintext, group_context, key_schedule)?;
        return Ok(&local == self); //FIXME: Constant time equals
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ciphersuite::test_util::MockCipherSuite as CipherSuite;
    use crate::epoch::test_utils::get_test_epoch_key_schedule;
    use crate::framing::test_utils::get_test_plaintext;
    use crate::group::test_utils::get_test_group_context;
    use crate::hash::HashFunction;
    use crate::hash::Sha256;

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
            .returning_st(move || get_mock_cipher_suite());
        cipher_suite
    }

    #[test]
    fn test_membership_tag_value() {
        let context = get_test_group_context(1);
        let plaintext = get_test_plaintext(b"hello".to_vec());

        let epoch = get_test_epoch_key_schedule(
            get_mock_cipher_suite(),
            b"membership_key_a".to_vec(),
            vec![],
        );

        let tag = MembershipTag::create(&plaintext, &context, &epoch).unwrap();

        assert_eq!(
            hex::encode(&tag.mac_value),
            "6c3b77b35f28c6ef9beb3459e0dbdaf56e86a00f881a0a188395c9703694437a"
        );
    }

    #[test]
    fn test_membership_tag_matching() {
        let context_a = get_test_group_context(1);
        let context_b = get_test_group_context(2);
        let plaintext_a = get_test_plaintext(b"hello".to_vec());
        let plaintext_b = get_test_plaintext(b"world".to_vec());

        let epoch_a = get_test_epoch_key_schedule(
            get_mock_cipher_suite(),
            b"membership_key_a".to_vec(),
            vec![],
        );

        let epoch_b = get_test_epoch_key_schedule(
            get_mock_cipher_suite(),
            b"membership_key_b".to_vec(),
            vec![],
        );

        let tag = MembershipTag::create(&plaintext_a, &context_a, &epoch_a).unwrap();

        assert_eq!(
            tag.matches(&plaintext_a, &context_a, &epoch_a).unwrap(),
            true
        );

        assert_eq!(
            tag.matches(&plaintext_b, &context_a, &epoch_a).unwrap(),
            false
        );

        assert_eq!(
            tag.matches(&plaintext_a, &context_b, &epoch_a).unwrap(),
            false
        );

        assert_eq!(
            tag.matches(&plaintext_a, &context_a, &epoch_b).unwrap(),
            false
        );
    }
}
