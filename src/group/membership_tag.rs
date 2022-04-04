use crate::group::epoch::Epoch;
use crate::group::framing::{MLSPlaintext, WireFormat};
use crate::group::message_signature::{MLSMessageAuth, MLSMessageContentTBS};
use crate::group::GroupContext;
use ferriscrypt::hmac::{HMacError, Key, Tag};
use std::{
    io::{Read, Write},
    ops::Deref,
};
use thiserror::Error;
use tls_codec::{Deserialize, Serialize, Size};
use tls_codec_derive::{TlsDeserialize, TlsSerialize, TlsSize};

#[derive(Error, Debug)]
pub enum MembershipTagError {
    #[error(transparent)]
    HMacError(#[from] HMacError),
    #[error(transparent)]
    SerializationError(#[from] tls_codec::Error),
}

#[derive(Clone, Debug, PartialEq)]
struct MLSPlaintextTBM {
    content_tbs: MLSMessageContentTBS,
    auth: MLSMessageAuth,
}

impl Size for MLSPlaintextTBM {
    fn tls_serialized_len(&self) -> usize {
        self.content_tbs.tls_serialized_len() + self.auth.tls_serialized_len()
    }
}

impl Serialize for MLSPlaintextTBM {
    fn tls_serialize<W: Write>(&self, writer: &mut W) -> Result<usize, tls_codec::Error> {
        Ok(self.content_tbs.tls_serialize(writer)? + self.auth.tls_serialize(writer)?)
    }
}

impl Deserialize for MLSPlaintextTBM {
    fn tls_deserialize<R: Read>(bytes: &mut R) -> Result<Self, tls_codec::Error> {
        let content_tbs = MLSMessageContentTBS::tls_deserialize(bytes)?;
        let auth = MLSMessageAuth::tls_deserialize(bytes, content_tbs.content.content_type())?;
        Ok(Self { content_tbs, auth })
    }
}

impl MLSPlaintextTBM {
    pub fn from_plaintext(
        plaintext: &MLSPlaintext,
        group_context: &GroupContext,
        wire_format: WireFormat,
    ) -> MLSPlaintextTBM {
        MLSPlaintextTBM {
            content_tbs: MLSMessageContentTBS {
                wire_format,
                content: plaintext.content.clone(),
                context: Some(group_context.clone()),
            },
            auth: plaintext.auth.clone(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, TlsDeserialize, TlsSerialize, TlsSize)]
pub struct MembershipTag(#[tls_codec(with = "crate::tls::ByteVec")] Tag);

impl Deref for MembershipTag {
    type Target = Tag;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl From<Tag> for MembershipTag {
    fn from(m: Tag) -> Self {
        Self(m)
    }
}

impl MembershipTag {
    pub(crate) fn create(
        plaintext: &MLSPlaintext,
        group_context: &GroupContext,
        epoch: &Epoch,
    ) -> Result<Self, MembershipTagError> {
        let plaintext_tbm =
            MLSPlaintextTBM::from_plaintext(plaintext, group_context, WireFormat::Plain);
        let serialized_tbm = plaintext_tbm.tls_serialize_detached()?;

        let hmac_key = Key::new(&epoch.membership_key, epoch.cipher_suite.hash_function())?;
        let tag = hmac_key.generate_tag(&serialized_tbm)?;

        Ok(MembershipTag(tag))
    }

    pub(crate) fn matches(
        &self,
        plaintext: &MLSPlaintext,
        group_context: &GroupContext,
        epoch: &Epoch,
    ) -> Result<bool, MembershipTagError> {
        let local = MembershipTag::create(plaintext, group_context, epoch)?;
        Ok(&local == self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cipher_suite::CipherSuite;
    use crate::group::epoch::test_utils::get_test_epoch;
    use crate::group::framing::test_utils::get_test_plaintext;
    use crate::group::test_utils::get_test_group_context;

    #[cfg(target_arch = "wasm32")]
    use wasm_bindgen_test::wasm_bindgen_test as test;

    #[test]
    fn test_membership_tag_matching() {
        for cipher_suite in CipherSuite::all() {
            let context_a = get_test_group_context(1);
            let context_b = get_test_group_context(2);
            let plaintext_a = get_test_plaintext(b"hello".to_vec());
            let plaintext_b = get_test_plaintext(b"world".to_vec());

            let epoch_a = get_test_epoch(cipher_suite, b"membership_key_a".to_vec(), vec![]);

            let epoch_b = get_test_epoch(cipher_suite, b"membership_key_b".to_vec(), vec![]);

            let tag = MembershipTag::create(&plaintext_a, &context_a, &epoch_a).unwrap();

            assert!(tag.matches(&plaintext_a, &context_a, &epoch_a).unwrap());

            assert!(!tag.matches(&plaintext_b, &context_a, &epoch_a).unwrap(),);

            assert!(!tag.matches(&plaintext_a, &context_b, &epoch_a).unwrap());

            assert!(!tag.matches(&plaintext_a, &context_a, &epoch_b).unwrap());
        }
    }
}
