use crate::group::framing::{MLSPlaintext, WireFormat};
use crate::group::message_signature::{MLSContentAuthData, MLSContentTBS};
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
struct MLSContentTBM {
    content_tbs: MLSContentTBS,
    auth: MLSContentAuthData,
}

impl Size for MLSContentTBM {
    fn tls_serialized_len(&self) -> usize {
        self.content_tbs.tls_serialized_len() + self.auth.tls_serialized_len()
    }
}

impl Serialize for MLSContentTBM {
    fn tls_serialize<W: Write>(&self, writer: &mut W) -> Result<usize, tls_codec::Error> {
        Ok(self.content_tbs.tls_serialize(writer)? + self.auth.tls_serialize(writer)?)
    }
}

impl Deserialize for MLSContentTBM {
    fn tls_deserialize<R: Read>(bytes: &mut R) -> Result<Self, tls_codec::Error> {
        let content_tbs = MLSContentTBS::tls_deserialize(bytes)?;
        let auth = MLSContentAuthData::tls_deserialize(bytes, content_tbs.content.content_type())?;
        Ok(Self { content_tbs, auth })
    }
}

impl MLSContentTBM {
    pub fn from_plaintext(
        plaintext: &MLSPlaintext,
        group_context: &GroupContext,
        wire_format: WireFormat,
    ) -> MLSContentTBM {
        MLSContentTBM {
            content_tbs: MLSContentTBS {
                wire_format,
                content: plaintext.content.clone(),
                context: Some(group_context.clone()),
            },
            auth: plaintext.auth.clone(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, TlsDeserialize, TlsSerialize, TlsSize)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
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
        membership_key: &[u8],
    ) -> Result<Self, MembershipTagError> {
        let plaintext_tbm =
            MLSContentTBM::from_plaintext(plaintext, group_context, WireFormat::Plain);

        let serialized_tbm = plaintext_tbm.tls_serialize_detached()?;
        let hmac_key = Key::new(membership_key, group_context.cipher_suite.hash_function())?;
        let tag = hmac_key.generate_tag(&serialized_tbm)?;
        Ok(MembershipTag(tag))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cipher_suite::CipherSuite;
    use crate::group::framing::test_utils::get_test_plaintext;
    use crate::group::test_utils::get_test_group_context;

    #[cfg(target_arch = "wasm32")]
    use wasm_bindgen_test::wasm_bindgen_test as test;

    #[derive(Debug, serde::Serialize, serde::Deserialize)]
    struct TestCase {
        cipher_suite: u16,
        #[serde(with = "hex::serde")]
        tag: Vec<u8>,
    }

    fn generate_test_cases() -> Vec<TestCase> {
        let mut test_cases = Vec::new();

        for cipher_suite in CipherSuite::all() {
            let tag = MembershipTag::create(
                &get_test_plaintext(b"hello".to_vec()),
                &get_test_group_context(1, cipher_suite),
                b"membership_key".as_ref(),
            )
            .unwrap();

            test_cases.push(TestCase {
                cipher_suite: cipher_suite as u16,
                tag: tag.to_vec(),
            });
        }

        test_cases
    }

    fn load_test_cases() -> Vec<TestCase> {
        load_test_cases!(membership_tag, generate_test_cases)
    }

    #[test]
    fn test_membership_tag() {
        for case in load_test_cases() {
            let cipher_suite = CipherSuite::from_raw(case.cipher_suite);

            if cipher_suite.is_none() {
                println!("Skipping test for unsupported cipher suite");
                continue;
            }

            let tag = MembershipTag::create(
                &get_test_plaintext(b"hello".to_vec()),
                &get_test_group_context(1, cipher_suite.unwrap()),
                b"membership_key".as_ref(),
            )
            .unwrap();

            assert_eq!(**tag, case.tag);
        }
    }
}
