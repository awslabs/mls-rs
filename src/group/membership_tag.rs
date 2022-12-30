use crate::group::framing::WireFormat;
use crate::group::message_signature::{MLSContentAuthData, MLSContentTBS};
use crate::group::GroupContext;
use crate::provider::crypto::CipherSuiteProvider;
use std::{io::Write, ops::Deref};
use thiserror::Error;
use tls_codec::{Serialize, Size};
use tls_codec_derive::{TlsDeserialize, TlsSerialize, TlsSize};

use super::message_signature::MLSAuthenticatedContent;

#[derive(Error, Debug)]
pub enum MembershipTagError {
    #[error(transparent)]
    SerializationError(#[from] tls_codec::Error),
    #[error("Membership tags can only be created for the plaintext wire format, found: {0:?}")]
    NonPlainWireFormat(WireFormat),
    #[error(transparent)]
    CipherSuiteProviderError(Box<dyn std::error::Error + Send + Sync + 'static>),
}

#[derive(Clone, Debug, PartialEq)]
struct MLSContentTBM<'a> {
    content_tbs: MLSContentTBS<'a>,
    auth: &'a MLSContentAuthData,
}

impl Size for MLSContentTBM<'_> {
    fn tls_serialized_len(&self) -> usize {
        self.content_tbs.tls_serialized_len() + self.auth.tls_serialized_len()
    }
}

impl Serialize for MLSContentTBM<'_> {
    fn tls_serialize<W: Write>(&self, writer: &mut W) -> Result<usize, tls_codec::Error> {
        Ok(self.content_tbs.tls_serialize(writer)? + self.auth.tls_serialize(writer)?)
    }
}

impl<'a> MLSContentTBM<'a> {
    pub fn from_authenticated_content(
        auth_content: &'a MLSAuthenticatedContent,
        group_context: &'a GroupContext,
    ) -> MLSContentTBM<'a> {
        MLSContentTBM {
            content_tbs: MLSContentTBS::from_authenticated_content(
                auth_content,
                Some(group_context),
            ),
            auth: &auth_content.auth,
        }
    }
}

#[derive(Clone, Debug, PartialEq, TlsDeserialize, TlsSerialize, TlsSize)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct MembershipTag(#[tls_codec(with = "crate::tls::ByteVec")] Vec<u8>);

impl Deref for MembershipTag {
    type Target = Vec<u8>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl From<Vec<u8>> for MembershipTag {
    fn from(m: Vec<u8>) -> Self {
        Self(m)
    }
}

impl MembershipTag {
    pub(crate) fn create<P: CipherSuiteProvider>(
        authenticated_content: &MLSAuthenticatedContent,
        group_context: &GroupContext,
        membership_key: &[u8],
        cipher_suite_provider: &P,
    ) -> Result<Self, MembershipTagError> {
        if authenticated_content.wire_format != WireFormat::Plain {
            return Err(MembershipTagError::NonPlainWireFormat(
                authenticated_content.wire_format,
            ));
        }

        let plaintext_tbm =
            MLSContentTBM::from_authenticated_content(authenticated_content, group_context);

        let serialized_tbm = plaintext_tbm.tls_serialize_detached()?;

        let tag = cipher_suite_provider
            .mac(membership_key, &serialized_tbm)
            .map_err(|e| MembershipTagError::CipherSuiteProviderError(e.into()))?;

        Ok(MembershipTag(tag))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cipher_suite::CipherSuite;
    use crate::group::framing::test_utils::get_test_auth_content;
    use crate::group::test_utils::get_test_group_context;
    use crate::provider::crypto::test_utils::test_cipher_suite_provider;

    use num_enum::TryFromPrimitive;
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
                &get_test_auth_content(b"hello".to_vec()),
                &get_test_group_context(1, cipher_suite),
                b"membership_key".as_ref(),
                &test_cipher_suite_provider(cipher_suite),
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
            let cipher_suite = CipherSuite::try_from_primitive(case.cipher_suite);

            if cipher_suite.is_err() {
                println!("Skipping test for unsupported cipher suite");
                continue;
            }

            let tag = MembershipTag::create(
                &get_test_auth_content(b"hello".to_vec()),
                &get_test_group_context(1, cipher_suite.unwrap()),
                b"membership_key".as_ref(),
                &test_cipher_suite_provider(cipher_suite.unwrap()),
            )
            .unwrap();

            assert_eq!(**tag, case.tag);
        }
    }
}
