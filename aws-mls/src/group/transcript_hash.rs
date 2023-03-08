use super::*;
use std::{
    fmt::{self, Debug},
    ops::Deref,
};
use thiserror::Error;
use tls_codec::Serialize;
use tls_codec_derive::{TlsDeserialize, TlsSerialize, TlsSize};

#[derive(Error, Debug)]
pub enum TranscriptHashError {
    #[error(transparent)]
    TlsCodecError(#[from] tls_codec::Error),
    #[error(transparent)]
    CipherSuiteProviderError(Box<dyn std::error::Error + Send + Sync + 'static>),
}

#[serde_as]
#[derive(
    Clone,
    PartialEq,
    Eq,
    TlsDeserialize,
    TlsSerialize,
    TlsSize,
    serde::Deserialize,
    serde::Serialize,
)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct ConfirmedTranscriptHash(
    #[tls_codec(with = "crate::tls::ByteVec")]
    #[serde_as(as = "VecAsBase64")]
    Vec<u8>,
);

impl Deref for ConfirmedTranscriptHash {
    type Target = Vec<u8>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl From<Vec<u8>> for ConfirmedTranscriptHash {
    fn from(value: Vec<u8>) -> Self {
        Self(value)
    }
}

impl Debug for ConfirmedTranscriptHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&hex::encode(&self.0))
    }
}

impl ConfirmedTranscriptHash {
    pub(crate) fn create<P: CipherSuiteProvider>(
        cipher_suite_provider: &P,
        interim_transcript_hash: &InterimTranscriptHash,
        content: &AuthenticatedContent,
    ) -> Result<Self, TranscriptHashError> {
        #[derive(Debug, TlsSerialize, TlsSize)]
        struct ConfirmedTranscriptHashInput<'a> {
            wire_format: WireFormat,
            content: &'a FramedContent,
            signature: &'a MessageSignature,
        }

        let input = ConfirmedTranscriptHashInput {
            wire_format: content.wire_format,
            content: &content.content,
            signature: &content.auth.signature,
        };

        let hash_input = [
            interim_transcript_hash.deref(),
            input.tls_serialize_detached()?.deref(),
        ]
        .concat();

        cipher_suite_provider
            .hash(&hash_input)
            .map(Into::into)
            .map_err(|e| TranscriptHashError::CipherSuiteProviderError(e.into()))
    }
}

#[serde_as]
#[derive(
    Clone, PartialEq, TlsDeserialize, TlsSerialize, TlsSize, serde::Deserialize, serde::Serialize,
)]
pub(crate) struct InterimTranscriptHash(
    #[tls_codec(with = "crate::tls::ByteVec")]
    #[serde_as(as = "VecAsBase64")]
    Vec<u8>,
);

impl Deref for InterimTranscriptHash {
    type Target = Vec<u8>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl From<Vec<u8>> for InterimTranscriptHash {
    fn from(value: Vec<u8>) -> Self {
        Self(value)
    }
}

impl Debug for InterimTranscriptHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&hex::encode(&self.0))
    }
}

impl InterimTranscriptHash {
    pub fn create<P: CipherSuiteProvider>(
        cipher_suite_provider: &P,
        confirmed: &ConfirmedTranscriptHash,
        confirmation_tag: &ConfirmationTag,
    ) -> Result<Self, TranscriptHashError> {
        #[derive(Debug, TlsSerialize, TlsSize)]
        struct InterimTranscriptHashInput<'a> {
            confirmation_tag: &'a ConfirmationTag,
        }

        let input = InterimTranscriptHashInput { confirmation_tag }.tls_serialize_detached()?;

        cipher_suite_provider
            .hash(&[confirmed.0.deref(), &input].concat())
            .map(Into::into)
            .map_err(|e| TranscriptHashError::CipherSuiteProviderError(e.into()))
    }
}

#[cfg(test)]
mod tests {
    use aws_mls_core::crypto::{CipherSuite, CipherSuiteProvider};
    use tls_codec::{Deserialize, Serialize};

    use crate::{
        crypto::test_utils::{test_cipher_suite_provider, try_test_cipher_suite_provider},
        group::{
            confirmation_tag::ConfirmationTag,
            framing::{Content, ContentType},
            message_signature::AuthenticatedContent,
            proposal::ProposalOrRef,
            proposal_ref::ProposalRef,
            test_utils::get_test_group_context,
            transcript_hashes, Commit, Sender,
        },
        WireFormat,
    };

    use super::{ConfirmedTranscriptHash, InterimTranscriptHash};

    #[derive(serde::Serialize, serde::Deserialize, Debug, Default, Clone)]
    struct TestCase {
        pub cipher_suite: u16,

        #[serde(with = "hex::serde")]
        pub confirmation_key: Vec<u8>,
        #[serde(with = "hex::serde")]
        pub authenticated_content: Vec<u8>,
        #[serde(with = "hex::serde")]
        pub interim_transcript_hash_before: Vec<u8>,

        #[serde(with = "hex::serde")]
        pub confirmed_transcript_hash_after: Vec<u8>,
        #[serde(with = "hex::serde")]
        pub interim_transcript_hash_after: Vec<u8>,
    }

    #[futures_test::test]
    async fn transcript_hash() {
        let test_cases: Vec<TestCase> =
            load_test_cases!(interop_transcript_hashes, generate_test_vector().await);

        for test_case in test_cases.into_iter() {
            let Some(cs) = try_test_cipher_suite_provider(test_case.cipher_suite) else {
                continue;
            };

            let auth_content =
                AuthenticatedContent::tls_deserialize(&mut &*test_case.authenticated_content)
                    .unwrap();

            assert!(auth_content.content.content_type() == ContentType::Commit);

            let conf_key = &test_case.confirmation_key;
            let conf_hash_after = test_case.confirmed_transcript_hash_after.into();
            let conf_tag = auth_content.auth.confirmation_tag.clone().unwrap();

            assert!(conf_tag.matches(conf_key, &conf_hash_after, &cs).unwrap());

            let (expected_interim, expected_conf) = transcript_hashes(
                &cs,
                &test_case.interim_transcript_hash_before.into(),
                &auth_content,
            )
            .unwrap();

            assert_eq!(*expected_interim, test_case.interim_transcript_hash_after);
            assert_eq!(expected_conf, conf_hash_after);
        }
    }

    async fn generate_test_vector() -> Vec<TestCase> {
        CipherSuite::all().fold(vec![], |mut test_cases, cs| {
            let cs = test_cipher_suite_provider(cs);

            let context = get_test_group_context(0x3456, cs.cipher_suite());

            let proposal_ref = ProposalRef::new_fake(cs.hash(&[9, 9, 9]).unwrap());
            let proposal_ref = ProposalOrRef::Reference(proposal_ref);

            let commit = Commit {
                proposals: vec![proposal_ref],
                path: None,
            };

            let signer = cs.signature_key_generate().unwrap().0;

            let mut auth_content = AuthenticatedContent::new_signed(
                &cs,
                &context,
                Sender::Member(0),
                Content::Commit(commit),
                &signer,
                WireFormat::PublicMessage,
                vec![],
            )
            .unwrap();

            let interim_hash_before = cs.random_bytes_vec(cs.kdf_extract_size()).unwrap().into();

            let conf_hash_after =
                ConfirmedTranscriptHash::create(&cs, &interim_hash_before, &auth_content).unwrap();

            let conf_key = cs.random_bytes_vec(cs.kdf_extract_size()).unwrap();
            let conf_tag = ConfirmationTag::create(&conf_key, &conf_hash_after, &cs).unwrap();

            let interim_hash_after =
                InterimTranscriptHash::create(&cs, &conf_hash_after, &conf_tag).unwrap();

            auth_content.auth.confirmation_tag = Some(conf_tag);

            let test_case = TestCase {
                cipher_suite: cs.cipher_suite().into(),

                confirmation_key: conf_key,
                authenticated_content: auth_content.tls_serialize_detached().unwrap(),
                interim_transcript_hash_before: interim_hash_before.0,

                confirmed_transcript_hash_after: conf_hash_after.0,
                interim_transcript_hash_after: interim_hash_after.0,
            };

            test_cases.push(test_case);
            test_cases
        })
    }
}
