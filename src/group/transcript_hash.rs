use super::*;
use crate::cipher_suite::CipherSuite;
use std::ops::Deref;
use thiserror::Error;
use tls_codec::Serialize;
use tls_codec_derive::{TlsDeserialize, TlsSerialize, TlsSize};

#[derive(Error, Debug)]
pub enum TranscriptHashError {
    #[error(transparent)]
    TlsCodecError(#[from] tls_codec::Error),
    #[error("expected commit, found: {0:?}")]
    NotCommitContent(ContentType),
}

#[derive(Clone, Debug, PartialEq, TlsSerialize, TlsSize)]
pub(crate) struct MLSPlaintextCommitContent<'a> {
    #[tls_codec(with = "crate::tls::ByteVec::<u32>")]
    pub group_id: &'a [u8],
    pub epoch: u64,
    pub sender: &'a Sender,
    #[tls_codec(with = "crate::tls::ByteVec::<u32>")]
    pub authenticated_data: &'a [u8],
    pub content_type: ContentType,
    pub commit: &'a Commit,
    pub signature: &'a MessageSignature,
}

#[derive(Clone, Debug, PartialEq, TlsSerialize, TlsSize)]
pub(crate) struct MLSPlaintextCommitAuthData<'a> {
    pub confirmation_tag: Option<&'a ConfirmationTag>,
}

impl<'a> TryFrom<&'a MLSPlaintext> for MLSPlaintextCommitContent<'a> {
    type Error = TranscriptHashError;

    fn try_from(value: &'a MLSPlaintext) -> Result<Self, Self::Error> {
        match &value.content {
            Content::Commit(c) => Ok(MLSPlaintextCommitContent {
                group_id: &value.group_id,
                epoch: value.epoch,
                sender: &value.sender,
                authenticated_data: &value.authenticated_data,
                content_type: ContentType::Commit,
                commit: c,
                signature: &value.signature,
            }),
            Content::Proposal(_) => {
                Err(TranscriptHashError::NotCommitContent(ContentType::Proposal))
            }
            Content::Application(_) => Err(TranscriptHashError::NotCommitContent(
                ContentType::Application,
            )),
        }
    }
}

impl<'a> From<&'a MLSPlaintext> for MLSPlaintextCommitAuthData<'a> {
    fn from(plaintext: &'a MLSPlaintext) -> Self {
        let confirmation_tag = plaintext.confirmation_tag.as_ref();
        MLSPlaintextCommitAuthData { confirmation_tag }
    }
}

impl<'a> From<&'a ConfirmationTag> for MLSPlaintextCommitAuthData<'a> {
    fn from(tag: &'a ConfirmationTag) -> Self {
        MLSPlaintextCommitAuthData {
            confirmation_tag: Some(tag),
        }
    }
}

impl<'a> From<Option<&'a ConfirmationTag>> for MLSPlaintextCommitAuthData<'a> {
    fn from(tag: Option<&'a ConfirmationTag>) -> Self {
        MLSPlaintextCommitAuthData {
            confirmation_tag: tag,
        }
    }
}

#[derive(Clone, Debug, PartialEq, TlsDeserialize, TlsSerialize, TlsSize)]
pub(crate) struct ConfirmedTranscriptHash(
    #[tls_codec(with = "crate::tls::ByteVec::<u32>")] Vec<u8>,
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

impl ConfirmedTranscriptHash {
    pub fn create(
        cipher_suite: CipherSuite,
        interim_transcript_hash: &InterimTranscriptHash,
        commit_content: MLSPlaintextCommitContent,
    ) -> Result<Self, TranscriptHashError> {
        let confirmed_input = [
            interim_transcript_hash.0.deref(),
            &commit_content.tls_serialize_detached()?,
        ]
        .concat();

        let value = cipher_suite.hash_function().digest(&confirmed_input);

        Ok(Self::from(value))
    }
}

#[derive(Clone, Debug, PartialEq, TlsDeserialize, TlsSerialize, TlsSize)]
pub(crate) struct InterimTranscriptHash(#[tls_codec(with = "crate::tls::ByteVec::<u32>")] Vec<u8>);

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

impl InterimTranscriptHash {
    pub fn create(
        cipher_suite: CipherSuite,
        confirmed: &ConfirmedTranscriptHash,
        auth_data: MLSPlaintextCommitAuthData,
    ) -> Result<Self, TranscriptHashError> {
        let interim_input = [confirmed.0.deref(), &auth_data.tls_serialize_detached()?].concat();
        let value = cipher_suite.hash_function().digest(&interim_input);

        Ok(InterimTranscriptHash::from(value))
    }
}
