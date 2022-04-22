use super::*;
use crate::cipher_suite::CipherSuite;
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
    #[error("expected commit, found: {0:?}")]
    NotCommitContent(ContentType),
}

#[derive(Clone, Debug, PartialEq, TlsSerialize, TlsSize)]
pub(crate) struct MLSMessageCommitContent<'a> {
    pub wire_format: WireFormat,
    #[tls_codec(with = "crate::tls::ByteVec")]
    pub group_id: &'a [u8],
    pub epoch: u64,
    pub sender: &'a Sender,
    #[tls_codec(with = "crate::tls::ByteVec")]
    pub authenticated_data: &'a [u8],
    pub content_type: ContentType,
    pub commit: &'a Commit,
    pub signature: &'a MessageSignature,
}

#[derive(Clone, Debug, PartialEq, TlsSerialize, TlsSize)]
pub(crate) struct MLSPlaintextCommitAuthData<'a> {
    pub confirmation_tag: Option<&'a ConfirmationTag>,
}

impl<'a> MLSMessageCommitContent<'a> {
    pub fn new(value: &'a MLSPlaintext, encrypted: bool) -> Result<Self, TranscriptHashError> {
        match &value.content.content {
            Content::Commit(c) => Ok(MLSMessageCommitContent {
                wire_format: if encrypted {
                    WireFormat::Cipher
                } else {
                    WireFormat::Plain
                },
                group_id: &value.content.group_id,
                epoch: value.content.epoch,
                sender: &value.content.sender,
                authenticated_data: &value.content.authenticated_data,
                content_type: ContentType::Commit,
                commit: c,
                signature: &value.auth.signature,
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
        let confirmation_tag = plaintext.auth.confirmation_tag.as_ref();
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

#[derive(
    Clone, PartialEq, TlsDeserialize, TlsSerialize, TlsSize, serde::Deserialize, serde::Serialize,
)]
pub struct ConfirmedTranscriptHash(#[tls_codec(with = "crate::tls::ByteVec")] Vec<u8>);

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
    pub(crate) fn create(
        cipher_suite: CipherSuite,
        interim_transcript_hash: &InterimTranscriptHash,
        commit_content: MLSMessageCommitContent,
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

#[derive(
    Clone, PartialEq, TlsDeserialize, TlsSerialize, TlsSize, serde::Deserialize, serde::Serialize,
)]
pub(crate) struct InterimTranscriptHash(#[tls_codec(with = "crate::tls::ByteVec")] Vec<u8>);

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
