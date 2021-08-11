use crate::ciphersuite::CipherSuite;
use crate::group::confirmation_tag::ConfirmationTag;
use crate::group::framing::{MLSPlaintextCommitAuthData, MLSPlaintextCommitContent};
use serde::{Deserialize, Serialize};
use std::ops::Deref;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum TranscriptHashError {
    #[error(transparent)]
    BincodeError(#[from] bincode::Error),
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub(crate) struct ConfirmedTranscriptHash(Vec<u8>);

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
        commit_content: &MLSPlaintextCommitContent,
    ) -> Result<Self, TranscriptHashError> {
        let confirmed_input = [
            interim_transcript_hash.0.deref(),
            &bincode::serialize(commit_content)?,
        ]
        .concat();

        let value = cipher_suite.hash_function().digest(&confirmed_input);

        Ok(Self::from(value))
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub(crate) struct InterimTranscriptHash(Vec<u8>);

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
        confirmation_tag: &ConfirmationTag,
    ) -> Result<Self, TranscriptHashError> {
        let auth_data = MLSPlaintextCommitAuthData { confirmation_tag };

        let interim_input = [confirmed.0.deref(), &bincode::serialize(&auth_data)?].concat();

        let value = cipher_suite.hash_function().digest(&interim_input);

        Ok(InterimTranscriptHash::from(value))
    }
}
