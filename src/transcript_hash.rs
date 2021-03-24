use crate::framing::{MLSPlaintextCommitContent, MLSPlaintextCommitAuthData};
use thiserror::Error;
use serde::{Serialize, Deserialize};
use crate::ciphersuite::{CipherSuiteError};
use cfg_if::cfg_if;
use crate::hash::Mac;
use std::ops::Deref;

cfg_if! {
    if #[cfg(test)] {
        use crate::ciphersuite::test_util::MockCipherSuite as CipherSuite;
    } else {
        use crate::ciphersuite::{CipherSuite};
    }
}

#[derive(Error, Debug)]
pub enum TranscriptHashError {
    #[error(transparent)]
    CipherSuiteError(#[from] CipherSuiteError),
    #[error(transparent)]
    BincodeError(#[from] bincode::Error),
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub (crate) struct ConfirmedTranscriptHash {
    pub cipher_suite: CipherSuite,
    pub value: Vec<u8>
}

impl Deref for ConfirmedTranscriptHash {
    type Target = Vec<u8>;

    fn deref(&self) -> &Self::Target {
        &self.value
    }
}

impl ConfirmedTranscriptHash {
    pub fn new(cipher_suite: CipherSuite, value: Vec<u8>) -> Self {
        Self {
            cipher_suite,
            value
        }
    }

    pub fn new_from_commit(cipher_suite: CipherSuite,
                           interim_transcript_hash: &InterimTranscriptHash,
                           commit_content: &MLSPlaintextCommitContent)
                           -> Result<Self, TranscriptHashError> {
        let confirmed_input = [
            interim_transcript_hash.value.deref(),
            &bincode::serialize(commit_content)?
        ].concat();

        let value = cipher_suite.hash(&confirmed_input)?;

        Ok(Self {
            cipher_suite,
            value
        })
    }

    pub fn get_interim_transcript_hash(&self, confirmation_tag: Mac)
        -> Result<InterimTranscriptHash, TranscriptHashError> {
        InterimTranscriptHash::new_from_confirmation_tag(self.cipher_suite.clone(),
                                                         self, confirmation_tag)
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub (crate) struct InterimTranscriptHash {
    cipher_suite: CipherSuite,
    value: Vec<u8>
}

impl Deref for InterimTranscriptHash {
    type Target = Vec<u8>;

    fn deref(&self) -> &Self::Target {
        &self.value
    }
}

impl InterimTranscriptHash {
    pub fn new(cipher_suite: CipherSuite, value: Vec<u8>) -> Self {
        Self {
            cipher_suite,
            value,
        }
    }

    pub fn new_from_confirmation_tag(cipher_suite: CipherSuite,
                                     confirmed: &ConfirmedTranscriptHash,
                                     confirmation_tag: Mac) -> Result<Self, TranscriptHashError> {
        let auth_data = MLSPlaintextCommitAuthData {
            confirmation_tag
        };

        let interim_input = [
            confirmed.value.deref(),
            &bincode::serialize(&auth_data)?
        ].concat();

        let value = cipher_suite.hash(&interim_input)?;

        Ok(InterimTranscriptHash {
            cipher_suite,
            value
        })
    }

    pub fn get_confirmed_transcript_hash(&self,
                                         commit_content: &MLSPlaintextCommitContent)
        -> Result<ConfirmedTranscriptHash, TranscriptHashError> {
        ConfirmedTranscriptHash::new_from_commit(self.cipher_suite.clone(),
                                                 self, commit_content)
    }
}



