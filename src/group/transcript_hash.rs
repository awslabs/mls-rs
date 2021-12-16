use crate::cipher_suite::CipherSuite;
use crate::group::confirmation_tag::ConfirmationTag;
use crate::group::framing::{MLSPlaintextCommitAuthData, MLSPlaintextCommitContent};
use std::ops::Deref;
use thiserror::Error;
use tls_codec::Serialize;
use tls_codec_derive::{TlsDeserialize, TlsSerialize, TlsSize};

#[derive(Error, Debug)]
pub enum TranscriptHashError {
    #[error(transparent)]
    TlsCodecError(#[from] tls_codec::Error),
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
        commit_content: &MLSPlaintextCommitContent,
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
        confirmation_tag: Option<&ConfirmationTag>,
    ) -> Result<Self, TranscriptHashError> {
        let auth_data = MLSPlaintextCommitAuthData { confirmation_tag };

        let interim_input = [confirmed.0.deref(), &auth_data.tls_serialize_detached()?].concat();

        let value = cipher_suite.hash_function().digest(&interim_input);

        Ok(InterimTranscriptHash::from(value))
    }
}
