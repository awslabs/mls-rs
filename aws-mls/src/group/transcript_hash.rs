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
