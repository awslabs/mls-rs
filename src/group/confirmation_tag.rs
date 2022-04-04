use crate::group::epoch::Epoch;
use crate::group::transcript_hash::ConfirmedTranscriptHash;
use ferriscrypt::hmac::{HMacError, Key, Tag};
use std::{
    fmt::{self, Debug},
    ops::Deref,
};
use thiserror::Error;
use tls_codec_derive::{TlsDeserialize, TlsSerialize, TlsSize};

#[derive(Debug, Error)]
pub enum ConfirmationTagError {
    #[error(transparent)]
    HMacError(#[from] HMacError),
}

#[derive(Clone, PartialEq, TlsDeserialize, TlsSerialize, TlsSize)]
pub struct ConfirmationTag(#[tls_codec(with = "crate::tls::ByteVec")] Tag);

impl Deref for ConfirmationTag {
    type Target = Tag;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Debug for ConfirmationTag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&hex::encode(self.0.as_ref()))
    }
}

impl ConfirmationTag {
    pub(crate) fn create(
        epoch: &Epoch,
        confirmed_transcript_hash: &ConfirmedTranscriptHash,
    ) -> Result<Self, ConfirmationTagError> {
        let hmac_key = Key::new(&epoch.confirmation_key, epoch.cipher_suite.hash_function())?;
        let mac = hmac_key.generate_tag(confirmed_transcript_hash)?;
        Ok(ConfirmationTag(mac))
    }

    pub(crate) fn matches(
        &self,
        epoch: &Epoch,
        confirmed_transcript_hash: &ConfirmedTranscriptHash,
    ) -> Result<bool, ConfirmationTagError> {
        let tag = ConfirmationTag::create(epoch, confirmed_transcript_hash)?;
        Ok(&tag == self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cipher_suite::CipherSuite;
    use crate::group::epoch::test_utils::get_test_epoch;

    #[cfg(target_arch = "wasm32")]
    use wasm_bindgen_test::wasm_bindgen_test as test;

    #[test]
    fn test_confirmation_tag_matching() {
        for cipher_suite in CipherSuite::all() {
            println!("Running confirmation tag tests for {:?}", cipher_suite);

            let confirmed_hash_a = ConfirmedTranscriptHash::from(b"foo_a".to_vec());

            let epoch_a = get_test_epoch(cipher_suite, vec![], b"bar_a".to_vec());

            let confirmed_hash_b = ConfirmedTranscriptHash::from(b"foo_b".to_vec());

            let epoch_b = get_test_epoch(cipher_suite, vec![], b"bar_b".to_vec());

            let confirmation_tag = ConfirmationTag::create(&epoch_a, &confirmed_hash_a).unwrap();

            assert!(confirmation_tag
                .matches(&epoch_a, &confirmed_hash_a)
                .unwrap());

            assert!(!confirmation_tag
                .matches(&epoch_b, &confirmed_hash_a)
                .unwrap());

            assert!(!confirmation_tag
                .matches(&epoch_a, &confirmed_hash_b)
                .unwrap());
        }
    }
}
