use crate::cipher_suite::CipherSuite;
use crate::group::transcript_hash::ConfirmedTranscriptHash;
use crate::serde_utils::vec_u8_as_base64::VecAsBase64;
use ferriscrypt::hmac::{HMacError, Key, Tag};
use ferriscrypt::kdf::hkdf::Hkdf;
use serde_with::serde_as;
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

#[serde_as]
#[derive(
    Clone, PartialEq, TlsDeserialize, TlsSerialize, TlsSize, serde::Deserialize, serde::Serialize,
)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct ConfirmationTag(
    #[tls_codec(with = "crate::tls::ByteVec")]
    #[serde_as(as = "VecAsBase64")]
    Tag,
);

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
        confirmation_key: &[u8],
        confirmed_transcript_hash: &ConfirmedTranscriptHash,
        cipher_suite: &CipherSuite,
    ) -> Result<Self, ConfirmationTagError> {
        let hmac_key = Key::new(confirmation_key, cipher_suite.hash_function())?;
        let mac = hmac_key.generate_tag(confirmed_transcript_hash)?;
        Ok(ConfirmationTag(mac))
    }

    pub(crate) fn matches(
        &self,
        confirmation_key: &[u8],
        confirmed_transcript_hash: &ConfirmedTranscriptHash,
        cipher_suite: &CipherSuite,
    ) -> Result<bool, ConfirmationTagError> {
        let tag =
            ConfirmationTag::create(confirmation_key, confirmed_transcript_hash, cipher_suite)?;

        Ok(&tag == self)
    }

    pub(crate) fn empty(cipher_suite: &CipherSuite) -> Result<Self, ConfirmationTagError> {
        let size = Hkdf::from(cipher_suite.kdf_type()).extract_size();
        let key = Key::new(&vec![0u8; size], cipher_suite.hash_function())?;

        Ok(ConfirmationTag(key.generate_tag(&[])?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cipher_suite::CipherSuite;

    #[cfg(target_arch = "wasm32")]
    use wasm_bindgen_test::wasm_bindgen_test as test;

    #[test]
    fn test_confirmation_tag_matching() {
        for cipher_suite in CipherSuite::all() {
            println!("Running confirmation tag tests for {:?}", cipher_suite);

            let confirmed_hash_a = ConfirmedTranscriptHash::from(b"foo_a".to_vec());

            let confirmation_key_a = b"bar_a".to_vec();

            let confirmed_hash_b = ConfirmedTranscriptHash::from(b"foo_b".to_vec());

            let confirmation_key_b = b"bar_b".to_vec();

            let confirmation_tag =
                ConfirmationTag::create(&confirmation_key_a, &confirmed_hash_a, &cipher_suite)
                    .unwrap();

            assert!(confirmation_tag
                .matches(&confirmation_key_a, &confirmed_hash_a, &cipher_suite)
                .unwrap());

            assert!(!confirmation_tag
                .matches(&confirmation_key_b, &confirmed_hash_a, &cipher_suite)
                .unwrap());

            assert!(!confirmation_tag
                .matches(&confirmation_key_a, &confirmed_hash_b, &cipher_suite)
                .unwrap());
        }
    }

    #[test]
    fn test_empty_tag() {
        for cipher_suite in CipherSuite::all() {
            println!("Running confirmation tag tests for {:?}", cipher_suite);
            ConfirmationTag::empty(&cipher_suite).unwrap();
        }
    }
}
