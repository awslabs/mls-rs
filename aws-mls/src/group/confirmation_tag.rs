use crate::serde_utils::vec_u8_as_base64::VecAsBase64;
use crate::CipherSuiteProvider;
use crate::{client::MlsError, group::transcript_hash::ConfirmedTranscriptHash};
use alloc::vec::Vec;
use aws_mls_codec::{MlsDecode, MlsEncode, MlsSize};
use core::ops::Deref;
use serde_with::serde_as;

#[serde_as]
#[derive(
    Debug, Clone, PartialEq, MlsSize, MlsEncode, MlsDecode, serde::Deserialize, serde::Serialize,
)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct ConfirmationTag(
    #[mls_codec(with = "aws_mls_codec::byte_vec")]
    #[serde_as(as = "VecAsBase64")]
    Vec<u8>,
);

impl Deref for ConfirmationTag {
    type Target = Vec<u8>;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl ConfirmationTag {
    pub(crate) fn create<P: CipherSuiteProvider>(
        confirmation_key: &[u8],
        confirmed_transcript_hash: &ConfirmedTranscriptHash,
        cipher_suite_provider: &P,
    ) -> Result<Self, MlsError> {
        cipher_suite_provider
            .mac(confirmation_key, confirmed_transcript_hash)
            .map(ConfirmationTag)
            .map_err(|e| MlsError::CryptoProviderError(e.into()))
    }

    pub(crate) fn matches<P: CipherSuiteProvider>(
        &self,
        confirmation_key: &[u8],
        confirmed_transcript_hash: &ConfirmedTranscriptHash,
        cipher_suite_provider: &P,
    ) -> Result<bool, MlsError> {
        let tag = ConfirmationTag::create(
            confirmation_key,
            confirmed_transcript_hash,
            cipher_suite_provider,
        )?;

        Ok(&tag == self)
    }
}

#[cfg(test)]
impl ConfirmationTag {
    pub(crate) fn empty<P: CipherSuiteProvider>(cipher_suite_provider: &P) -> Self {
        Self(
            cipher_suite_provider
                .mac(
                    &alloc::vec![0; cipher_suite_provider.kdf_extract_size()],
                    &[],
                )
                .unwrap(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::test_utils::{test_cipher_suite_provider, TestCryptoProvider};

    #[cfg(target_arch = "wasm32")]
    use wasm_bindgen_test::wasm_bindgen_test as test;

    #[test]
    fn test_confirmation_tag_matching() {
        for cipher_suite in TestCryptoProvider::all_supported_cipher_suites() {
            let cipher_suite_provider = test_cipher_suite_provider(cipher_suite);

            let confirmed_hash_a = ConfirmedTranscriptHash::from(b"foo_a".to_vec());

            let confirmation_key_a = b"bar_a".to_vec();

            let confirmed_hash_b = ConfirmedTranscriptHash::from(b"foo_b".to_vec());

            let confirmation_key_b = b"bar_b".to_vec();

            let confirmation_tag = ConfirmationTag::create(
                &confirmation_key_a,
                &confirmed_hash_a,
                &cipher_suite_provider,
            )
            .unwrap();

            assert!(confirmation_tag
                .matches(
                    &confirmation_key_a,
                    &confirmed_hash_a,
                    &cipher_suite_provider
                )
                .unwrap());

            assert!(!confirmation_tag
                .matches(
                    &confirmation_key_b,
                    &confirmed_hash_a,
                    &cipher_suite_provider
                )
                .unwrap());

            assert!(!confirmation_tag
                .matches(
                    &confirmation_key_a,
                    &confirmed_hash_b,
                    &cipher_suite_provider
                )
                .unwrap());
        }
    }
}
