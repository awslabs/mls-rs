use tls_codec::{Deserialize, Serialize};
use tls_codec_derive::{TlsDeserialize, TlsSerialize, TlsSize};
use zeroize::Zeroize;

use crate::{
    group::{framing::ContentType, key_schedule::kdf_expand_with_label},
    provider::crypto::CipherSuiteProvider,
    tree_kem::node::LeafIndex,
};

use super::{CiphertextProcessor, CiphertextProcessorError, GroupStateProvider, ReuseGuard};

#[derive(Clone, Debug, PartialEq, Eq, TlsDeserialize, TlsSerialize, TlsSize)]
pub(crate) struct MLSSenderData {
    pub sender: LeafIndex,
    pub generation: u32,
    pub reuse_guard: ReuseGuard,
}

#[derive(Clone, Debug, PartialEq, Eq, TlsDeserialize, TlsSerialize, TlsSize)]
pub(crate) struct MLSSenderDataAAD {
    #[tls_codec(with = "crate::tls::ByteVec")]
    pub group_id: Vec<u8>,
    pub epoch: u64,
    pub content_type: ContentType,
}

#[derive(Debug, Zeroize)]
pub(crate) struct SenderDataKey {
    pub(crate) key: Vec<u8>,
    pub(crate) nonce: Vec<u8>,
}

impl SenderDataKey {
    pub(crate) fn seal<P: CipherSuiteProvider>(
        &self,
        provider: &P,
        sender_data: &MLSSenderData,
        aad: &MLSSenderDataAAD,
    ) -> Result<Vec<u8>, CiphertextProcessorError> {
        provider
            .aead_seal(
                &self.key,
                &sender_data.tls_serialize_detached()?,
                Some(&aad.tls_serialize_detached()?),
                &self.nonce,
            )
            .map_err(|e| CiphertextProcessorError::CipherSuiteProviderError(e.into()))
    }

    pub(crate) fn open<P: CipherSuiteProvider>(
        &self,
        provider: &P,
        sender_data: &[u8],
        aad: &MLSSenderDataAAD,
    ) -> Result<MLSSenderData, CiphertextProcessorError> {
        provider
            .aead_open(
                &self.key,
                sender_data,
                Some(&aad.tls_serialize_detached()?),
                &self.nonce,
            )
            .map_err(|e| CiphertextProcessorError::CipherSuiteProviderError(e.into()))
            .and_then(|data| MLSSenderData::tls_deserialize(&mut &*data).map_err(From::from))
    }
}

impl<'a, GS, CP> CiphertextProcessor<'a, GS, CP>
where
    GS: GroupStateProvider,
    CP: CipherSuiteProvider,
{
    pub(super) fn sender_data_key(
        &self,
        ciphertext: &[u8],
    ) -> Result<SenderDataKey, CiphertextProcessorError> {
        // Sample the first extract_size bytes of the ciphertext, and if it is shorter, just use
        // the ciphertext itself
        let extract_size = self.cipher_suite_provider.kdf_extract_size();
        let ciphertext_sample = ciphertext.get(0..extract_size).unwrap_or(ciphertext);

        // Generate a sender data key and nonce using the sender_data_secret from the current
        // epoch's key schedule
        let key = kdf_expand_with_label(
            &self.cipher_suite_provider,
            &self.group_state.epoch_secrets().sender_data_secret,
            "key",
            ciphertext_sample,
            Some(self.cipher_suite_provider.aead_key_size()),
        )?;

        let nonce = kdf_expand_with_label(
            &self.cipher_suite_provider,
            &self.group_state.epoch_secrets().sender_data_secret,
            "nonce",
            ciphertext_sample,
            Some(self.cipher_suite_provider.aead_nonce_size()),
        )?;

        Ok(SenderDataKey { key, nonce })
    }
}
// TODO: Write test vectors
