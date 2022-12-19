use tls_codec::{Deserialize, Serialize};
use tls_codec_derive::{TlsDeserialize, TlsSerialize, TlsSize};
use zeroize::Zeroize;

use crate::{
    cipher_suite::CipherSuite, group::framing::ContentType, provider::crypto::CryptoProvider,
    tree_kem::node::LeafIndex,
};

use super::{CiphertextProcessorError, ReuseGuard};

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
    pub(crate) fn seal<P: CryptoProvider>(
        &self,
        provider: &P,
        cipher_suite: CipherSuite,
        sender_data: &MLSSenderData,
        aad: &MLSSenderDataAAD,
    ) -> Result<Vec<u8>, CiphertextProcessorError> {
        provider
            .aead_seal(
                cipher_suite,
                &self.key,
                &sender_data.tls_serialize_detached()?,
                Some(&aad.tls_serialize_detached()?),
                &self.nonce,
            )
            .map_err(|e| CiphertextProcessorError::CryptoProviderError(e.into()))
    }

    pub(crate) fn open<P: CryptoProvider>(
        &self,
        provider: &P,
        cipher_suite: CipherSuite,
        sender_data: &[u8],
        aad: &MLSSenderDataAAD,
    ) -> Result<MLSSenderData, CiphertextProcessorError> {
        provider
            .aead_open(
                cipher_suite,
                &self.key,
                sender_data,
                Some(&aad.tls_serialize_detached()?),
                &self.nonce,
            )
            .map_err(|e| CiphertextProcessorError::CryptoProviderError(e.into()))
            .and_then(|data| MLSSenderData::tls_deserialize(&mut &*data).map_err(From::from))
    }
}

// TODO: Write test vectors
