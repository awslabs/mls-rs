use crate::{group::secret_tree::MessageKeyData, provider::crypto::CipherSuiteProvider};

use super::reuse_guard::ReuseGuard;

#[derive(Debug, PartialEq, Eq)]
pub struct MessageKey(MessageKeyData);

impl MessageKey {
    pub(crate) fn new(key: MessageKeyData) -> MessageKey {
        MessageKey(key)
    }

    pub(crate) fn encrypt<P: CipherSuiteProvider>(
        &self,
        provider: &P,
        data: &[u8],
        aad: &[u8],
        reuse_guard: &ReuseGuard,
    ) -> Result<Vec<u8>, P::Error> {
        provider.aead_seal(
            &self.0.key,
            data,
            Some(aad),
            &reuse_guard.apply(&self.0.nonce),
        )
    }

    pub(crate) fn decrypt<P: CipherSuiteProvider>(
        &self,
        provider: &P,
        data: &[u8],
        aad: &[u8],
        reuse_guard: &ReuseGuard,
    ) -> Result<Vec<u8>, P::Error> {
        provider.aead_open(
            &self.0.key,
            data,
            Some(aad),
            &reuse_guard.apply(&self.0.nonce),
        )
    }
}

// TODO: Write test vectors
