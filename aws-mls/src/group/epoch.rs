use crate::crypto::SignaturePublicKey;
use crate::group::GroupContext;
use crate::psk::PreSharedKey;
use crate::serde_utils::vec_u8_as_base64::VecAsBase64;
use crate::tree_kem::node::LeafIndex;
use alloc::vec::Vec;
use core::ops::Deref;
use serde_with::serde_as;
use zeroize::Zeroizing;

#[cfg(feature = "std")]
use std::collections::HashMap;

#[cfg(not(feature = "std"))]
use alloc::collections::BTreeMap;

#[cfg(feature = "private_message")]
use super::ciphertext_processor::GroupStateProvider;

#[cfg(any(feature = "secret_tree_access", feature = "private_message"))]
use crate::group::secret_tree::SecretTree;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq)]
pub(crate) struct PriorEpoch {
    pub(crate) context: GroupContext,
    pub(crate) self_index: LeafIndex,
    pub(crate) secrets: EpochSecrets,

    #[cfg(feature = "std")]
    pub(crate) signature_public_keys: HashMap<LeafIndex, SignaturePublicKey>,
    #[cfg(not(feature = "std"))]
    pub(crate) signature_public_keys: BTreeMap<LeafIndex, SignaturePublicKey>,
}

impl PriorEpoch {
    #[inline(always)]
    pub(crate) fn epoch_id(&self) -> u64 {
        self.context.epoch
    }

    #[inline(always)]
    pub(crate) fn group_id(&self) -> &[u8] {
        &self.context.group_id
    }
}

#[cfg(feature = "private_message")]
impl GroupStateProvider for PriorEpoch {
    fn group_context(&self) -> &GroupContext {
        &self.context
    }

    fn self_index(&self) -> LeafIndex {
        self.self_index
    }

    fn epoch_secrets_mut(&mut self) -> &mut EpochSecrets {
        &mut self.secrets
    }

    fn epoch_secrets(&self) -> &EpochSecrets {
        &self.secrets
    }
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub(crate) struct EpochSecrets {
    pub(crate) resumption_secret: PreSharedKey,
    pub(crate) sender_data_secret: SenderDataSecret,
    #[cfg(any(feature = "secret_tree_access", feature = "private_message"))]
    pub(crate) secret_tree: SecretTree,
}

#[serde_as]
#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
pub(crate) struct SenderDataSecret(#[serde_as(as = "VecAsBase64")] Zeroizing<Vec<u8>>);

impl Deref for SenderDataSecret {
    type Target = Vec<u8>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl From<Vec<u8>> for SenderDataSecret {
    fn from(bytes: Vec<u8>) -> Self {
        Self(Zeroizing::new(bytes))
    }
}

impl From<Zeroizing<Vec<u8>>> for SenderDataSecret {
    fn from(bytes: Zeroizing<Vec<u8>>) -> Self {
        Self(bytes)
    }
}

#[cfg(test)]
pub(crate) mod test_utils {
    use aws_mls_core::crypto::CipherSuiteProvider;

    use super::*;
    use crate::cipher_suite::CipherSuite;
    use crate::crypto::test_utils::test_cipher_suite_provider;

    #[cfg(any(feature = "secret_tree_access", feature = "private_message"))]
    use crate::group::secret_tree::test_utils::get_test_tree;

    use crate::group::test_utils::{get_test_group_context_with_id, random_bytes};

    pub(crate) fn get_test_epoch_secrets(cipher_suite: CipherSuite) -> EpochSecrets {
        let cs_provider = test_cipher_suite_provider(cipher_suite);

        #[cfg(any(feature = "secret_tree_access", feature = "private_message"))]
        let secret_tree = get_test_tree(random_bytes(cs_provider.kdf_extract_size()), 2);

        EpochSecrets {
            resumption_secret: random_bytes(cs_provider.kdf_extract_size()).into(),
            sender_data_secret: random_bytes(cs_provider.kdf_extract_size()).into(),
            #[cfg(any(feature = "secret_tree_access", feature = "private_message"))]
            secret_tree,
        }
    }

    pub(crate) fn get_test_epoch(cipher_suite: CipherSuite) -> PriorEpoch {
        get_test_epoch_with_id(Vec::new(), cipher_suite, 0)
    }

    pub(crate) fn get_test_epoch_with_id(
        group_id: Vec<u8>,
        cipher_suite: CipherSuite,
        id: u64,
    ) -> PriorEpoch {
        PriorEpoch {
            context: get_test_group_context_with_id(group_id, id, cipher_suite),
            self_index: LeafIndex(0),
            secrets: get_test_epoch_secrets(cipher_suite),
            signature_public_keys: Default::default(),
        }
    }
}
