use crate::group::GroupContext;
use crate::psk::Psk;
use crate::serde_utils::vec_u8_as_base64::VecAsBase64;
use crate::tree_kem::node::LeafIndex;
use crate::{group::secret_tree::SecretTree, provider::crypto::SignaturePublicKey};
use serde_with::serde_as;
use std::collections::HashMap;
use std::ops::Deref;
use zeroize::Zeroize;

use super::ciphertext_processor::GroupStateProvider;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq)]
pub struct PriorEpoch {
    pub(crate) context: GroupContext,
    pub(crate) self_index: LeafIndex,
    pub(crate) secrets: EpochSecrets,
    pub(crate) signature_public_keys: HashMap<LeafIndex, SignaturePublicKey>,
}

impl PriorEpoch {
    pub fn epoch_id(&self) -> u64 {
        self.context.epoch
    }

    pub fn group_id(&self) -> &[u8] {
        &self.context.group_id
    }
}

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
    pub(crate) resumption_secret: Psk,
    pub(crate) sender_data_secret: SenderDataSecret,
    pub(crate) secret_tree: SecretTree,
}

#[serde_as]
#[derive(Clone, Debug, PartialEq, Zeroize, serde::Serialize, serde::Deserialize)]
#[zeroize(drop)]
pub(crate) struct SenderDataSecret(#[serde_as(as = "VecAsBase64")] Vec<u8>);

impl Deref for SenderDataSecret {
    type Target = Vec<u8>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl From<Vec<u8>> for SenderDataSecret {
    fn from(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }
}

#[cfg(test)]
pub mod test_utils {
    use super::*;
    use crate::cipher_suite::CipherSuite;
    use crate::group::secret_tree::test_utils::get_test_tree;
    use crate::group::test_utils::get_test_group_context_with_id;
    use ferriscrypt::kdf::hkdf::Hkdf;
    use ferriscrypt::rand::SecureRng;

    pub(crate) fn get_test_epoch_secrets(cipher_suite: CipherSuite) -> EpochSecrets {
        let secret_tree = get_test_tree(
            cipher_suite,
            vec![0_u8; Hkdf::from(cipher_suite.kdf_type()).extract_size()],
            2,
        );

        EpochSecrets {
            resumption_secret: SecureRng::gen(cipher_suite.hash_function().digest_size())
                .unwrap()
                .into(),
            sender_data_secret: SecureRng::gen(cipher_suite.hash_function().digest_size())
                .unwrap()
                .into(),
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
