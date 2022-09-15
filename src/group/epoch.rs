use crate::cipher_suite::SignaturePublicKey;
use crate::group::secret_tree::SecretTree;
use crate::group::GroupContext;
use crate::psk::Psk;
use crate::serde_utils::vec_u8_as_base64::VecAsBase64;
use crate::tree_kem::node::LeafIndex;
use serde_with::serde_as;
use std::collections::HashMap;
use std::ops::Deref;
use tls_codec_derive::{TlsDeserialize, TlsSerialize, TlsSize};
use zeroize::Zeroize;

use super::ciphertext_processor::EpochSecretsProvider;

#[derive(
    Debug,
    Clone,
    TlsSerialize,
    TlsSize,
    TlsDeserialize,
    serde::Serialize,
    serde::Deserialize,
    PartialEq,
)]
pub(crate) struct Epoch {
    pub context: GroupContext,
    pub self_index: LeafIndex,
    pub(crate) secrets: EpochSecrets,
    #[tls_codec(with = "crate::tls::DefMap")]
    pub signature_public_keys: HashMap<LeafIndex, SignaturePublicKey>,
}

#[derive(
    Debug,
    Clone,
    PartialEq,
    serde::Serialize,
    serde::Deserialize,
    TlsSerialize,
    TlsSize,
    TlsDeserialize,
)]
pub(crate) struct EpochSecrets {
    pub(crate) resumption_secret: Psk,
    pub(crate) sender_data_secret: SenderDataSecret,
    pub(crate) secret_tree: SecretTree,
}

#[serde_as]
#[derive(
    Clone,
    Debug,
    PartialEq,
    Zeroize,
    serde::Serialize,
    serde::Deserialize,
    TlsSerialize,
    TlsSize,
    TlsDeserialize,
)]
#[zeroize(drop)]
pub(crate) struct SenderDataSecret(
    #[tls_codec(with = "crate::tls::ByteVec")]
    #[serde_as(as = "VecAsBase64")]
    Vec<u8>,
);

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

impl EpochSecretsProvider for Epoch {
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

#[cfg(test)]
pub mod test_utils {
    use super::*;
    use crate::cipher_suite::CipherSuite;
    use crate::group::secret_tree::test_utils::get_test_tree;
    use crate::group::test_utils::get_test_group_context;
    use ferriscrypt::kdf::hkdf::Hkdf;
    use ferriscrypt::rand::SecureRng;

    pub(crate) fn get_test_epoch(cipher_suite: CipherSuite) -> Epoch {
        let secret_tree = get_test_tree(
            cipher_suite,
            vec![0_u8; Hkdf::from(cipher_suite.kdf_type()).extract_size()],
            2,
        );

        Epoch {
            context: get_test_group_context(0, cipher_suite),
            self_index: LeafIndex(0),
            secrets: EpochSecrets {
                resumption_secret: SecureRng::gen(cipher_suite.hash_function().digest_size())
                    .unwrap()
                    .into(),
                sender_data_secret: SecureRng::gen(cipher_suite.hash_function().digest_size())
                    .unwrap()
                    .into(),
                secret_tree,
            },
            signature_public_keys: Default::default(),
        }
    }
}
