use crate::cipher_suite::CipherSuite;
use crate::group::key_schedule::{KeyScheduleKdf, KeyScheduleKdfError};
use crate::group::secret_tree::{
    KeyType, MessageKey, SecretKeyRatchet, SecretTree, SecretTreeError,
};
use crate::group::{GroupContext, MLSCiphertext, MLSCiphertextContentAAD};
use crate::psk::{Psk, PskSecretError};
use crate::tree_kem::node::LeafIndex;
use crate::tree_kem::TreeKemPublic;
use ferriscrypt::asym::ec_key::PublicKey;
use ferriscrypt::cipher::aead::{AeadError, AeadNonce, Key};
use ferriscrypt::cipher::NonceError;
use ferriscrypt::kdf::KdfError;
use std::collections::HashMap;
use thiserror::Error;
use tls_codec::Serialize;
use zeroize::Zeroize;

#[derive(Error, Debug)]
pub enum EpochError {
    #[error(transparent)]
    KeyScheduleKdfError(#[from] KeyScheduleKdfError),
    #[error(transparent)]
    KdfError(#[from] KdfError),
    #[error(transparent)]
    SecretTreeError(#[from] SecretTreeError),
    #[error(transparent)]
    TlsCodecError(#[from] tls_codec::Error),
    #[error(transparent)]
    AeadError(#[from] AeadError),
    #[error(transparent)]
    PskSecretError(#[from] PskSecretError),
    #[error(transparent)]
    NonceError(#[from] NonceError),
    #[error("key derivation failure")]
    KeyDerivationFailure,
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub struct PublicEpoch {
    pub(crate) identifier: u64,
    pub(crate) cipher_suite: CipherSuite,
    pub(crate) public_tree: TreeKemPublic,
}

#[derive(Debug, Clone)]
pub(crate) struct Epoch {
    pub context: GroupContext,
    pub self_index: LeafIndex,
    pub(crate) resumption_secret: Psk,
    sender_data_secret: SenderDataSecret,
    secret_tree: SecretTree,
    handshake_ratchets: HashMap<LeafIndex, SecretKeyRatchet>,
    application_ratchets: HashMap<LeafIndex, SecretKeyRatchet>,
    pub cipher_suite: CipherSuite,
    pub signature_public_keys: HashMap<LeafIndex, PublicKey>,
}

#[derive(Clone, Debug, PartialEq, Zeroize)]
#[zeroize(drop)]
struct SenderDataSecret(Vec<u8>);

impl From<Vec<u8>> for SenderDataSecret {
    fn from(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }
}

impl PartialEq for Epoch {
    fn eq(&self, other: &Self) -> bool {
        self.context == other.context
            && self.self_index == other.self_index
            && self.resumption_secret == other.resumption_secret
            && self.sender_data_secret == other.sender_data_secret
            && self.cipher_suite == other.cipher_suite
            && self.signature_public_keys == other.signature_public_keys
    }
}

impl Epoch {
    pub fn new(
        context: GroupContext,
        self_index: LeafIndex,
        resumption_secret: Vec<u8>,
        sender_data_secret: Vec<u8>,
        secret_tree: SecretTree,
        cipher_suite: CipherSuite,
        signature_public_keys: HashMap<LeafIndex, PublicKey>,
    ) -> Self {
        Self {
            context,
            self_index,
            resumption_secret: resumption_secret.into(),
            sender_data_secret: sender_data_secret.into(),
            secret_tree,
            handshake_ratchets: Default::default(),
            application_ratchets: Default::default(),
            cipher_suite,
            signature_public_keys,
        }
    }

    #[inline]
    fn get_ratchet(
        &mut self,
        leaf_index: LeafIndex,
        key_type: &KeyType,
    ) -> Option<&mut SecretKeyRatchet> {
        match key_type {
            KeyType::Handshake => self.handshake_ratchets.get_mut(&leaf_index),
            KeyType::Application => self.application_ratchets.get_mut(&leaf_index),
        }
    }

    #[inline]
    fn derive_ratchets(
        &mut self,
        leaf_index: LeafIndex,
        out_type: &KeyType,
    ) -> Result<&mut SecretKeyRatchet, EpochError> {
        let ratchets = self.secret_tree.get_leaf_secret_ratchets(leaf_index)?;
        self.application_ratchets
            .insert(leaf_index, ratchets.application);
        self.handshake_ratchets
            .insert(leaf_index, ratchets.handshake);
        self.get_ratchet(leaf_index, out_type)
            .ok_or(EpochError::KeyDerivationFailure)
    }

    #[inline]
    fn get_key(
        &mut self,
        leaf_index: LeafIndex,
        generation: Option<u32>,
        key_type: &KeyType,
    ) -> Result<MessageKey, EpochError> {
        let ratchet = match self.get_ratchet(leaf_index, key_type) {
            Some(ratchet) => ratchet,
            None => self.derive_ratchets(leaf_index, key_type)?,
        };

        match generation {
            None => ratchet.next_message_key(),
            Some(gen) => ratchet.get_message_key(gen),
        }
        .map_err(|e| e.into())
    }

    pub fn encrypt(
        &mut self,
        key_type: KeyType,
        plaintext: &[u8],
        aad: &[u8],
        reuse_guard: &[u8; 4],
    ) -> Result<(Vec<u8>, u32), EpochError> {
        let key = self.get_key(self.self_index, None, &key_type)?;
        Ok((key.encrypt(plaintext, aad, reuse_guard)?, key.generation))
    }

    pub fn decrypt(
        &mut self,
        sender: LeafIndex,
        generation: u32,
        key_type: KeyType,
        ciphertext: &MLSCiphertext,
        reuse_guard: &[u8; 4],
    ) -> Result<Vec<u8>, EpochError> {
        let key = self.get_key(sender, Some(generation), &key_type)?;

        Ok(key.decrypt(
            &ciphertext.ciphertext,
            &MLSCiphertextContentAAD::from(ciphertext).tls_serialize_detached()?,
            reuse_guard,
        )?)
    }

    pub fn get_sender_data_params(
        &self,
        ciphertext: &[u8],
    ) -> Result<(Key, AeadNonce), EpochError> {
        let kdf = KeyScheduleKdf::new(self.cipher_suite.kdf_type());
        // Sample the first extract_size bytes of the ciphertext, and if it is shorter, just use
        // the ciphertext itself
        let ciphertext_sample = if ciphertext.len() <= kdf.extract_size() as usize {
            ciphertext
        } else {
            ciphertext.get(0..kdf.extract_size() as usize).unwrap()
        };

        // Generate a sender data key and nonce using the sender_data_secret from the current
        // epoch's key schedule
        let sender_data_key = kdf.expand_with_label(
            &self.sender_data_secret.0,
            "key",
            ciphertext_sample,
            self.cipher_suite.aead_type().key_size(),
        )?;

        let sender_data_nonce = kdf.expand_with_label(
            &self.sender_data_secret.0,
            "nonce",
            ciphertext_sample,
            self.cipher_suite.aead_type().nonce_size(),
        )?;

        Ok((
            Key::new(self.cipher_suite.aead_type(), sender_data_key)?,
            AeadNonce::new(&sender_data_nonce)?,
        ))
    }

    #[cfg(feature = "benchmark")]
    pub fn get_secret_tree(&self) -> &SecretTree {
        &self.secret_tree
    }
}

#[cfg(test)]
pub mod test_utils {
    use super::*;
    use crate::group::secret_tree::test_utils::get_test_tree;
    use crate::group::test_utils::get_test_group_context;
    use ferriscrypt::kdf::hkdf::Hkdf;

    pub(crate) fn get_test_epoch(cipher_suite: CipherSuite) -> Epoch {
        let secret_tree = get_test_tree(
            cipher_suite,
            vec![0_u8; Hkdf::from(cipher_suite.kdf_type()).extract_size()],
            2,
        );

        Epoch {
            context: get_test_group_context(0, cipher_suite),
            self_index: LeafIndex(0),
            resumption_secret: vec![].into(),
            sender_data_secret: vec![].into(),
            secret_tree,
            handshake_ratchets: Default::default(),
            application_ratchets: Default::default(),
            cipher_suite,
            signature_public_keys: Default::default(),
        }
    }
}

#[cfg(test)]
mod tests {
    use tls_codec::Serialize;

    use crate::{
        cipher_suite::CipherSuite,
        group::{
            epoch::test_utils::get_test_epoch,
            framing::{ContentType, MLSCiphertext, MLSCiphertextContentAAD},
            secret_tree::KeyType,
        },
        tree_kem::node::LeafIndex,
    };

    #[test]
    fn test_crypt() {
        let cipher_suite = CipherSuite::Curve25519Aes128;

        let mut epoch_alice = get_test_epoch(cipher_suite);

        let mut epoch_bob = epoch_alice.clone();
        epoch_bob.self_index = LeafIndex(1);

        let aad = MLSCiphertextContentAAD {
            group_id: b"group".to_vec(),
            epoch: 0,
            content_type: ContentType::Application,
            authenticated_data: b"auth data".to_vec(),
        };

        for key_type in [KeyType::Application, KeyType::Handshake] {
            let (ctxts, generations) = std::iter::repeat_with(|| {
                epoch_alice
                    .encrypt(
                        key_type,
                        b"secret message".as_ref(),
                        &aad.tls_serialize_detached().unwrap(),
                        &[1, 2, 3, 4],
                    )
                    .unwrap()
            })
            .take(10)
            .unzip::<_, _, Vec<_>, Vec<_>>();

            assert_eq!(generations, (0..10).collect::<Vec<_>>());

            let random_permutation: [u32; 10] = [2, 9, 6, 4, 0, 8, 1, 3, 5, 7];

            for i in random_permutation {
                let ctxt = MLSCiphertext {
                    group_id: b"group".to_vec(),
                    epoch: 0,
                    content_type: ContentType::Application,
                    authenticated_data: b"auth data".to_vec(),
                    encrypted_sender_data: vec![],
                    ciphertext: ctxts[i as usize].clone(),
                };
                assert_eq!(
                    b"secret message".to_vec(),
                    epoch_bob
                        .decrypt(LeafIndex(0), i, key_type, &ctxt, &[1, 2, 3, 4])
                        .unwrap()
                );

                assert!(epoch_bob
                    .decrypt(LeafIndex(0), i, key_type, &ctxt, &[1, 2, 3, 4])
                    .is_err());
            }
        }
    }
}
