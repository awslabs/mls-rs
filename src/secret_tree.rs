use crate::ciphersuite::{CipherSuiteError, ExpandType};
use crate::tree_kem::math as tree_math;
use crate::tree_kem::math::TreeMathError;
use crate::tree_kem::node::{LeafIndex, NodeIndex};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use cfg_if::cfg_if;
use std::ops::{Deref, DerefMut};

cfg_if! {
    if #[cfg(test)] {
        use crate::ciphersuite::test_util::MockCipherSuite as CipherSuite;
    } else {
        use crate::ciphersuite::{CipherSuite};
    }
}

#[derive(Error, Debug)]
pub enum SecretTreeError {
    #[error(transparent)]
    TreeMathError(#[from] TreeMathError),
    #[error("requested invalid index")]
    InvalidIndex,
    #[error(transparent)]
    CipherSuiteError(#[from] CipherSuiteError),
    #[error("attempted to consume an already consumed node")]
    InvalidNodeConsumption,
    #[error("leaf secret already consumed")]
    InvalidLeafConsumption,
    #[error("key not available, invalid generation {0}")]
    KeyMissing(u32),
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
struct TreeSecretsVec(Vec<Option<Vec<u8>>>);

impl Deref for TreeSecretsVec {
    type Target = Vec<Option<Vec<u8>>>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for TreeSecretsVec {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl TreeSecretsVec {
    fn replace_node(
        &mut self,
        index: NodeIndex,
        value: Option<Vec<u8>>,
    ) -> Result<(), SecretTreeError> {
        self.get_mut(index)
            .ok_or(SecretTreeError::InvalidIndex)
            .map(|n| *n = value)
    }

    fn get_secret(&self, index: NodeIndex) -> Option<&Vec<u8>> {
        self.get(index).and_then(|n| n.as_ref())
    }

    fn direct_path(&self, index: LeafIndex) -> Result<Vec<NodeIndex>, TreeMathError> {
        index.direct_path(self.len() / 2 + 1)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub(crate) struct SecretTree {
    cipher_suite: CipherSuite,
    known_secrets: TreeSecretsVec,
    leaf_count: usize,
}

#[derive(Serialize, Deserialize)]
struct TreeContext {
    node: u32,
    generation: u32,
}

#[derive(Clone, Debug, PartialEq)]
pub struct SecretRatchets {
    pub application: SecretKeyRatchet,
    pub handshake: SecretKeyRatchet,
}

impl SecretTree {
    pub fn new(
        cipher_suite: CipherSuite,
        leaf_count: usize,
        encryption_secret: Vec<u8>,
    ) -> SecretTree {
        let mut known_secrets = TreeSecretsVec(vec![None; leaf_count * 2 - 1]);
        known_secrets[tree_math::root(leaf_count)] = Some(encryption_secret);

        Self {
            cipher_suite,
            known_secrets,
            leaf_count,
        }
    }

    fn consume_node(&mut self, index: NodeIndex) -> Result<(), SecretTreeError> {
        if let Some(secret) = self.known_secrets.get_secret(index) {
            let left_index = tree_math::left(index)?;
            let right_index = tree_math::right(index, self.leaf_count)?;

            let left_secret = self.cipher_suite.derive_tree_secret(
                secret,
                "tree",
                left_index as u32,
                0,
                ExpandType::Secret,
            )?;

            let right_secret = self.cipher_suite.derive_tree_secret(
                secret,
                "tree",
                right_index as u32,
                0,
                ExpandType::Secret,
            )?;

            self.known_secrets
                .replace_node(left_index, Some(left_secret))?;
            self.known_secrets
                .replace_node(right_index, Some(right_secret))?;
            self.known_secrets.replace_node(index, None)
        } else {
            Ok(()) // If the node is empty we can just skip it
        }
    }

    // Start at the root node and work your way down consuming any intermediates needed
    pub fn get_leaf_secret_ratchets(
        &mut self,
        leaf_index: LeafIndex,
    ) -> Result<SecretRatchets, SecretTreeError> {
        self.known_secrets
            .direct_path(leaf_index)?
            .iter()
            .rev()
            .try_for_each(|&i| self.consume_node(i))?;

        let node_index = NodeIndex::from(leaf_index);

        let secret = self
            .known_secrets
            .get_secret(node_index)
            .ok_or(SecretTreeError::InvalidLeafConsumption)?
            .clone();

        self.known_secrets.replace_node(node_index, None)?;

        Ok(SecretRatchets {
            application: SecretKeyRatchet::new(
                self.cipher_suite.clone(),
                leaf_index,
                &secret,
                KeyType::Application,
            )?,
            handshake: SecretKeyRatchet::new(
                self.cipher_suite.clone(),
                leaf_index,
                &secret,
                KeyType::Handshake,
            )?,
        })
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct EncryptionKey {
    pub nonce: Vec<u8>,
    pub key: Vec<u8>,
    pub generation: u32,
}

impl EncryptionKey {
    pub fn reuse_safe_nonce(&self, reuse_guard: &[u8]) -> Vec<u8> {
        let mut reuse_nonce = self.nonce.clone();
        reuse_nonce
            .iter_mut()
            .zip(reuse_guard.iter())
            .for_each(|(nonce_byte, &guard_byte)| *nonce_byte ^= guard_byte);

        reuse_nonce
    }
}

#[derive(Clone, Copy)]
pub enum KeyType {
    Handshake,
    Application,
}

impl ToString for KeyType {
    fn to_string(&self) -> String {
        match self {
            Self::Handshake => "handshake".to_string(),
            Self::Application => "application".to_string(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SecretKeyRatchet {
    cipher_suite: CipherSuite,
    secret: Vec<u8>,
    node_index: NodeIndex,
    generation: u32,
}

impl SecretKeyRatchet {
    pub fn new(
        cipher_suite: CipherSuite,
        leaf: LeafIndex,
        secret: &[u8],
        key_type: KeyType,
    ) -> Result<Self, SecretTreeError> {
        let node_index = NodeIndex::from(leaf);

        let secret = cipher_suite.derive_tree_secret(
            secret,
            &key_type.to_string(),
            node_index as u32,
            0,
            ExpandType::Secret,
        )?;

        Ok(Self {
            cipher_suite,
            secret,
            node_index,
            generation: 1,
        })
    }

    fn derive_key(&self) -> Result<Vec<u8>, SecretTreeError> {
        self.cipher_suite
            .derive_tree_secret(
                &self.secret,
                "key",
                self.node_index as u32,
                self.generation,
                ExpandType::AeadKey,
            )
            .map_err(|e| e.into())
    }

    fn derive_nonce(&self) -> Result<Vec<u8>, SecretTreeError> {
        self.cipher_suite
            .derive_tree_secret(
                &self.secret,
                "nonce",
                self.node_index as u32,
                self.generation,
                ExpandType::AeadNonce,
            )
            .map_err(|e| e.into())
    }

    fn ratchet_secret(&mut self) -> Result<(), SecretTreeError> {
        self.secret = self.cipher_suite.derive_tree_secret(
            &self.secret,
            "secret",
            self.node_index as u32,
            self.generation,
            ExpandType::Secret,
        )?;

        Ok(())
    }

    pub fn get_key(&mut self, generation: u32) -> Result<EncryptionKey, SecretTreeError> {
        if generation <= self.generation {
            // TODO: Look at the cache and see if we can return an older key
            Err(SecretTreeError::KeyMissing(generation))
        } else {
            let generated_keys = self
                .take((generation - self.generation) as usize)
                .collect::<Result<Vec<EncryptionKey>, SecretTreeError>>()?;

            // TODO: Store all these keys someplace to handle out of order packets
            generated_keys
                .last()
                .cloned()
                .ok_or(SecretTreeError::KeyMissing(generation))
        }
    }

    pub fn next_key(&mut self) -> Result<EncryptionKey, SecretTreeError> {
        let key = EncryptionKey {
            nonce: self.derive_nonce()?,
            key: self.derive_key()?,
            generation: self.generation + 1,
        };

        self.ratchet_secret()?;
        self.generation += 1;
        Ok(key)
    }
}

impl Iterator for SecretKeyRatchet {
    type Item = Result<EncryptionKey, SecretTreeError>;

    fn next(&mut self) -> Option<Self::Item> {
        Some(self.next_key())
    }
}

#[cfg(test)]
pub(crate) mod test {
    use super::*;

    fn get_mock_cipher_suite_tree() -> CipherSuite {
        let mut cipher_suite = CipherSuite::new();
        cipher_suite.expect_derive_tree_secret().returning_st(
            move |secret, label, index, generation, _e_type| {
                Ok([
                    secret,
                    label.as_bytes(),
                    &generation.to_be_bytes().to_vec(),
                    &index.to_be_bytes().to_vec(),
                ]
                .concat())
            },
        );
        cipher_suite.expect_get_id().returning_st(move || 42);
        cipher_suite
            .expect_clone()
            .returning_st(get_mock_cipher_suite_tree);
        cipher_suite
    }

    pub(crate) fn get_test_tree(secret: Vec<u8>, leaf_count: usize) -> SecretTree {
        let mock_cipher = get_mock_cipher_suite_tree();
        SecretTree::new(mock_cipher, leaf_count, secret)
    }

    // Note: This test is designed to test basic functionality not algorithm correctness
    // There are additional tests to validate correctness elsewhere
    #[test]
    fn test_secret_tree() {
        let test_secret = b"foo".to_vec();
        let mut test_tree = get_test_tree(test_secret.clone(), 4);

        let mut secrets: Vec<SecretRatchets> = (0..4)
            .into_iter()
            .map(|i| test_tree.get_leaf_secret_ratchets(LeafIndex(i)).unwrap())
            .collect();

        // Verify the tree is now completely empty
        let full = test_tree
            .known_secrets
            .iter()
            .filter(|n| n.is_some())
            .count();
        assert_eq!(full, 0);

        // Verify that the secrets were derived started with the root
        for one_secret in &secrets {
            assert_eq!(one_secret.handshake.secret.get(0..3).unwrap(), &test_secret);
            assert_eq!(
                one_secret.application.secret.get(0..3).unwrap(),
                &test_secret
            );
            assert_ne!(one_secret.handshake, one_secret.application);
        }

        // Verify that all the secrets are unique
        let count = secrets.len();
        secrets.dedup();
        assert_eq!(count, secrets.len());
    }

    #[test]
    fn test_secret_key_ratchet() {
        let app_ratchet = SecretKeyRatchet::new(
            get_mock_cipher_suite_tree(),
            LeafIndex(42),
            &b"foo".to_vec(),
            KeyType::Application,
        )
        .unwrap();

        let handshake_ratchet = SecretKeyRatchet::new(
            get_mock_cipher_suite_tree(),
            LeafIndex(42),
            &b"foo".to_vec(),
            KeyType::Handshake,
        )
        .unwrap();

        let app_keys: Vec<EncryptionKey> = app_ratchet.into_iter().take(2).flatten().collect();
        let handshake_keys: Vec<EncryptionKey> =
            handshake_ratchet.into_iter().take(2).flatten().collect();

        // Verify that the secrets were derived started with the root
        for one_secret in &app_keys {
            assert_eq!(one_secret.key.get(0..3).unwrap(), &b"foo".to_vec());
            assert_eq!(one_secret.nonce.get(0..3).unwrap(), &b"foo".to_vec());
        }

        // Verify that the keys have different outcomes due to their different labels
        assert_ne!(app_keys, handshake_keys);

        // Verify that the keys at each generation are different
        assert_ne!(handshake_keys[0], handshake_keys[1]);
    }

    #[test]
    fn test_get_key() {
        let mut ratchet = SecretKeyRatchet::new(
            get_mock_cipher_suite_tree(),
            LeafIndex(42),
            &b"foo".to_vec(),
            KeyType::Application,
        )
        .unwrap();

        let mut ratchet_clone = ratchet.clone();
        let _ = ratchet_clone.next_key().unwrap();
        let clone_2 = ratchet_clone.next_key().unwrap();

        // Going back in time should result in an error
        assert!(ratchet_clone.get_key(0).is_err());

        // Calling get key should be the same as calling next until hitting the desired generation
        let second_key = ratchet.get_key(3).unwrap();
        assert_eq!(second_key.generation, 3);
        assert_eq!(clone_2, second_key)
    }

    #[test]
    fn test_secret_ratchet() {
        let mut ratchet = SecretKeyRatchet::new(
            get_mock_cipher_suite_tree(),
            LeafIndex(42),
            &b"foo".to_vec(),
            KeyType::Application,
        )
        .unwrap();

        let original_secret = ratchet.secret.clone();
        let _ = ratchet.next_key().unwrap();
        let new_secret = ratchet.secret;
        assert_ne!(original_secret, new_secret)
    }
}
