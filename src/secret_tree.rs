use crate::ciphersuite::{CipherSuiteError, ExpandType};
use serde::{Serialize, Deserialize};
use crate::tree_node::{NodeIndex, LeafIndex};
use crate::tree_math;
use thiserror::Error;
use crate::tree_math::{TreeMathError};

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
    fn replace_node(&mut self, index: NodeIndex, value: Option<Vec<u8>>) -> Result<(), SecretTreeError> {
        self.get_mut(index)
            .ok_or(SecretTreeError::InvalidIndex)
            .and_then(|n| Ok(*n = value))
    }

    fn get_secret(&self, index: NodeIndex) -> Option<&Vec<u8>> {
        self.get(index).and_then(|n| n.as_ref())
    }

    fn direct_path(&self, index: LeafIndex) -> Result<Vec<NodeIndex>, TreeMathError> {
        index.direct_path(self.len() / 2 + 1)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub (crate) struct SecretTree {
    cipher_suite: CipherSuite,
    known_secrets: TreeSecretsVec,
    leaf_count: usize,
}

#[derive(Serialize, Deserialize)]
struct TreeContext {
    node: u32,
    generation: u32
}

#[derive(Clone, Debug, PartialEq)]
pub struct SecretRatchets {
    pub application: SecretKeyRatchet,
    pub handshake: SecretKeyRatchet,
}

impl SecretTree {
    pub fn new(cipher_suite: CipherSuite, leaf_count: usize, encryption_secret: Vec<u8>) -> SecretTree {
        let mut known_secrets = TreeSecretsVec(vec![None;leaf_count * 2 - 1]);
        known_secrets[tree_math::root(leaf_count)] = Some(encryption_secret);

        Self {
            cipher_suite,
            known_secrets,
            leaf_count
        }
    }

    fn consume_node(&mut self, index: NodeIndex) -> Result<(), SecretTreeError> {
        if let Some(secret) = self.known_secrets.get_secret(index) {
            let left_index = tree_math::left(index)?;
            let right_index = tree_math::right(index, self.leaf_count)?;

            let left_secret = self.cipher_suite
                .derive_tree_secret(secret,
                                    "tree",
                                    left_index as u32,
                                    0,
                                    ExpandType::Secret)?;

            let right_secret = self.cipher_suite
                .derive_tree_secret(secret,
                                    "tree",
                                    right_index as u32,
                                    0,
                                    ExpandType::Secret)?;

            self.known_secrets.replace_node(left_index, Some(left_secret))?;
            self.known_secrets.replace_node(right_index, Some(right_secret))?;
            self.known_secrets.replace_node(index, None)
        } else {
            Ok(()) // If the node is empty we can just skip it
        }
    }

    // Start at the root node and work your way down consuming any intermediates needed
    pub fn get_leaf_secret_ratchets(&mut self, leaf_index: LeafIndex) -> Result<SecretRatchets, SecretTreeError> {
        self.known_secrets
            .direct_path(leaf_index)?
            .iter()
            .rev()
            .try_for_each(|&i| {
                self.consume_node(i)
            })?;

        let node_index = NodeIndex::from(leaf_index);

        let secret = self.known_secrets
            .get_secret(node_index)
            .ok_or(SecretTreeError::InvalidLeafConsumption)?.clone();

        self.known_secrets.replace_node(node_index, None)?;

        Ok(SecretRatchets {
            application: SecretKeyRatchet::new(self.cipher_suite.clone(),
                                               leaf_index,
                                               &secret,
                                               KeyType::Application)?,
            handshake: SecretKeyRatchet::new(self.cipher_suite.clone(),
                                             leaf_index,
                                             &secret,
                                             KeyType::Handshake)?
        })
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct EncryptionKey {
    pub nonce: Vec<u8>,
    pub key: Vec<u8>
}

#[derive(Clone, Copy)]
pub enum KeyType {
    Handshake,
    Application
}

impl ToString for KeyType {
    fn to_string(&self) -> String {
        match self {
            Self::Handshake => "handshake".to_string(),
            Self::Application => "application".to_string()
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
    pub fn new(cipher_suite: CipherSuite,
               leaf: LeafIndex,
               secret: &[u8],
               key_type: KeyType)
        -> Result<Self, SecretTreeError> {
        let node_index = NodeIndex::from(leaf);

        let secret = cipher_suite.derive_tree_secret(secret,
                                                     &key_type.to_string(),
                                                     node_index as u32,
                                                     0,
                                                     ExpandType::Secret)?;

        Ok(Self {
            cipher_suite,
            secret,
            node_index,
            generation: 1
        })
    }

    fn derive_value(&self, label: &str) -> Result<Vec<u8>, SecretTreeError> {
        self.cipher_suite
            .derive_tree_secret(&self.secret, label,
                                self.node_index as u32,
                                self.generation,
                                ExpandType::AeadKey)
            .map_err(|e| e.into())
    }

    pub fn next_key(&mut self) -> Result<EncryptionKey, SecretTreeError> {
        let key = EncryptionKey {
            nonce: self.derive_value("nonce")?,
            key: self.derive_value("key")?
        };

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
mod test {
    use super::*;
    use crate::kdf::KdfError;

    fn get_mock_cipher_suite_tree() -> CipherSuite {
        let mut cipher_suite = CipherSuite::new();
        cipher_suite.expect_derive_tree_secret().returning_st(move |secret, label, index, generation, _e_type| {
            Ok([secret, label.as_bytes(),
                &generation.to_be_bytes().to_vec(),
                &index.to_be_bytes().to_vec()]
                .concat())
        });
        cipher_suite.expect_get_id().returning_st(move || 42);
        cipher_suite.expect_clone().returning_st(move || get_mock_cipher_suite_tree());
        cipher_suite
    }

    fn get_test_tree(secret: Vec<u8>, leaf_count: usize) -> SecretTree {
        let mock_cipher = get_mock_cipher_suite_tree();
        SecretTree::new(mock_cipher, leaf_count, secret)
    }

    // Note: This test is designed to test basic functionality not algorithm correctness
    // There are additional tests to validate correctness elsewhere
    #[test]
    fn test_secret_tree() {
        let test_secret = b"foo".to_vec();
        let mut test_tree = get_test_tree(test_secret.clone(), 4);

        let mut secrets: Vec<SecretRatchets> = (0..4).into_iter()
            .map(|i| test_tree.get_leaf_secret_ratchets(LeafIndex(i)).unwrap())
            .collect();

        // Verify the tree is now completely empty
        let full = test_tree.known_secrets.iter().filter(|n| n.is_some()).count();
        assert_eq!(full, 0);

        // Verify that the secrets were derived started with the root
        for one_secret in &secrets {
            assert_eq!(one_secret.handshake.secret.get(0..3).unwrap(), &test_secret);
            assert_eq!(one_secret.application.secret.get(0..3).unwrap(), &test_secret);
            assert_ne!(one_secret.handshake, one_secret.application);
        }

        // Verify that all the secrets are unique
        let count = secrets.len();
        secrets.dedup();
        assert_eq!(count, secrets.len());
    }

    fn get_key_ratchet_cipher_suite() -> CipherSuite {
        let mut mock_cipher = CipherSuite::new();
        mock_cipher.expect_derive_tree_secret().returning_st(move |secret, label, index, generation, e_type| {
            if e_type != ExpandType::AeadKey && generation != 0 {
                Err(CipherSuiteError::KdfError(KdfError::Other("test failure".to_string())))
            } else {
                Ok([secret, label.as_bytes(),
                    &generation.to_be_bytes().to_vec(),
                    &index.to_be_bytes().to_vec()]
                    .concat())
            }
        });
        mock_cipher.expect_clone().returning_st(move || get_key_ratchet_cipher_suite());
        mock_cipher
    }

    #[test]
    fn test_secret_key_ratchet() {
        let app_ratchet = SecretKeyRatchet::new(get_key_ratchet_cipher_suite(),
                                                LeafIndex(42),
                                                &b"foo".to_vec(),
                                                KeyType::Application).unwrap();

        let handshake_ratchet = SecretKeyRatchet::new(get_key_ratchet_cipher_suite(),
                                                      LeafIndex(42),
                                                      &b"foo".to_vec(),
                                                      KeyType::Handshake).unwrap();

        let app_keys: Vec<EncryptionKey> = app_ratchet.into_iter().take(2).flatten().collect();
        let handshake_keys: Vec<EncryptionKey> = handshake_ratchet.into_iter().take(2).flatten().collect();

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
}