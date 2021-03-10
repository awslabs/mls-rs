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
    pub fn get_leaf_secret(&mut self, leaf_index: LeafIndex) -> Result<Vec<u8>, SecretTreeError> {
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

        Ok(secret)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::kdf::KdfError;

    fn get_mock_cipher_suite() -> CipherSuite {
        let mut cipher_suite = CipherSuite::new();
        cipher_suite.expect_derive_tree_secret().returning_st(move |secret, label, index, generation, e_type| {
            if generation !=0 || label != "tree" || e_type != ExpandType::Secret {
                Err(CipherSuiteError::KdfError(KdfError::Other("test failure".to_string())))
            } else {
                Ok([secret, &index.to_be_bytes().to_vec()].concat())
            }
        });
        cipher_suite
    }

    fn get_test_tree(secret: Vec<u8>, leaf_count: usize) -> SecretTree {
        SecretTree::new(get_mock_cipher_suite(), leaf_count, secret)
    }

    // Note: This test is designed to test basic functionality not algorithm correctness
    // There are additional tests to validate correctness elsewhere
    #[test]
    fn test_secret_tree() {
        let test_secret = b"foo".to_vec();
        let mut test_tree = get_test_tree(test_secret.clone(), 4);

        let mut secrets: Vec<Vec<u8>> = (0..4).into_iter()
            .map(|i| test_tree.get_leaf_secret(LeafIndex(i)).unwrap())
            .collect();

        // Verify the tree is now completely empty
        let full = test_tree.known_secrets.iter().filter(|n| n.is_some()).count();
        assert_eq!(full, 0);

        // Verify that the secrets were derived started with the root
        for one_secret in &secrets {
            assert_eq!(one_secret.get(0..3).unwrap(), &test_secret);
        }

        // Verify that all the secrets are unique
        let count = secrets.len();
        secrets.dedup();
        assert_eq!(count, secrets.len());
    }
}