use std::collections::HashMap;
use std::ops::Deref;

use ferriscrypt::asym::ec_key::EcKeyError;
use ferriscrypt::hpke::kem::{HpkePublicKey, HpkeSecretKey};
use ferriscrypt::hpke::HpkeError;

use thiserror::Error;
use tls_codec_derive::{TlsDeserialize, TlsSerialize, TlsSize};

use math as tree_math;
use math::TreeMathError;
use node::{LeafIndex, Node, NodeIndex, NodeVec, NodeVecError};

use self::leaf_node::{LeafNode, LeafNodeError};

use crate::cipher_suite::CipherSuite;
use crate::extension::ExtensionError;
use crate::group::key_schedule::KeyScheduleKdfError;
use crate::key_package::{KeyPackageError, KeyPackageGenerationError, KeyPackageValidationError};
use crate::tree_kem::parent_hash::ParentHashError;
use crate::tree_kem::path_secret::PathSecretError;

mod capabilities;
mod lifetime;
pub(crate) mod math;
pub mod node;
pub mod parent_hash;
pub mod path_secret;
mod private;
mod tree_hash;
pub mod tree_validator;
pub mod update_path;

pub use capabilities::*;
pub use lifetime::*;
pub use private::*;
pub use update_path::*;

use tree_index::*;

use self::path_secret::{PathSecret, PathSecretGeneration, PathSecretGenerator};
pub mod kem;
pub mod leaf_node;
pub mod leaf_node_validator;
mod tree_index;

#[derive(Error, Debug)]
pub enum RatchetTreeError {
    #[error(transparent)]
    TreeMathError(#[from] TreeMathError),
    #[error(transparent)]
    KeyPackageError(#[from] KeyPackageError),
    #[error(transparent)]
    EcKeyError(#[from] EcKeyError),
    #[error(transparent)]
    KeyPackageGeneratorError(#[from] KeyPackageGenerationError),
    #[error(transparent)]
    NodeVecError(#[from] NodeVecError),
    #[error(transparent)]
    TlsCodecError(#[from] tls_codec::Error),
    #[error(transparent)]
    ParentHashError(#[from] ParentHashError),
    #[error(transparent)]
    ExtensionError(#[from] ExtensionError),
    #[error(transparent)]
    KeyScheduleKdfError(#[from] KeyScheduleKdfError),
    #[error(transparent)]
    HpkeError(#[from] HpkeError),
    #[error(transparent)]
    PathSecretError(#[from] PathSecretError),
    #[error(transparent)]
    KeyPackageValidationError(#[from] KeyPackageValidationError),
    #[error(transparent)]
    LeafNodeError(#[from] LeafNodeError),
    #[error(transparent)]
    TreeIndexError(#[from] TreeIndexError),
    #[error("invalid update path signature")]
    InvalidUpdatePathSignature,
    // TODO: This should probably tell you the expected key vs actual key
    #[error("update path pub key mismatch")]
    PubKeyMismatch,
    #[error("invalid leaf signature")]
    InvalidLeafSignature,
    #[error("tree hash mismatch")]
    TreeHashMismatch,
    #[error("bad update: no suitable secret key")]
    UpdateErrorNoSecretKey,
    #[error("invalid lca, not found on direct path")]
    LcaNotFoundInDirectPath,
    #[error("bad state: missing own credential")]
    MissingSelfCredential,
    #[error("update path missing parent hash")]
    ParentHashNotFound,
    #[error("update path parent hash mismatch")]
    ParentHashMismatch,
    #[error("invalid parent hash: {0}")]
    InvalidParentHash(String),
    #[error("HPKE decrypt called with incorrect secret key, ciphertext or context")]
    HPKEDecryptionError,
    #[error("decrypting commit from self")]
    DecryptFromSelf,
}

#[derive(Clone, Debug, PartialEq, serde::Deserialize, serde::Serialize)]
pub struct TreeKemPublic {
    pub cipher_suite: CipherSuite,
    index: TreeIndex,
    nodes: NodeVec,
}

#[derive(Clone, Debug, PartialEq, TlsDeserialize, TlsSerialize, TlsSize)]
pub struct SecretPath {
    #[tls_codec(with = "crate::tls::DefMap")]
    path_secrets: HashMap<NodeIndex, PathSecret>,
    pub root_secret: PathSecret,
}

impl SecretPath {
    pub fn get_path_secret(&self, index: NodeIndex) -> Option<PathSecret> {
        self.path_secrets.get(&index).cloned()
    }
}

#[derive(Clone, Debug, TlsDeserialize, TlsSerialize, TlsSize)]
pub struct UpdatePathGeneration {
    pub update_path: UpdatePath,
    pub secrets: TreeSecrets,
}

impl UpdatePathGeneration {
    pub fn get_common_path_secret(&self, leaf: LeafIndex) -> Option<PathSecret> {
        let lca = tree_math::common_ancestor_direct(
            self.secrets.private_key.self_index.into(),
            leaf.into(),
        );

        self.secrets.secret_path.get_path_secret(lca)
    }
}

struct EncryptedResolution {
    path_secret: PathSecretGeneration,
    index: NodeIndex,
    update_path_node: UpdatePathNode,
}

#[derive(Clone, Debug, TlsDeserialize, TlsSerialize, TlsSize)]
pub struct TreeSecrets {
    pub private_key: TreeKemPrivate,
    pub secret_path: SecretPath,
}

impl TreeKemPublic {
    pub fn new(cipher_suite: CipherSuite) -> TreeKemPublic {
        TreeKemPublic {
            cipher_suite,
            index: Default::default(),
            nodes: Default::default(),
        }
    }

    pub(crate) fn import_node_data(
        cipher_suite: CipherSuite,
        nodes: NodeVec,
    ) -> Result<TreeKemPublic, RatchetTreeError> {
        let index = nodes.non_empty_leaves().try_fold(
            TreeIndex::new(),
            |mut tree_index, (leaf_index, leaf)| {
                tree_index.insert(leaf_index, leaf)?;
                Ok::<_, RatchetTreeError>(tree_index)
            },
        )?;

        Ok(TreeKemPublic {
            cipher_suite,
            index,
            nodes,
        })
    }

    pub(crate) fn export_node_data(&self) -> NodeVec {
        self.nodes.clone()
    }

    pub fn derive(
        cipher_suite: CipherSuite,
        leaf_node: LeafNode,
        secret_key: HpkeSecretKey,
    ) -> Result<(TreeKemPublic, TreeKemPrivate), RatchetTreeError> {
        let mut public_tree = TreeKemPublic::new(cipher_suite);
        public_tree.add_leaves(vec![leaf_node])?;

        let private_tree = TreeKemPrivate::new_self_leaf(LeafIndex(0), secret_key);

        Ok((public_tree, private_tree))
    }

    pub fn total_leaf_count(&self) -> u32 {
        self.nodes.total_leaf_count()
    }

    pub fn occupied_leaf_count(&self) -> u32 {
        self.nodes.occupied_leaf_count()
    }

    pub fn get_leaf_node(&self, index: LeafIndex) -> Result<&LeafNode, RatchetTreeError> {
        self.nodes.borrow_as_leaf(index).map_err(|e| e.into())
    }

    pub fn find_leaf_node(&self, leaf_node: &LeafNode) -> Option<LeafIndex> {
        self.nodes.non_empty_leaves().find_map(|(index, node)| {
            if node.deref() == leaf_node {
                Some(index)
            } else {
                None
            }
        })
    }

    fn update_unmerged(&mut self, index: LeafIndex) -> Result<(), RatchetTreeError> {
        // For a given leaf index, find parent nodes and add the leaf to the unmerged leaf
        self.nodes.direct_path(index)?.into_iter().for_each(|i| {
            if let Ok(p) = self.nodes.borrow_as_parent_mut(i) {
                p.unmerged_leaves.push(index)
            }
        });

        Ok(())
    }

    fn fill_empty_leaves(
        &mut self,
        leaf_nodes: &[LeafNode],
    ) -> Result<Vec<LeafIndex>, RatchetTreeError> {
        // Fill a set of empty leaves given a particular array, return the leaf indexes that were
        // overwritten
        self.nodes.empty_leaves().zip(leaf_nodes.iter()).try_fold(
            Vec::new(),
            |mut indexs, ((index, empty_node), leaf_node)| {
                // See TODO in add_nodes, we have to clone here because we can't iterate the list
                // of packages to insert a single time
                *empty_node = Some(Node::from(leaf_node.clone()));
                self.index.insert(index, leaf_node)?;
                indexs.push(index);

                Ok::<_, RatchetTreeError>(indexs)
            },
        )
    }

    pub fn can_add_leaf(&self, leaf: &LeafNode) -> Result<(), RatchetTreeError> {
        self.index.can_insert(leaf).map_err(Into::into)
    }

    pub fn can_update_leaf(
        &self,
        current_leaf_index: LeafIndex,
        new_leaf: &LeafNode,
    ) -> Result<(), RatchetTreeError> {
        self.index
            .can_update(current_leaf_index, new_leaf)
            .map_err(Into::into)
    }

    // Note that a partial failure of this function will leave the tree in a bad state. Modifying a
    // tree should always be done on a clone of the tree, which is how commits are processed
    pub fn add_leaves(
        &mut self,
        leaf_nodes: Vec<LeafNode>,
    ) -> Result<Vec<LeafIndex>, RatchetTreeError> {
        // Fill empty leaves first, then add the remaining nodes by extending
        // the tree to the right

        // TODO: Find a way to predetermine a single list of nodes to fill by pre-populating new
        // empty nodes and iterating through a chain of empty leaves + new leaves
        let mut added_leaf_indexs = self.fill_empty_leaves(&leaf_nodes)?;

        leaf_nodes
            .into_iter()
            .skip(added_leaf_indexs.len())
            .try_for_each(|leaf_node| {
                if !self.nodes.is_empty() {
                    self.nodes.push(None);
                }

                let index = LeafIndex(self.nodes.len() as u32 / 2);
                self.index.insert(index, &leaf_node)?;
                self.nodes.push(Option::from(leaf_node));
                added_leaf_indexs.push(index);
                Ok::<_, RatchetTreeError>(())
            })?;

        added_leaf_indexs
            .iter()
            .try_for_each(|index| self.update_unmerged(*index))?;

        Ok(added_leaf_indexs)
    }

    pub fn remove_leaves(
        &mut self,
        indexes: Vec<LeafIndex>,
    ) -> Result<Vec<(LeafIndex, LeafNode)>, RatchetTreeError> {
        // Identify a leaf node containing a key package matching removed.
        // This lookup MUST be done on the tree before any non-Remove proposals have been applied
        let removed_leaves: Vec<(LeafIndex, LeafNode)> =
            indexes.iter().try_fold(Vec::new(), |mut vec, index| {
                // Replace the leaf node at position removed with a blank node
                if let Some(removed) = self.nodes.blank_leaf_node(*index)? {
                    self.index.remove(&removed)?;
                    vec.push((*index, removed));
                }

                // Blank the intermediate nodes along the path from the removed leaf to the root
                self.nodes.blank_direct_path(*index)?;
                Ok::<_, RatchetTreeError>(vec)
            })?;

        // Truncate the tree by reducing the size of tree until the rightmost non-blank leaf node
        self.nodes.trim();

        let removed_indices = indexes
            .into_iter()
            .zip(removed_leaves.into_iter())
            .map(|(index, (_, leaf))| (index, leaf))
            .collect::<Vec<(_, _)>>();

        Ok(removed_indices)
    }

    pub fn update_leaf(
        &mut self,
        index: LeafIndex,
        leaf_node: LeafNode,
    ) -> Result<(), RatchetTreeError> {
        // Update the leaf node
        let existing_leaf = self.nodes.borrow_as_leaf_mut(index)?;

        // Update the cache
        self.index.remove(existing_leaf)?;
        self.index.insert(index, &leaf_node)?;

        *existing_leaf = leaf_node;

        // Blank the intermediate nodes along the path from the sender's leaf to the root
        self.nodes
            .blank_direct_path(index)
            .map(|_| ())
            .map_err(RatchetTreeError::from)
    }

    pub fn get_leaf_nodes(&self) -> Vec<&LeafNode> {
        self.nodes.non_empty_leaves().map(|(_, l)| l).collect()
    }

    pub fn non_empty_leaves(&self) -> impl Iterator<Item = (LeafIndex, &LeafNode)> + '_ {
        self.nodes.non_empty_leaves()
    }

    fn update_node(
        &mut self,
        pub_key: HpkePublicKey,
        index: NodeIndex,
    ) -> Result<(), RatchetTreeError> {
        self.nodes
            .borrow_or_fill_node_as_parent(index, &pub_key)
            .map_err(|e| e.into())
            .map(|p| {
                p.public_key = pub_key;
                p.unmerged_leaves = vec![];
            })
    }

    // Swap in a new key package at index `sender` and return the old key package
    fn apply_update_path(
        &mut self,
        sender: LeafIndex,
        update_path: &ValidatedUpdatePath,
    ) -> Result<LeafNode, RatchetTreeError> {
        // Install the new leaf node
        let existing_leaf = self.nodes.borrow_as_leaf_mut(sender)?;
        let original_leaf_node = existing_leaf.clone();

        *existing_leaf = update_path.leaf_node.clone();

        // Update the rest of the nodes on the direct path
        self.apply_parent_node_updates(sender, &update_path.nodes)?;

        Ok(original_leaf_node)
    }

    fn apply_parent_node_updates(
        &mut self,
        sender: LeafIndex,
        node_updates: &[UpdatePathNode],
    ) -> Result<(), RatchetTreeError> {
        node_updates
            .iter()
            .zip(self.nodes.filtered_direct_path(sender)?)
            .try_for_each(|(one_node, node_index)| {
                self.update_node(one_node.public_key.clone(), node_index)
            })
    }

    pub fn apply_self_update(
        &mut self,
        update_path: &ValidatedUpdatePath,
        sender: LeafIndex,
    ) -> Result<(), RatchetTreeError> {
        let existing_key_package = self.apply_update_path(sender, update_path)?;

        self.index.remove(&existing_key_package)?;
        self.index.insert(sender, &update_path.leaf_node)?;

        // Verify the parent hash of the new sender leaf node and update the parent hash values
        // in the local tree
        self.update_parent_hashes(sender, Some(update_path))?;

        Ok(())
    }

    pub fn direct_path_keys(
        &self,
        index: LeafIndex,
    ) -> Result<Vec<Option<HpkePublicKey>>, RatchetTreeError> {
        let indexes = self.nodes.direct_path(index)?;

        indexes
            .iter()
            .map(|&i| {
                Ok(self
                    .nodes
                    .borrow_node(i)?
                    .as_ref()
                    .map(|n| n.public_key())
                    .cloned())
            })
            .collect::<Result<Vec<_>, RatchetTreeError>>()
    }
}

#[cfg(test)]
pub(crate) mod test_utils {
    use ferriscrypt::{asym::ec_key::SecretKey, hpke::kem::HpkeSecretKey};

    use crate::tree_kem::leaf_node::test_utils::get_basic_test_node_sig_key;

    use super::{
        leaf_node::{test_utils::get_basic_test_node, LeafNode},
        TreeKemPrivate, TreeKemPublic,
    };
    use crate::cipher_suite::CipherSuite;

    #[derive(Debug)]
    pub struct TestTree {
        pub public: TreeKemPublic,
        pub private: TreeKemPrivate,
        pub creator_leaf: LeafNode,
        pub creator_signing_key: SecretKey,
        pub creator_hpke_secret: HpkeSecretKey,
    }

    pub fn get_test_tree(cipher_suite: CipherSuite) -> TestTree {
        let (creator_leaf, creator_hpke_secret, creator_signing_key) =
            get_basic_test_node_sig_key(cipher_suite, "creator");

        let (test_public, test_private) = TreeKemPublic::derive(
            cipher_suite,
            creator_leaf.clone(),
            creator_hpke_secret.clone(),
        )
        .unwrap();

        TestTree {
            public: test_public,
            private: test_private,
            creator_leaf,
            creator_signing_key,
            creator_hpke_secret,
        }
    }

    pub fn get_test_leaf_nodes(cipher_suite: CipherSuite) -> Vec<LeafNode> {
        [
            get_basic_test_node(cipher_suite, "A"),
            get_basic_test_node(cipher_suite, "B"),
            get_basic_test_node(cipher_suite, "C"),
        ]
        .to_vec()
    }
}

#[cfg(test)]
mod tests {
    use crate::cipher_suite::CipherSuite;

    use crate::tree_kem::leaf_node::test_utils::get_basic_test_node;
    use crate::tree_kem::leaf_node::LeafNode;
    use crate::tree_kem::node::{
        LeafIndex, Node, NodeIndex, NodeTypeResolver, NodeVecError, Parent,
    };
    use crate::tree_kem::parent_hash::ParentHash;
    use crate::tree_kem::test_utils::{get_test_leaf_nodes, get_test_tree};
    use crate::tree_kem::tree_index::TreeIndexError;
    use crate::tree_kem::{RatchetTreeError, TreeKemPublic};
    use assert_matches::assert_matches;

    #[cfg(target_arch = "wasm32")]
    use wasm_bindgen_test::wasm_bindgen_test as test;

    #[test]
    pub fn test_derive() {
        for cipher_suite in CipherSuite::all() {
            let test_tree = get_test_tree(cipher_suite);

            assert_eq!(
                test_tree.public.nodes[0],
                Some(Node::Leaf(test_tree.creator_leaf.clone()))
            );

            assert_eq!(test_tree.private.self_index, LeafIndex(0));

            assert_eq!(
                test_tree.private.secret_keys[&0],
                test_tree.creator_hpke_secret
            );
        }
    }

    #[test]
    fn test_import_export() {
        let cipher_suite = CipherSuite::P256Aes128;
        let mut test_tree = get_test_tree(cipher_suite);

        let additional_key_packages = get_test_leaf_nodes(cipher_suite);

        test_tree
            .public
            .add_leaves(additional_key_packages)
            .unwrap();

        let exported = test_tree.public.export_node_data();
        let imported = TreeKemPublic::import_node_data(cipher_suite, exported).unwrap();

        assert_eq!(test_tree.public, imported);
    }

    #[test]
    fn test_add_leaf() {
        let cipher_suite = CipherSuite::Curve25519Aes128;
        let mut tree = TreeKemPublic::new(cipher_suite);

        let leaf_nodes = get_test_leaf_nodes(cipher_suite);
        let res = tree.add_leaves(leaf_nodes.clone()).unwrap();

        // The leaf count should be equal to the number of packages we added
        assert_eq!(res.len(), leaf_nodes.len());
        assert_eq!(tree.occupied_leaf_count(), leaf_nodes.len() as u32);

        // Each added package should be at the proper index and searchable in the tree
        res.into_iter().zip(leaf_nodes.clone()).for_each(|(r, kp)| {
            assert_eq!(tree.get_leaf_node(r).unwrap(), &kp);
        });

        // Verify the underlying state
        assert_eq!(tree.index.len(), tree.occupied_leaf_count() as usize);
        assert_eq!(tree.nodes.len(), 5);
        assert_eq!(tree.nodes[0], leaf_nodes[0].clone().into());
        assert_eq!(tree.nodes[1], None);
        assert_eq!(tree.nodes[2], leaf_nodes[1].clone().into());
        assert_eq!(tree.nodes[3], None);
        assert_eq!(tree.nodes[4], leaf_nodes[2].clone().into());
    }

    #[test]
    fn test_get_key_packages() {
        let cipher_suite = CipherSuite::Curve25519Aes128;
        let mut tree = TreeKemPublic::new(cipher_suite);

        let key_packages = get_test_leaf_nodes(cipher_suite);
        tree.add_leaves(key_packages).unwrap();

        let key_packages = tree.get_leaf_nodes();
        assert_eq!(key_packages, key_packages.to_owned());
    }

    #[test]
    fn test_add_leaf_duplicate() {
        let cipher_suite = CipherSuite::P256Aes128;
        let mut tree = TreeKemPublic::new(cipher_suite);

        let key_packages = get_test_leaf_nodes(cipher_suite);
        tree.add_leaves(key_packages.clone()).unwrap();

        let add_res = tree.add_leaves(key_packages);

        assert_matches!(
            add_res,
            Err(RatchetTreeError::TreeIndexError(
                TreeIndexError::DuplicateSignatureKeys(LeafIndex(0))
            ))
        );
    }

    #[test]
    fn test_add_leaf_empty_leaf() {
        let cipher_suite = CipherSuite::Curve25519Aes128;
        let mut tree = get_test_tree(cipher_suite).public;
        let key_packages = get_test_leaf_nodes(cipher_suite);

        tree.add_leaves([key_packages[0].clone()].to_vec()).unwrap();
        tree.nodes[0] = None; // Set the original first node to none
        tree.add_leaves([key_packages[1].clone()].to_vec()).unwrap();

        assert_eq!(tree.nodes[0], key_packages[1].clone().into());
        assert_eq!(tree.nodes[1], None);
        assert_eq!(tree.nodes[2], key_packages[0].clone().into());
        assert_eq!(tree.nodes.len(), 3)
    }

    #[test]
    fn test_add_leaf_unmerged() {
        let cipher_suite = CipherSuite::Curve25519Aes128;
        let mut tree = get_test_tree(cipher_suite).public;
        let key_packages = get_test_leaf_nodes(cipher_suite);

        tree.add_leaves([key_packages[0].clone(), key_packages[1].clone()].to_vec())
            .unwrap();

        tree.nodes[3] = Parent {
            public_key: vec![].into(),
            parent_hash: ParentHash::empty(),
            unmerged_leaves: vec![],
        }
        .into();

        tree.add_leaves([key_packages[2].clone()].to_vec()).unwrap();

        assert_eq!(
            tree.nodes[3].as_parent().unwrap().unmerged_leaves,
            vec![LeafIndex(3)]
        )
    }

    #[test]
    fn test_update_leaf() {
        let cipher_suite = CipherSuite::Curve25519Aes128;

        // Create a tree
        let mut tree = get_test_tree(cipher_suite).public;

        let key_packages = get_test_leaf_nodes(cipher_suite);
        tree.add_leaves(key_packages).unwrap();

        // Add in parent nodes so we can detect them clearing after update
        tree.nodes
            .direct_path(LeafIndex(0))
            .unwrap()
            .iter()
            .for_each(|&i| {
                tree.nodes
                    .borrow_or_fill_node_as_parent(i, &b"pub_key".to_vec().into())
                    .unwrap();
            });

        let original_size = tree.occupied_leaf_count();
        let original_leaf_index = LeafIndex(1);

        let updated_leaf = get_basic_test_node(cipher_suite, "newpk");

        tree.update_leaf(original_leaf_index, updated_leaf.clone())
            .unwrap();

        // The tree should not have grown due to an update
        assert_eq!(tree.occupied_leaf_count(), original_size);

        // The cache of tree package indexs should not have grown
        assert_eq!(tree.index.len() as u32, tree.occupied_leaf_count());

        // The key package should be updated in the tree
        assert_eq!(
            tree.get_leaf_node(original_leaf_index).unwrap(),
            &updated_leaf
        );

        // Verify that the direct path has been cleared
        tree.nodes
            .direct_path(LeafIndex(0))
            .unwrap()
            .iter()
            .for_each(|&i| {
                assert!(tree.nodes[i as usize].is_none());
            });
    }

    #[test]
    fn test_update_leaf_not_found() {
        let cipher_suite = CipherSuite::Curve25519Aes128;

        // Create a tree
        let mut tree = get_test_tree(cipher_suite).public;
        let key_packages = get_test_leaf_nodes(cipher_suite);
        tree.add_leaves(key_packages).unwrap();

        let new_key_package = get_basic_test_node(cipher_suite, "new");

        assert_matches!(
            tree.update_leaf(LeafIndex(128), new_key_package),
            Err(RatchetTreeError::NodeVecError(
                NodeVecError::InvalidNodeIndex(256)
            ))
        );
    }

    #[test]
    fn test_remove_leaf() {
        let cipher_suite = CipherSuite::Curve25519Aes128;

        // Create a tree
        let mut tree = get_test_tree(cipher_suite).public;
        let key_packages = get_test_leaf_nodes(cipher_suite);
        let indexes = tree.add_leaves(key_packages.clone()).unwrap();

        let original_leaf_count = tree.occupied_leaf_count();

        // Remove two leaves from the tree
        let expected_result: Vec<(LeafIndex, LeafNode)> = indexes
            .clone()
            .into_iter()
            .zip(key_packages)
            .map(|(index, ln)| (index, ln))
            .collect();

        let res = tree.remove_leaves(indexes.clone()).unwrap();

        assert_eq!(res, expected_result);

        // The leaves should be removed from the tree
        assert_eq!(
            tree.occupied_leaf_count(),
            original_leaf_count - indexes.len() as u32
        );
    }

    #[test]
    fn test_remove_leaf_middle() {
        let cipher_suite = CipherSuite::Curve25519Aes128;

        // Create a tree
        let mut tree = get_test_tree(cipher_suite).public;
        let leaf_nodes = get_test_leaf_nodes(cipher_suite);
        let to_remove = tree.add_leaves(leaf_nodes.clone()).unwrap()[0];
        let original_leaf_count = tree.occupied_leaf_count();

        let res = tree.remove_leaves(vec![to_remove]).unwrap();

        assert_eq!(res, vec![(to_remove, leaf_nodes[0].clone())]);

        // The leaf count should have been reduced by 1
        assert_eq!(tree.occupied_leaf_count(), original_leaf_count - 1);

        // There should be a blank in the tree
        assert_eq!(
            tree.nodes.get(NodeIndex::from(to_remove) as usize).unwrap(),
            &None
        );
    }

    #[test]
    fn test_create_blanks() {
        let cipher_suite = CipherSuite::Curve25519Aes128;

        // Create a tree
        let mut tree = get_test_tree(cipher_suite).public;
        let key_packages = get_test_leaf_nodes(cipher_suite);
        tree.add_leaves(key_packages).unwrap();

        let original_leaf_count = tree.occupied_leaf_count();

        let to_remove = vec![LeafIndex(2)];

        // Remove the leaf from the tree
        tree.remove_leaves(to_remove).unwrap();

        // The occupied leaf count should have been reduced by 1
        assert_eq!(tree.occupied_leaf_count(), original_leaf_count - 1);

        // The total leaf count should remain unchanged
        assert_eq!(tree.total_leaf_count(), original_leaf_count);

        // The location of key_packages[1] should now be blank
        let removed_location = tree
            .nodes
            .get(NodeIndex::from(LeafIndex(2)) as usize)
            .unwrap();

        assert_eq!(removed_location, &None);
    }

    #[test]
    fn test_remove_leaf_failure() {
        let cipher_suite = CipherSuite::Curve25519Aes128;

        // Create a tree
        let mut tree = get_test_tree(cipher_suite).public;

        assert_matches!(
            tree.remove_leaves(vec![LeafIndex(128)]),
            Err(RatchetTreeError::NodeVecError(
                NodeVecError::InvalidNodeIndex(256)
            ))
        );
    }

    #[test]
    fn test_find_leaf_node() {
        let cipher_suite = CipherSuite::Curve25519Aes128;

        // Create a tree
        let mut tree = get_test_tree(cipher_suite).public;
        let leaf_nodes = get_test_leaf_nodes(cipher_suite);
        tree.add_leaves(leaf_nodes.clone()).unwrap();

        // Find each node
        for (i, leaf_node) in leaf_nodes.iter().enumerate() {
            let expected_index = LeafIndex(i as u32 + 1);
            assert_eq!(tree.find_leaf_node(leaf_node), Some(expected_index));
        }
    }
}
