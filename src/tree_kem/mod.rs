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
use self::leaf_node_ref::LeafNodeRef;
use self::leaf_node_validator::ValidatedLeafNode;

use crate::cipher_suite::CipherSuite;
use crate::extension::ExtensionError;
use crate::group::key_schedule::KeyScheduleKdfError;
use crate::key_package::{KeyPackageError, KeyPackageGenerationError, KeyPackageValidationError};
use crate::tree_kem::parent_hash::ParentHashError;
use crate::tree_kem::path_secret::PathSecretError;

pub(crate) mod math;
pub mod node;
pub mod parent_hash;
pub mod path_secret;
mod private;
mod tree_hash;
pub mod tree_validator;
pub mod update_path;

pub use private::*;
pub use update_path::*;

use tree_index::*;

use self::path_secret::{PathSecret, PathSecretGeneration, PathSecretGenerator};
pub mod kem;
pub mod leaf_node;
pub mod leaf_node_ref;
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
    #[error("leaf node not found: {0}")]
    LeafNodeNotFound(String),
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
                tree_index.insert(leaf.to_reference(cipher_suite)?, leaf_index, leaf)?;
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
        leaf_node: ValidatedLeafNode,
        secret_key: HpkeSecretKey,
    ) -> Result<(TreeKemPublic, TreeKemPrivate), RatchetTreeError> {
        let mut public_tree = TreeKemPublic::new(cipher_suite);

        let leaf_node_ref = leaf_node.to_reference(cipher_suite)?;
        public_tree.add_leaves(vec![leaf_node])?;

        let private_tree = TreeKemPrivate::new_self_leaf(LeafIndex(0), leaf_node_ref, secret_key);

        Ok((public_tree, private_tree))
    }

    pub fn total_leaf_count(&self) -> u32 {
        self.nodes.total_leaf_count()
    }

    pub fn occupied_leaf_count(&self) -> u32 {
        self.nodes.occupied_leaf_count()
    }

    pub fn leaf_node_index(
        &self,
        leaf_node_ref: &LeafNodeRef,
    ) -> Result<LeafIndex, RatchetTreeError> {
        self.index
            .get_leaf_node_index(leaf_node_ref)
            .ok_or_else(|| RatchetTreeError::LeafNodeNotFound(leaf_node_ref.to_string()))
    }

    pub fn get_leaf_node_ref(
        &self,
        leaf_index: LeafIndex,
    ) -> Result<LeafNodeRef, RatchetTreeError> {
        self.nodes
            .borrow_as_leaf(leaf_index)
            .map_err(RatchetTreeError::NodeVecError)?
            .to_reference(self.cipher_suite)
            .map_err(RatchetTreeError::LeafNodeError)
    }

    pub fn get_leaf_node(
        &self,
        leaf_node_ref: &LeafNodeRef,
    ) -> Result<&LeafNode, RatchetTreeError> {
        self.get_validated_leaf_node(leaf_node_ref).map(|p| &**p)
    }

    pub fn get_validated_leaf_node(
        &self,
        leaf_node_ref: &LeafNodeRef,
    ) -> Result<&ValidatedLeafNode, RatchetTreeError> {
        let index = self.leaf_node_index(leaf_node_ref)?;
        self.nodes.borrow_as_leaf(index).map_err(|e| e.into())
    }

    fn update_unmerged(&mut self, leaf_node_ref: &LeafNodeRef) -> Result<(), RatchetTreeError> {
        let index = self.leaf_node_index(leaf_node_ref)?;

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
        leaf_nodes: &[(LeafNodeRef, ValidatedLeafNode)],
    ) -> Result<Vec<LeafNodeRef>, RatchetTreeError> {
        // Fill a set of empty leaves given a particular array, return the leaf indexes that were
        // overwritten
        self.nodes.empty_leaves().zip(leaf_nodes.iter()).try_fold(
            Vec::new(),
            |mut indexs, ((index, empty_node), (package_ref, package))| {
                // See TODO in add_nodes, we have to clone here because we can't iterate the list
                // of packages to insert a single time
                *empty_node = Some(Node::from(package.clone()));
                self.index.insert(package_ref.clone(), index, package)?;
                indexs.push(package_ref.clone());

                Ok::<_, RatchetTreeError>(indexs)
            },
        )
    }

    // Note that a partial failure of this function will leave the tree in a bad state. Modifying a
    // tree should always be done on a clone of the tree, which is how commits are processed
    pub fn add_leaves(
        &mut self,
        leaf_nodes: Vec<ValidatedLeafNode>,
    ) -> Result<Vec<LeafNodeRef>, RatchetTreeError> {
        // Get key package references for all packages we are going to insert
        let leaves_to_insert = leaf_nodes
            .into_iter()
            .map(|ln| {
                let reference = ln.to_reference(self.cipher_suite)?;
                Ok((reference, ln))
            })
            .collect::<Result<Vec<(LeafNodeRef, ValidatedLeafNode)>, RatchetTreeError>>()?;

        // Fill empty leaves first, then add the remaining nodes by extending
        // the tree to the right

        // TODO: Find a way to predetermine a single list of nodes to fill by pre-populating new
        // empty nodes and iterating through a chain of empty leaves + new leaves
        let mut added_leaf_indexs = self.fill_empty_leaves(&leaves_to_insert)?;

        leaves_to_insert
            .into_iter()
            .skip(added_leaf_indexs.len())
            .try_for_each(|(package_ref, package)| {
                if !self.nodes.is_empty() {
                    self.nodes.push(None);
                }

                let index = LeafIndex(self.nodes.len() as u32 / 2);
                self.index.insert(package_ref.clone(), index, &package)?;
                self.nodes.push(Option::from(package));
                added_leaf_indexs.push(package_ref);
                Ok::<_, RatchetTreeError>(())
            })?;

        added_leaf_indexs
            .iter()
            .try_for_each(|index| self.update_unmerged(index))?;

        Ok(added_leaf_indexs)
    }

    // Remove a node given a lookup tree. The lookup tree aids with situations where the reference
    // you are removing might have changed via an update that was applied before calling this
    // function. Removes must be based on an initial state before updates are applied.
    pub fn remove_leaves(
        &mut self,
        lookup_tree: &TreeKemPublic,
        leaf_node_refs: Vec<LeafNodeRef>,
    ) -> Result<Vec<(LeafIndex, LeafNode)>, RatchetTreeError> {
        // Identify a leaf node containing a key package matching removed.
        // This lookup MUST be done on the tree before any non-Remove proposals have been applied

        let indexes = leaf_node_refs
            .iter()
            .map(|reference| lookup_tree.leaf_node_index(reference))
            .collect::<Result<Vec<LeafIndex>, RatchetTreeError>>()?;

        let removed_leaves: Vec<(LeafNodeRef, LeafNode)> = indexes
            .iter()
            .zip(leaf_node_refs)
            .try_fold(Vec::new(), |mut vec, (index, node_ref)| {
                // Replace the leaf node at position removed with a blank node
                if let Some(removed) = self.nodes.blank_leaf_node(*index)? {
                    self.index.remove(&node_ref, &removed)?;
                    vec.push((node_ref.clone(), removed.into()));
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
        leaf_ref: &LeafNodeRef,
        leaf_node: ValidatedLeafNode,
    ) -> Result<(), RatchetTreeError> {
        // Determine if this key package is unique
        let new_key_package_ref = leaf_node.to_reference(self.cipher_suite)?;

        // Update the leaf node
        let leaf_index = self.leaf_node_index(leaf_ref)?;
        let existing_leaf = self.nodes.borrow_as_leaf_mut(leaf_index)?;

        // Update the cache
        self.index.remove(leaf_ref, existing_leaf)?;

        self.index
            .insert(new_key_package_ref, leaf_index, &leaf_node)?;

        *existing_leaf = leaf_node;

        // Blank the intermediate nodes along the path from the sender's leaf to the root
        self.nodes
            .blank_direct_path(leaf_index)
            .map(|_| ())
            .map_err(RatchetTreeError::from)
    }

    pub fn get_leaf_nodes(&self) -> Vec<&LeafNode> {
        self.nodes
            .non_empty_leaves()
            .map(|(_, l)| l.deref())
            .collect()
    }

    pub(crate) fn get_leaf_node_refs(&self) -> impl Iterator<Item = &'_ LeafNodeRef> {
        self.index.leaf_node_refs()
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
    ) -> Result<ValidatedLeafNode, RatchetTreeError> {
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
        original_leaf_node_ref: &LeafNodeRef,
    ) -> Result<(), RatchetTreeError> {
        let sender = self.leaf_node_index(original_leaf_node_ref)?;
        let existing_key_package = self.apply_update_path(sender, update_path)?;

        self.index
            .remove(original_leaf_node_ref, &existing_key_package)?;

        self.index.insert(
            update_path.leaf_node.to_reference(self.cipher_suite)?,
            sender,
            &update_path.leaf_node,
        )?;

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
        Ok(indexes
            .iter()
            .map(|&i| {
                self.nodes[i as usize]
                    .as_ref()
                    .map(|n| n.public_key())
                    .cloned()
            })
            .collect())
    }
}

#[cfg(test)]
pub(crate) mod test_utils {
    use ferriscrypt::{asym::ec_key::SecretKey, hpke::kem::HpkeSecretKey};

    use crate::tree_kem::leaf_node::test_utils::get_basic_test_node_sig_key;

    use super::{
        leaf_node::{test_utils::get_basic_test_node, LeafNode},
        leaf_node_validator::ValidatedLeafNode,
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
            creator_leaf.clone().into(),
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

    pub fn get_test_leaf_nodes(cipher_suite: CipherSuite) -> Vec<ValidatedLeafNode> {
        [
            get_basic_test_node(cipher_suite, "A").into(),
            get_basic_test_node(cipher_suite, "B").into(),
            get_basic_test_node(cipher_suite, "C").into(),
        ]
        .to_vec()
    }
}

#[cfg(test)]
mod tests {
    use crate::cipher_suite::CipherSuite;

    use crate::tree_kem::leaf_node::test_utils::get_basic_test_node;
    use crate::tree_kem::leaf_node::LeafNode;
    use crate::tree_kem::node::{LeafIndex, Node, NodeTypeResolver, Parent};
    use crate::tree_kem::parent_hash::ParentHash;
    use crate::tree_kem::test_utils::{get_test_leaf_nodes, get_test_tree};
    use crate::tree_kem::tree_index::TreeIndexError;
    use crate::tree_kem::{RatchetTreeError, TreeKemPublic};
    use crate::LeafNodeRef;
    use assert_matches::assert_matches;

    #[cfg(target_arch = "wasm32")]
    use wasm_bindgen_test::wasm_bindgen_test as test;

    #[test]
    pub fn test_derive() {
        for cipher_suite in CipherSuite::all() {
            let test_tree = get_test_tree(cipher_suite);

            assert_eq!(
                test_tree.public.nodes[0],
                Some(Node::Leaf(test_tree.creator_leaf.clone().into()))
            );

            assert_eq!(test_tree.private.self_index, LeafIndex(0));

            assert_eq!(
                test_tree.private.leaf_node_ref,
                test_tree.creator_leaf.to_reference(cipher_suite).unwrap()
            );

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

        // The result of adding a node should be all the references that were added
        assert_eq!(
            res,
            leaf_nodes
                .iter()
                .map(|kp| kp.to_reference(cipher_suite).unwrap())
                .collect::<Vec<LeafNodeRef>>()
        );

        // The leaf count should be equal to the number of packages we added
        assert_eq!(tree.occupied_leaf_count(), leaf_nodes.len() as u32);

        // Each added package should be at the proper index and searchable in the tree
        res.iter()
            .zip(leaf_nodes.clone())
            .enumerate()
            .for_each(|(index, (r, kp))| {
                assert_eq!(tree.get_leaf_node(r).unwrap(), &*kp);
                assert_eq!(tree.leaf_node_index(r).unwrap(), LeafIndex(index as u32));
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
    fn test_find_leaf() {
        let cipher_suite = CipherSuite::P256Aes128;
        let mut tree = TreeKemPublic::new(cipher_suite);

        let key_packages = get_test_leaf_nodes(cipher_suite);
        tree.add_leaves(key_packages.clone()).unwrap();

        for (index, key_package_generation) in key_packages.iter().enumerate() {
            let key_package_index = tree
                .leaf_node_index(&key_package_generation.to_reference(cipher_suite).unwrap())
                .unwrap();

            assert_eq!(key_package_index, LeafIndex(index as u32));
        }
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
                TreeIndexError::DuplicateLeafNode(_, _)
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
        tree.add_leaves(key_packages.clone()).unwrap();

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
        let original_package_ref = key_packages[0].to_reference(cipher_suite).unwrap();
        let original_leaf_index = tree.leaf_node_index(&original_package_ref).unwrap();

        let updated_leaf = get_basic_test_node(cipher_suite, "newpk");
        let updated_key_ref = updated_leaf.to_reference(cipher_suite).unwrap();

        tree.update_leaf(&original_package_ref, updated_leaf.clone().into())
            .unwrap();

        // The tree should not have grown due to an update
        assert_eq!(tree.occupied_leaf_count(), original_size);

        // The leaf should not have moved due to an update
        assert_eq!(
            tree.leaf_node_index(&updated_key_ref).unwrap(),
            original_leaf_index
        );

        // The cache of tree package indexs should not have grown
        assert_eq!(tree.index.len() as u32, tree.occupied_leaf_count());

        // The key package should be updated in the tree
        assert_eq!(tree.get_leaf_node(&updated_key_ref).unwrap(), &updated_leaf);

        // There should be an error when looking for the original key package ref
        assert_matches!(
            tree.get_leaf_node(&original_package_ref),
            Err(RatchetTreeError::LeafNodeNotFound(_))
        );
        assert_matches!(
            tree.leaf_node_index(&original_package_ref),
            Err(RatchetTreeError::LeafNodeNotFound(_))
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
            tree.update_leaf(&LeafNodeRef::from([0u8; 16]), new_key_package.into()),
            Err(RatchetTreeError::LeafNodeNotFound(_))
        );
    }

    #[test]
    fn test_update_leaf_duplicate() {
        let cipher_suite = CipherSuite::Curve25519Aes128;

        // Create a tree
        let mut tree = get_test_tree(cipher_suite).public;
        let key_packages = get_test_leaf_nodes(cipher_suite);
        tree.add_leaves(key_packages.clone()).unwrap();

        let duplicate_key_package = key_packages[1].clone();
        let key_package_ref = key_packages[0].to_reference(cipher_suite).unwrap();

        assert_matches!(
            tree.update_leaf(&key_package_ref, duplicate_key_package),
            Err(RatchetTreeError::TreeIndexError(
                TreeIndexError::DuplicateLeafNode(_, _)
            ))
        );
    }

    #[test]
    fn test_remove_leaf() {
        let cipher_suite = CipherSuite::Curve25519Aes128;

        // Create a tree
        let mut tree = get_test_tree(cipher_suite).public;
        let key_packages = get_test_leaf_nodes(cipher_suite);
        tree.add_leaves(key_packages.clone()).unwrap();

        let original_leaf_count = tree.occupied_leaf_count();

        let to_remove = vec![
            key_packages[1].to_reference(cipher_suite).unwrap(),
            key_packages[2].to_reference(cipher_suite).unwrap(),
        ];

        // Remove two leaves from the tree
        let expected_result: Vec<(LeafIndex, LeafNode)> = to_remove
            .clone()
            .into_iter()
            .zip(key_packages[1..].to_owned())
            .map(|(leaf_ref, ln)| (tree.leaf_node_index(&leaf_ref).unwrap(), ln.into()))
            .collect();

        let res = tree
            .remove_leaves(&tree.clone(), to_remove.clone())
            .unwrap();

        assert_eq!(res, expected_result);

        // The leaf count should have been reduced by 2
        assert_eq!(tree.occupied_leaf_count(), original_leaf_count - 2);

        // We should no longer be able to find the removed leaves
        for key_package_ref in to_remove {
            assert_matches!(
                tree.get_leaf_node(&key_package_ref),
                Err(RatchetTreeError::LeafNodeNotFound(_))
            );

            assert_matches!(
                tree.leaf_node_index(&key_package_ref),
                Err(RatchetTreeError::LeafNodeNotFound(_))
            );
        }
    }

    #[test]
    fn test_create_blanks() {
        let cipher_suite = CipherSuite::Curve25519Aes128;

        // Create a tree
        let mut tree = get_test_tree(cipher_suite).public;
        let key_packages = get_test_leaf_nodes(cipher_suite);
        tree.add_leaves(key_packages.clone()).unwrap();

        let original_leaf_count = tree.occupied_leaf_count();

        let remove_ref = key_packages[1].to_reference(cipher_suite).unwrap();
        let remove_location = tree.leaf_node_index(&remove_ref).unwrap();

        let to_remove = vec![remove_ref];

        // Remove the leaf from the tree
        tree.remove_leaves(&tree.clone(), to_remove).unwrap();

        // The occupied leaf count should have been reduced by 1
        assert_eq!(tree.occupied_leaf_count(), original_leaf_count - 1);

        // The total leaf count should remain unchanged
        assert_eq!(tree.total_leaf_count(), original_leaf_count);

        // The location of key_packages[1] should now be blank
        let removed_location = tree.nodes.borrow_node(remove_location.into()).unwrap();
        assert_eq!(removed_location, &None);
    }

    #[test]
    fn test_remove_leaf_failure() {
        let cipher_suite = CipherSuite::Curve25519Aes128;

        // Create a tree
        let mut tree = get_test_tree(cipher_suite).public;

        assert_matches!(
            tree.remove_leaves(&tree.clone(), vec![LeafNodeRef::from([0u8; 16])]),
            Err(RatchetTreeError::LeafNodeNotFound(_))
        );
    }
}
