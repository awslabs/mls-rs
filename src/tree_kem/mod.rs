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

use crate::cipher_suite::{CipherSuite, HpkeCiphertext};
use crate::extension::ExtensionError;
use crate::group::key_schedule::KeyScheduleKdfError;
use crate::key_package::{KeyPackageError, KeyPackageGenerationError, KeyPackageValidationError};
use crate::signer::Signer;
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
    ) -> Result<Vec<(LeafNodeRef, LeafNode)>, RatchetTreeError> {
        // Identify a leaf node containing a key package matching removed.
        // This lookup MUST be done on the tree before any non-Remove proposals have been applied

        let indexes = leaf_node_refs
            .iter()
            .map(|reference| lookup_tree.leaf_node_index(reference))
            .collect::<Result<Vec<LeafIndex>, RatchetTreeError>>()?;

        let removed_leaves = indexes.into_iter().zip(leaf_node_refs).try_fold(
            Vec::new(),
            |mut vec, (index, node_ref)| {
                // Replace the leaf node at position removed with a blank node
                if let Some(removed) = self.nodes.blank_leaf_node(index)? {
                    self.index.remove(&node_ref, &removed)?;
                    vec.push((node_ref.clone(), removed.into()));
                }

                // Blank the intermediate nodes along the path from the removed leaf to the root
                self.nodes.blank_direct_path(index)?;
                Ok::<_, RatchetTreeError>(vec)
            },
        )?;

        // Truncate the tree by reducing the size of tree until the rightmost non-blank leaf node
        self.nodes.trim();

        Ok(removed_leaves)
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

    fn encrypt_copath_node_resolution(
        &self,
        path_secret: PathSecretGeneration,
        index: NodeIndex,
        copath_node_resolution: Vec<&Node>,
        context: &[u8],
    ) -> Result<EncryptedResolution, RatchetTreeError> {
        let ciphertext = copath_node_resolution
            .iter()
            .map(|&copath_node| {
                self.cipher_suite
                    .hpke()
                    .seal(
                        copath_node.public_key(),
                        context,
                        None,
                        None,
                        &path_secret.path_secret,
                    )
                    .map(HpkeCiphertext::from)
            })
            .collect::<Result<Vec<HpkeCiphertext>, HpkeError>>()?;

        let (_, public_key) = path_secret.to_hpke_key_pair()?;

        let update_path_node = UpdatePathNode {
            public_key,
            encrypted_path_secret: ciphertext,
        };

        Ok(EncryptedResolution {
            path_secret,
            index,
            update_path_node,
        })
    }

    // TODO: Make UpdatePathGeneration not return a private key to simplify this function
    pub fn encap<S: Signer>(
        &mut self,
        private_key: &TreeKemPrivate,
        group_id: &[u8],
        context: &[u8],
        excluding: &[LeafNodeRef],
        signer: &S,
    ) -> Result<UpdatePathGeneration, RatchetTreeError> {
        let secret_generator = PathSecretGenerator::new(self.cipher_suite);

        let excluding: Vec<LeafIndex> = excluding
            .iter()
            .flat_map(|reference| self.leaf_node_index(reference))
            .collect();

        // Generate all the new path secrets and encrypt them to their copath node resolutions
        let (node_secrets, node_updates): (
            HashMap<NodeIndex, PathSecretGeneration>,
            Vec<UpdatePathNode>,
        ) = secret_generator
            .zip(
                self.nodes
                    .direct_path_copath_resolution(private_key.self_index, &excluding)?,
            )
            .map(|(path_secret, (index, copath_nodes))| {
                self.encrypt_copath_node_resolution(path_secret?, index, copath_nodes, context)
            })
            .try_fold(
                (HashMap::new(), Vec::new()),
                |(mut secrets, mut updates), resolution| {
                    let encrypted_resolution = resolution?;
                    secrets.insert(encrypted_resolution.index, encrypted_resolution.path_secret);
                    updates.push(encrypted_resolution.update_path_node);
                    Ok::<_, RatchetTreeError>((secrets, updates))
                },
            )?;

        let root_secret = node_secrets
            .get(&tree_math::root(self.nodes.total_leaf_count()))
            .cloned()
            .map(Ok)
            .unwrap_or_else(|| PathSecretGeneration::random(self.cipher_suite))?
            .path_secret;

        // Update the private key with the new keys
        let mut private_key = private_key.clone();

        for (index, path_secret) in &node_secrets {
            private_key
                .secret_keys
                .insert(*index, path_secret.to_hpke_key_pair()?.0);
        }

        let secret_path = SecretPath {
            path_secrets: node_secrets
                .into_iter()
                .map(|(index, ps)| (index, ps.path_secret))
                .collect(),
            root_secret,
        };

        let mut own_leaf_copy = self.nodes.borrow_as_leaf(private_key.self_index)?.clone();

        // Remove the original leaf from the index
        self.index
            .remove(&private_key.leaf_node_ref, &own_leaf_copy)?;

        // Apply parent node updates to the tree to aid with the parent hash calculation
        self.apply_parent_node_updates(private_key.self_index, &node_updates)?;

        // Evolve your leaf forward
        // TODO: Support updating extensions and capabilities at this point
        let secret_key =
            own_leaf_copy.commit(self.cipher_suite, group_id, None, None, signer, |_| {
                self.update_parent_hashes(private_key.self_index, None)
                    .map_err(Into::into)
            })?;

        let own_leaf = self.nodes.borrow_as_leaf_mut(private_key.self_index)?;
        let new_leaf_ref = own_leaf_copy.to_reference(self.cipher_suite)?;
        *own_leaf = own_leaf_copy;

        self.index
            .insert(new_leaf_ref.clone(), private_key.self_index, own_leaf)?;

        private_key
            .secret_keys
            .insert(NodeIndex::from(private_key.self_index), secret_key);

        private_key.leaf_node_ref = new_leaf_ref;

        // Create an update path with the new node and parent node updates
        let update_path = UpdatePath {
            leaf_node: own_leaf.clone().into(),
            nodes: node_updates,
        };

        Ok(UpdatePathGeneration {
            update_path,
            secrets: TreeSecrets {
                private_key,
                secret_path,
            },
        })
    }

    fn decrypt_parent_path_secret(
        &self,
        private_key: &TreeKemPrivate,
        update_node: &UpdatePathNode,
        lca_direct_path_child: NodeIndex,
        excluding: &[NodeIndex],
        context: &[u8],
    ) -> Result<PathSecret, RatchetTreeError> {
        self.nodes
            .get_resolution_index(lca_direct_path_child)? // Resolution of the lca child node
            .iter()
            .zip(update_node.encrypted_path_secret.iter())
            .filter(|(i, _)| !excluding.contains(i)) // Match up the nodes with their ciphertexts
            .find_map(|(i, ct)| private_key.secret_keys.get(i).map(|sk| (sk, ct)))
            .ok_or(RatchetTreeError::UpdateErrorNoSecretKey)
            .and_then(|(sk, ct)| {
                // Decrypt the path secret
                self.cipher_suite
                    .hpke()
                    .open(&ct.clone().into(), sk, context, None, None)
                    .map_err(Into::into)
            })
            .map(PathSecret::from)
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

    pub fn decap(
        &mut self,
        private_key: TreeKemPrivate,
        sender: &LeafNodeRef,
        update_path: &ValidatedUpdatePath,
        added_leaves: &[LeafNodeRef],
        context: &[u8],
    ) -> Result<TreeSecrets, RatchetTreeError> {
        let sender_index = self.leaf_node_index(sender)?;

        // Exclude newly added leaf indexes
        let excluding = added_leaves
            .iter()
            .flat_map(|index| self.leaf_node_index(index).map(Into::into))
            .collect::<Vec<NodeIndex>>();

        // Find the least common ancestor shared by us and the sender
        let lca =
            tree_math::common_ancestor_direct(private_key.self_index.into(), sender_index.into());

        let lca_path_secret = self
            .nodes
            .filtered_direct_path_co_path(sender_index)?
            .into_iter()
            .zip(&update_path.nodes)
            .find_map(|((direct_path_index, co_path_index), update_path_node)| {
                if direct_path_index == lca {
                    self.decrypt_parent_path_secret(
                        &private_key,
                        update_path_node,
                        co_path_index,
                        &excluding,
                        context,
                    )
                    .into()
                } else {
                    None
                }
            })
            .ok_or(RatchetTreeError::LcaNotFoundInDirectPath)??;

        // Derive the rest of the secrets for the tree and assign to the proper nodes
        let node_secret_gen =
            PathSecretGenerator::starting_with(self.cipher_suite, lca_path_secret);

        // Update secrets based on the decrypted path secret in the update
        let (path_secrets, private_key) = node_secret_gen
            .zip(
                // Get a pairing of direct path index + associated update
                // This will help us verify that the calculated public key is the expected one
                self.nodes
                    .filtered_direct_path(sender_index)?
                    .iter()
                    .zip(update_path.nodes.iter())
                    .skip_while(|(dp, _)| **dp != lca),
            )
            .try_fold(
                (HashMap::new(), private_key),
                |(mut path_secrets, mut private_key), (secret, (&index, update))| {
                    let secret = secret?;
                    // Verify the private key we calculated properly matches the public key we were
                    // expecting
                    let (hpke_private, hpke_public) = secret.to_hpke_key_pair()?;

                    if hpke_public != update.public_key {
                        return Err(RatchetTreeError::PubKeyMismatch);
                    }

                    private_key.secret_keys.insert(index, hpke_private);
                    path_secrets.insert(index, secret.path_secret);

                    Ok((path_secrets, private_key))
                },
            )?;

        let root_secret = path_secrets
            .get(&tree_math::root(self.total_leaf_count()))
            .cloned()
            .map(Ok)
            .unwrap_or_else(|| PathSecret::random(self.cipher_suite))?;

        let tree_secrets = TreeSecrets {
            private_key,
            secret_path: SecretPath {
                path_secrets,
                root_secret,
            },
        };

        let removed_key_package = self.apply_update_path(sender_index, update_path)?;
        self.index.remove(sender, &removed_key_package)?;

        self.index.insert(
            update_path.leaf_node.to_reference(self.cipher_suite)?,
            sender_index,
            &update_path.leaf_node,
        )?;

        // Verify the parent hash of the new sender leaf node and update the parent hash values
        // in the local tree
        self.update_parent_hashes(sender_index, Some(update_path))?;

        Ok(tree_secrets)
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
    use super::leaf_node::test_utils::get_basic_test_node_sig_key;
    use super::leaf_node_validator::ValidatedLeafNode;
    use super::tree_math;
    use super::{TreeKemPrivate, UpdatePath, ValidatedUpdatePath};
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
    use ferriscrypt::asym::ec_key::SecretKey;
    use ferriscrypt::hpke::kem::HpkePublicKey;

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
        let cipher_suite = CipherSuite::P256Aes128V1;
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
        let cipher_suite = CipherSuite::Curve25519Aes128V1;
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
        let cipher_suite = CipherSuite::Curve25519Aes128V1;
        let mut tree = TreeKemPublic::new(cipher_suite);

        let key_packages = get_test_leaf_nodes(cipher_suite);
        tree.add_leaves(key_packages).unwrap();

        let key_packages = tree.get_leaf_nodes();
        assert_eq!(key_packages, key_packages.to_owned());
    }

    #[test]
    fn test_find_leaf() {
        let cipher_suite = CipherSuite::P256Aes128V1;
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
        let cipher_suite = CipherSuite::P256Aes128V1;
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
        let cipher_suite = CipherSuite::Curve25519Aes128V1;
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
        let cipher_suite = CipherSuite::Curve25519Aes128V1;
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
        let cipher_suite = CipherSuite::Curve25519Aes128V1;

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
        let cipher_suite = CipherSuite::Curve25519Aes128V1;

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
        let cipher_suite = CipherSuite::Curve25519Aes128V1;

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
        let cipher_suite = CipherSuite::Curve25519Aes128V1;

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
        let res = tree
            .remove_leaves(&tree.clone(), to_remove.clone())
            .unwrap();

        let expected_result: Vec<(LeafNodeRef, LeafNode)> = to_remove
            .clone()
            .into_iter()
            .zip(key_packages[1..].to_owned())
            .map(|(index, ln)| (index, ln.into()))
            .collect();

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
        let cipher_suite = CipherSuite::Curve25519Aes128V1;

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
        let cipher_suite = CipherSuite::Curve25519Aes128V1;

        // Create a tree
        let mut tree = get_test_tree(cipher_suite).public;

        assert_matches!(
            tree.remove_leaves(&tree.clone(), vec![LeafNodeRef::from([0u8; 16])]),
            Err(RatchetTreeError::LeafNodeNotFound(_))
        );
    }

    // Verify that the tree is in the correct state after generating an update path
    fn verify_tree_update_path(tree: &TreeKemPublic, update_path: &UpdatePath, index: LeafIndex) {
        // Make sure the update path is based on the direct path of the sender
        let direct_path = tree.nodes.direct_path(index).unwrap();
        for (i, &dpi) in direct_path.iter().enumerate() {
            assert_eq!(
                *tree.nodes[dpi as usize].as_ref().unwrap().public_key(),
                update_path.nodes[i].public_key
            );
        }

        // Verify that the leaf from the update path has been installed
        assert_eq!(
            tree.leaf_node_index(
                &update_path
                    .leaf_node
                    .to_reference(tree.cipher_suite)
                    .unwrap()
            )
            .unwrap(),
            index
        );

        // Verify that we have a public keys up to the root
        assert!(tree.nodes[tree_math::root(tree.total_leaf_count()) as usize].is_some());
    }

    fn verify_tree_private_path(
        cipher_suite: &CipherSuite,
        public_tree: &TreeKemPublic,
        private_tree: &TreeKemPrivate,
        index: LeafIndex,
    ) {
        assert_eq!(private_tree.self_index, index);
        // Make sure we have private values along the direct path, and the public keys match
        for one_index in public_tree.nodes.direct_path(index).unwrap() {
            let secret_key = private_tree.secret_keys.get(&one_index).unwrap();
            let public_key = public_tree.nodes[one_index as usize]
                .as_ref()
                .unwrap()
                .public_key();
            let secret_key =
                SecretKey::from_bytes(secret_key.as_ref(), cipher_suite.kem_type().curve())
                    .unwrap();
            assert_eq!(
                HpkePublicKey::from(
                    secret_key
                        .to_public()
                        .unwrap()
                        .to_uncompressed_bytes()
                        .unwrap()
                ),
                *public_key
            );
        }
    }

    fn encap_decap(cipher_suite: CipherSuite, size: usize) {
        // Generate signing keys and key package generations, and private keys for multiple
        // participants in order to set up state
        let (leaf_nodes, private_keys): (_, Vec<TreeKemPrivate>) = (1..size)
            .map(|index| {
                let (leaf_node, hpke_secret, _) =
                    get_basic_test_node_sig_key(cipher_suite, &format!("{}", index));

                let private_key = TreeKemPrivate::new_self_leaf(
                    LeafIndex(index as u32),
                    leaf_node.to_reference(cipher_suite).unwrap(),
                    hpke_secret,
                );

                (ValidatedLeafNode::from(leaf_node), private_key)
            })
            .unzip();

        let (encap_node, encap_hpke_secret, encap_signer) =
            get_basic_test_node_sig_key(cipher_suite, "encap");

        // Build a test tree we can clone for all leaf nodes
        let (mut test_tree, encap_private_key) =
            TreeKemPublic::derive(cipher_suite, encap_node.clone().into(), encap_hpke_secret)
                .unwrap();

        test_tree.add_leaves(leaf_nodes).unwrap();

        // Clone the tree for the first leaf, generate a new key package for that leaf
        let mut encap_tree = test_tree.clone();

        // Perform the encap function
        let update_path_gen = encap_tree
            .encap(
                &encap_private_key,
                b"test_group",
                b"test_ctx",
                &[],
                &encap_signer,
            )
            .unwrap();

        // Verify that the state of the tree matches the produced update path
        verify_tree_update_path(&encap_tree, &update_path_gen.update_path, LeafIndex(0));

        // Verify that the private key matches the data in the public key
        verify_tree_private_path(
            &cipher_suite,
            &encap_tree,
            &update_path_gen.secrets.private_key,
            LeafIndex(0),
        );

        // Apply the update path to the rest of the leaf nodes using the decap function
        let validated_update_path = ValidatedUpdatePath {
            leaf_node: ValidatedLeafNode::from(update_path_gen.update_path.leaf_node),
            nodes: update_path_gen.update_path.nodes,
        };

        let mut receiver_trees: Vec<TreeKemPublic> = (1..size).map(|_| test_tree.clone()).collect();

        for (i, tree) in receiver_trees.iter_mut().enumerate() {
            println!("Decap for {:?}, user: {:?}", i, private_keys[i].self_index);
            let secrets = tree
                .decap(
                    private_keys[i].clone(),
                    &encap_node.to_reference(cipher_suite).unwrap(),
                    &validated_update_path,
                    &[],
                    b"test_ctx".as_ref(),
                )
                .unwrap();

            assert_eq!(tree, &encap_tree);

            assert_eq!(
                secrets.secret_path.root_secret,
                update_path_gen.secrets.secret_path.root_secret
            );
        }
    }

    #[test]
    fn test_encap_decap() {
        for cipher_suite in CipherSuite::all() {
            println!("Testing Tree KEM encap / decap for: {cipher_suite:?}");
            encap_decap(cipher_suite, 10);
        }
    }
}
