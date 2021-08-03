pub(crate) mod math;
pub mod node;
mod node_secrets;
pub mod parent_hash;
mod tree_hash;

use crate::ciphersuite::{CipherSuite, HpkeCiphertext};
use crate::credential::Credential;
use crate::extension::{ExtensionError, ParentHashExt};
use crate::group::GroupSecrets;
use crate::key_package::{KeyPackage, KeyPackageError, KeyPackageGeneration};
use crate::key_schedule::KeyScheduleKdfError;
use crate::leaf_secret::{LeafSecret, LeafSecretError};
use crate::tree_kem::node_secrets::NodeSecretGeneratorError;
use crate::tree_kem::parent_hash::ParentHashError;
use ferriscrypt::asym::ec_key::{EcKeyError, SecretKey};
use ferriscrypt::hpke::{HPKECiphertext, HpkeError};
use math as tree_math;
use math::TreeMathError;
use node::{Leaf, LeafIndex, Node, NodeIndex, NodeVec, NodeVecError};
use node_secrets::{NodeSecretGenerator, NodeSecrets};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::SystemTime;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum RatchetTreeError {
    #[error(transparent)]
    TreeMathError(#[from] TreeMathError),
    #[error(transparent)]
    KeyPackageError(#[from] KeyPackageError),
    #[error(transparent)]
    EcKeyError(#[from] EcKeyError),
    #[error(transparent)]
    NodeVecError(#[from] NodeVecError),
    #[error(transparent)]
    BincodeError(#[from] bincode::Error),
    #[error(transparent)]
    ParentHashError(#[from] ParentHashError),
    #[error(transparent)]
    ExtensionError(#[from] ExtensionError),
    #[error(transparent)]
    KeyScheduleKdfError(#[from] KeyScheduleKdfError),
    #[error(transparent)]
    HpkeError(#[from] HpkeError),
    #[error(transparent)]
    LeafSecretError(#[from] LeafSecretError),
    #[error(transparent)]
    NodeSecretGeneratorError(#[from] NodeSecretGeneratorError),
    #[error("invalid update path signature")]
    InvalidUpdatePathSignature,
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
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct RatchetTree {
    pub cipher_suite: CipherSuite,
    pub(crate) nodes: NodeVec,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TreeKemPrivate {
    pub self_index: LeafIndex,
    pub secret_keys: HashMap<NodeIndex, SecretKey>,
}

impl From<KeyPackageGeneration> for TreeKemPrivate {
    fn from(kg: KeyPackageGeneration) -> Self {
        Self::from(kg.secret_key)
    }
}

impl TreeKemPrivate {
    pub fn new(self_index: LeafIndex) -> Self {
        TreeKemPrivate {
            self_index,
            secret_keys: Default::default(),
        }
    }

    //TODO: This function should take SecretKey not Vec<u8>
    pub fn new_self_leaf(self_index: LeafIndex, leaf_secret: SecretKey) -> Self {
        let mut private_key = TreeKemPrivate {
            self_index,
            secret_keys: Default::default(),
        };
        private_key
            .secret_keys
            .insert(NodeIndex::from(self_index), leaf_secret);
        private_key
    }

    pub fn new_from_secret(
        cipher_suite: CipherSuite,
        self_index: LeafIndex,
        leaf_secret: SecretKey,
        sender_index: LeafIndex,
        leaf_count: usize,
        group_secrets: &GroupSecrets,
    ) -> Result<Self, RatchetTreeError> {
        // Update the leaf at index index with the private key corresponding to the public key
        // in the node.
        let mut private_key = TreeKemPrivate::new_self_leaf(self_index, leaf_secret);

        if let Some(path_secret) = &group_secrets.path_secret {
            // If the path_secret value is set in the GroupSecrets object: Identify the lowest common
            // ancestor of the leaves at index and at GroupInfo.signer_index. Set the private key
            // for this node to the private key derived from the path_secret.
            let lca = tree_math::common_ancestor_direct(sender_index.into(), self_index.into());

            let path_gen = NodeSecretGenerator::new_from_path_secret(
                cipher_suite,
                path_secret.path_secret.clone(),
            )
            .flatten(); //TODO: This is skipping errors

            // For each parent of the common ancestor, up to the root of the tree, derive a new
            // path secret and set the private key for the node to the private key derived from the
            // path secret. The private key MUST be the private key that corresponds to the public
            // key in the node.
            self_index
                .direct_path(leaf_count)?
                .iter()
                .skip_while(|&&i| i != lca)
                .zip(path_gen)
                .for_each(|(&index, secrets)| {
                    private_key.secret_keys.insert(index, secrets.secret_key);
                });
        }

        Ok(private_key)
    }

    pub fn update_leaf(
        &mut self,
        num_leaves: usize,
        new_leaf: SecretKey,
    ) -> Result<(), RatchetTreeError> {
        self.secret_keys
            .insert(NodeIndex::from(self.self_index), new_leaf);

        self.self_index
            .direct_path(num_leaves)?
            .iter()
            .for_each(|i| {
                self.secret_keys.remove(i);
            });

        Ok(())
    }

    pub fn remove_leaf(
        &mut self,
        num_leaves: usize,
        index: LeafIndex,
    ) -> Result<(), RatchetTreeError> {
        self.secret_keys.remove(&NodeIndex::from(index));

        index.direct_path(num_leaves)?.iter().for_each(|i| {
            self.secret_keys.remove(i);
        });

        Ok(())
    }
}

impl From<SecretKey> for TreeKemPrivate {
    fn from(secret_key: SecretKey) -> Self {
        let mut secret_keys = HashMap::new();
        secret_keys.insert(0usize, secret_key);

        TreeKemPrivate {
            self_index: LeafIndex(0),
            secret_keys,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SecretPath {
    pub root_secret: Vec<u8>,
    path_secrets: HashMap<NodeIndex, Vec<u8>>,
}

impl SecretPath {
    pub fn get_path_secret(&self, index: NodeIndex) -> Option<Vec<u8>> {
        self.path_secrets.get(&index).cloned()
    }
}

impl Default for SecretPath {
    fn default() -> Self {
        SecretPath {
            root_secret: vec![],
            path_secrets: Default::default(),
        }
    }
}

impl From<Vec<IndexedNodeSecrets>> for SecretPath {
    fn from(path_secrets: Vec<IndexedNodeSecrets>) -> Self {
        let mut secrets = HashMap::new();
        let root_secret = path_secrets.iter().fold(Vec::new(), |_, secret| {
            secrets.insert(secret.index, secret.secrets.path_secret.clone());
            secret.secrets.path_secret.clone()
        });
        SecretPath {
            root_secret,
            path_secrets: secrets,
        }
    }
}

struct IndexedNodeSecrets {
    index: NodeIndex,
    secrets: NodeSecrets,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UpdatePathGeneration {
    pub update_path: UpdatePath,
    pub secrets: TreeSecrets,
}

impl UpdatePathGeneration {
    pub fn get_common_path_secret(&self, leaf: LeafIndex) -> Option<Vec<u8>> {
        let lca = tree_math::common_ancestor_direct(
            self.secrets.private_key.self_index.into(),
            leaf.into(),
        );

        self.secrets.secret_path.get_path_secret(lca)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TreeSecrets {
    pub private_key: TreeKemPrivate,
    pub secret_path: SecretPath,
}

impl TreeSecrets {
    fn new(private_key: TreeKemPrivate) -> TreeSecrets {
        TreeSecrets {
            private_key,
            secret_path: Default::default(),
        }
    }
}

impl RatchetTree {
    pub fn derive(
        key_package: KeyPackageGeneration,
    ) -> Result<(RatchetTree, TreeKemPrivate), RatchetTreeError> {
        let public_tree = RatchetTree {
            cipher_suite: key_package.key_package.cipher_suite,
            nodes: vec![Leaf::from(key_package.key_package.clone()).into()].into(),
        };

        let private_tree = TreeKemPrivate::from(key_package);

        Ok((public_tree, private_tree))
    }

    pub fn new(cipher_suite: CipherSuite) -> RatchetTree {
        RatchetTree {
            cipher_suite,
            nodes: NodeVec::from(vec![]),
        }
    }

    pub fn leaf_count(&self) -> usize {
        self.nodes.leaf_count()
    }

    pub fn find_leaf(&self, key_package: &KeyPackage) -> Option<LeafIndex> {
        self.nodes
            .non_empty_leaves()
            .find(|(_, leaf)| &leaf.key_package == key_package)
            .map(|r| r.0)
    }

    pub fn get_key_package(&self, leaf: LeafIndex) -> Result<&KeyPackage, RatchetTreeError> {
        self.nodes
            .borrow_as_leaf(leaf)
            .map(|l| &l.key_package)
            .map_err(|e| e.into())
    }

    pub fn validate(&self, expected_tree_hash: &[u8]) -> Result<(), RatchetTreeError> {
        //Verify that the tree hash of the ratchet tree matches the tree_hash field in the GroupInfo.
        if self.tree_hash()? != expected_tree_hash {
            return Err(RatchetTreeError::TreeHashMismatch);
        }

        // Validate the parent hashes in the tree
        self.validate_parent_hashes()?;

        // For each non-empty leaf node, verify the signature on the KeyPackage.
        for one_leaf in self.nodes.non_empty_leaves().map(|l| l.1) {
            if !one_leaf.key_package.has_valid_signature()? {
                return Err(RatchetTreeError::InvalidLeafSignature);
            }
        }

        Ok(())
    }

    fn update_unmerged(&mut self, index: LeafIndex) -> Result<(), RatchetTreeError> {
        // For a given leaf index, find parent nodes and add the leaf to the unmerged leaf
        self.nodes.direct_path(index)?.iter().for_each(|&i| {
            if let Ok(p) = self.nodes.borrow_as_parent_mut(i) {
                p.unmerged_leaves.push(index)
            }
        });

        Ok(())
    }

    fn fill_empty_leaves(&mut self, nodes: &[Node]) -> Vec<LeafIndex> {
        // Fill a set of empty leaves given a particular array, return the amount of
        // nodes consumed
        self.nodes.empty_leaves().zip(nodes.iter()).fold(
            Vec::new(),
            |mut indexs, ((index, empty_node), new_node)| {
                *empty_node = Some(new_node.clone());
                indexs.push(index);
                indexs
            },
        )
    }

    pub fn add_nodes(
        &mut self,
        key_packages: Vec<KeyPackage>,
    ) -> Result<Vec<LeafIndex>, RatchetTreeError> {
        // Validate the validity of the key signatures and lifetimes
        key_packages
            .iter()
            .try_for_each(|kp| kp.validate(SystemTime::now()))?;

        // Convert all the key packages into nodes
        let new_nodes: Vec<Node> = key_packages.iter().map(|n| Node::from(n.clone())).collect();

        // Fill empty leaves first, then add the remaining nodes by extending
        // the tree to the right
        let mut added_leaf_index = self.fill_empty_leaves(&new_nodes);

        new_nodes.iter().skip(added_leaf_index.len()).for_each(|n| {
            if !self.nodes.is_empty() {
                self.nodes.push(None);
            }
            self.nodes.push(n.clone().into());
            added_leaf_index.push(LeafIndex(self.nodes.len() / 2))
        });

        added_leaf_index
            .iter()
            .try_for_each(|&i| self.update_unmerged(i))?;

        Ok(added_leaf_index)
    }

    pub fn remove_nodes(
        &mut self,
        indexes: Vec<LeafIndex>,
    ) -> Result<Vec<(LeafIndex, KeyPackage)>, RatchetTreeError> {
        let mut removed_leaves = Vec::new();

        for one_index in indexes {
            // Replace the leaf node at position removed with a blank node
            if let Some(removed) = self.nodes.blank_leaf_node(one_index)? {
                removed_leaves.push((one_index, removed.key_package));
            }

            // Blank the intermediate nodes along the path from the removed leaf to the root
            self.nodes.blank_direct_path(one_index)?;
        }

        // Truncate the tree by reducing the size of tree until the rightmost non-blank leaf node
        self.nodes.trim();

        Ok(removed_leaves)
    }

    pub fn update_leaf(
        &mut self,
        leaf_index: LeafIndex,
        key_package: KeyPackage,
    ) -> Result<(), RatchetTreeError> {
        // Validate the validity of the key signature
        key_package.validate(SystemTime::now())?;

        // Update the leaf node
        self.nodes.borrow_as_leaf_mut(leaf_index)?.key_package = key_package;

        // Blank the intermediate nodes along the path from the sender's leaf to the root
        self.nodes
            .blank_direct_path(leaf_index)
            .map(|_| ())
            .map_err(RatchetTreeError::from)
    }

    pub fn get_credential(&self, leaf_index: LeafIndex) -> Result<Credential, RatchetTreeError> {
        let leaf = self.nodes.borrow_as_leaf(leaf_index)?;
        Ok(leaf.key_package.credential.clone())
    }

    pub fn get_credentials(&self) -> Vec<Credential> {
        self.nodes
            .non_empty_leaves()
            .map(|(_, l)| l.key_package.credential.clone())
            .collect()
    }

    fn encrypt_copath_node_resolution(
        &self,
        path_secret: &NodeSecrets,
        index: NodeIndex,
        copath_node_resolution: Vec<&Node>,
        context: &[u8],
    ) -> Result<(IndexedNodeSecrets, UpdatePathNode), RatchetTreeError> {
        let ciphertext = copath_node_resolution
            .iter()
            .map(|&copath_node| {
                self.cipher_suite
                    .hpke()
                    .seal_base(
                        copath_node.get_public_key(),
                        &[],
                        Some(context),
                        &path_secret.path_secret,
                    )
                    .map(HpkeCiphertext::from)
            })
            .collect::<Result<Vec<HpkeCiphertext>, HpkeError>>()?;

        let update_path_node = UpdatePathNode {
            public_key: path_secret.public_key.clone(),
            encrypted_path_secret: ciphertext,
        };

        let indexed_node_secrets = IndexedNodeSecrets {
            index,
            secrets: path_secret.clone(),
        };

        Ok((indexed_node_secrets, update_path_node))
    }

    pub fn encap(
        &mut self,
        private_key: &TreeKemPrivate,
        signer: &SecretKey,
        context: &[u8],
        excluding: &[LeafIndex],
    ) -> Result<UpdatePathGeneration, RatchetTreeError> {
        // random leaf secret
        let leaf_secret = LeafSecret::generate(self.cipher_suite)?;

        let mut secret_generator =
            NodeSecretGenerator::new_from_leaf_secret(self.cipher_suite, leaf_secret);

        // new leaf keypair
        let leaf_secrets = secret_generator.next_secret()?;

        // Clone the current key package, and swap in the new public key
        let mut leaf_key_package = self
            .nodes
            .borrow_as_leaf(private_key.self_index)?
            .key_package
            .clone();

        leaf_key_package.hpke_init_key = leaf_secrets.public_key;

        // Generate all the new path secrets and encrypt them to their copath node resolutions
        let (node_secrets, node_updates): (Vec<IndexedNodeSecrets>, Vec<UpdatePathNode>) =
            secret_generator
                .flatten() //TODO: Remove flatmap + flatten
                .zip(
                    self.nodes
                        .direct_path_copath_resolution(private_key.self_index, excluding)?,
                )
                .flat_map(|(path_secret, (index, copath_nodes))| {
                    self.encrypt_copath_node_resolution(&path_secret, index, copath_nodes, context)
                })
                .unzip();

        let mut private_key = private_key.clone();
        private_key.secret_keys.insert(
            NodeIndex::from(private_key.self_index),
            leaf_secrets.secret_key,
        );

        for one_secret in &node_secrets {
            private_key
                .secret_keys
                .insert(one_secret.index, one_secret.secrets.secret_key.clone());
        }

        let secret_path = SecretPath::from(node_secrets);

        let mut update_path = UpdatePath {
            leaf_key_package,
            nodes: node_updates,
        };

        // Apply the new update path to the tree
        self.apply_update_path(private_key.self_index, &update_path)?;

        // Apply the parent hash updates to the tree
        let leaf_parent_hash = self.update_parent_hashes(private_key.self_index, None)?;

        // Update the leaf in the tree by applying the parent hash and signing the package
        let leaf = self.nodes.borrow_as_leaf_mut(private_key.self_index)?;

        leaf.key_package
            .extensions
            .set_extension(ParentHashExt::from(leaf_parent_hash))?;

        leaf.key_package.sign(signer)?;

        // Overwrite the key package in the update path with the signed version
        update_path.leaf_key_package = leaf.key_package.clone();

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
    ) -> Result<Vec<u8>, RatchetTreeError> {
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
                    .open_base(
                        &HPKECiphertext::from(ct.clone()),
                        &sk.to_bytes()?,
                        &[],
                        Some(context),
                    )
                    .map_err(Into::into)
            })
    }

    fn update_node(&mut self, pub_key: Vec<u8>, index: NodeIndex) -> Result<(), RatchetTreeError> {
        self.nodes
            .borrow_or_fill_node_as_parent(index, &pub_key)
            .map_err(|e| e.into())
            .map(|p| {
                p.public_key = pub_key;
                p.unmerged_leaves = vec![];
            })
    }

    fn apply_update_path(
        &mut self,
        sender: LeafIndex,
        update_path: &UpdatePath,
    ) -> Result<(), RatchetTreeError> {
        // Install the new leaf node
        self.nodes.borrow_as_leaf_mut(sender).map(|l| {
            l.key_package = update_path.leaf_key_package.clone();
        })?;

        // Update the rest of the nodes on the direct path
        update_path
            .nodes
            .iter()
            .zip(self.nodes.direct_path(sender)?)
            .try_for_each(|(one_node, node_index)| {
                self.update_node(one_node.public_key.clone(), node_index)
            })?;

        Ok(())
    }

    pub fn apply_pending_update(
        &mut self,
        update_path_generation: &UpdatePathGeneration,
    ) -> Result<(), RatchetTreeError> {
        let sender = update_path_generation.secrets.private_key.self_index;
        self.apply_update_path(sender, &update_path_generation.update_path)?;

        // Verify the parent hash of the new sender leaf node and update the parent hash values
        // in the local tree
        self.update_parent_hashes(sender, Some(&update_path_generation.update_path))?;

        Ok(())
    }

    pub fn decap(
        &mut self,
        private_key: TreeKemPrivate,
        sender: LeafIndex,
        update_path: &UpdatePath,
        added_leaves: Vec<LeafIndex>,
        context: &[u8],
    ) -> Result<TreeSecrets, RatchetTreeError> {
        // Verify the signature on the key package
        update_path.leaf_key_package.validate(SystemTime::now())?;

        // Exclude newly added leaf indexes
        let excluding = added_leaves
            .iter()
            .map(NodeIndex::from)
            .collect::<Vec<NodeIndex>>();

        // Find the least common ancestor shared by us and the sender
        let lca = tree_math::common_ancestor_direct(private_key.self_index.into(), sender.into());

        let sender_direct = self.nodes.direct_path(sender)?;
        let sender_co = self.nodes.copath(sender)?;

        let lca_path_secret = sender_direct
            .iter()
            .zip(sender_co.iter().zip(&update_path.nodes))
            .find_map(|(&direct_path_index, (&co_path_index, update_path_node))| {
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
            NodeSecretGenerator::new_from_path_secret(self.cipher_suite, lca_path_secret);

        // Update secrets based on the decrypted path secret in the update
        let tree_secrets = node_secret_gen
            .flatten() //TODO: Remove flatten maybe this should just be a for loop
            .zip(
                // Get a pairing of direct path index + associated update
                // This will help us verify that the calculated public key is the expected one
                self.nodes
                    .direct_path(sender)?
                    .iter()
                    .zip(update_path.nodes.iter())
                    .skip_while(|(dp, _)| **dp != lca),
            )
            .try_fold(
                TreeSecrets::new(private_key),
                |mut secrets, (secret, (&index, update))| {
                    // Verify the private key we calculated properly matches the public key we were
                    // expecting
                    if secret.public_key != update.public_key {
                        return Err(RatchetTreeError::PubKeyMismatch);
                    }
                    secrets
                        .private_key
                        .secret_keys
                        .insert(index, secret.secret_key);
                    secrets.secret_path.root_secret = secret.path_secret.clone();
                    secrets
                        .secret_path
                        .path_secrets
                        .insert(index, secret.path_secret);
                    Ok(secrets)
                },
            )?;

        self.apply_update_path(sender, update_path)?;

        // Verify the parent hash of the new sender leaf node and update the parent hash values
        // in the local tree
        self.update_parent_hashes(sender, Some(update_path))?;

        Ok(tree_secrets)
    }

    pub fn direct_path_keys(
        &self,
        index: LeafIndex,
    ) -> Result<Vec<Option<Vec<u8>>>, RatchetTreeError> {
        let indexes = self.nodes.direct_path(index)?;
        Ok(indexes
            .iter()
            .map(|&i| self.nodes[i].as_ref().map(|n| n.get_public_key().to_vec()))
            .collect())
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct UpdatePathNode {
    pub public_key: Vec<u8>,
    pub encrypted_path_secret: Vec<HpkeCiphertext>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct UpdatePath {
    pub leaf_key_package: KeyPackage,
    pub nodes: Vec<UpdatePathNode>,
}

#[cfg(test)]
pub(crate) mod test {
    use super::*;
    use crate::credential::BasicCredential;
    use crate::extension::{CapabilitiesExt, ExtensionList, ExtensionTrait, LifetimeExt};
    use crate::key_package::KeyPackageGenerator;
    use crate::tree_kem::node::{NodeTypeResolver, Parent};
    use crate::tree_kem::parent_hash::ParentHash;
    use ferriscrypt::asym::ec_key::Curve;

    pub fn get_test_key_package_sig_key(
        cipher_suite: CipherSuite,
        id: Vec<u8>,
        sig_key: &SecretKey,
    ) -> KeyPackageGeneration {
        let credential =
            Credential::Basic(BasicCredential::new(id, sig_key.to_public().unwrap()).unwrap());

        let extensions = vec![
            CapabilitiesExt::default().to_extension().unwrap(),
            LifetimeExt::years(1, SystemTime::now())
                .unwrap()
                .to_extension()
                .unwrap(),
        ];

        let key_package_gen = KeyPackageGenerator {
            cipher_suite,
            credential: &credential,
            extensions: ExtensionList(extensions),
            signing_key: &sig_key,
        };

        key_package_gen.generate().unwrap()
    }

    pub fn get_test_key_package(cipher_suite: CipherSuite, id: Vec<u8>) -> KeyPackageGeneration {
        let signing_key =
            SecretKey::generate(Curve::from(cipher_suite.signature_scheme())).unwrap();
        get_test_key_package_sig_key(cipher_suite, id, &signing_key)
    }

    pub fn get_invalid_key_package(cipher_suite: CipherSuite) -> KeyPackage {
        let mut key_package = get_test_key_package(cipher_suite, b"foo".to_vec()).key_package;
        key_package.signature = vec![];
        key_package
    }

    pub fn get_test_tree(cipher_suite: CipherSuite) -> (RatchetTree, TreeKemPrivate) {
        let test_key_package = get_test_key_package(cipher_suite, b"foo".to_vec());

        let test_tree = RatchetTree::derive(test_key_package.clone()).unwrap();
        assert_eq!(
            test_tree.0.nodes[0],
            Some(Node::Leaf(Leaf {
                key_package: test_key_package.key_package
            }))
        );

        assert_eq!(test_tree.1.self_index, LeafIndex(0));
        assert_eq!(
            test_tree.1.secret_keys.get(&0).unwrap().to_bytes().unwrap(),
            test_key_package.secret_key.to_bytes().unwrap()
        );
        test_tree
    }

    pub fn get_test_key_packages(cipher_suite: CipherSuite) -> Vec<KeyPackage> {
        [
            get_test_key_package(cipher_suite, b"A".to_vec()).key_package,
            get_test_key_package(cipher_suite, b"B".to_vec()).key_package,
            get_test_key_package(cipher_suite, b"C".to_vec()).key_package,
        ]
        .to_vec()
    }

    #[test]
    fn test_add_node_new_tree() {
        let cipher_suite = CipherSuite::Mls10128Dhkemx25519Aes128gcmSha256Ed25519;

        let mut tree = RatchetTree::new(cipher_suite);
        let key_packages = get_test_key_packages(cipher_suite);
        tree.add_nodes(key_packages.clone()).unwrap();

        assert_eq!(tree.nodes.len(), 5);
        assert_eq!(
            tree.nodes[0],
            Leaf {
                key_package: key_packages[0].clone(),
            }
            .into()
        );
        assert_eq!(tree.nodes[1], None);
        assert_eq!(
            tree.nodes[2],
            Leaf {
                key_package: key_packages[1].clone(),
            }
            .into()
        );
        assert_eq!(tree.nodes[3], None);
        assert_eq!(
            tree.nodes[4],
            Leaf {
                key_package: key_packages[2].clone(),
            }
            .into()
        );
    }

    #[test]
    fn test_add_node_empty_leaf() {
        let cipher_suite = CipherSuite::Mls10128Dhkemx25519Aes128gcmSha256Ed25519;

        let (mut tree, _) = get_test_tree(cipher_suite);
        let key_packages = get_test_key_packages(cipher_suite);

        tree.add_nodes([key_packages[0].clone()].to_vec()).unwrap();
        tree.nodes[0] = None; // Set the original first node to none
        tree.add_nodes([key_packages[1].clone()].to_vec()).unwrap();

        assert_eq!(tree.nodes[0], Leaf::from(key_packages[1].clone()).into());
        assert_eq!(tree.nodes[1], None);
        assert_eq!(tree.nodes[2], Leaf::from(key_packages[0].clone()).into());
        assert_eq!(tree.nodes.len(), 3)
    }

    #[test]
    fn test_add_node_unmerged() {
        let cipher_suite = CipherSuite::Mls10128Dhkemx25519Aes128gcmSha256Ed25519;

        let (mut tree, _) = get_test_tree(cipher_suite);

        let key_packages = get_test_key_packages(cipher_suite);

        tree.add_nodes([key_packages[0].clone(), key_packages[1].clone()].to_vec())
            .unwrap();

        tree.nodes[3] = Parent {
            public_key: vec![],
            parent_hash: ParentHash::empty(),
            unmerged_leaves: vec![],
        }
        .into();

        tree.add_nodes([key_packages[2].clone()].to_vec()).unwrap();

        assert_eq!(
            tree.nodes[3].as_parent().unwrap().unmerged_leaves,
            vec![LeafIndex(3)]
        )
    }

    #[test]
    fn test_add_node_bad_package() {
        let cipher_suite = CipherSuite::Mls10128Dhkemx25519Aes128gcmSha256Ed25519;

        let (mut tree, _) = get_test_tree(cipher_suite);
        let tree_clone = tree.clone();

        let mut key_packages = get_test_key_packages(cipher_suite);
        key_packages[0] = get_invalid_key_package(cipher_suite);

        let res = tree.add_nodes([key_packages[0].clone(), key_packages[1].clone()].to_vec());

        assert!(res.is_err());
        assert_eq!(tree, tree_clone);
    }

    #[test]
    fn test_update_leaf() {
        let cipher_suite = CipherSuite::Mls10128Dhkemx25519Aes128gcmSha256Ed25519;

        // Create a tree
        let (mut tree, _) = get_test_tree(cipher_suite);
        let key_packages = get_test_key_packages(cipher_suite);
        tree.add_nodes(key_packages).unwrap();

        // Add in parent nodes so we can detect them clearing after update
        tree.nodes
            .direct_path(LeafIndex(0))
            .unwrap()
            .iter()
            .for_each(|&i| {
                tree.nodes
                    .borrow_or_fill_node_as_parent(i, &b"pub_key".to_vec())
                    .unwrap();
            });

        let updated_leaf = get_test_key_package(cipher_suite, b"newpk".to_vec()).key_package;

        tree.update_leaf(LeafIndex(0), updated_leaf.clone())
            .unwrap();
        assert_eq!(
            tree.nodes.borrow_as_leaf(LeafIndex(0)).unwrap().key_package,
            updated_leaf
        );

        // Verify that the direct path has been cleared
        tree.nodes
            .direct_path(LeafIndex(0))
            .unwrap()
            .iter()
            .for_each(|&i| {
                assert!(tree.nodes[i].is_none());
            });
    }

    #[test]
    fn test_update_bad_leaf() {
        let cipher_suite = CipherSuite::Mls10128Dhkemx25519Aes128gcmSha256Ed25519;

        let (mut tree, _) = get_test_tree(cipher_suite);
        let bad_key_package = get_invalid_key_package(cipher_suite);

        let tree_clone = tree.clone();
        let res = tree.update_leaf(LeafIndex(0), bad_key_package);
        assert!(res.is_err());
        assert_eq!(tree, tree_clone);
    }

    // Verify that the tree is in the correct state after generating an update path
    fn verify_tree_update_path(tree: &RatchetTree, update_path: &UpdatePath, index: LeafIndex) {
        // Make sure the update path is based on the direct path of the sender
        let direct_path = tree.nodes.direct_path(index).unwrap();
        for (i, &dpi) in direct_path.iter().enumerate() {
            assert_eq!(
                tree.nodes[dpi].as_ref().unwrap().get_public_key(),
                update_path.nodes[i].public_key
            );
        }

        // Verify that the leaf from the update path has been installed
        assert_eq!(
            tree.find_leaf(&update_path.leaf_key_package).unwrap(),
            index
        );

        // Verify that we have a public keys up to the root
        assert!(tree.nodes[tree_math::root(tree.leaf_count())].is_some());
    }

    fn verify_tree_private_path(
        public_tree: &RatchetTree,
        private_tree: &TreeKemPrivate,
        index: LeafIndex,
    ) {
        assert_eq!(private_tree.self_index, index);
        // Make sure we have private values along the direct path, and the public keys match
        for one_index in public_tree.nodes.direct_path(index).unwrap() {
            let secret_key = private_tree.secret_keys.get(&one_index).unwrap();
            let public_key = public_tree.nodes[one_index]
                .as_ref()
                .unwrap()
                .get_public_key();
            assert_eq!(
                secret_key
                    .to_public()
                    .unwrap()
                    .to_uncompressed_bytes()
                    .unwrap(),
                public_key
            );
        }
    }

    fn encap_decap(cipher_suite: CipherSuite, size: usize) {
        // Generate signing keys and key package generations, and private keys for multiple
        // participants in order to set up state
        let signing_keys: Vec<SecretKey> = (0..size)
            .map(|_| SecretKey::generate(Curve::from(cipher_suite.signature_scheme())).unwrap())
            .collect();

        let key_package_generations: Vec<KeyPackageGeneration> = (0..size)
            .zip(signing_keys.iter())
            .map(|(index, sk)| {
                get_test_key_package_sig_key(cipher_suite, index.to_be_bytes().into(), sk)
            })
            .collect();

        let key_packages = key_package_generations
            .iter()
            .map(|kp| kp.key_package.clone())
            .collect();

        let private_keys: Vec<TreeKemPrivate> = key_package_generations
            .iter()
            .enumerate()
            .map(|(index, p)| TreeKemPrivate::new_self_leaf(LeafIndex(index), p.secret_key.clone()))
            .collect();

        // Build a test tree we can clone for all leaf nodes
        let mut test_tree = RatchetTree::new(cipher_suite);
        test_tree.add_nodes(key_packages).unwrap();

        // Clone the tree for the first leaf, generate a new key package for that leaf
        let mut encap_tree = test_tree.clone();

        // Perform the encap function
        let update_path_gen = encap_tree
            .encap(
                &private_keys[0],
                &signing_keys[0],
                &b"test_ctx".to_vec(),
                &[],
            )
            .unwrap();

        // Verify that the state of the tree matches the produced update path
        verify_tree_update_path(&encap_tree, &update_path_gen.update_path, LeafIndex(0));

        // Verify that the private key matches the data in the public key
        verify_tree_private_path(
            &encap_tree,
            &update_path_gen.secrets.private_key,
            LeafIndex(0),
        );

        // Apply the update path to the rest of the leaf nodes using the decap function
        let mut receiver_trees: Vec<RatchetTree> = (1..size).map(|_| test_tree.clone()).collect();

        for (i, tree) in receiver_trees.iter_mut().enumerate() {
            let secrets = tree
                .decap(
                    private_keys[i + 1].clone(),
                    LeafIndex(0),
                    &update_path_gen.update_path,
                    vec![],
                    &b"test_ctx".to_vec(),
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
        for one_cipher_suite in CipherSuite::all() {
            println!("Testing Tree KEM encap / decap for: {:?}", one_cipher_suite);
            encap_decap(one_cipher_suite, 10);
        }
    }

    #[test]
    fn test_encap_bad_cred() {
        let cipher_suite = CipherSuite::Mls10128Dhkemx25519Aes128gcmSha256Ed25519;

        let (mut tree, private_key) = get_test_tree(cipher_suite);
        tree.add_nodes(get_test_key_packages(cipher_suite)).unwrap();
        let tree_copy = tree.clone();

        let invalid_update_path = UpdatePathGeneration {
            update_path: UpdatePath {
                leaf_key_package: get_invalid_key_package(cipher_suite),
                nodes: vec![],
            },
            secrets: TreeSecrets {
                private_key: private_key.clone(),
                secret_path: Default::default(),
            },
        };

        let apply_res = tree.decap(
            private_key,
            LeafIndex(0),
            &invalid_update_path.update_path,
            vec![],
            &[],
        );

        assert!(apply_res.is_err());
        assert_eq!(tree, tree_copy);
    }

    #[test]
    fn test_private_key_update_leaf() {
        let cipher_suite = CipherSuite::Mls10128Dhkemx25519Aes128gcmSha256Ed25519;

        let signing_key =
            SecretKey::generate(Curve::from(cipher_suite.signature_scheme())).unwrap();
        let test_key_package =
            get_test_key_package_sig_key(cipher_suite, b"foo".to_vec(), &signing_key);
        let (mut tree, mut private_key) = RatchetTree::derive(test_key_package.clone()).unwrap();

        tree.add_nodes(get_test_key_packages(cipher_suite)).unwrap();

        // Insert private key values so we can determine the direct path was cleared
        tree.nodes
            .direct_path(private_key.self_index)
            .unwrap()
            .iter()
            .for_each(|&i| {
                private_key.secret_keys.insert(
                    i,
                    SecretKey::generate(cipher_suite.kem_type().curve()).unwrap(),
                );
            });

        // Update your own key package
        let key_package_generation =
            get_test_key_package_sig_key(cipher_suite, b"foo".to_vec(), &signing_key);

        private_key
            .update_leaf(tree.leaf_count(), key_package_generation.secret_key.clone())
            .unwrap();

        // Verify the secret key value was updated properly
        assert_eq!(private_key.self_index, LeafIndex(0));
        assert_eq!(
            private_key.secret_keys[&0].to_bytes().unwrap(),
            key_package_generation.secret_key.to_bytes().unwrap()
        );

        // Verify that the keys in the direct path were cleared
        tree.nodes
            .direct_path(private_key.self_index)
            .unwrap()
            .iter()
            .for_each(|i| {
                assert!(!private_key.secret_keys.contains_key(i));
            });
    }
}
