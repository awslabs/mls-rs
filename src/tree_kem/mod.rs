use std::collections::HashMap;
use std::time::SystemTime;

use ferriscrypt::asym::ec_key::{EcKeyError, SecretKey};
use ferriscrypt::hpke::kem::{HpkePublicKey, HpkeSecretKey};
use ferriscrypt::hpke::{HPKECiphertext, HpkeError};
use thiserror::Error;
use tls_codec::{Deserialize, Serialize};
use tls_codec_derive::{TlsDeserialize, TlsSerialize, TlsSize};

use math as tree_math;
use math::TreeMathError;
use node::{Leaf, LeafIndex, Node, NodeIndex, NodeVec, NodeVecError};
use node_secrets::{NodeSecretGenerator, NodeSecrets};

use crate::cipher_suite::{CipherSuite, HpkeCiphertext};
use crate::extension::{ExtensionError, ParentHashExt};
use crate::group::key_schedule::KeyScheduleKdfError;
use crate::key_package::{KeyPackage, KeyPackageError, KeyPackageGeneration, KeyPackageRef};
use crate::tree_kem::leaf_secret::{LeafSecret, LeafSecretError};
use crate::tree_kem::node_secrets::NodeSecretGeneratorError;
use crate::tree_kem::parent_hash::ParentHashError;

pub mod leaf_secret;
pub(crate) mod math;
pub mod node;
mod node_secrets;
pub mod parent_hash;
mod private;
mod tree_hash;

pub use self::private::TreeKemPrivate;

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
    LeafSecretError(#[from] LeafSecretError),
    #[error(transparent)]
    NodeSecretGeneratorError(#[from] NodeSecretGeneratorError),
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
    #[error("duplicate key packages found: {0:?}")]
    DuplicateKeyPackages(Vec<String>),
    #[error("key package not found: {0}")]
    KeyPackageNotFound(String),
}

#[derive(Clone, Debug, PartialEq, TlsDeserialize, TlsSerialize, TlsSize)]
pub struct TreeKemPublic {
    pub cipher_suite: CipherSuite,
    #[tls_codec(with = "crate::tls::DefMap")]
    key_package_index: HashMap<KeyPackageRef, LeafIndex>,
    nodes: NodeVec,
}

#[derive(Clone, Debug, Default, PartialEq, TlsDeserialize, TlsSerialize, TlsSize)]
pub struct SecretPath {
    #[tls_codec(with = "crate::tls::ByteVec::<u32>")]
    pub root_secret: Vec<u8>,
    #[tls_codec(with = "crate::tls::Map::<crate::tls::DefaultSer, crate::tls::ByteVec>")]
    path_secrets: HashMap<NodeIndex, Vec<u8>>,
}

impl SecretPath {
    pub fn get_path_secret(&self, index: NodeIndex) -> Option<Vec<u8>> {
        self.path_secrets.get(&index).cloned()
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

#[derive(Clone, Debug, TlsDeserialize, TlsSerialize, TlsSize)]
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

#[derive(Clone, Debug, TlsDeserialize, TlsSerialize, TlsSize)]
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

impl TreeKemPublic {
    pub fn new(cipher_suite: CipherSuite) -> TreeKemPublic {
        TreeKemPublic {
            cipher_suite,
            key_package_index: Default::default(),
            nodes: Default::default(),
        }
    }

    pub fn import_node_data(
        cipher_suite: CipherSuite,
        data: &[u8],
    ) -> Result<TreeKemPublic, RatchetTreeError> {
        let nodes = NodeVec::tls_deserialize(&mut &*data)?;

        let key_package_index = nodes
            .non_empty_leaves()
            .map(|(index, leaf)| Ok((leaf.key_package.to_reference()?, index)))
            .collect::<Result<HashMap<KeyPackageRef, LeafIndex>, RatchetTreeError>>()?;

        Ok(TreeKemPublic {
            cipher_suite,
            key_package_index,
            nodes,
        })
    }

    pub fn export_node_data(&self) -> Result<Vec<u8>, RatchetTreeError> {
        self.nodes.tls_serialize_detached().map_err(Into::into)
    }

    pub fn derive(
        key_package: KeyPackageGeneration,
    ) -> Result<(TreeKemPublic, TreeKemPrivate), RatchetTreeError> {
        let mut public_tree = TreeKemPublic::new(key_package.key_package.cipher_suite);

        let key_package_ref = key_package.key_package.to_reference()?;

        public_tree.add_leaves(vec![key_package.key_package])?;

        let private_tree =
            TreeKemPrivate::new_self_leaf(LeafIndex(0), key_package_ref, key_package.secret_key);

        Ok((public_tree, private_tree))
    }

    pub fn leaf_count(&self) -> u32 {
        self.nodes.leaf_count()
    }

    pub fn package_leaf_index(
        &self,
        key_package_ref: &KeyPackageRef,
    ) -> Result<LeafIndex, RatchetTreeError> {
        self.key_package_index
            .get(key_package_ref)
            .cloned()
            .ok_or_else(|| RatchetTreeError::KeyPackageNotFound(key_package_ref.to_string()))
    }

    pub fn get_key_package(
        &self,
        key_package_ref: &KeyPackageRef,
    ) -> Result<&KeyPackage, RatchetTreeError> {
        let index = self.package_leaf_index(key_package_ref)?;

        self.nodes
            .borrow_as_leaf(index)
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

    fn update_unmerged(&mut self, key_package_ref: &KeyPackageRef) -> Result<(), RatchetTreeError> {
        let index = self.package_leaf_index(key_package_ref)?;

        // For a given leaf index, find parent nodes and add the leaf to the unmerged leaf
        self.nodes.direct_path(index)?.iter().for_each(|&i| {
            if let Ok(p) = self.nodes.borrow_as_parent_mut(i) {
                p.unmerged_leaves.push(index)
            }
        });

        Ok(())
    }

    fn fill_empty_leaves(
        &mut self,
        key_packages: &[(KeyPackageRef, KeyPackage)],
    ) -> Vec<KeyPackageRef> {
        // Fill a set of empty leaves given a particular array, return the leaf indexes that were
        // overwritten
        self.nodes.empty_leaves().zip(key_packages.iter()).fold(
            Vec::new(),
            |mut indexs, ((index, empty_node), (package_ref, package))| {
                // See TODO in add_nodes, we have to clone here because we can't iterate the list
                // of packages to insert a single time
                *empty_node = Some(Node::from(Leaf::from(package.clone())));
                self.key_package_index.insert(package_ref.clone(), index);
                indexs.push(package_ref.clone());
                indexs
            },
        )
    }

    pub fn add_leaves(
        &mut self,
        key_packages: Vec<KeyPackage>,
    ) -> Result<Vec<KeyPackageRef>, RatchetTreeError> {
        // Validate the validity of the key signatures and lifetimes
        key_packages
            .iter()
            .try_for_each(|kp| kp.validate(SystemTime::now()))?;

        // Convert all the key packages into nodes
        let packages_to_insert = key_packages
            .into_iter()
            .map(|kp| {
                let reference = kp.to_reference()?;
                Ok((reference, kp))
            })
            .collect::<Result<Vec<(KeyPackageRef, KeyPackage)>, RatchetTreeError>>()?;

        // Determine if there are any duplicate entries in the existing tree
        let duplicate_kpr: Vec<KeyPackageRef> = packages_to_insert
            .iter()
            .filter(|(kp_ref, _)| self.key_package_index.contains_key(kp_ref))
            .map(|(kp_ref, _)| kp_ref.clone())
            .collect();

        if !duplicate_kpr.is_empty() {
            return Err(RatchetTreeError::DuplicateKeyPackages(
                duplicate_kpr
                    .into_iter()
                    .map(|kpr| kpr.to_string())
                    .collect(),
            ));
        }

        // Fill empty leaves first, then add the remaining nodes by extending
        // the tree to the right

        // TODO: Find a way to predetermine a single list of nodes to fill by pre-populating new
        // empty nodes and iterating through a chain of empty leaves + new leaves
        let mut added_leaf_indexs = self.fill_empty_leaves(&packages_to_insert);

        packages_to_insert
            .into_iter()
            .skip(added_leaf_indexs.len())
            .for_each(|(package_ref, package)| {
                if !self.nodes.is_empty() {
                    self.nodes.push(None);
                }

                self.nodes.push(Some(Node::from(Leaf::from(package))));

                let index = LeafIndex(self.nodes.len() as u32 / 2);
                self.key_package_index.insert(package_ref.clone(), index);
                added_leaf_indexs.push(package_ref);
            });

        added_leaf_indexs
            .iter()
            .try_for_each(|kpr| self.update_unmerged(kpr))?;

        Ok(added_leaf_indexs)
    }

    // Remove a node given a lookup tree. The lookup tree aids with situations where the reference
    // you are removing might have changed via an update that was applied before calling this
    // function. Removes must be based on an initial state before updates are applied.
    pub fn remove_leaves(
        &mut self,
        lookup_tree: &TreeKemPublic,
        key_package_refs: Vec<KeyPackageRef>,
    ) -> Result<Vec<(KeyPackageRef, KeyPackage)>, RatchetTreeError> {
        // Identify a leaf node containing a key package matching removed.
        // This lookup MUST be done on the tree before any non-Remove proposals have been applied

        let indexes = key_package_refs
            .iter()
            .map(|reference| lookup_tree.package_leaf_index(reference))
            .collect::<Result<Vec<LeafIndex>, RatchetTreeError>>()?;

        let removed_leaves = indexes.iter().zip(key_package_refs).try_fold(
            Vec::new(),
            |mut vec, (index, package_ref)| {
                // Replace the leaf node at position removed with a blank node
                if let Some(removed) = self.nodes.blank_leaf_node(*index)? {
                    self.key_package_index.remove(&package_ref);
                    vec.push((package_ref.clone(), removed.key_package));
                }

                // Blank the intermediate nodes along the path from the removed leaf to the root
                self.nodes.blank_direct_path(*index)?;

                Ok::<_, RatchetTreeError>(vec)
            },
        )?;

        // Truncate the tree by reducing the size of tree until the rightmost non-blank leaf node
        self.nodes.trim();

        Ok(removed_leaves)
    }

    pub fn update_leaf(
        &mut self,
        package_ref: &KeyPackageRef,
        key_package: KeyPackage,
    ) -> Result<(), RatchetTreeError> {
        // Validate the validity of the key signature
        key_package.validate(SystemTime::now())?;

        // Determine if this key package is unique
        let new_key_package_ref = key_package.to_reference()?;

        if self.package_leaf_index(&new_key_package_ref).is_ok() {
            return Err(RatchetTreeError::DuplicateKeyPackages(vec![
                new_key_package_ref.to_string(),
            ]));
        }

        // Update the leaf node
        let leaf_index = self.package_leaf_index(package_ref)?;
        self.nodes.borrow_as_leaf_mut(leaf_index)?.key_package = key_package;

        // Update the cache
        self.key_package_index.remove(package_ref);
        self.key_package_index
            .insert(new_key_package_ref, leaf_index);

        // Blank the intermediate nodes along the path from the sender's leaf to the root
        self.nodes
            .blank_direct_path(leaf_index)
            .map(|_| ())
            .map_err(RatchetTreeError::from)
    }

    pub fn get_key_packages(&self) -> Vec<&KeyPackage> {
        self.nodes
            .non_empty_leaves()
            .map(|(_, l)| &l.key_package)
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
                        copath_node.public_key(),
                        context,
                        None,
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

    // TODO: Make UpdatePathGeneration not return a private key to simplify this function
    pub fn encap(
        &mut self,
        private_key: &TreeKemPrivate,
        signer: &SecretKey,
        context: &[u8],
        excluding: &[KeyPackageRef],
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

        let excluding: Vec<LeafIndex> = excluding
            .iter()
            .flat_map(|kpr| self.package_leaf_index(kpr))
            .collect();

        // Generate all the new path secrets and encrypt them to their copath node resolutions
        let (node_secrets, node_updates): (Vec<IndexedNodeSecrets>, Vec<UpdatePathNode>) =
            secret_generator
                .zip(
                    self.nodes
                        .direct_path_copath_resolution(private_key.self_index, &excluding)?,
                )
                .map(|(path_secret, (index, copath_nodes))| {
                    self.encrypt_copath_node_resolution(&path_secret?, index, copath_nodes, context)
                })
                .try_fold(
                    (Vec::new(), Vec::new()),
                    |(mut secrets, mut updates), resolution| {
                        let (secret, update) = resolution?;
                        secrets.push(secret);
                        updates.push(update);
                        Ok::<_, RatchetTreeError>((secrets, updates))
                    },
                )?;

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

        let key_package_ref = leaf.key_package.to_reference()?;

        // Update the key package index with the new reference value
        self.key_package_index.remove(&private_key.key_package_ref);
        self.key_package_index
            .insert(key_package_ref.clone(), private_key.self_index);

        // Update the private key with the new reference value
        private_key.key_package_ref = key_package_ref;

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
                    .open_base(&HPKECiphertext::from(ct.clone()), sk, context, None)
                    .map_err(Into::into)
            })
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
        original_key_package_ref: &KeyPackageRef,
    ) -> Result<(), RatchetTreeError> {
        let sender = update_path_generation.secrets.private_key.self_index;
        self.apply_update_path(sender, &update_path_generation.update_path)?;

        self.key_package_index.remove(original_key_package_ref);

        self.key_package_index.insert(
            update_path_generation
                .secrets
                .private_key
                .key_package_ref
                .clone(),
            sender,
        );
        // Verify the parent hash of the new sender leaf node and update the parent hash values
        // in the local tree
        self.update_parent_hashes(sender, Some(&update_path_generation.update_path))?;

        Ok(())
    }

    pub fn decap(
        &mut self,
        private_key: TreeKemPrivate,
        sender: &KeyPackageRef,
        update_path: &UpdatePath,
        added_leaves: &[KeyPackageRef],
        context: &[u8],
    ) -> Result<TreeSecrets, RatchetTreeError> {
        // Verify the signature on the key package
        update_path.leaf_key_package.validate(SystemTime::now())?;

        let sender_index = self.package_leaf_index(sender)?;

        // Exclude newly added leaf indexes
        let excluding = added_leaves
            .iter()
            .flat_map(|kpr| self.package_leaf_index(kpr).map(Into::into))
            .collect::<Vec<NodeIndex>>();

        // Find the least common ancestor shared by us and the sender
        let lca =
            tree_math::common_ancestor_direct(private_key.self_index.into(), sender_index.into());

        let sender_direct = self.nodes.direct_path(sender_index)?;
        let sender_co = self.nodes.copath(sender_index)?;

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
            .zip(
                // Get a pairing of direct path index + associated update
                // This will help us verify that the calculated public key is the expected one
                self.nodes
                    .direct_path(sender_index)?
                    .iter()
                    .zip(update_path.nodes.iter())
                    .skip_while(|(dp, _)| **dp != lca),
            )
            .try_fold(
                TreeSecrets::new(private_key),
                |mut secrets, (secret, (&index, update))| {
                    let secret = secret?;
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

        self.apply_update_path(sender_index, update_path)?;

        self.key_package_index.remove(sender);
        self.key_package_index
            .insert(update_path.leaf_key_package.to_reference()?, sender_index);

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

#[derive(Clone, Debug, PartialEq, TlsDeserialize, TlsSerialize, TlsSize)]
pub struct UpdatePathNode {
    #[tls_codec(with = "crate::tls::ByteVec::<u32>")]
    pub public_key: HpkePublicKey,
    #[tls_codec(with = "crate::tls::DefVec::<u32>")]
    pub encrypted_path_secret: Vec<HpkeCiphertext>,
}

#[derive(Clone, Debug, PartialEq, TlsDeserialize, TlsSerialize, TlsSize)]
pub struct UpdatePath {
    pub leaf_key_package: KeyPackage,
    #[tls_codec(with = "crate::tls::DefVec::<u32>")]
    pub nodes: Vec<UpdatePathNode>,
}

#[cfg(test)]
pub(crate) mod test {
    use ferriscrypt::asym::ec_key::Curve;

    use crate::credential::{BasicCredential, Credential};
    use crate::extension::{CapabilitiesExt, ExtensionList, LifetimeExt, MlsExtension};
    use crate::key_package::KeyPackageGenerator;
    use crate::tree_kem::node::{NodeTypeResolver, Parent};
    use crate::tree_kem::parent_hash::ParentHash;

    use super::*;

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
            extensions: ExtensionList::from(extensions),
            signing_key: sig_key,
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

    pub fn get_test_tree(
        cipher_suite: CipherSuite,
    ) -> (TreeKemPublic, TreeKemPrivate, KeyPackageGeneration) {
        let test_key_package = get_test_key_package(cipher_suite, b"foo".to_vec());

        let (test_public, test_private) = TreeKemPublic::derive(test_key_package.clone()).unwrap();
        assert_eq!(
            test_public.nodes[0],
            Some(Node::Leaf(Leaf {
                key_package: test_key_package.key_package.clone()
            }))
        );

        assert_eq!(test_private.self_index, LeafIndex(0));
        assert_eq!(
            test_private.key_package_ref,
            test_key_package.key_package.to_reference().unwrap()
        );
        assert_eq!(test_private.secret_keys[&0], test_key_package.secret_key);

        (test_public, test_private, test_key_package)
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
    fn test_import_export() {
        let cipher_suite = CipherSuite::Mls10128Dhkemp256Aes128gcmSha256P256;
        let (mut test_tree, _, _) = get_test_tree(cipher_suite);

        let additional_key_packages = get_test_key_packages(cipher_suite);

        test_tree.add_leaves(additional_key_packages).unwrap();

        let exported = test_tree.export_node_data().unwrap();
        let imported = TreeKemPublic::import_node_data(cipher_suite, &exported).unwrap();

        assert_eq!(test_tree, imported);
    }

    #[test]
    fn test_add_leaf() {
        let cipher_suite = CipherSuite::Mls10128Dhkemx25519Aes128gcmSha256Ed25519;

        let mut tree = TreeKemPublic::new(cipher_suite);

        let key_packages = get_test_key_packages(cipher_suite);
        let res = tree.add_leaves(key_packages.clone()).unwrap();

        // The result of adding a node should be all the references that were added
        assert_eq!(
            res,
            key_packages
                .iter()
                .map(|kp| kp.to_reference().unwrap())
                .collect::<Vec<KeyPackageRef>>()
        );

        // The leaf count should be equal to the number of packages we added
        assert_eq!(tree.leaf_count(), key_packages.len() as u32);

        // Each added package should be at the proper index and searchable in the tree
        res.iter()
            .zip(key_packages.clone())
            .enumerate()
            .for_each(|(index, (r, kp))| {
                assert_eq!(tree.get_key_package(r).unwrap(), &kp);
                assert_eq!(tree.package_leaf_index(r).unwrap(), LeafIndex(index as u32));
            });

        // Verify the underlying state

        assert_eq!(tree.key_package_index.len(), tree.leaf_count() as usize);

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
    fn test_get_key_packages() {
        let cipher_suite = CipherSuite::Mls10128Dhkemx25519Aes128gcmSha256Ed25519;

        let mut tree = TreeKemPublic::new(cipher_suite);

        let key_packages = get_test_key_packages(cipher_suite);
        tree.add_leaves(key_packages).unwrap();

        let key_packages = tree.get_key_packages();
        assert_eq!(key_packages, key_packages.to_owned());
    }

    #[test]
    fn test_find_leaf() {
        let cipher_suite = CipherSuite::Mls10256Dhkemp521Aes256gcmSha512P521;

        let mut tree = TreeKemPublic::new(cipher_suite);

        let key_packages = get_test_key_packages(cipher_suite);

        tree.add_leaves(key_packages.clone()).unwrap();

        for (index, key_package_generation) in key_packages.iter().enumerate() {
            let key_package_index = tree
                .package_leaf_index(&key_package_generation.to_reference().unwrap())
                .unwrap();
            assert_eq!(key_package_index, LeafIndex(index as u32));
        }
    }

    #[test]
    fn test_add_leaf_duplicate() {
        let cipher_suite = CipherSuite::Mls10256Dhkemp521Aes256gcmSha512P521;

        let mut tree = TreeKemPublic::new(cipher_suite);

        let key_packages = get_test_key_packages(cipher_suite);
        tree.add_leaves(key_packages.clone()).unwrap();

        let add_res = tree.add_leaves(key_packages);

        assert!(matches!(
            add_res,
            Err(RatchetTreeError::DuplicateKeyPackages(_))
        ));
    }

    #[test]
    fn test_add_leaf_empty_leaf() {
        let cipher_suite = CipherSuite::Mls10128Dhkemx25519Aes128gcmSha256Ed25519;

        let (mut tree, _, _) = get_test_tree(cipher_suite);
        let key_packages = get_test_key_packages(cipher_suite);

        tree.add_leaves([key_packages[0].clone()].to_vec()).unwrap();
        tree.nodes[0] = None; // Set the original first node to none
        tree.add_leaves([key_packages[1].clone()].to_vec()).unwrap();

        assert_eq!(tree.nodes[0], Leaf::from(key_packages[1].clone()).into());
        assert_eq!(tree.nodes[1], None);
        assert_eq!(tree.nodes[2], Leaf::from(key_packages[0].clone()).into());
        assert_eq!(tree.nodes.len(), 3)
    }

    #[test]
    fn test_add_leaf_unmerged() {
        let cipher_suite = CipherSuite::Mls10128Dhkemx25519Aes128gcmSha256Ed25519;

        let (mut tree, _, _) = get_test_tree(cipher_suite);

        let key_packages = get_test_key_packages(cipher_suite);

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
    fn test_add_node_bad_package() {
        let cipher_suite = CipherSuite::Mls10128Dhkemx25519Aes128gcmSha256Ed25519;

        let (mut tree, _, _) = get_test_tree(cipher_suite);
        let tree_clone = tree.clone();

        let mut key_packages = get_test_key_packages(cipher_suite);
        key_packages[0] = get_invalid_key_package(cipher_suite);

        let res = tree.add_leaves([key_packages[0].clone(), key_packages[1].clone()].to_vec());

        assert!(res.is_err());
        assert_eq!(tree, tree_clone);
    }

    #[test]
    fn test_update_leaf() {
        let cipher_suite = CipherSuite::Mls10128Dhkemx25519Aes128gcmSha256Ed25519;

        // Create a tree
        let (mut tree, _, _) = get_test_tree(cipher_suite);
        let key_packages = get_test_key_packages(cipher_suite);
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

        let original_size = tree.leaf_count();
        let original_package_ref = key_packages[0].to_reference().unwrap();
        let original_leaf_index = tree.package_leaf_index(&original_package_ref).unwrap();

        let updated_leaf = get_test_key_package(cipher_suite, b"newpk".to_vec()).key_package;
        let updated_key_ref = updated_leaf.to_reference().unwrap();

        tree.update_leaf(&original_package_ref, updated_leaf.clone())
            .unwrap();

        // The tree should not have grown due to an update
        assert_eq!(tree.leaf_count(), original_size);

        // The leaf should not have moved due to an update
        assert_eq!(
            tree.package_leaf_index(&updated_key_ref).unwrap(),
            original_leaf_index
        );

        // The cache of tree package indexs should not have grown
        assert_eq!(tree.key_package_index.len() as u32, tree.leaf_count());

        // The key package should be updated in the tree
        assert_eq!(
            tree.get_key_package(&updated_key_ref).unwrap(),
            &updated_leaf
        );

        // There should be an error when looking for the original key package ref
        assert!(matches!(
            tree.get_key_package(&original_package_ref),
            Err(RatchetTreeError::KeyPackageNotFound(_))
        ));
        assert!(matches!(
            tree.package_leaf_index(&original_package_ref),
            Err(RatchetTreeError::KeyPackageNotFound(_))
        ));

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
    fn test_update_leaf_bad_leaf() {
        let cipher_suite = CipherSuite::Mls10128Dhkemx25519Aes128gcmSha256Ed25519;

        let (mut tree, _, key_package_generation) = get_test_tree(cipher_suite);
        let bad_key_package = get_invalid_key_package(cipher_suite);

        let tree_clone = tree.clone();
        let res = tree.update_leaf(
            &key_package_generation.key_package.to_reference().unwrap(),
            bad_key_package,
        );
        assert!(res.is_err());
        assert_eq!(tree, tree_clone);
    }

    #[test]
    fn test_update_leaf_not_found() {
        let cipher_suite = CipherSuite::Mls10128Dhkemx25519Aes128gcmSha256Ed25519;

        // Create a tree
        let (mut tree, _, _) = get_test_tree(cipher_suite);
        let key_packages = get_test_key_packages(cipher_suite);
        tree.add_leaves(key_packages).unwrap();

        let new_key_package = get_test_key_package(cipher_suite, b"new".to_vec());

        assert!(matches!(
            tree.update_leaf(&KeyPackageRef::from([0u8; 16]), new_key_package.key_package),
            Err(RatchetTreeError::KeyPackageNotFound(_))
        ));
    }

    #[test]
    fn test_update_leaf_duplicate() {
        let cipher_suite = CipherSuite::Mls10128Dhkemx25519Aes128gcmSha256Ed25519;

        // Create a tree
        let (mut tree, _, _) = get_test_tree(cipher_suite);
        let key_packages = get_test_key_packages(cipher_suite);
        tree.add_leaves(key_packages.clone()).unwrap();

        let duplicate_key_package = key_packages[1].clone();
        let key_package_ref = key_packages[0].to_reference().unwrap();

        assert!(matches!(
            tree.update_leaf(&key_package_ref, duplicate_key_package),
            Err(RatchetTreeError::DuplicateKeyPackages(_))
        ));
    }

    #[test]
    fn test_remove_leaf() {
        let cipher_suite = CipherSuite::Mls10128Dhkemx25519Aes128gcmSha256Ed25519;

        // Create a tree
        let (mut tree, _, _) = get_test_tree(cipher_suite);
        let key_packages = get_test_key_packages(cipher_suite);
        tree.add_leaves(key_packages.clone()).unwrap();

        let original_leaf_count = tree.leaf_count();

        let to_remove = vec![
            key_packages[1].to_reference().unwrap(),
            key_packages[2].to_reference().unwrap(),
        ];

        // Remove two leaves from the tree
        let res = tree
            .remove_leaves(&tree.clone(), to_remove.clone())
            .unwrap();

        let expected_result: Vec<(KeyPackageRef, KeyPackage)> = to_remove
            .clone()
            .into_iter()
            .zip(key_packages[1..].to_owned())
            .collect();

        assert_eq!(res, expected_result);

        // The leaf count should have been reduced by 2
        assert_eq!(tree.leaf_count(), original_leaf_count - 2);

        // We should no longer be able to find the removed leaves
        for key_package_ref in to_remove {
            assert!(matches!(
                tree.get_key_package(&key_package_ref),
                Err(RatchetTreeError::KeyPackageNotFound(_))
            ));

            assert!(matches!(
                tree.package_leaf_index(&key_package_ref),
                Err(RatchetTreeError::KeyPackageNotFound(_))
            ));
        }
    }

    #[test]
    fn test_remove_leaf_failure() {
        let cipher_suite = CipherSuite::Mls10128Dhkemx25519Aes128gcmSha256Ed25519;

        // Create a tree
        let (mut tree, _, _) = get_test_tree(cipher_suite);

        assert!(matches!(
            tree.remove_leaves(&tree.clone(), vec![KeyPackageRef::from([0u8; 16])]),
            Err(RatchetTreeError::KeyPackageNotFound(_))
        ));
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
            tree.package_leaf_index(&update_path.leaf_key_package.to_reference().unwrap())
                .unwrap(),
            index
        );

        // Verify that we have a public keys up to the root
        assert!(tree.nodes[tree_math::root(tree.leaf_count()) as usize].is_some());
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
            .map(|(index, p)| {
                TreeKemPrivate::new_self_leaf(
                    LeafIndex(index as u32),
                    p.key_package.to_reference().unwrap(),
                    p.secret_key.clone(),
                )
            })
            .collect();

        // Build a test tree we can clone for all leaf nodes
        let mut test_tree = TreeKemPublic::new(cipher_suite);
        test_tree.add_leaves(key_packages).unwrap();

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
            &cipher_suite,
            &encap_tree,
            &update_path_gen.secrets.private_key,
            LeafIndex(0),
        );

        // Apply the update path to the rest of the leaf nodes using the decap function
        let mut receiver_trees: Vec<TreeKemPublic> = (1..size).map(|_| test_tree.clone()).collect();

        for (i, tree) in receiver_trees.iter_mut().enumerate() {
            let secrets = tree
                .decap(
                    private_keys[i + 1].clone(),
                    &key_package_generations[0]
                        .key_package
                        .to_reference()
                        .unwrap(),
                    &update_path_gen.update_path,
                    &[],
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

        let (mut tree, private_key, key_package_generation) = get_test_tree(cipher_suite);
        tree.add_leaves(get_test_key_packages(cipher_suite))
            .unwrap();
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
            &key_package_generation.key_package.to_reference().unwrap(),
            &invalid_update_path.update_path,
            &[],
            &[],
        );

        assert!(apply_res.is_err());
        assert_eq!(tree, tree_copy);
    }
}
