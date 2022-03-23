use std::collections::HashMap;

use ferriscrypt::asym::ec_key::EcKeyError;
use ferriscrypt::hpke::kem::{HpkePublicKey, HpkeSecretKey};
use ferriscrypt::hpke::{HPKECiphertext, HpkeError};

use thiserror::Error;
use tls_codec_derive::{TlsDeserialize, TlsSerialize, TlsSize};

use math as tree_math;
use math::TreeMathError;
use node::{Leaf, LeafIndex, Node, NodeIndex, NodeVec, NodeVecError};

use crate::cipher_suite::{CipherSuite, HpkeCiphertext};
use crate::extension::{ExtensionError, ParentHashExt};
use crate::group::key_schedule::KeyScheduleKdfError;
use crate::key_package::{
    KeyPackage, KeyPackageError, KeyPackageGeneration, KeyPackageGenerationError, KeyPackageRef,
    KeyPackageValidationError, KeyPackageValidator, ValidatedKeyPackage,
};
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
    #[error("key package not found: {0}")]
    KeyPackageNotFound(String),
}

#[derive(Clone, Debug, PartialEq)]
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
                tree_index.insert(
                    leaf.key_package.to_reference()?,
                    leaf_index,
                    &leaf.key_package,
                )?;

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
        key_package_generation: KeyPackageGeneration,
    ) -> Result<(TreeKemPublic, TreeKemPrivate), RatchetTreeError> {
        let mut public_tree = TreeKemPublic::new(key_package_generation.key_package.cipher_suite);

        let key_package_ref = key_package_generation.key_package.to_reference()?;

        public_tree.add_leaves(vec![key_package_generation.key_package])?;

        let private_tree = TreeKemPrivate::new_self_leaf(
            LeafIndex(0),
            key_package_ref,
            key_package_generation.secret_key,
        );

        Ok((public_tree, private_tree))
    }

    pub fn total_leaf_count(&self) -> u32 {
        self.nodes.total_leaf_count()
    }

    pub fn occupied_leaf_count(&self) -> u32 {
        self.nodes.occupied_leaf_count()
    }

    pub fn package_leaf_index(
        &self,
        key_package_ref: &KeyPackageRef,
    ) -> Result<LeafIndex, RatchetTreeError> {
        self.index
            .get_key_package_index(key_package_ref)
            .ok_or_else(|| RatchetTreeError::KeyPackageNotFound(key_package_ref.to_string()))
    }

    pub fn get_key_package(
        &self,
        key_package_ref: &KeyPackageRef,
    ) -> Result<&KeyPackage, RatchetTreeError> {
        self.get_validated_key_package(key_package_ref)
            .map(|p| &**p)
    }

    pub fn get_validated_key_package(
        &self,
        key_package_ref: &KeyPackageRef,
    ) -> Result<&ValidatedKeyPackage, RatchetTreeError> {
        let index = self.package_leaf_index(key_package_ref)?;

        self.nodes
            .borrow_as_leaf(index)
            .map(|l| &l.key_package)
            .map_err(|e| e.into())
    }

    fn update_unmerged(&mut self, key_package_ref: &KeyPackageRef) -> Result<(), RatchetTreeError> {
        let index = self.package_leaf_index(key_package_ref)?;

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
        key_packages: &[(KeyPackageRef, ValidatedKeyPackage)],
    ) -> Result<Vec<KeyPackageRef>, RatchetTreeError> {
        // Fill a set of empty leaves given a particular array, return the leaf indexes that were
        // overwritten
        self.nodes.empty_leaves().zip(key_packages.iter()).try_fold(
            Vec::new(),
            |mut indexs, ((index, empty_node), (package_ref, package))| {
                // See TODO in add_nodes, we have to clone here because we can't iterate the list
                // of packages to insert a single time
                *empty_node = Some(Node::from(Leaf::from(package.clone())));
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
        key_packages: Vec<ValidatedKeyPackage>,
    ) -> Result<Vec<KeyPackageRef>, RatchetTreeError> {
        // Get key package references for all packages we are going to insert
        let packages_to_insert = key_packages
            .into_iter()
            .map(|kp| {
                let reference = kp.to_reference()?;
                Ok((reference, kp))
            })
            .collect::<Result<Vec<(KeyPackageRef, ValidatedKeyPackage)>, RatchetTreeError>>()?;

        // Fill empty leaves first, then add the remaining nodes by extending
        // the tree to the right

        // TODO: Find a way to predetermine a single list of nodes to fill by pre-populating new
        // empty nodes and iterating through a chain of empty leaves + new leaves
        let mut added_leaf_indexs = self.fill_empty_leaves(&packages_to_insert)?;

        packages_to_insert
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

        let removed_leaves = indexes.into_iter().zip(key_package_refs).try_fold(
            Vec::new(),
            |mut vec, (index, package_ref)| {
                // Replace the leaf node at position removed with a blank node
                if let Some(removed) = self.nodes.blank_leaf_node(index)? {
                    self.index.remove(&package_ref, &removed.key_package)?;
                    vec.push((package_ref.clone(), removed.key_package.into()));
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
        package_ref: &KeyPackageRef,
        key_package: ValidatedKeyPackage,
    ) -> Result<(), RatchetTreeError> {
        // Determine if this key package is unique
        let new_key_package_ref = key_package.to_reference()?;

        // Update the leaf node
        let leaf_index = self.package_leaf_index(package_ref)?;
        let existing_leaf = self.nodes.borrow_as_leaf_mut(leaf_index)?;

        // Update the cache
        self.index.remove(package_ref, &existing_leaf.key_package)?;

        self.index
            .insert(new_key_package_ref, leaf_index, &key_package)?;

        existing_leaf.key_package = key_package;

        // Blank the intermediate nodes along the path from the sender's leaf to the root
        self.nodes
            .blank_direct_path(leaf_index)
            .map(|_| ())
            .map_err(RatchetTreeError::from)
    }

    pub fn get_key_packages(&self) -> Vec<&KeyPackage> {
        self.nodes
            .non_empty_leaves()
            .map(|(_, l)| &*l.key_package)
            .collect()
    }

    pub(crate) fn get_key_package_refs(&self) -> impl Iterator<Item = &'_ KeyPackageRef> {
        self.index.key_package_refs()
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
                    .seal_base(
                        copath_node.public_key(),
                        context,
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
    pub fn encap<E: Into<RatchetTreeError>>(
        &mut self,
        private_key: &TreeKemPrivate,
        key_package_generation: KeyPackageGeneration,
        context: &[u8],
        excluding: &[KeyPackageRef],
        mut package_resign: impl FnMut(&mut ValidatedKeyPackage) -> Result<(), E>,
    ) -> Result<UpdatePathGeneration, RatchetTreeError> {
        let secret_generator = PathSecretGenerator::new(self.cipher_suite);

        let excluding: Vec<LeafIndex> = excluding
            .iter()
            .flat_map(|kpr| self.package_leaf_index(kpr))
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

        let mut private_key = private_key.clone();

        private_key.secret_keys.insert(
            NodeIndex::from(private_key.self_index),
            key_package_generation.secret_key,
        );

        for (index, path_secret) in &node_secrets {
            private_key
                .secret_keys
                .insert(*index, path_secret.to_hpke_key_pair()?.0);
        }

        let root_secret = node_secrets
            .get(&tree_math::root(self.nodes.total_leaf_count()))
            .cloned()
            .map(Ok)
            .unwrap_or_else(|| PathSecretGeneration::random(self.cipher_suite))?
            .path_secret;

        let secret_path = SecretPath {
            path_secrets: node_secrets
                .into_iter()
                .map(|(index, ps)| (index, ps.path_secret))
                .collect(),
            root_secret,
        };

        let update_path = ValidatedUpdatePath {
            leaf_key_package: key_package_generation.key_package,
            nodes: node_updates,
        };

        // Apply the new update path to the tree
        let old_key_package = self.apply_update_path(private_key.self_index, &update_path)?;

        // Apply the parent hash updates to the tree
        let leaf_parent_hash = self.update_parent_hashes(private_key.self_index, None)?;

        // Update the leaf in the tree by applying the parent hash and signing the package
        let own_leaf = self.nodes.borrow_as_leaf_mut(private_key.self_index)?;

        own_leaf
            .key_package
            .extensions
            .set_extension(ParentHashExt::from(leaf_parent_hash))?;

        package_resign(&mut own_leaf.key_package).map_err(Into::into)?;

        let key_package_ref = own_leaf.key_package.to_reference()?;

        // Update the key package index with the new reference value
        self.index
            .remove(&private_key.key_package_ref, &old_key_package)?;

        self.index.insert(
            key_package_ref.clone(),
            private_key.self_index,
            &own_leaf.key_package,
        )?;

        // Update the private key with the new reference value
        private_key.key_package_ref = key_package_ref;

        // Overwrite the key package in the update path with the signed version
        let update_path = UpdatePath {
            leaf_key_package: own_leaf.key_package.clone().into(),
            nodes: update_path.nodes,
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
                    .open_base(&HPKECiphertext::from(ct.clone()), sk, context, None)
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
    ) -> Result<ValidatedKeyPackage, RatchetTreeError> {
        // Install the new leaf node
        let mut existing_leaf = self.nodes.borrow_as_leaf_mut(sender)?;
        let existing_key_package = existing_leaf.key_package.clone();

        existing_leaf.key_package = update_path.leaf_key_package.clone();

        // Update the rest of the nodes on the direct path
        update_path
            .nodes
            .iter()
            .zip(self.nodes.filtered_direct_path(sender)?)
            .try_for_each(|(one_node, node_index)| {
                self.update_node(one_node.public_key.clone(), node_index)
            })?;

        Ok(existing_key_package)
    }

    pub fn apply_self_update(
        &mut self,
        update_path: &ValidatedUpdatePath,
        original_key_package_ref: &KeyPackageRef,
    ) -> Result<(), RatchetTreeError> {
        let sender = self.package_leaf_index(original_key_package_ref)?;
        let existing_key_package = self.apply_update_path(sender, update_path)?;

        self.index
            .remove(original_key_package_ref, &existing_key_package)?;

        self.index.insert(
            update_path.leaf_key_package.to_reference()?,
            sender,
            &update_path.leaf_key_package,
        )?;

        // Verify the parent hash of the new sender leaf node and update the parent hash values
        // in the local tree
        self.update_parent_hashes(sender, Some(update_path))?;

        Ok(())
    }

    pub fn decap(
        &mut self,
        private_key: TreeKemPrivate,
        sender: &KeyPackageRef,
        update_path: &ValidatedUpdatePath,
        added_leaves: &[KeyPackageRef],
        context: &[u8],
    ) -> Result<TreeSecrets, RatchetTreeError> {
        let sender_index = self.package_leaf_index(sender)?;

        // Exclude newly added leaf indexes
        let excluding = added_leaves
            .iter()
            .flat_map(|kpr| self.package_leaf_index(kpr).map(Into::into))
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
            update_path.leaf_key_package.to_reference()?,
            sender_index,
            &update_path.leaf_key_package,
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
pub(crate) mod test {
    use assert_matches::assert_matches;
    use ferriscrypt::asym::ec_key::{Curve, SecretKey};

    use crate::credential::{BasicCredential, Credential};
    use crate::extension::{CapabilitiesExt, ExtensionList, LifetimeExt, MlsExtension};
    use crate::key_package::{KeyPackageGeneration, KeyPackageGenerator};
    use crate::tree_kem::node::{NodeTypeResolver, Parent};
    use crate::tree_kem::parent_hash::ParentHash;
    use crate::ProtocolVersion;

    use super::*;

    #[cfg(target_arch = "wasm32")]
    use wasm_bindgen_test::{wasm_bindgen_test as test, wasm_bindgen_test_configure};

    #[cfg(target_arch = "wasm32")]
    wasm_bindgen_test_configure!(run_in_browser);

    pub fn get_test_key_package_sig_key(
        protocol_version: ProtocolVersion,
        cipher_suite: CipherSuite,
        id: Vec<u8>,
        sig_key: &SecretKey,
    ) -> KeyPackageGeneration {
        let credential =
            Credential::Basic(BasicCredential::new(id, sig_key.to_public().unwrap()).unwrap());

        let extensions = vec![
            CapabilitiesExt::default().to_extension().unwrap(),
            LifetimeExt::years(1).unwrap().to_extension().unwrap(),
        ];

        let key_package_gen = KeyPackageGenerator {
            protocol_version,
            cipher_suite,
            signing_key: sig_key,
            credential: &credential,
            extensions: &ExtensionList::from(extensions),
        };

        key_package_gen.generate(None).unwrap()
    }

    pub fn get_test_key_package(
        protocol_version: ProtocolVersion,
        cipher_suite: CipherSuite,
        id: Vec<u8>,
    ) -> KeyPackageGeneration {
        let signing_key =
            SecretKey::generate(Curve::from(cipher_suite.signature_scheme())).unwrap();
        get_test_key_package_sig_key(protocol_version, cipher_suite, id, &signing_key)
    }

    pub fn get_test_tree(
        protocol_version: ProtocolVersion,
        cipher_suite: CipherSuite,
    ) -> (TreeKemPublic, TreeKemPrivate, KeyPackageGeneration) {
        let signing_key =
            SecretKey::generate(Curve::from(cipher_suite.signature_scheme())).unwrap();

        get_test_tree_with_signer(protocol_version, cipher_suite, &signing_key)
    }

    pub fn get_test_tree_with_signer(
        protocol_version: ProtocolVersion,
        cipher_suite: CipherSuite,
        signing_key: &SecretKey,
    ) -> (TreeKemPublic, TreeKemPrivate, KeyPackageGeneration) {
        let test_key_package = get_test_key_package_sig_key(
            protocol_version,
            cipher_suite,
            b"foo".to_vec(),
            signing_key,
        );

        let (test_public, test_private) = TreeKemPublic::derive(test_key_package.clone()).unwrap();
        (test_public, test_private, test_key_package)
    }

    #[test]
    pub fn test_derive() {
        for (protocol_version, cipher_suite) in
            ProtocolVersion::all().flat_map(|p| CipherSuite::all().map(move |cs| (p, cs)))
        {
            let (test_public, test_private, test_key_package) =
                get_test_tree(protocol_version, cipher_suite);

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
        }
    }

    pub fn get_test_key_packages(
        protocol_version: ProtocolVersion,
        cipher_suite: CipherSuite,
    ) -> Vec<ValidatedKeyPackage> {
        [
            get_test_key_package(protocol_version, cipher_suite, b"A".to_vec()).key_package,
            get_test_key_package(protocol_version, cipher_suite, b"B".to_vec()).key_package,
            get_test_key_package(protocol_version, cipher_suite, b"C".to_vec()).key_package,
        ]
        .to_vec()
    }

    #[test]
    fn test_import_export() {
        let protocol_version = ProtocolVersion::Mls10;
        let cipher_suite = CipherSuite::P256Aes128V1;
        let (mut test_tree, _, _) = get_test_tree(protocol_version, cipher_suite);

        let additional_key_packages = get_test_key_packages(protocol_version, cipher_suite);

        test_tree.add_leaves(additional_key_packages).unwrap();

        let exported = test_tree.export_node_data();
        let imported = TreeKemPublic::import_node_data(cipher_suite, exported).unwrap();

        assert_eq!(test_tree, imported);
    }

    #[test]
    fn test_add_leaf() {
        let protocol_version = ProtocolVersion::Mls10;
        let cipher_suite = CipherSuite::Curve25519Aes128V1;

        let mut tree = TreeKemPublic::new(cipher_suite);

        let key_packages = get_test_key_packages(protocol_version, cipher_suite);
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
        assert_eq!(tree.occupied_leaf_count(), key_packages.len() as u32);

        // Each added package should be at the proper index and searchable in the tree
        res.iter()
            .zip(key_packages.clone())
            .enumerate()
            .for_each(|(index, (r, kp))| {
                assert_eq!(tree.get_key_package(r).unwrap(), &*kp);
                assert_eq!(tree.package_leaf_index(r).unwrap(), LeafIndex(index as u32));
            });

        // Verify the underlying state
        assert_eq!(tree.index.len(), tree.occupied_leaf_count() as usize);

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
        let protocol_version = ProtocolVersion::Mls10;
        let cipher_suite = CipherSuite::Curve25519Aes128V1;

        let mut tree = TreeKemPublic::new(cipher_suite);

        let key_packages = get_test_key_packages(protocol_version, cipher_suite);
        tree.add_leaves(key_packages).unwrap();

        let key_packages = tree.get_key_packages();
        assert_eq!(key_packages, key_packages.to_owned());
    }

    #[test]
    fn test_find_leaf() {
        let protocol_version = ProtocolVersion::Mls10;
        let cipher_suite = CipherSuite::P256Aes128V1;

        let mut tree = TreeKemPublic::new(cipher_suite);

        let key_packages = get_test_key_packages(protocol_version, cipher_suite);

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
        let protocol_version = ProtocolVersion::Mls10;
        let cipher_suite = CipherSuite::P256Aes128V1;

        let mut tree = TreeKemPublic::new(cipher_suite);

        let key_packages = get_test_key_packages(protocol_version, cipher_suite);
        tree.add_leaves(key_packages.clone()).unwrap();

        let add_res = tree.add_leaves(key_packages);

        assert_matches!(
            add_res,
            Err(RatchetTreeError::TreeIndexError(
                TreeIndexError::DuplicateKeyPackage(_, _)
            ))
        );
    }

    #[test]
    fn test_add_leaf_empty_leaf() {
        let protocol_version = ProtocolVersion::Mls10;
        let cipher_suite = CipherSuite::Curve25519Aes128V1;

        let (mut tree, _, _) = get_test_tree(protocol_version, cipher_suite);
        let key_packages = get_test_key_packages(protocol_version, cipher_suite);

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
        let protocol_version = ProtocolVersion::Mls10;
        let cipher_suite = CipherSuite::Curve25519Aes128V1;

        let (mut tree, _, _) = get_test_tree(protocol_version, cipher_suite);

        let key_packages = get_test_key_packages(protocol_version, cipher_suite);

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
        let protocol_version = ProtocolVersion::Mls10;
        let cipher_suite = CipherSuite::Curve25519Aes128V1;

        // Create a tree
        let (mut tree, _, _) = get_test_tree(protocol_version, cipher_suite);
        let key_packages = get_test_key_packages(protocol_version, cipher_suite);
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
        let original_package_ref = key_packages[0].to_reference().unwrap();
        let original_leaf_index = tree.package_leaf_index(&original_package_ref).unwrap();

        let updated_leaf =
            get_test_key_package(protocol_version, cipher_suite, b"newpk".to_vec()).key_package;
        let updated_key_ref = updated_leaf.to_reference().unwrap();

        tree.update_leaf(&original_package_ref, updated_leaf.clone())
            .unwrap();

        // The tree should not have grown due to an update
        assert_eq!(tree.occupied_leaf_count(), original_size);

        // The leaf should not have moved due to an update
        assert_eq!(
            tree.package_leaf_index(&updated_key_ref).unwrap(),
            original_leaf_index
        );

        // The cache of tree package indexs should not have grown
        assert_eq!(tree.index.len() as u32, tree.occupied_leaf_count());

        // The key package should be updated in the tree
        assert_eq!(
            tree.get_key_package(&updated_key_ref).unwrap(),
            &*updated_leaf
        );

        // There should be an error when looking for the original key package ref
        assert_matches!(
            tree.get_key_package(&original_package_ref),
            Err(RatchetTreeError::KeyPackageNotFound(_))
        );
        assert_matches!(
            tree.package_leaf_index(&original_package_ref),
            Err(RatchetTreeError::KeyPackageNotFound(_))
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
        let protocol_version = ProtocolVersion::Mls10;
        let cipher_suite = CipherSuite::Curve25519Aes128V1;

        // Create a tree
        let (mut tree, _, _) = get_test_tree(protocol_version, cipher_suite);
        let key_packages = get_test_key_packages(protocol_version, cipher_suite);
        tree.add_leaves(key_packages).unwrap();

        let new_key_package =
            get_test_key_package(protocol_version, cipher_suite, b"new".to_vec()).key_package;

        assert_matches!(
            tree.update_leaf(&KeyPackageRef::from([0u8; 16]), new_key_package),
            Err(RatchetTreeError::KeyPackageNotFound(_))
        );
    }

    #[test]
    fn test_update_leaf_duplicate() {
        let protocol_version = ProtocolVersion::Mls10;
        let cipher_suite = CipherSuite::Curve25519Aes128V1;

        // Create a tree
        let (mut tree, _, _) = get_test_tree(protocol_version, cipher_suite);
        let key_packages = get_test_key_packages(protocol_version, cipher_suite);
        tree.add_leaves(key_packages.clone()).unwrap();

        let duplicate_key_package = key_packages[1].clone();
        let key_package_ref = key_packages[0].to_reference().unwrap();

        assert_matches!(
            tree.update_leaf(&key_package_ref, duplicate_key_package),
            Err(RatchetTreeError::TreeIndexError(
                TreeIndexError::DuplicateKeyPackage(_, _)
            ))
        );
    }

    #[test]
    fn test_remove_leaf() {
        let protocol_version = ProtocolVersion::Mls10;
        let cipher_suite = CipherSuite::Curve25519Aes128V1;

        // Create a tree
        let (mut tree, _, _) = get_test_tree(protocol_version, cipher_suite);
        let key_packages = get_test_key_packages(protocol_version, cipher_suite);
        tree.add_leaves(key_packages.clone()).unwrap();

        let original_leaf_count = tree.occupied_leaf_count();

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
            .map(|(kpr, kp)| (kpr, kp.into()))
            .collect();

        assert_eq!(res, expected_result);

        // The leaf count should have been reduced by 2
        assert_eq!(tree.occupied_leaf_count(), original_leaf_count - 2);

        // We should no longer be able to find the removed leaves
        for key_package_ref in to_remove {
            assert_matches!(
                tree.get_key_package(&key_package_ref),
                Err(RatchetTreeError::KeyPackageNotFound(_))
            );

            assert_matches!(
                tree.package_leaf_index(&key_package_ref),
                Err(RatchetTreeError::KeyPackageNotFound(_))
            );
        }
    }

    #[test]
    fn test_create_blanks() {
        let protocol_version = ProtocolVersion::Mls10;
        let cipher_suite = CipherSuite::Curve25519Aes128V1;

        // Create a tree
        let (mut tree, _, _) = get_test_tree(protocol_version, cipher_suite);
        let key_packages = get_test_key_packages(protocol_version, cipher_suite);
        tree.add_leaves(key_packages.clone()).unwrap();

        let original_leaf_count = tree.occupied_leaf_count();

        let remove_ref = key_packages[1].to_reference().unwrap();
        let remove_location = tree.package_leaf_index(&remove_ref).unwrap();

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
        let protocol_version = ProtocolVersion::Mls10;
        let cipher_suite = CipherSuite::Curve25519Aes128V1;

        // Create a tree
        let (mut tree, _, _) = get_test_tree(protocol_version, cipher_suite);

        assert_matches!(
            tree.remove_leaves(&tree.clone(), vec![KeyPackageRef::from([0u8; 16])]),
            Err(RatchetTreeError::KeyPackageNotFound(_))
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
            tree.package_leaf_index(&update_path.leaf_key_package.to_reference().unwrap())
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

    fn encap_decap(protocol_version: ProtocolVersion, cipher_suite: CipherSuite, size: usize) {
        // Generate signing keys and key package generations, and private keys for multiple
        // participants in order to set up state
        let signing_keys: Vec<SecretKey> = (0..size)
            .map(|_| SecretKey::generate(Curve::from(cipher_suite.signature_scheme())).unwrap())
            .collect();

        let key_package_generations: Vec<KeyPackageGeneration> = (0..size)
            .zip(signing_keys.iter())
            .map(|(index, sk)| {
                get_test_key_package_sig_key(
                    protocol_version,
                    cipher_suite,
                    index.to_be_bytes().into(),
                    sk,
                )
            })
            .collect();

        let key_packages: Vec<ValidatedKeyPackage> = key_package_generations
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
        test_tree.add_leaves(key_packages.clone()).unwrap();

        // Clone the tree for the first leaf, generate a new key package for that leaf
        let mut encap_tree = test_tree.clone();

        let key_package_generator = KeyPackageGenerator {
            protocol_version,
            cipher_suite,
            signing_key: &signing_keys[0],
            credential: &key_packages[0].credential,
            extensions: &key_packages[0].extensions,
        };

        let key_package_update = key_package_generator.generate(None).unwrap();

        // Perform the encap function
        let update_path_gen = encap_tree
            .encap(
                &private_keys[0],
                key_package_update,
                &b"test_ctx".to_vec(),
                &[],
                |_| Ok::<_, RatchetTreeError>(()),
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
            leaf_key_package: ValidatedKeyPackage::from(
                update_path_gen.update_path.leaf_key_package,
            ),
            nodes: update_path_gen.update_path.nodes,
        };

        let mut receiver_trees: Vec<TreeKemPublic> = (1..size).map(|_| test_tree.clone()).collect();

        for (i, tree) in receiver_trees.iter_mut().enumerate() {
            let secrets = tree
                .decap(
                    private_keys[i + 1].clone(),
                    &key_package_generations[0]
                        .key_package
                        .to_reference()
                        .unwrap(),
                    &validated_update_path,
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
        for (protocol_version, one_cipher_suite) in
            ProtocolVersion::all().flat_map(|p| CipherSuite::all().map(move |cs| (p, cs)))
        {
            println!(
                "Testing Tree KEM encap / decap for: {protocol_version:?} {one_cipher_suite:?}"
            );
            encap_decap(protocol_version, one_cipher_suite, 10);
        }
    }
}
