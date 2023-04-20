use alloc::boxed::Box;
use alloc::vec;
use alloc::vec::Vec;
#[cfg(feature = "std")]
use core::fmt::Display;
use core::ops::Deref;

#[cfg(feature = "std")]
use std::collections::{HashMap, HashSet};

#[cfg(not(feature = "std"))]
use alloc::collections::{BTreeMap, BTreeSet};

use aws_mls_core::identity::IdentityProvider;
use futures::TryStreamExt;
use thiserror::Error;

use math as tree_math;
use math::TreeMathError;
use node::{LeafIndex, NodeIndex, NodeVec, NodeVecError};

use self::hpke_encryption::HpkeEncryptionError;
use self::leaf_node::{LeafNode, LeafNodeError};

use crate::crypto::{self, CipherSuiteProvider, HpkePublicKey, HpkeSecretKey};
use crate::group::key_schedule::KeyScheduleError;
use crate::group::proposal::ProposalType;
use crate::tree_kem::tree_hash::TreeHashes;

pub use tree_index::TreeIndexError;

mod capabilities;
pub(crate) mod hpke_encryption;
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
pub(crate) use private::*;
pub use update_path::*;

use tree_index::*;

use self::path_secret::{PathSecret, PathSecretGenerator};
pub mod kem;
pub mod leaf_node;
pub mod leaf_node_validator;
mod tree_index;

#[cfg(feature = "std")]
pub(crate) mod tree_utils;

#[cfg(all(test, feature = "external_commit"))]
mod interop_test_vectors;

#[cfg(feature = "std")]
use std::error::Error;

#[cfg(not(feature = "std"))]
use core::error::Error;

#[derive(thiserror::Error, Debug)]
pub enum RatchetTreeError {
    #[error(transparent)]
    TreeMathError(#[from] TreeMathError),
    #[error(transparent)]
    NodeVecError(#[from] NodeVecError),
    #[error(transparent)]
    MlsCodecError(#[from] aws_mls_codec::Error),
    #[error(transparent)]
    LeafNodeError(#[from] LeafNodeError),
    #[error(transparent)]
    TreeIndexError(#[from] TreeIndexError),
    #[error(transparent)]
    KeyScheduleError(#[from] KeyScheduleError),
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
    #[error("decrypting commit from self")]
    DecryptFromSelf,
    #[error(transparent)]
    CredentialValidationError(Box<dyn Error + Send + Sync>),
    #[error("update and remove proposals for same leaf {0:?}")]
    UpdateAndRemoveForSameLeaf(LeafIndex),
    #[error("multiple removals for leaf {0:?}")]
    MultipleRemovals(LeafIndex),
    #[error("different identity in update for leaf {0:?}")]
    DifferentIdentityInUpdate(LeafIndex),
    #[error(transparent)]
    CipherSuiteProviderError(Box<dyn Error + Send + Sync + 'static>),
    #[error(transparent)]
    HpkeEncryptionError(#[from] HpkeEncryptionError),
}

fn credential_validation_error<E>(e: E) -> RatchetTreeError
where
    E: Into<Box<dyn Error + Send + Sync>>,
{
    RatchetTreeError::CredentialValidationError(e.into())
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize, Default)]
pub struct TreeKemPublic {
    index: TreeIndex,
    pub(crate) nodes: NodeVec,
    tree_hashes: TreeHashes,
}

impl PartialEq for TreeKemPublic {
    fn eq(&self, other: &Self) -> bool {
        self.nodes == other.nodes
    }
}

impl TreeKemPublic {
    pub fn new() -> TreeKemPublic {
        Default::default()
    }

    pub(crate) async fn import_node_data<IP>(
        nodes: NodeVec,
        identity_provider: &IP,
    ) -> Result<TreeKemPublic, RatchetTreeError>
    where
        IP: IdentityProvider,
    {
        let mut tree = TreeKemPublic {
            nodes,
            ..Default::default()
        };

        tree.initialize_index_if_necessary(identity_provider)
            .await?;

        Ok(tree)
    }

    pub(crate) async fn initialize_index_if_necessary<IP: IdentityProvider>(
        &mut self,
        identity_provider: &IP,
    ) -> Result<(), RatchetTreeError> {
        if !self.index.is_initialized() {
            self.index = futures::stream::iter(self.nodes.non_empty_leaves().map(Ok))
                .try_fold(
                    TreeIndex::new(),
                    |mut tree_index, (leaf_index, leaf)| async move {
                        let identity = identity_provider
                            .identity(&leaf.signing_identity)
                            .await
                            .map_err(credential_validation_error)?;

                        tree_index.insert(leaf_index, leaf, identity)?;
                        Ok::<_, RatchetTreeError>(tree_index)
                    },
                )
                .await?;
        }

        Ok(())
    }

    pub(crate) fn get_leaf_node_with_identity(&self, identity: &[u8]) -> Option<LeafIndex> {
        self.index.get_leaf_index_with_identity(identity)
    }

    pub(crate) fn export_node_data(&self) -> NodeVec {
        self.nodes.clone()
    }

    pub async fn derive<I, CP>(
        leaf_node: LeafNode,
        secret_key: HpkeSecretKey,
        identity_provider: &I,
        cipher_suite_provider: &CP,
    ) -> Result<(TreeKemPublic, TreeKemPrivate), RatchetTreeError>
    where
        I: IdentityProvider,
        CP: CipherSuiteProvider,
    {
        let mut public_tree = TreeKemPublic::new();
        public_tree
            .add_leaves(vec![leaf_node], identity_provider, cipher_suite_provider)
            .await?;

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

    pub fn can_support_proposal(&self, proposal_type: ProposalType) -> bool {
        self.index.count_supporting_proposal(proposal_type) as u32 == self.occupied_leaf_count()
    }

    // Note that a partial failure of this function will leave the tree in a bad state. Modifying a
    // tree should always be done on a clone of the tree, which is how commits are processed
    pub async fn add_leaves<I, CP>(
        &mut self,
        leaf_nodes: Vec<LeafNode>,
        identity_provider: &I,
        cipher_suite_provider: &CP,
    ) -> Result<Vec<LeafIndex>, RatchetTreeError>
    where
        I: IdentityProvider,
        CP: CipherSuiteProvider,
    {
        #[derive(Default)]
        struct Accumulator {
            new_leaf_indexes: Vec<LeafIndex>,
        }

        impl AccumulateBatchResults for Accumulator {
            type Output = Vec<LeafIndex>;

            fn on_add(
                &mut self,
                _: usize,
                r: Result<LeafIndex, RatchetTreeError>,
            ) -> Result<(), RatchetTreeError> {
                self.new_leaf_indexes.push(r?);
                Ok(())
            }

            fn finish(self) -> Result<Self::Output, RatchetTreeError> {
                Ok(self.new_leaf_indexes)
            }
        }

        self.batch_edit(
            Accumulator::default(),
            &[],
            &[],
            &leaf_nodes,
            identity_provider,
            cipher_suite_provider,
        )
        .await
    }

    pub async fn rekey_leaf<C>(
        &mut self,
        index: LeafIndex,
        leaf_node: LeafNode,
        identity_provider: C,
    ) -> Result<(), RatchetTreeError>
    where
        C: IdentityProvider,
    {
        // Update the leaf node
        let existing_leaf = self.nodes.borrow_as_leaf_mut(index)?;

        let existing_identity = identity_provider
            .identity(&existing_leaf.signing_identity)
            .await
            .map_err(credential_validation_error)?;

        let new_identity = identity_provider
            .identity(&leaf_node.signing_identity)
            .await
            .map_err(credential_validation_error)?;

        // Update the cache
        self.index.remove(existing_leaf, &existing_identity);
        self.index.insert(index, &leaf_node, new_identity)?;
        *existing_leaf = leaf_node;

        Ok(())
    }

    pub fn non_empty_leaves(&self) -> impl Iterator<Item = (LeafIndex, &LeafNode)> + '_ {
        self.nodes.non_empty_leaves()
    }

    pub(crate) fn update_node(
        &mut self,
        pub_key: crypto::HpkePublicKey,
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

    pub(crate) async fn apply_update_path<IP, CP>(
        &mut self,
        sender: LeafIndex,
        update_path: &ValidatedUpdatePath,
        identity_provider: IP,
        cipher_suite_provider: &CP,
    ) -> Result<Vec<(u32, u32)>, RatchetTreeError>
    where
        IP: IdentityProvider,
        CP: CipherSuiteProvider,
    {
        // Install the new leaf node
        let existing_leaf = self.nodes.borrow_as_leaf_mut(sender)?;
        let original_leaf_node = existing_leaf.clone();

        let original_identity = identity_provider
            .identity(&original_leaf_node.signing_identity)
            .await
            .map_err(credential_validation_error)?;

        let updated_identity = identity_provider
            .identity(&update_path.leaf_node.signing_identity)
            .await
            .map_err(credential_validation_error)?;

        *existing_leaf = update_path.leaf_node.clone();

        // Update the rest of the nodes on the direct path
        let updated_pks = update_path
            .nodes
            .iter()
            .map(|update| &update.public_key)
            .collect::<Vec<_>>();

        let filtered_direct_path_co_path = self.nodes.filtered_direct_path_co_path(sender)?;

        self.apply_parent_node_updates(updated_pks, &filtered_direct_path_co_path)?;

        self.index.remove(&original_leaf_node, &original_identity);
        self.index
            .insert(sender, &update_path.leaf_node, updated_identity)?;

        // Verify the parent hash of the new sender leaf node and update the parent hash values
        // in the local tree
        self.update_parent_hashes(sender, Some(update_path), cipher_suite_provider)?;

        Ok(filtered_direct_path_co_path)
    }

    fn apply_parent_node_updates(
        &mut self,
        updated_pks: Vec<&HpkePublicKey>,
        filtered_direct_path_co_path: &[(u32, u32)],
    ) -> Result<(), RatchetTreeError> {
        updated_pks
            .into_iter()
            .zip(filtered_direct_path_co_path)
            .try_for_each(|(pub_key, (node_index, _))| {
                self.update_node(pub_key.clone(), *node_index)
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

    pub async fn batch_edit<A, I, CP>(
        &mut self,
        mut accumulator: A,
        updates: &[(LeafIndex, LeafNode)],
        removals: &[LeafIndex],
        additions: &[LeafNode],
        identity_provider: &I,
        cipher_suite_provider: &CP,
    ) -> Result<A::Output, RatchetTreeError>
    where
        A: AccumulateBatchResults,
        I: IdentityProvider,
        CP: CipherSuiteProvider,
    {
        let identity_provider = &identity_provider;
        let mut removals = removals.iter().copied().map(Some).collect::<Vec<_>>();
        let tree_index = core::mem::take(&mut self.index);

        #[cfg(feature = "std")]
        let mut removed_indexes = HashSet::<LeafIndex>::new();

        #[cfg(not(feature = "std"))]
        let mut removed_indexes = BTreeSet::<LeafIndex>::new();

        // Remove about-to-be-removed leaves from tree index.
        let (new_tree_index, ..) = futures::stream::iter(removals.iter_mut().enumerate().map(Ok))
            .try_fold(
                (
                    tree_index,
                    &mut removed_indexes,
                    &mut accumulator,
                    &mut *self,
                ),
                |(mut tree_index, removed_indexes, accumulator, self_), (i, op)| async move {
                    let r = async {
                        if let Some(leaf_index) = *op {
                            let mut op = EmptyOnDrop::new(op);
                            let leaf = self_.nodes.borrow_as_leaf(leaf_index)?;

                            let identity = identity_provider
                                .identity(&leaf.signing_identity)
                                .await
                                .map_err(credential_validation_error)?;

                            removed_indexes
                                .insert(leaf_index)
                                .then_some(())
                                .ok_or(RatchetTreeError::MultipleRemovals(leaf_index))?;

                            tree_index.remove(leaf, &identity);
                            op.disarm();
                        }
                        Ok(())
                    }
                    .await;

                    r.or_else(|e| accumulator.on_remove(i, Err(e)))
                        .map(|_| (tree_index, removed_indexes, accumulator, self_))
                },
            )
            .await?;

        // Verify updates have valid indexes and old and new leaves have the same identity.
        let (mut updates, ..) = futures::stream::iter(updates.iter().enumerate().map(Ok))
            .try_fold((Vec::new(), &mut accumulator, &mut *self), {
                let removed_indexes = &removed_indexes;
                move |(mut updates, accumulator, self_), (i, (leaf_index, new_leaf))| async move {
                    let r = async {
                        (!removed_indexes.contains(leaf_index))
                            .then_some(())
                            .ok_or(RatchetTreeError::UpdateAndRemoveForSameLeaf(*leaf_index))?;

                        let old_leaf = self_.nodes.borrow_as_leaf(*leaf_index)?;
                        let old_identity = identity_provider
                            .identity(&old_leaf.signing_identity)
                            .await
                            .map_err(credential_validation_error)?;

                        let new_identity = identity_provider
                            .identity(&new_leaf.signing_identity)
                            .await
                            .map_err(credential_validation_error)?;

                        (old_identity == new_identity)
                            .then_some((*leaf_index, new_leaf, old_identity, new_identity))
                            .ok_or(RatchetTreeError::DifferentIdentityInUpdate(*leaf_index))
                    }
                    .await;

                    match r {
                        Ok(update) => {
                            updates.push(Some(update));
                            Ok((updates, accumulator, self_))
                        }
                        Err(e) => {
                            updates.push(None);
                            accumulator
                                .on_update(i, Err(e))
                                .map(|()| (updates, accumulator, self_))
                        }
                    }
                }
            })
            .await?;

        let mut tree_index = loop {
            let tree_index = new_tree_index.clone();

            // Remove about-to-be-updated leaves from tree index.
            //
            // This is done to ensure that inter-dependent updates will not be rejected, e.g.
            // when an update U1 updates `pk1` to `pk2` and another update U2 updates `pk2` to `pk3`.
            // Applying U1 fails unless U2 is applied first or `pk2` is removed. The latter approach
            // is implemented here.
            let tree_index = updates
                .iter()
                .flatten()
                .map(|(leaf_index, _, old_identity, _)| (*leaf_index, old_identity))
                .fold(tree_index, |mut tree_index, (leaf_index, old_identity)| {
                    let old_leaf = self.nodes.borrow_as_leaf(leaf_index);

                    if let Ok(old_leaf) = old_leaf {
                        tree_index.remove(old_leaf, old_identity);
                    }

                    tree_index
                });

            // Add updates to tree index.
            let tree_index =
                updates
                    .iter_mut()
                    .enumerate()
                    .try_fold(tree_index, |mut tree_index, (i, op)| {
                        let mut update_failed = false;

                        let r = empty_on_fail(op, |(leaf_index, new_leaf, _, new_identity)| {
                            let r = tree_index
                                .insert(*leaf_index, new_leaf, new_identity.clone())
                                .map_err(Into::into);

                            if r.is_err() {
                                update_failed = true;
                            }

                            r
                        });

                        r.or_else(|e| accumulator.on_update(i, Err(e)))
                            .map_err(Some)?;

                        if update_failed {
                            Err(None::<RatchetTreeError>)
                        } else {
                            Ok(tree_index)
                        }
                    });

            match tree_index {
                Ok(tree_index) => break Ok(tree_index),
                Err(Some(e)) => break Err(e),
                Err(None) => {
                    // An update could not be applied, so its removal from the tree index needs to
                    // be reverted. However it may not be possible to revert it because another
                    // update might have introduced the same key in the index. To solve this,
                    // the failed update is removed from the list of updates to apply, the tree
                    // index is reverted to its state from before any update and updates are
                    // processed from the beginning.
                }
            }
        }?;

        updates
            .iter()
            .enumerate()
            .filter_map(|(i, update)| Some((i, update.as_ref()?)))
            .try_for_each(|(i, &(leaf_index, new_leaf, ..))| {
                *self
                    .nodes
                    .borrow_as_leaf_mut(leaf_index)
                    .expect("Index points to a leaf") = new_leaf.clone();

                self.nodes
                    .blank_direct_path(leaf_index)
                    .expect("Index points to a leaf");

                accumulator.on_update(i, Ok(leaf_index))
            })?;

        removals
            .iter()
            .copied()
            .enumerate()
            .filter_map(|(i, leaf_index)| Some((i, leaf_index?)))
            .try_for_each(|(i, leaf_index)| {
                let leaf = self
                    .nodes
                    .blank_leaf_node(leaf_index)
                    .expect("Index is valid")
                    .expect("Index points to a leaf");

                self.nodes
                    .blank_direct_path(leaf_index)
                    .expect("Index points to a leaf");

                accumulator.on_remove(i, Ok((leaf_index, leaf)))
            })?;

        let (new_leaf_indexes, ..) = futures::stream::iter(additions.iter().enumerate().map(Ok))
            .try_fold(
                (
                    Vec::new(),
                    LeafIndex(0),
                    &mut tree_index,
                    &mut accumulator,
                    &mut *self,
                ),
                |(mut leaf_indexes, start, tree_index, accumulator, self_), (i, leaf)| async move {
                    let leaf_index = self_.nodes.insert_leaf(start, leaf.clone());

                    let r = identity_provider
                        .identity(&leaf.signing_identity)
                        .await
                        .map_err(credential_validation_error)
                        .and_then(|identity| {
                            tree_index
                                .insert(leaf_index, leaf, identity)
                                .map(|_| leaf_index)
                                .map_err(Into::into)
                        });

                    let failed = r.is_err();
                    accumulator.on_add(i, r)?;

                    if failed {
                        // Revert insertion in the tree.
                        self_
                            .nodes
                            .blank_leaf_node(leaf_index)
                            .expect("Index points to a leaf");
                    } else {
                        leaf_indexes.push(leaf_index);
                    }

                    Ok::<_, RatchetTreeError>((
                        leaf_indexes,
                        leaf_index,
                        tree_index,
                        accumulator,
                        self_,
                    ))
                },
            )
            .await?;

        self.nodes.trim();

        new_leaf_indexes.iter().copied().for_each(|leaf_index| {
            self.update_unmerged(leaf_index)
                .expect("Index points to a leaf");
        });

        self.index = tree_index;

        let mut path_blanked = removals
            .iter()
            .copied()
            .flatten()
            .chain(updates.iter().flatten().map(|&(leaf_index, ..)| leaf_index))
            .collect();

        self.update_hashes(&mut path_blanked, &new_leaf_indexes, cipher_suite_provider)?;

        accumulator.finish()
    }
}

fn empty_on_fail<T, F>(opt: &mut Option<T>, f: F) -> Result<(), RatchetTreeError>
where
    F: FnOnce(&T) -> Result<(), RatchetTreeError>,
{
    let mut opt = EmptyOnDrop::new(opt);
    if let Some(x) = &*opt.value {
        f(x)?;
    }
    opt.disarm();
    Ok(())
}

struct EmptyOnDrop<'a, T> {
    armed: bool,
    value: &'a mut Option<T>,
}

impl<'a, T> EmptyOnDrop<'a, T> {
    fn new(value: &'a mut Option<T>) -> Self {
        Self { armed: true, value }
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl<T> Drop for EmptyOnDrop<'_, T> {
    fn drop(&mut self) {
        if self.armed {
            *self.value = None;
        }
    }
}

#[cfg(feature = "std")]
impl Display for TreeKemPublic {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", tree_utils::build_ascii_tree(&self.nodes))
    }
}

pub trait AccumulateBatchResults {
    type Output;

    fn on_update(
        &mut self,
        _: usize,
        r: Result<LeafIndex, RatchetTreeError>,
    ) -> Result<(), RatchetTreeError> {
        r.map(|_| ())
    }

    fn on_remove(
        &mut self,
        _: usize,
        r: Result<(LeafIndex, LeafNode), RatchetTreeError>,
    ) -> Result<(), RatchetTreeError> {
        r.map(|_| ())
    }

    fn on_add(
        &mut self,
        _: usize,
        r: Result<LeafIndex, RatchetTreeError>,
    ) -> Result<(), RatchetTreeError> {
        r.map(|_| ())
    }

    fn finish(self) -> Result<Self::Output, RatchetTreeError>;
}

#[cfg(test)]
impl TreeKemPublic {
    pub async fn update_leaf<I, CP>(
        &mut self,
        index: LeafIndex,
        leaf_node: LeafNode,
        identity_provider: &I,
        cipher_suite_provider: &CP,
    ) -> Result<(), RatchetTreeError>
    where
        I: IdentityProvider,
        CP: CipherSuiteProvider,
    {
        struct Accumulator;

        impl AccumulateBatchResults for Accumulator {
            type Output = ();

            fn finish(self) -> Result<Self::Output, RatchetTreeError> {
                Ok(())
            }
        }

        self.batch_edit(
            Accumulator,
            &[(index, leaf_node)],
            &[],
            &[],
            identity_provider,
            cipher_suite_provider,
        )
        .await
    }

    pub async fn remove_leaves<I, CP>(
        &mut self,
        indexes: Vec<LeafIndex>,
        identity_provider: &I,
        cipher_suite_provider: &CP,
    ) -> Result<Vec<(LeafIndex, LeafNode)>, RatchetTreeError>
    where
        I: IdentityProvider,
        CP: CipherSuiteProvider,
    {
        #[derive(Default)]
        struct Accumulator {
            removed: Vec<(LeafIndex, LeafNode)>,
        }

        impl AccumulateBatchResults for Accumulator {
            type Output = Vec<(LeafIndex, LeafNode)>;

            fn on_remove(
                &mut self,
                _: usize,
                r: Result<(LeafIndex, LeafNode), RatchetTreeError>,
            ) -> Result<(), RatchetTreeError> {
                self.removed.push(r?);
                Ok(())
            }

            fn finish(self) -> Result<Self::Output, RatchetTreeError> {
                Ok(self.removed)
            }
        }

        self.batch_edit(
            Accumulator::default(),
            &[],
            &indexes,
            &[],
            identity_provider,
            cipher_suite_provider,
        )
        .await
    }

    pub fn get_leaf_nodes(&self) -> Vec<&LeafNode> {
        self.nodes.non_empty_leaves().map(|(_, l)| l).collect()
    }
}

#[cfg(test)]
pub(crate) mod test_utils {
    use crate::crypto::test_utils::TestCryptoProvider;
    use crate::signer::Signable;
    use alloc::vec::Vec;
    use alloc::{format, vec};
    use aws_mls_core::crypto::CipherSuiteProvider;
    use aws_mls_core::group::Capabilities;
    use aws_mls_core::identity::BasicCredential;

    use crate::identity::test_utils::get_test_signing_identity;
    use crate::{
        cipher_suite::CipherSuite,
        crypto::{test_utils::test_cipher_suite_provider, HpkeSecretKey, SignatureSecretKey},
        identity::basic::BasicIdentityProvider,
        tree_kem::leaf_node::test_utils::get_basic_test_node_sig_key,
    };

    use super::leaf_node::{ConfigProperties, LeafNodeSigningContext, LeafNodeSource};
    use super::node::LeafIndex;
    use super::Lifetime;
    use super::{
        leaf_node::{test_utils::get_basic_test_node, LeafNode},
        TreeKemPrivate, TreeKemPublic,
    };

    #[derive(Debug)]
    pub(crate) struct TestTree {
        pub public: TreeKemPublic,
        pub private: TreeKemPrivate,
        pub creator_leaf: LeafNode,
        pub creator_signing_key: SignatureSecretKey,
        pub creator_hpke_secret: HpkeSecretKey,
    }

    pub(crate) async fn get_test_tree(cipher_suite: CipherSuite) -> TestTree {
        let cipher_suite_provider = test_cipher_suite_provider(cipher_suite);

        let (creator_leaf, creator_hpke_secret, creator_signing_key) =
            get_basic_test_node_sig_key(cipher_suite, "creator").await;

        let (test_public, test_private) = TreeKemPublic::derive(
            creator_leaf.clone(),
            creator_hpke_secret.clone(),
            &BasicIdentityProvider,
            &cipher_suite_provider,
        )
        .await
        .unwrap();

        TestTree {
            public: test_public,
            private: test_private,
            creator_leaf,
            creator_signing_key,
            creator_hpke_secret,
        }
    }

    pub async fn get_test_leaf_nodes(cipher_suite: CipherSuite) -> Vec<LeafNode> {
        [
            get_basic_test_node(cipher_suite, "A").await,
            get_basic_test_node(cipher_suite, "B").await,
            get_basic_test_node(cipher_suite, "C").await,
        ]
        .to_vec()
    }

    impl TreeKemPublic {
        pub fn equal_internals(&self, other: &TreeKemPublic) -> bool {
            self.tree_hashes == other.tree_hashes && self.index == other.index
        }
    }

    #[derive(Debug, Clone)]
    pub struct TreeWithSigners {
        pub tree: TreeKemPublic,
        pub signers: Vec<Option<SignatureSecretKey>>,
        pub group_id: Vec<u8>,
    }

    impl TreeWithSigners {
        pub async fn make_full_tree<P: CipherSuiteProvider>(
            n_leaves: u32,
            cs: &P,
        ) -> TreeWithSigners {
            let mut tree = TreeWithSigners {
                tree: TreeKemPublic::new(),
                signers: vec![],
                group_id: cs.random_bytes_vec(cs.kdf_extract_size()).unwrap(),
            };

            tree.add_member("Alice", cs).await;

            // A adds B, B adds C, C adds D etc.
            for i in 1..n_leaves {
                tree.add_member(&format!("Alice{i}"), cs).await;
                tree.update_committer_path(i - 1, cs).await;
            }

            tree
        }

        pub async fn add_member<P: CipherSuiteProvider>(&mut self, name: &str, cs: &P) {
            let (leaf, signer) = make_leaf(name, cs).await;
            let index = self.tree.nodes.insert_leaf(LeafIndex(0), leaf);
            self.tree.update_unmerged(index).unwrap();
            let index = *index as usize;

            match self.signers.len() {
                l if l == index => self.signers.push(Some(signer)),
                l if l > index => self.signers[index] = Some(signer),
                _ => panic!("signer tree size mismatch"),
            }
        }

        pub fn remove_member(&mut self, member: u32) {
            self.tree
                .nodes
                .blank_direct_path(LeafIndex(member))
                .unwrap();

            self.tree.nodes.blank_leaf_node(LeafIndex(member)).unwrap();

            *self
                .signers
                .get_mut(member as usize)
                .expect("signer tree size mismatch") = None;
        }

        pub async fn update_committer_path<P: CipherSuiteProvider>(
            &mut self,
            committer: u32,
            cs: &P,
        ) {
            let path = self
                .tree
                .nodes
                .filtered_direct_path(LeafIndex(committer))
                .unwrap();

            for i in path.into_iter() {
                self.tree
                    .update_node(cs.kem_generate().unwrap().1, i)
                    .unwrap();
            }

            self.tree.tree_hashes.current = vec![];
            self.tree.tree_hashes.original = vec![];
            self.tree.tree_hash(cs).unwrap();

            let parent_hash = self
                .tree
                .update_parent_hashes(LeafIndex(committer), None, cs)
                .unwrap();

            self.tree
                .nodes
                .borrow_as_leaf_mut(LeafIndex(committer))
                .unwrap()
                .leaf_node_source = LeafNodeSource::Commit(parent_hash);

            self.tree.tree_hashes.current = vec![];
            self.tree.tree_hashes.original = vec![];
            self.tree.tree_hash(cs).unwrap();

            let context = LeafNodeSigningContext {
                group_id: Some(&self.group_id),
                leaf_index: Some(committer),
            };

            let signer = self.signers[committer as usize].as_ref().unwrap();

            self.tree
                .nodes
                .borrow_as_leaf_mut(LeafIndex(committer))
                .unwrap()
                .sign(cs, signer, &context)
                .unwrap();

            self.tree.tree_hashes.current = vec![];
            self.tree.tree_hashes.original = vec![];
            self.tree.tree_hash(cs).unwrap();
        }
    }

    pub async fn make_leaf<P: CipherSuiteProvider>(
        name: &str,
        cs: &P,
    ) -> (LeafNode, SignatureSecretKey) {
        let (signing_identity, signature_key) =
            get_test_signing_identity(cs.cipher_suite(), name.as_bytes().to_vec());

        let capabilities = Capabilities {
            credentials: vec![BasicCredential::credential_type()],
            cipher_suites: TestCryptoProvider::all_supported_cipher_suites(),
            ..Default::default()
        };

        let properties = ConfigProperties {
            capabilities,
            extensions: Default::default(),
        };

        let (leaf, _) = LeafNode::generate(
            cs,
            properties,
            signing_identity,
            &signature_key,
            Lifetime::years(1).unwrap(),
        )
        .await
        .unwrap();

        (leaf, signature_key)
    }
}

#[cfg(test)]
mod tests {
    use crate::client::test_utils::TEST_CIPHER_SUITE;
    use crate::crypto::test_utils::{test_cipher_suite_provider, TestCryptoProvider};
    use crate::group::proposal::ProposalType;
    use crate::identity::basic::BasicIdentityProvider;
    use crate::tree_kem::leaf_node::test_utils::get_basic_test_node;
    use crate::tree_kem::leaf_node::LeafNode;
    use crate::tree_kem::node::{
        LeafIndex, Node, NodeIndex, NodeTypeResolver, NodeVecError, Parent,
    };
    use crate::tree_kem::parent_hash::ParentHash;
    use crate::tree_kem::test_utils::{get_test_leaf_nodes, get_test_tree};
    use crate::tree_kem::tree_index::TreeIndexError;
    use crate::tree_kem::{AccumulateBatchResults, RatchetTreeError, TreeKemPublic};
    use alloc::borrow::ToOwned;
    use alloc::vec;
    use alloc::vec::Vec;
    use assert_matches::assert_matches;

    #[cfg(target_arch = "wasm32")]
    use wasm_bindgen_test::wasm_bindgen_test as test;

    #[cfg(not(target_arch = "wasm32"))]
    use futures_test::test;

    #[test]
    async fn test_derive() {
        for cipher_suite in TestCryptoProvider::all_supported_cipher_suites() {
            let test_tree = get_test_tree(cipher_suite).await;

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
    async fn test_import_export() {
        let cipher_suite_provider = test_cipher_suite_provider(TEST_CIPHER_SUITE);

        let mut test_tree = get_test_tree(TEST_CIPHER_SUITE).await;

        let additional_key_packages = get_test_leaf_nodes(TEST_CIPHER_SUITE).await;

        test_tree
            .public
            .add_leaves(
                additional_key_packages,
                &BasicIdentityProvider,
                &cipher_suite_provider,
            )
            .await
            .unwrap();

        let exported = test_tree.public.export_node_data();

        let imported = TreeKemPublic::import_node_data(exported, &BasicIdentityProvider)
            .await
            .unwrap();

        assert_eq!(test_tree.public.nodes, imported.nodes);
        assert_eq!(test_tree.public.index, imported.index);
    }

    #[test]
    async fn test_add_leaf() {
        let cipher_suite_provider = test_cipher_suite_provider(TEST_CIPHER_SUITE);
        let mut tree = TreeKemPublic::new();

        let leaf_nodes = get_test_leaf_nodes(TEST_CIPHER_SUITE).await;

        let res = tree
            .add_leaves(
                leaf_nodes.clone(),
                &BasicIdentityProvider,
                &cipher_suite_provider,
            )
            .await
            .unwrap();

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
    async fn test_get_key_packages() {
        let cipher_suite_provider = test_cipher_suite_provider(TEST_CIPHER_SUITE);

        let mut tree = TreeKemPublic::new();

        let key_packages = get_test_leaf_nodes(TEST_CIPHER_SUITE).await;

        tree.add_leaves(key_packages, &BasicIdentityProvider, &cipher_suite_provider)
            .await
            .unwrap();

        let key_packages = tree.get_leaf_nodes();
        assert_eq!(key_packages, key_packages.to_owned());
    }

    #[test]
    async fn test_add_leaf_duplicate() {
        let cipher_suite_provider = test_cipher_suite_provider(TEST_CIPHER_SUITE);

        let mut tree = TreeKemPublic::new();

        let key_packages = get_test_leaf_nodes(TEST_CIPHER_SUITE).await;

        tree.add_leaves(
            key_packages.clone(),
            &BasicIdentityProvider,
            &cipher_suite_provider,
        )
        .await
        .unwrap();

        let add_res = tree
            .add_leaves(key_packages, &BasicIdentityProvider, &cipher_suite_provider)
            .await;

        assert_matches!(
            add_res,
            Err(RatchetTreeError::TreeIndexError(
                TreeIndexError::DuplicateSignatureKeys(LeafIndex(0))
            ))
        );
    }

    #[test]
    async fn test_add_leaf_empty_leaf() {
        let cipher_suite_provider = test_cipher_suite_provider(TEST_CIPHER_SUITE);

        let mut tree = get_test_tree(TEST_CIPHER_SUITE).await.public;
        let key_packages = get_test_leaf_nodes(TEST_CIPHER_SUITE).await;

        tree.add_leaves(
            [key_packages[0].clone()].to_vec(),
            &BasicIdentityProvider,
            &cipher_suite_provider,
        )
        .await
        .unwrap();

        tree.nodes[0] = None; // Set the original first node to none
                              //
        tree.add_leaves(
            [key_packages[1].clone()].to_vec(),
            &BasicIdentityProvider,
            &cipher_suite_provider,
        )
        .await
        .unwrap();

        assert_eq!(tree.nodes[0], key_packages[1].clone().into());
        assert_eq!(tree.nodes[1], None);
        assert_eq!(tree.nodes[2], key_packages[0].clone().into());
        assert_eq!(tree.nodes.len(), 3)
    }

    #[test]
    async fn test_add_leaf_unmerged() {
        let cipher_suite_provider = test_cipher_suite_provider(TEST_CIPHER_SUITE);

        let mut tree = get_test_tree(TEST_CIPHER_SUITE).await.public;
        let key_packages = get_test_leaf_nodes(TEST_CIPHER_SUITE).await;

        tree.add_leaves(
            [key_packages[0].clone(), key_packages[1].clone()].to_vec(),
            &BasicIdentityProvider,
            &cipher_suite_provider,
        )
        .await
        .unwrap();

        tree.nodes[3] = Parent {
            public_key: vec![].into(),
            parent_hash: ParentHash::empty(),
            unmerged_leaves: vec![],
        }
        .into();

        tree.add_leaves(
            [key_packages[2].clone()].to_vec(),
            &BasicIdentityProvider,
            &cipher_suite_provider,
        )
        .await
        .unwrap();

        assert_eq!(
            tree.nodes[3].as_parent().unwrap().unmerged_leaves,
            vec![LeafIndex(3)]
        )
    }

    #[test]
    async fn test_update_leaf() {
        let cipher_suite_provider = test_cipher_suite_provider(TEST_CIPHER_SUITE);

        // Create a tree
        let mut tree = get_test_tree(TEST_CIPHER_SUITE).await.public;

        let key_packages = get_test_leaf_nodes(TEST_CIPHER_SUITE).await;

        tree.add_leaves(key_packages, &BasicIdentityProvider, &cipher_suite_provider)
            .await
            .unwrap();

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

        let updated_leaf = get_basic_test_node(TEST_CIPHER_SUITE, "A").await;

        tree.update_leaf(
            original_leaf_index,
            updated_leaf.clone(),
            &BasicIdentityProvider,
            &cipher_suite_provider,
        )
        .await
        .unwrap();

        // The tree should not have grown due to an update
        assert_eq!(tree.occupied_leaf_count(), original_size);

        // The cache of tree package indexes should not have grown
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
    async fn test_update_leaf_not_found() {
        let cipher_suite_provider = test_cipher_suite_provider(TEST_CIPHER_SUITE);

        // Create a tree
        let mut tree = get_test_tree(TEST_CIPHER_SUITE).await.public;

        let key_packages = get_test_leaf_nodes(TEST_CIPHER_SUITE).await;

        tree.add_leaves(key_packages, &BasicIdentityProvider, &cipher_suite_provider)
            .await
            .unwrap();

        let new_key_package = get_basic_test_node(TEST_CIPHER_SUITE, "new").await;

        assert_matches!(
            tree.update_leaf(
                LeafIndex(128),
                new_key_package,
                &BasicIdentityProvider,
                &cipher_suite_provider
            )
            .await,
            Err(RatchetTreeError::NodeVecError(
                NodeVecError::InvalidNodeIndex(256)
            ))
        );
    }

    #[test]
    async fn test_remove_leaf() {
        let cipher_suite_provider = test_cipher_suite_provider(TEST_CIPHER_SUITE);

        // Create a tree
        let mut tree = get_test_tree(TEST_CIPHER_SUITE).await.public;
        let key_packages = get_test_leaf_nodes(TEST_CIPHER_SUITE).await;

        let indexes = tree
            .add_leaves(
                key_packages.clone(),
                &BasicIdentityProvider,
                &cipher_suite_provider,
            )
            .await
            .unwrap();

        let original_leaf_count = tree.occupied_leaf_count();

        // Remove two leaves from the tree
        let expected_result: Vec<(LeafIndex, LeafNode)> = indexes
            .clone()
            .into_iter()
            .zip(key_packages)
            .map(|(index, ln)| (index, ln))
            .collect();

        let res = tree
            .remove_leaves(
                indexes.clone(),
                &BasicIdentityProvider,
                &cipher_suite_provider,
            )
            .await
            .unwrap();

        assert_eq!(res, expected_result);

        // The leaves should be removed from the tree
        assert_eq!(
            tree.occupied_leaf_count(),
            original_leaf_count - indexes.len() as u32
        );
    }

    #[test]
    async fn test_remove_leaf_middle() {
        let cipher_suite_provider = test_cipher_suite_provider(TEST_CIPHER_SUITE);

        // Create a tree
        let mut tree = get_test_tree(TEST_CIPHER_SUITE).await.public;
        let leaf_nodes = get_test_leaf_nodes(TEST_CIPHER_SUITE).await;

        let to_remove = tree
            .add_leaves(
                leaf_nodes.clone(),
                &BasicIdentityProvider,
                &cipher_suite_provider,
            )
            .await
            .unwrap()[0];

        let original_leaf_count = tree.occupied_leaf_count();

        let res = tree
            .remove_leaves(
                vec![to_remove],
                &BasicIdentityProvider,
                &cipher_suite_provider,
            )
            .await
            .unwrap();

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
    async fn test_create_blanks() {
        let cipher_suite_provider = test_cipher_suite_provider(TEST_CIPHER_SUITE);

        // Create a tree
        let mut tree = get_test_tree(TEST_CIPHER_SUITE).await.public;

        let key_packages = get_test_leaf_nodes(TEST_CIPHER_SUITE).await;

        tree.add_leaves(key_packages, &BasicIdentityProvider, &cipher_suite_provider)
            .await
            .unwrap();

        let original_leaf_count = tree.occupied_leaf_count();

        let to_remove = vec![LeafIndex(2)];

        // Remove the leaf from the tree
        tree.remove_leaves(to_remove, &BasicIdentityProvider, &cipher_suite_provider)
            .await
            .unwrap();

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
    async fn test_remove_leaf_failure() {
        let cipher_suite_provider = test_cipher_suite_provider(TEST_CIPHER_SUITE);

        // Create a tree
        let mut tree = get_test_tree(TEST_CIPHER_SUITE).await.public;

        assert_matches!(
            tree.remove_leaves(
                vec![LeafIndex(128)],
                &BasicIdentityProvider,
                &cipher_suite_provider
            )
            .await,
            Err(RatchetTreeError::NodeVecError(
                NodeVecError::InvalidNodeIndex(256)
            ))
        );
    }

    #[test]
    async fn test_find_leaf_node() {
        let cipher_suite_provider = test_cipher_suite_provider(TEST_CIPHER_SUITE);

        // Create a tree
        let mut tree = get_test_tree(TEST_CIPHER_SUITE).await.public;

        let leaf_nodes = get_test_leaf_nodes(TEST_CIPHER_SUITE).await;

        tree.add_leaves(
            leaf_nodes.clone(),
            &BasicIdentityProvider,
            &cipher_suite_provider,
        )
        .await
        .unwrap();

        // Find each node
        for (i, leaf_node) in leaf_nodes.iter().enumerate() {
            let expected_index = LeafIndex(i as u32 + 1);
            assert_eq!(tree.find_leaf_node(leaf_node), Some(expected_index));
        }
    }

    #[derive(Debug, Default)]
    struct BatchAccumulator {
        additions: Vec<LeafIndex>,
        removals: Vec<(LeafIndex, LeafNode)>,
        updates: Vec<LeafIndex>,
    }

    impl AccumulateBatchResults for BatchAccumulator {
        type Output = Self;

        fn on_add(
            &mut self,
            _: usize,
            r: Result<LeafIndex, RatchetTreeError>,
        ) -> Result<(), RatchetTreeError> {
            self.additions.push(r?);
            Ok(())
        }

        fn on_remove(
            &mut self,
            _: usize,
            r: Result<(LeafIndex, LeafNode), RatchetTreeError>,
        ) -> Result<(), RatchetTreeError> {
            self.removals.push(r?);
            Ok(())
        }

        fn on_update(
            &mut self,
            _: usize,
            r: Result<LeafIndex, RatchetTreeError>,
        ) -> Result<(), RatchetTreeError> {
            self.updates.push(r?);
            Ok(())
        }

        fn finish(self) -> Result<Self::Output, RatchetTreeError> {
            Ok(self)
        }
    }

    #[test]
    async fn batch_edit_works() {
        let cipher_suite_provider = test_cipher_suite_provider(TEST_CIPHER_SUITE);

        let mut tree = get_test_tree(TEST_CIPHER_SUITE).await.public;

        let leaf_nodes = get_test_leaf_nodes(TEST_CIPHER_SUITE).await;

        tree.add_leaves(
            leaf_nodes.clone(),
            &BasicIdentityProvider,
            &cipher_suite_provider,
        )
        .await
        .unwrap();

        let acc = tree
            .batch_edit(
                BatchAccumulator::default(),
                &[(
                    LeafIndex(1),
                    get_basic_test_node(TEST_CIPHER_SUITE, "A").await,
                )],
                &[LeafIndex(2)],
                &[get_basic_test_node(TEST_CIPHER_SUITE, "D").await],
                &BasicIdentityProvider,
                &cipher_suite_provider,
            )
            .await
            .unwrap();

        assert_eq!(acc.additions, [LeafIndex(2)]);
        assert_eq!(acc.removals, [(LeafIndex(2), leaf_nodes[1].clone())]);
        assert_eq!(acc.updates, [LeafIndex(1)]);
    }

    #[test]
    async fn custom_proposal_support() {
        let cipher_suite_provider = test_cipher_suite_provider(TEST_CIPHER_SUITE);
        let mut tree = TreeKemPublic::new();

        let test_proposal_type = ProposalType::from(42);

        let mut leaf_nodes = get_test_leaf_nodes(TEST_CIPHER_SUITE).await;

        leaf_nodes
            .iter_mut()
            .for_each(|n| n.capabilities.proposals.push(test_proposal_type));

        tree.add_leaves(leaf_nodes, &BasicIdentityProvider, &cipher_suite_provider)
            .await
            .unwrap();

        assert!(tree.can_support_proposal(test_proposal_type));
        assert!(!tree.can_support_proposal(ProposalType::from(43)));

        tree.add_leaves(
            vec![get_basic_test_node(TEST_CIPHER_SUITE, "another").await],
            &BasicIdentityProvider,
            &cipher_suite_provider,
        )
        .await
        .unwrap();

        assert!(!tree.can_support_proposal(test_proposal_type));
    }
}
