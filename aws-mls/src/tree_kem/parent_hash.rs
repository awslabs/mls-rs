use crate::client::MlsError;
use crate::crypto::{CipherSuiteProvider, HpkePublicKey};
use crate::tree_kem::math as tree_math;
use crate::tree_kem::node::{LeafIndex, Node, NodeIndex};
use crate::tree_kem::TreeKemPublic;
use alloc::vec;
use alloc::vec::Vec;
use aws_mls_codec::{MlsDecode, MlsEncode, MlsSize};
use aws_mls_core::error::IntoAnyError;
use core::ops::Deref;

use super::leaf_node::{LeafNode, LeafNodeSource};
use super::tree_hash::TreeHash;

#[cfg(feature = "std")]
use std::collections::HashSet;

#[cfg(not(feature = "std"))]
use alloc::collections::BTreeSet;

#[derive(Clone, Debug, MlsSize, MlsEncode)]
struct ParentHashInput<'a> {
    #[mls_codec(with = "aws_mls_codec::byte_vec")]
    public_key: &'a HpkePublicKey,
    #[mls_codec(with = "aws_mls_codec::byte_vec")]
    parent_hash: &'a [u8],
    #[mls_codec(with = "aws_mls_codec::byte_vec")]
    original_sibling_tree_hash: &'a [u8],
}

#[derive(Clone, Debug, MlsSize, MlsEncode, MlsDecode, PartialEq, Eq)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct ParentHash(#[mls_codec(with = "aws_mls_codec::byte_vec")] Vec<u8>);

impl From<Vec<u8>> for ParentHash {
    fn from(v: Vec<u8>) -> Self {
        Self(v)
    }
}

impl Deref for ParentHash {
    type Target = Vec<u8>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl ParentHash {
    pub fn new<P: CipherSuiteProvider>(
        cipher_suite_provider: &P,
        public_key: &HpkePublicKey,
        parent_hash: &ParentHash,
        original_sibling_tree_hash: &[u8],
    ) -> Result<Self, MlsError> {
        let input = ParentHashInput {
            public_key,
            parent_hash,
            original_sibling_tree_hash,
        };

        let input_bytes = input.mls_encode_to_vec()?;

        let hash = cipher_suite_provider
            .hash(&input_bytes)
            .map_err(|e| MlsError::CryptoProviderError(e.into_any_error()))?;

        Ok(Self(hash))
    }

    pub fn empty() -> Self {
        ParentHash(Vec::new())
    }

    pub fn matches(&self, hash: &ParentHash) -> bool {
        //TODO: Constant time equals
        hash == self
    }
}

impl Node {
    fn get_parent_hash(&self) -> Option<ParentHash> {
        match self {
            Node::Parent(p) => Some(p.parent_hash.clone()),
            Node::Leaf(l) => match &l.leaf_node_source {
                LeafNodeSource::Commit(parent_hash) => Some(parent_hash.clone()),
                _ => None,
            },
        }
    }
}

impl TreeKemPublic {
    fn parent_hash<P: CipherSuiteProvider>(
        &self,
        parent_parent_hash: &ParentHash,
        node_index: NodeIndex,
        co_path_child_index: NodeIndex,
        cipher_suite_provider: &P,
        original_hashes: Option<&[TreeHash]>,
    ) -> Result<ParentHash, MlsError> {
        let node = self.nodes.borrow_as_parent(node_index)?;
        let original_hashes = original_hashes.unwrap_or(&self.tree_hashes.current);

        ParentHash::new(
            cipher_suite_provider,
            &node.public_key,
            parent_parent_hash,
            &original_hashes[co_path_child_index as usize],
        )
        .map_err(MlsError::from)
    }

    fn parent_hash_for_leaf<P: CipherSuiteProvider>(
        &mut self,
        cipher_suite_provider: &P,
        index: LeafIndex,
    ) -> Result<ParentHash, MlsError> {
        if self.total_leaf_count() <= 1 {
            return Ok(ParentHash::empty());
        }

        let mut filtered_direct_co_path = self
            .nodes
            .direct_path_copath(index)?
            .into_iter()
            .zip(self.nodes.filtered(index)?)
            .filter_map(|(cpdp, f)| (!f).then_some(cpdp))
            .rev();

        // Calculate all the parent hash values along the direct path from root to leaf
        filtered_direct_co_path.try_fold(
            ParentHash::empty(),
            |last_hash, (index, sibling_index)| {
                let calculated = self.parent_hash(
                    &last_hash,
                    index,
                    sibling_index,
                    cipher_suite_provider,
                    None,
                )?;

                if !self.nodes.is_leaf(index) {
                    self.nodes.borrow_as_parent_mut(index)?.parent_hash = last_hash;
                }

                Ok(calculated)
            },
        )
    }

    // Updates all of the required parent hash values, and returns the calculated parent hash value for the leaf node
    // If an update path is provided, additionally verify that the calculated parent hash matches
    pub(crate) fn update_parent_hashes<P: CipherSuiteProvider>(
        &mut self,
        index: LeafIndex,
        updated_leaf: Option<&LeafNode>,
        cipher_suite_provider: &P,
    ) -> Result<ParentHash, MlsError> {
        // First update the relevant original hashes used for parent hash computation.
        self.update_hashes(&mut vec![index], &[], cipher_suite_provider)?;

        let leaf_hash = self.parent_hash_for_leaf(cipher_suite_provider, index)?;

        if let Some(leaf) = updated_leaf {
            // Verify the parent hash of the new sender leaf node and update the parent hash values
            // in the local tree
            if let LeafNodeSource::Commit(parent_hash) = &leaf.leaf_node_source {
                if !leaf_hash.matches(parent_hash) {
                    return Err(MlsError::ParentHashMismatch);
                }
            } else {
                return Err(MlsError::InvalidLeafNodeSource);
            }
        }

        // Update hashes after changes to the tree.
        self.update_hashes(&mut vec![index], &[], cipher_suite_provider)?;

        Ok(leaf_hash)
    }

    pub(super) fn validate_parent_hashes<P: CipherSuiteProvider>(
        &self,
        cipher_suite_provider: &P,
    ) -> Result<(), MlsError> {
        let original_hashes = self.compute_original_hashes(cipher_suite_provider)?;

        let nodes_to_validate = self
            .nodes
            .non_empty_parents()
            .map(|(node_index, _)| node_index);

        #[cfg(feature = "std")]
        let mut nodes_to_validate = nodes_to_validate.collect::<HashSet<_>>();
        #[cfg(not(feature = "std"))]
        let mut nodes_to_validate = nodes_to_validate.collect::<BTreeSet<_>>();

        let num_leaves = self.total_leaf_count();
        let root = tree_math::root(num_leaves);

        // For each leaf l, validate all non-blank nodes on the chain from l up the tree.
        self.nodes
            .non_empty_leaves()
            .try_for_each(|(leaf_index, _)| {
                let mut n = NodeIndex::from(leaf_index);
                while n != root {
                    // Find the first non-blank ancestor p of n and p's co-path child s.
                    let mut p = tree_math::parent(n, num_leaves)?;
                    let mut s = tree_math::sibling(n, num_leaves)?;
                    while self.nodes.is_blank(p)? {
                        match tree_math::parent(p, num_leaves) {
                            Ok(p_parent) => {
                                s = tree_math::sibling(p, num_leaves)?;
                                p = p_parent;
                            }
                            // If we reached the root, we're done with this chain.
                            Err(_) => return Ok(()),
                        }
                    }

                    // Check is n's parent_hash field matches the parent hash of p with co-path child s.
                    let p_parent_hash = self
                        .nodes
                        .borrow_node(p)?
                        .as_ref()
                        .and_then(|p_node| p_node.get_parent_hash());
                    if let Some((p_parent_hash, n_node)) =
                        p_parent_hash.zip(self.nodes.borrow_node(n)?.as_ref())
                    {
                        if n_node.get_parent_hash()
                            == Some(self.parent_hash(
                                &p_parent_hash,
                                p,
                                s,
                                cipher_suite_provider,
                                Some(&original_hashes),
                            )?)
                        {
                            // Check that "n is in the resolution of c, and the intersection of p's unmerged_leaves with the subtree
                            // under c is equal to the resolution of c with n removed".
                            let c = tree_math::sibling(s, num_leaves)?;

                            let c_resolution = self.nodes.get_resolution_index(c)?.into_iter();

                            #[cfg(feature = "std")]
                            let mut c_resolution = c_resolution.collect::<HashSet<_>>();
                            #[cfg(not(feature = "std"))]
                            let mut c_resolution = c_resolution.collect::<BTreeSet<_>>();

                            let p_unmerged_in_c_subtree = self
                                .unmerged_in_subtree(p, c)?
                                .iter()
                                .copied()
                                .map(|x| *x * 2);

                            #[cfg(feature = "std")]
                            let p_unmerged_in_c_subtree =
                                p_unmerged_in_c_subtree.collect::<HashSet<_>>();
                            #[cfg(not(feature = "std"))]
                            let p_unmerged_in_c_subtree =
                                p_unmerged_in_c_subtree.collect::<BTreeSet<_>>();

                            if c_resolution.remove(&n)
                                && c_resolution == p_unmerged_in_c_subtree
                                && nodes_to_validate.remove(&p)
                            {
                                // If n's parent_hash field matches and p has not been validated yet, mark p as validated and continue.
                                n = p;
                            } else {
                                // If p is validated for the second time, the check fails ("all non-blank parent nodes are covered by exactly one such chain").
                                return Err(MlsError::ParentHashMismatch);
                            }
                        } else {
                            // If n's parent_hash field doesn't match, we're done with this chain.
                            return Ok(());
                        }
                    }
                }

                Ok(())
            })?;

        // The check passes iff all non-blank nodes are validated.
        if nodes_to_validate.is_empty() {
            Ok(())
        } else {
            Err(MlsError::ParentHashMismatch)
        }
    }
}

#[cfg(test)]
pub(crate) mod test_utils {

    use super::*;
    use crate::{
        cipher_suite::CipherSuite,
        crypto::test_utils::test_cipher_suite_provider,
        identity::basic::BasicIdentityProvider,
        tree_kem::{leaf_node::test_utils::get_basic_test_node, node::Parent},
    };

    pub(crate) fn test_parent(
        cipher_suite: CipherSuite,
        unmerged_leaves: Vec<LeafIndex>,
    ) -> Parent {
        let (_, public_key) = test_cipher_suite_provider(cipher_suite)
            .kem_generate()
            .unwrap();

        Parent {
            public_key,
            parent_hash: ParentHash::empty(),
            unmerged_leaves,
        }
    }

    pub(crate) fn test_parent_node(
        cipher_suite: CipherSuite,
        unmerged_leaves: Vec<LeafIndex>,
    ) -> Node {
        Node::Parent(test_parent(cipher_suite, unmerged_leaves))
    }

    // Create figure 12 from MLS RFC
    #[maybe_async::maybe_async]
    pub(crate) async fn get_test_tree_fig_12(cipher_suite: CipherSuite) -> TreeKemPublic {
        let cipher_suite_provider = test_cipher_suite_provider(cipher_suite);

        let mut tree = TreeKemPublic::new();

        let mut leaves = Vec::new();

        for l in ["A", "B", "C", "D", "E", "F", "G"] {
            leaves.push(get_basic_test_node(cipher_suite, l).await);
        }

        tree.add_leaves(leaves, &BasicIdentityProvider, &cipher_suite_provider)
            .await
            .unwrap();

        tree.nodes[1] = Some(test_parent_node(cipher_suite, vec![]));
        tree.nodes[3] = Some(test_parent_node(cipher_suite, vec![LeafIndex(3)]));

        tree.nodes[7] = Some(test_parent_node(
            cipher_suite,
            vec![LeafIndex(3), LeafIndex(6)],
        ));

        tree.nodes[9] = Some(test_parent_node(cipher_suite, vec![LeafIndex(5)]));

        tree.nodes[11] = Some(test_parent_node(
            cipher_suite,
            vec![LeafIndex(5), LeafIndex(6)],
        ));

        tree.update_parent_hashes(LeafIndex(0), None, &cipher_suite_provider)
            .unwrap();

        tree.update_parent_hashes(LeafIndex(4), None, &cipher_suite_provider)
            .unwrap();

        tree
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::test_utils::TEST_CIPHER_SUITE;
    use crate::crypto::test_utils::test_cipher_suite_provider;
    use crate::tree_kem::leaf_node::test_utils::get_basic_test_node;
    use crate::tree_kem::leaf_node::LeafNodeSource;
    use crate::tree_kem::test_utils::TreeWithSigners;
    use crate::tree_kem::update_path::ValidatedUpdatePath;
    use crate::tree_kem::MlsError;
    use assert_matches::assert_matches;

    #[cfg(target_arch = "wasm32")]
    use wasm_bindgen_test::wasm_bindgen_test as test;

    #[maybe_async::test(sync, async(not(sync), futures_test::test))]
    async fn test_missing_parent_hash() {
        let cs = test_cipher_suite_provider(TEST_CIPHER_SUITE);
        let mut test_tree = TreeWithSigners::make_full_tree(8, &cs).await.tree;

        let test_key_package = get_basic_test_node(TEST_CIPHER_SUITE, "foo").await;

        let test_update_path = ValidatedUpdatePath {
            leaf_node: test_key_package,
            nodes: vec![],
        };

        let missing_parent_hash_res = test_tree.update_parent_hashes(
            LeafIndex(0),
            Some(&test_update_path.leaf_node),
            &test_cipher_suite_provider(TEST_CIPHER_SUITE),
        );

        assert_matches!(
            missing_parent_hash_res,
            Err(MlsError::InvalidLeafNodeSource)
        );
    }

    #[maybe_async::test(sync, async(not(sync), futures_test::test))]
    async fn test_parent_hash_mismatch() {
        let cs = test_cipher_suite_provider(TEST_CIPHER_SUITE);
        let mut test_tree = TreeWithSigners::make_full_tree(8, &cs).await.tree;

        let mut test_update_path = ValidatedUpdatePath {
            leaf_node: get_basic_test_node(TEST_CIPHER_SUITE, "foo").await,
            nodes: vec![],
        };

        let unexpected_parent_hash = ParentHash::from(hex!("f00d"));

        test_update_path.leaf_node.leaf_node_source =
            LeafNodeSource::Commit(unexpected_parent_hash);

        let invalid_parent_hash_res = test_tree.update_parent_hashes(
            LeafIndex(0),
            Some(&test_update_path.leaf_node),
            &test_cipher_suite_provider(TEST_CIPHER_SUITE),
        );

        assert_matches!(invalid_parent_hash_res, Err(MlsError::ParentHashMismatch));
    }

    #[maybe_async::test(sync, async(not(sync), futures_test::test))]
    async fn test_parent_hash_invalid() {
        let cs = test_cipher_suite_provider(TEST_CIPHER_SUITE);
        let mut test_tree = TreeWithSigners::make_full_tree(8, &cs).await.tree;

        test_tree.nodes[2] = None;

        let res = test_tree.validate_parent_hashes(&test_cipher_suite_provider(TEST_CIPHER_SUITE));
        assert_matches!(res, Err(MlsError::ParentHashMismatch));
    }
}
