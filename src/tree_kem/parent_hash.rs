use crate::cipher_suite::CipherSuite;
use crate::tree_kem::math as tree_math;
use crate::tree_kem::math::TreeMathError;
use crate::tree_kem::node::{LeafIndex, Node, NodeIndex, NodeVecError};
use crate::tree_kem::RatchetTreeError;
use crate::tree_kem::TreeKemPublic;
use ferriscrypt::hpke::kem::HpkePublicKey;
use std::collections::{HashMap, HashSet};
use std::ops::Deref;
use thiserror::Error;
use tls_codec::Serialize;
use tls_codec_derive::{TlsDeserialize, TlsSerialize, TlsSize};

use super::leaf_node::LeafNodeSource;
use super::ValidatedUpdatePath;

#[derive(Error, Debug)]
pub enum ParentHashError {
    #[error(transparent)]
    SerializationError(#[from] tls_codec::Error),
    #[error(transparent)]
    NodeVecError(#[from] NodeVecError),
    #[error(transparent)]
    TreeMathError(#[from] TreeMathError),
}

#[derive(Clone, Debug, TlsSerialize, TlsSize)]
struct ParentHashInput<'a> {
    #[tls_codec(with = "crate::tls::ByteVec")]
    public_key: &'a HpkePublicKey,
    #[tls_codec(with = "crate::tls::ByteVec")]
    parent_hash: &'a [u8],
    #[tls_codec(with = "crate::tls::ByteVec")]
    original_sibling_tree_hash: &'a [u8],
}

#[derive(
    Clone, Debug, TlsDeserialize, TlsSerialize, TlsSize, serde::Deserialize, serde::Serialize,
)]
pub struct ParentHash(#[tls_codec(with = "crate::tls::ByteVec")] Vec<u8>);

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

impl PartialEq for ParentHash {
    fn eq(&self, other: &Self) -> bool {
        ferriscrypt::constant_time_eq::constant_time_eq(&self.0, &other.0)
    }
}

impl ParentHash {
    pub fn new(
        cipher_suite: CipherSuite,
        public_key: &HpkePublicKey,
        parent_hash: &ParentHash,
        original_sibling_tree_hash: &[u8],
    ) -> Result<Self, ParentHashError> {
        let input = ParentHashInput {
            public_key,
            parent_hash,
            original_sibling_tree_hash,
        };

        let input_bytes = input.tls_serialize_detached()?;
        let hash = cipher_suite.hash_function().digest(&input_bytes);
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
    fn parent_hash(
        &self,
        parent_parent_hash: &ParentHash,
        node_index: NodeIndex,
        co_path_child_index: NodeIndex,
    ) -> Result<ParentHash, RatchetTreeError> {
        let node = self.nodes.borrow_as_parent(node_index)?;

        let original_sibling_tree_hash =
            self.original_full_tree_hash(co_path_child_index, &node.unmerged_leaves)?;

        ParentHash::new(
            self.cipher_suite,
            &node.public_key,
            parent_parent_hash,
            &original_sibling_tree_hash,
        )
        .map_err(RatchetTreeError::from)
    }

    fn parent_hash_for_leaf<T>(
        &self,
        index: LeafIndex,
        mut on_node_calculation: T,
    ) -> Result<ParentHash, RatchetTreeError>
    where
        T: FnMut(NodeIndex, &ParentHash),
    {
        if self.total_leaf_count() <= 1 {
            return Ok(ParentHash::empty());
        }

        let mut filtered_direct_co_path = self
            .nodes
            .filtered_direct_path_co_path(index, self.total_leaf_count().next_power_of_two())?
            .into_iter()
            .rev();

        // Calculate all the parent hash values along the direct path from root to leaf
        filtered_direct_co_path.try_fold(
            ParentHash::empty(),
            |last_hash, (index, sibling_index)| {
                if !self.nodes.is_leaf(index) {
                    on_node_calculation(index, &last_hash);
                }

                let calculated = self.parent_hash(&last_hash, index, sibling_index)?;

                Ok(calculated)
            },
        )
    }

    // Updates all of the required parent hash values, and returns the calculated parent hash value for the leaf node
    // If an update path is provided, additionally verify that the calculated parent hash matches
    pub fn update_parent_hashes(
        &mut self,
        index: LeafIndex,
        update_path: Option<&ValidatedUpdatePath>,
    ) -> Result<ParentHash, RatchetTreeError> {
        let mut changes = HashMap::new();

        // Since we can't mut borrow self here we will just collect the list of changes
        // and apply them later
        let leaf_hash = self.parent_hash_for_leaf(index, |index, hash| {
            changes.insert(index, hash.clone());
        })?;

        changes.drain().try_for_each(|(index, hash)| {
            self.nodes
                .borrow_as_parent_mut(index)
                .map(|p| {
                    p.parent_hash = hash;
                })
                .map_err(RatchetTreeError::from)
        })?;

        if let Some(update_path) = update_path {
            // Verify the parent hash of the new sender leaf node and update the parent hash values
            // in the local tree
            if let LeafNodeSource::Commit(parent_hash) = &update_path.leaf_node.leaf_node_source {
                if !leaf_hash.matches(parent_hash) {
                    return Err(RatchetTreeError::ParentHashMismatch);
                }
            } else {
                return Err(RatchetTreeError::ParentHashNotFound);
            }
        }

        Ok(leaf_hash)
    }

    pub(super) fn validate_parent_hashes(&self) -> Result<(), RatchetTreeError> {
        let mut nodes_to_validate: HashSet<u32> = self
            .nodes
            .non_empty_parents()
            .map(|(node_index, _)| node_index)
            .collect();
        let num_leaves = self.total_leaf_count();
        let num_leaves_full = num_leaves.next_power_of_two();
        let root = tree_math::root(num_leaves);

        // For each leaf l, validate all non-blank nodes on the chain from l up the tree.
        self.nodes
            .non_empty_leaves()
            .try_for_each(|(leaf_index, _)| {
                let mut n = NodeIndex::from(leaf_index);
                while n != root {
                    // Find the first non-blank ancestor p of n and p's co-path child s.
                    let mut p = tree_math::parent(n, num_leaves)?;
                    let mut s = tree_math::sibling(n, num_leaves, num_leaves_full)?;
                    while self.nodes.is_blank(p)? {
                        match tree_math::parent(p, num_leaves) {
                            Ok(p_parent) => {
                                s = tree_math::sibling(p, num_leaves, num_leaves_full)?;
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
                            == Some(self.parent_hash(&p_parent_hash, p, s)?)
                        {
                            if nodes_to_validate.remove(&p) {
                                // If n's parent_hash field matches and p has not been validated yet, mark p as validated and continue.
                                n = p;
                            } else {
                                // If p is validated for the second time, the check fails ("all non-blank parent nodes are covered by exactly one such chain").
                                return Err(RatchetTreeError::ParentHashMismatch);
                            }
                        } else {
                            // If n' parent_hash field doesn't match, we're done with this chain.
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
            Err(RatchetTreeError::ParentHashMismatch)
        }
    }
}

#[cfg(test)]
pub(crate) mod test_utils {
    use ferriscrypt::asym::ec_key::SecretKey;

    use crate::tree_kem::{leaf_node::test_utils::get_basic_test_node, node::Parent};

    use super::*;

    pub(crate) fn test_parent(
        cipher_suite: CipherSuite,
        unmerged_leaves: Vec<LeafIndex>,
    ) -> Parent {
        let public_key = SecretKey::generate(cipher_suite.kem_type().curve())
            .unwrap()
            .to_public()
            .unwrap()
            .try_into()
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
    pub(crate) fn get_test_tree_fig_12(cipher_suite: CipherSuite) -> TreeKemPublic {
        let mut tree = TreeKemPublic::new(cipher_suite);

        let leaves = ["A", "B", "C", "D", "E", "F", "G"]
            .map(|l| get_basic_test_node(cipher_suite, l))
            .to_vec();

        tree.add_leaves(leaves).unwrap();

        tree.nodes[1] = Some(test_parent_node(cipher_suite, vec![]));
        tree.nodes[3] = Some(test_parent_node(cipher_suite, vec![LeafIndex(3)]));

        tree.nodes[7] = Some(test_parent_node(
            cipher_suite,
            vec![LeafIndex(3), LeafIndex(7)],
        ));

        tree.nodes[9] = Some(test_parent_node(cipher_suite, vec![LeafIndex(5)]));

        tree.nodes[11] = Some(test_parent_node(
            cipher_suite,
            vec![LeafIndex(5), LeafIndex(7)],
        ));

        tree.update_parent_hashes(LeafIndex(0), None).unwrap();
        tree.update_parent_hashes(LeafIndex(4), None).unwrap();

        tree
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tree_kem::leaf_node::test_utils::get_basic_test_node;
    use crate::tree_kem::leaf_node::LeafNodeSource;
    use crate::tree_kem::node::{NodeTypeResolver, NodeVec};
    use crate::tree_kem::parent_hash::test_utils::{get_test_tree_fig_12, test_parent_node};
    use crate::tree_kem::RatchetTreeError;
    use assert_matches::assert_matches;
    use tls_codec::Deserialize;

    #[cfg(target_arch = "wasm32")]
    use wasm_bindgen_test::wasm_bindgen_test as test;

    #[test]
    fn test_missing_parent_hash() {
        let cipher_suite = CipherSuite::Curve25519Aes128;

        let mut test_tree = get_test_tree_fig_12(cipher_suite);

        let test_key_package = get_basic_test_node(cipher_suite, "foo");

        let test_update_path = ValidatedUpdatePath {
            leaf_node: test_key_package,
            nodes: vec![],
        };

        let missing_parent_hash_res =
            test_tree.update_parent_hashes(LeafIndex(0), Some(&test_update_path));

        assert_matches!(
            missing_parent_hash_res,
            Err(RatchetTreeError::ParentHashNotFound)
        );
    }

    #[test]
    fn test_parent_hash_mismatch() {
        let cipher_suite = CipherSuite::Curve25519Aes128;

        let mut test_tree = get_test_tree_fig_12(cipher_suite);

        let test_key_package = get_basic_test_node(cipher_suite, "foo");

        let mut test_update_path = ValidatedUpdatePath {
            leaf_node: test_key_package,
            nodes: vec![],
        };

        let unexpected_parent_hash = ParentHash::from(hex!("f00d"));

        test_update_path.leaf_node.leaf_node_source =
            LeafNodeSource::Commit(unexpected_parent_hash);

        let invalid_parent_hash_res =
            test_tree.update_parent_hashes(LeafIndex(0), Some(&test_update_path));

        assert_matches!(
            invalid_parent_hash_res,
            Err(RatchetTreeError::ParentHashMismatch)
        );
    }

    #[test]
    fn test_parent_hash_invalid() {
        let cipher_suite = CipherSuite::Curve25519Aes128;

        let mut test_tree = get_test_tree_fig_12(cipher_suite);
        test_tree.nodes[2] = None;

        let res = test_tree.validate_parent_hashes();
        assert_matches!(res, Err(RatchetTreeError::ParentHashMismatch));
    }

    #[test]
    fn test_parent_hash_with_blanks() {
        // Create a tree with 4 blanks: leaves C and D, and their 2 ancestors.
        let cipher_suite = CipherSuite::Curve25519Aes128;

        let mut tree = TreeKemPublic::new(cipher_suite);

        let leaves = ["A", "B", "C", "D", "E", "F"]
            .map(|l| get_basic_test_node(cipher_suite, l))
            .to_vec();

        tree.add_leaves(leaves).unwrap();

        tree.nodes[1] = Some(test_parent_node(cipher_suite, vec![]));
        tree.nodes[7] = Some(test_parent_node(cipher_suite, vec![]));
        tree.nodes[9] = Some(test_parent_node(cipher_suite, vec![]));
        tree.nodes[4] = None;
        tree.nodes[6] = None;

        // Compute parent hashes after E commits and then A commits.
        tree.nodes
            .borrow_as_leaf_mut(LeafIndex(4))
            .unwrap()
            .leaf_node_source =
            LeafNodeSource::Commit(tree.update_parent_hashes(LeafIndex(4), None).unwrap());

        tree.nodes
            .borrow_as_leaf_mut(LeafIndex(0))
            .unwrap()
            .leaf_node_source =
            LeafNodeSource::Commit(tree.update_parent_hashes(LeafIndex(0), None).unwrap());

        assert!(tree.validate_parent_hashes().is_ok());
    }

    #[test]
    fn test_parent_hash_edge() {
        let cipher_suite = CipherSuite::Curve25519Aes128;

        let mut tree = TreeKemPublic::new(cipher_suite);

        let leaves = [
            "0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "10", "11", "12", "13",
        ]
        .map(|l| get_basic_test_node(cipher_suite, l))
        .to_vec();

        tree.add_leaves(leaves).unwrap();

        for i in [19, 23, 1, 3, 5, 9, 11, 13, 7, 15] {
            tree.nodes[i] = Some(test_parent_node(cipher_suite, vec![]));
        }

        for i in [16, 24] {
            tree.nodes[i] = None;
        }

        for i in [0, 2, 4, 6, 9] {
            tree.nodes
                .borrow_as_leaf_mut(LeafIndex(i))
                .unwrap()
                .leaf_node_source =
                LeafNodeSource::Commit(tree.update_parent_hashes(LeafIndex(i), None).unwrap());
        }

        for leaf_name in ["A", "B", "C"] {
            tree.add_leaves(vec![get_basic_test_node(cipher_suite, leaf_name)])
                .unwrap();
        }

        assert!(tree.validate_parent_hashes().is_ok());
    }

    #[derive(serde::Deserialize, serde::Serialize)]
    struct TestCase {
        cipher_suite: u16,
        #[serde(with = "hex::serde")]
        tree_data: Vec<u8>,
    }

    impl TestCase {
        fn generate() -> Vec<TestCase> {
            CipherSuite::all()
                .map(|cipher_suite| {
                    let tree = get_test_tree_fig_12(cipher_suite);

                    TestCase {
                        cipher_suite: cipher_suite as u16,
                        tree_data: tree.export_node_data().tls_serialize_detached().unwrap(),
                    }
                })
                .collect()
        }
    }

    fn load_test_cases() -> Vec<TestCase> {
        load_test_cases!(parent_hash, TestCase::generate)
    }

    #[test]
    fn test_parent_hash_test_vectors() {
        let cases = load_test_cases();

        for one_case in cases {
            let cipher_suite = CipherSuite::from_raw(one_case.cipher_suite);

            if cipher_suite.is_none() {
                println!("Skipping test for unsupported cipher suite");
                continue;
            }

            let tree = TreeKemPublic::import_node_data(
                cipher_suite.unwrap(),
                NodeVec::tls_deserialize(&mut &*one_case.tree_data).unwrap(),
            )
            .unwrap();

            for index in 0..tree.total_leaf_count() {
                if let LeafNodeSource::Commit(parent_hash) = &tree.nodes
                    [NodeIndex::from(LeafIndex(index)) as usize]
                    .as_leaf()
                    .unwrap()
                    .leaf_node_source
                {
                    let calculated_parent_hash = tree
                        .parent_hash_for_leaf(LeafIndex(index), |node_index, parent_hash| {
                            let expected_parent = &tree.nodes[node_index as usize]
                                .as_parent()
                                .unwrap()
                                .parent_hash;

                            assert_eq!(parent_hash, expected_parent);
                        })
                        .unwrap();

                    assert_eq!(&calculated_parent_hash, parent_hash);
                }
            }
        }
    }
}
