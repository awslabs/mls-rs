use crate::cipher_suite::CipherSuite;
use crate::tree_kem::math as tree_math;
use crate::tree_kem::math::TreeMathError;
use crate::tree_kem::node::{LeafIndex, Node, NodeIndex, NodeVecError, Parent};
use crate::tree_kem::RatchetTreeError;
use crate::tree_kem::TreeKemPublic;
use ferriscrypt::hpke::kem::HpkePublicKey;
use std::collections::HashMap;
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

#[derive(Clone, Debug, TlsDeserialize, TlsSerialize, TlsSize)]
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
        let original_tree_size = self.original_tree_size(node)?;

        let original_sibling_tree_hash = self.original_sub_tree_hash(
            co_path_child_index,
            original_tree_size,
            &node.unmerged_leaves,
        )?;

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
            .filtered_direct_path_co_path(index)?
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

    pub(super) fn validate_parent_hash(
        &self,
        node_index: NodeIndex,
        node: &Parent,
    ) -> Result<(), RatchetTreeError> {
        //Let L and R be the left and right children of P, respectively
        let mut r = tree_math::right(node_index, self.nodes.total_leaf_count())?;
        let l = tree_math::left(node_index)?;

        //If L.parent_hash is equal to the Parent Hash of P with Co-Path Child R, the check passes
        let parent_hash_right = self.parent_hash(&node.parent_hash, node_index, r)?;

        if let Some(l_node) = self.nodes.borrow_node(l)? {
            if l_node.get_parent_hash() == Some(parent_hash_right) {
                return Ok(());
            }
        }

        //If R is blank, replace R with its left child until R is either non-blank or a leaf node
        while self.nodes.is_blank(r)? && !self.nodes.is_leaf(r) {
            r = tree_math::left(r)?;
        }

        //If R is a blank leaf node, the check fails
        if self.nodes.is_leaf(r) && self.nodes.is_blank(r)? {
            return Err(RatchetTreeError::InvalidParentHash(
                "blank leaf".to_string(),
            ));
        }

        //If R.parent_hash is equal to the Parent Hash of P with Co-Path Child L, the check passes
        let parent_hash_left = self.parent_hash(&node.parent_hash, node_index, l)?;

        if let Some(r_node) = self.nodes.borrow_node(r)? {
            if r_node.get_parent_hash() == Some(parent_hash_left) {
                return Ok(());
            }
        }

        //Otherwise, the check fails
        Err(RatchetTreeError::InvalidParentHash(
            "no match found".to_string(),
        ))
    }
}

#[cfg(test)]
pub(crate) mod test_utils {
    use ferriscrypt::asym::ec_key::SecretKey;

    use crate::tree_kem::{
        leaf_node::test_utils::get_basic_test_node, leaf_node_validator::ValidatedLeafNode,
    };

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
            .map(|l| ValidatedLeafNode::from(get_basic_test_node(cipher_suite, l)))
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
    use crate::tree_kem::parent_hash::test_utils::{get_test_tree_fig_12, test_parent};
    use assert_matches::assert_matches;
    use tls_codec::Deserialize;

    #[cfg(target_arch = "wasm32")]
    use wasm_bindgen_test::wasm_bindgen_test as test;

    #[test]
    fn test_missing_parent_hash() {
        let cipher_suite = CipherSuite::Curve25519Aes128V1;

        let mut test_tree = get_test_tree_fig_12(cipher_suite);
        let test_key_package = get_basic_test_node(cipher_suite, "foo");

        let test_update_path = ValidatedUpdatePath {
            leaf_node: test_key_package.into(),
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
        let cipher_suite = CipherSuite::Curve25519Aes128V1;

        let mut test_tree = get_test_tree_fig_12(cipher_suite);

        let test_key_package = get_basic_test_node(cipher_suite, "foo");

        let mut test_update_path = ValidatedUpdatePath {
            leaf_node: test_key_package.into(),
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
        let cipher_suite = CipherSuite::Curve25519Aes128V1;

        let mut test_tree = get_test_tree_fig_12(cipher_suite);
        test_tree.nodes[2] = None;

        let res = test_tree.validate_parent_hash(1, &test_parent(cipher_suite, vec![]));
        assert_matches!(res, Err(RatchetTreeError::InvalidParentHash(_)));
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
