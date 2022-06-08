use super::leaf_node::LeafNode;
use super::node::{LeafIndex, NodeTypeResolver};
use crate::tree_kem::math as tree_math;
use crate::tree_kem::node::{Node, NodeIndex, Parent};
use crate::tree_kem::{RatchetTreeError, TreeKemPublic};
use std::ops::Deref;
use tls_codec::Serialize;
use tls_codec_derive::{TlsSerialize, TlsSize};

#[derive(Debug, TlsSerialize, TlsSize)]
struct LeafNodeHashInput<'a> {
    node_index: u32,
    leaf_node: Option<&'a LeafNode>,
}

#[derive(Debug, TlsSerialize, TlsSize)]
struct ParentNodeTreeHashInput<'a> {
    node_index: u32,
    parent_node: Option<&'a Parent>,
    #[tls_codec(with = "crate::tls::ByteVec")]
    left_hash: &'a [u8],
    #[tls_codec(with = "crate::tls::ByteVec")]
    right_hash: &'a [u8],
}

#[derive(Debug, TlsSerialize, TlsSize)]
#[repr(u8)]
enum TreeHashInput<'a> {
    #[tls_codec(discriminant = 1)]
    Leaf(LeafNodeHashInput<'a>),
    Parent(ParentNodeTreeHashInput<'a>),
}

trait TreeHashable {
    fn get_hash(&self, tree: &TreeKemPublic) -> Result<Vec<u8>, RatchetTreeError> {
        self.get_full_tree_hash(tree, tree.total_leaf_count(), &[])
    }

    fn get_full_tree_hash(
        &self,
        tree: &TreeKemPublic,
        full_size: u32,
        filtered_unmerged: &[LeafIndex],
    ) -> Result<Vec<u8>, RatchetTreeError>;
}

impl TreeHashable for (NodeIndex, &Option<Node>) {
    fn get_full_tree_hash(
        &self,
        tree: &TreeKemPublic,
        full_size: u32,
        filtered_unmerged: &[LeafIndex],
    ) -> Result<Vec<u8>, RatchetTreeError> {
        let (node_index, node) = *self;

        match node {
            None => {
                if tree_math::level(node_index) == 0 {
                    (node_index, None::<&LeafNode>).get_full_tree_hash(
                        tree,
                        full_size,
                        filtered_unmerged,
                    )
                } else {
                    (node_index, None::<&Parent>).get_full_tree_hash(
                        tree,
                        full_size,
                        filtered_unmerged,
                    )
                }
            }
            Some(_) => {
                if tree_math::level(node_index) == 0 {
                    (node_index, Some(node.as_leaf()?.deref())).get_full_tree_hash(
                        tree,
                        full_size,
                        filtered_unmerged,
                    )
                } else {
                    (node_index, Some(node.as_parent()?)).get_full_tree_hash(
                        tree,
                        full_size,
                        filtered_unmerged,
                    )
                }
            }
        }
    }
}

impl TreeHashable for (NodeIndex, Option<&LeafNode>) {
    fn get_full_tree_hash(
        &self,
        tree: &TreeKemPublic,
        _full_size: u32,
        filtered_unmerged: &[LeafIndex],
    ) -> Result<Vec<u8>, RatchetTreeError> {
        let input = TreeHashInput::Leaf(LeafNodeHashInput {
            node_index: self.0 as u32,
            leaf_node: if filtered_unmerged.contains(&LeafIndex((self.0 as u32) >> 1)) {
                None
            } else {
                self.1
            },
        });

        Ok(tree
            .cipher_suite
            .hash_function()
            .digest(&input.tls_serialize_detached()?))
    }
}

impl TreeHashable for (NodeIndex, Option<&Parent>) {
    fn get_full_tree_hash(
        &self,
        tree: &TreeKemPublic,
        full_size: u32,
        filtered_unmerged: &[LeafIndex],
    ) -> Result<Vec<u8>, RatchetTreeError> {
        let (node_index, parent_node) = *self;

        let left = tree_math::left(node_index)?;
        let right = tree_math::right(self.0, full_size)?;

        let left_node = tree.nodes.get(left as usize).unwrap_or(&None);
        let right_node = tree.nodes.get(right as usize).unwrap_or(&None);
        let left_hash = (left, left_node).get_full_tree_hash(tree, full_size, filtered_unmerged)?;

        let right_hash =
            (right, right_node).get_full_tree_hash(tree, full_size, filtered_unmerged)?;

        let mut parent_node = parent_node.cloned();

        if let Some(ref mut parent_node) = parent_node {
            parent_node
                .unmerged_leaves
                .retain(|unmerged_index| !filtered_unmerged.contains(unmerged_index));
        }

        let input = TreeHashInput::Parent(ParentNodeTreeHashInput {
            node_index,
            parent_node: parent_node.as_ref(),
            left_hash: &left_hash,
            right_hash: &right_hash,
        });

        Ok(tree
            .cipher_suite
            .hash_function()
            .digest(&input.tls_serialize_detached()?))
    }
}

impl TreeKemPublic {
    pub fn tree_hash(&self) -> Result<Vec<u8>, RatchetTreeError> {
        let root = tree_math::root(self.total_leaf_count());
        (root, &self.nodes[root as usize]).get_hash(self)
    }

    pub(super) fn original_full_tree_hash(
        &self,
        index: NodeIndex,
        unmerged_leaves: &[LeafIndex],
    ) -> Result<Vec<u8>, RatchetTreeError> {
        let node = self.nodes.get(index as usize).unwrap_or(&None);

        (index, node).get_full_tree_hash(
            self,
            self.total_leaf_count().next_power_of_two(),
            unmerged_leaves,
        )
    }
}

#[cfg(test)]
mod tests {
    use tls_codec::Deserialize;

    use crate::{
        cipher_suite::CipherSuite,
        tree_kem::{node::NodeVec, parent_hash::test_utils::get_test_tree_fig_12},
    };

    use super::*;

    #[cfg(target_arch = "wasm32")]
    use wasm_bindgen_test::wasm_bindgen_test as test;

    #[derive(serde::Deserialize, serde::Serialize)]
    struct TestCase {
        cipher_suite: u16,
        #[serde(with = "hex::serde")]
        tree_data: Vec<u8>,
        #[serde(with = "hex::serde")]
        tree_hash: Vec<u8>,
    }

    impl TestCase {
        fn generate() -> Vec<TestCase> {
            CipherSuite::all()
                .map(|cipher_suite| {
                    let tree = get_test_tree_fig_12(cipher_suite);

                    TestCase {
                        cipher_suite: cipher_suite as u16,
                        tree_data: tree.export_node_data().tls_serialize_detached().unwrap(),
                        tree_hash: tree.tree_hash().unwrap(),
                    }
                })
                .collect()
        }
    }

    fn load_test_cases() -> Vec<TestCase> {
        load_test_cases!(tree_hash, TestCase::generate)
    }

    #[test]
    fn test_tree_hash() {
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

            let calculated_hash = tree.tree_hash().unwrap();
            assert_eq!(calculated_hash, one_case.tree_hash);
        }
    }
}
