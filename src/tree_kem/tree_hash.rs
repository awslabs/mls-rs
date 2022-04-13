use super::leaf_node::LeafNode;
use super::node::{LeafIndex, NodeTypeResolver};
use crate::tree_kem::math as tree_math;
use crate::tree_kem::node::{Node, NodeIndex, Parent};
use crate::tree_kem::{RatchetTreeError, TreeKemPublic};
use std::ops::Deref;
use tls_codec::Serialize;
use tls_codec_derive::{TlsSerialize, TlsSize};

#[derive(TlsSerialize, TlsSize)]
struct LeafNodeHashInput<'a> {
    node_index: u32,
    leaf_node: Option<&'a LeafNode>,
}

#[derive(TlsSerialize, TlsSize)]
struct ParentNodeTreeHashInput<'a> {
    node_index: u32,
    parent_node: Option<&'a Parent>,
    #[tls_codec(with = "crate::tls::ByteVec")]
    left_hash: &'a [u8],
    #[tls_codec(with = "crate::tls::ByteVec")]
    right_hash: &'a [u8],
}

trait TreeHashable {
    fn get_hash(&self, tree: &TreeKemPublic) -> Result<Vec<u8>, RatchetTreeError> {
        self.get_filtered_hash(tree, tree.total_leaf_count(), &[])
    }

    fn get_filtered_hash(
        &self,
        tree: &TreeKemPublic,
        filtered_size: u32,
        filtered_unmerged: &[LeafIndex],
    ) -> Result<Vec<u8>, RatchetTreeError>;
}

impl TreeHashable for (NodeIndex, &Option<Node>) {
    fn get_filtered_hash(
        &self,
        tree: &TreeKemPublic,
        original_size: u32,
        filtered_unmerged: &[LeafIndex],
    ) -> Result<Vec<u8>, RatchetTreeError> {
        let (node_index, node) = *self;

        match node {
            None => {
                if tree_math::level(node_index) == 0 {
                    (node_index, None::<&LeafNode>).get_filtered_hash(
                        tree,
                        original_size,
                        filtered_unmerged,
                    )
                } else {
                    (node_index, None::<&Parent>).get_hash(tree)
                }
            }
            Some(_) => {
                if tree_math::level(node_index) == 0 {
                    (node_index, Some(node.as_leaf()?.deref())).get_filtered_hash(
                        tree,
                        original_size,
                        filtered_unmerged,
                    )
                } else {
                    (node_index, Some(node.as_parent()?)).get_filtered_hash(
                        tree,
                        original_size,
                        filtered_unmerged,
                    )
                }
            }
        }
    }
}

impl TreeHashable for (NodeIndex, Option<&LeafNode>) {
    fn get_filtered_hash(
        &self,
        tree: &TreeKemPublic,
        _original_size: u32,
        _filtered_unmerged: &[LeafIndex],
    ) -> Result<Vec<u8>, RatchetTreeError> {
        let input = LeafNodeHashInput {
            node_index: self.0 as u32,
            leaf_node: self.1,
        };

        Ok(tree
            .cipher_suite
            .hash_function()
            .digest(&input.tls_serialize_detached()?))
    }
}

impl TreeHashable for (NodeIndex, Option<&Parent>) {
    fn get_filtered_hash(
        &self,
        tree: &TreeKemPublic,
        original_size: u32,
        filtered_unmerged: &[LeafIndex],
    ) -> Result<Vec<u8>, RatchetTreeError> {
        let (node_index, parent_node) = *self;

        let left = tree_math::left(node_index)?;
        let right = tree_math::right(self.0, original_size)?;
        let left_hash = (left, &tree.nodes[left as usize]).get_hash(tree)?;
        let right_hash = (right, &tree.nodes[right as usize]).get_hash(tree)?;

        let mut parent_node = parent_node.cloned();

        if let Some(ref mut parent_node) = parent_node {
            parent_node
                .unmerged_leaves
                .retain(|unmerged_index| !filtered_unmerged.contains(unmerged_index));
        }

        let input = ParentNodeTreeHashInput {
            node_index,
            parent_node: parent_node.as_ref(),
            left_hash: &left_hash,
            right_hash: &right_hash,
        };

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

    pub(super) fn original_tree_size(&self, parent_node: &Parent) -> Result<u32, RatchetTreeError> {
        let mut original_size = self.total_leaf_count();

        while parent_node
            .unmerged_leaves
            .contains(&LeafIndex(original_size - 1))
        {
            original_size -= 1
        }

        Ok(original_size)
    }

    pub(super) fn original_sub_tree_hash(
        &self,
        index: NodeIndex,
        original_tree_size: u32,
        unmerged_leaves: &[LeafIndex],
    ) -> Result<Vec<u8>, RatchetTreeError> {
        (index, &self.nodes[index as usize]).get_filtered_hash(
            self,
            original_tree_size,
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
