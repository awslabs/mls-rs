use std::ops::Deref;

use crate::tree_kem::math as tree_math;
use crate::tree_kem::node::{Node, NodeIndex, Parent};
use crate::tree_kem::{RatchetTreeError, TreeKemPublic};
use tls_codec::Serialize;
use tls_codec_derive::{TlsDeserialize, TlsSerialize, TlsSize};

use super::leaf_node::LeafNode;
use super::node::NodeTypeResolver;

#[derive(TlsSerialize, TlsSize)]
struct LeafNodeHashInput<'a> {
    node_index: u32,
    leaf_node: Option<&'a LeafNode>,
}

#[derive(TlsDeserialize, TlsSerialize, TlsSize)]
struct ParentNodeTreeHashInput {
    node_index: u32,
    parent_node: Option<Parent>,
    #[tls_codec(with = "crate::tls::ByteVec")]
    left_hash: Vec<u8>,
    #[tls_codec(with = "crate::tls::ByteVec")]
    right_hash: Vec<u8>,
}

trait TreeHashable {
    fn get_hash(&self, tree: &TreeKemPublic) -> Result<Vec<u8>, RatchetTreeError>;
}

impl TreeHashable for (NodeIndex, &Option<Node>) {
    fn get_hash(&self, tree: &TreeKemPublic) -> Result<Vec<u8>, RatchetTreeError> {
        match self.1 {
            None => {
                if self.0 % 2 == 0 {
                    (self.0, None::<&LeafNode>).get_hash(tree)
                } else {
                    (self.0, None::<&Parent>).get_hash(tree)
                }
            }
            Some(_) => {
                if self.0 % 2 == 0 {
                    (self.0, Some(self.1.as_leaf()?.deref())).get_hash(tree)
                } else {
                    (self.0, Some(self.1.as_parent()?)).get_hash(tree)
                }
            }
        }
    }
}

impl TreeHashable for (NodeIndex, Option<&LeafNode>) {
    fn get_hash(&self, tree: &TreeKemPublic) -> Result<Vec<u8>, RatchetTreeError> {
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
    fn get_hash(&self, tree: &TreeKemPublic) -> Result<Vec<u8>, RatchetTreeError> {
        let left = tree_math::left(self.0)?;
        let right = tree_math::right(self.0, tree.total_leaf_count())?;
        let left_hash = (left, &tree.nodes[left as usize]).get_hash(tree)?;
        let right_hash = (right, &tree.nodes[right as usize]).get_hash(tree)?;

        let input = ParentNodeTreeHashInput {
            node_index: self.0 as u32,
            parent_node: self.1.cloned(),
            left_hash,
            right_hash,
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
}

#[cfg(test)]
mod tests {
    // use super::*;
    // use crate::tree_kem::node::LeafIndex;
    // use crate::tree_kem::parent_hash::ParentHash;
    // use crate::tree_kem::test::{get_test_key_packages, get_test_tree};

    // #[cfg(target_arch = "wasm32")]
    // use wasm_bindgen_test::wasm_bindgen_test as test;

    // Sanity check test to verify the input to the hash function isn't changing between releases
    // This is done with a mock hash that returns its input as output
    // #[test]
    // fn test_leaf_hash() {
    //     let test_tree = get_test_tree().0;
    //     let leaf = test_tree.nodes[0].as_leaf().unwrap();
    //     let hash = (0, Some(leaf)).get_hash(&test_tree).unwrap();
    //
    //     let expected = hex!("3f57a57f6fc7bee186e67bfdd8aa84431ad8406033bc31be14c8e86d543e570e");
    //
    //     assert_eq!(expected, hash)
    // }
    //
    // #[test]
    // fn test_empty_leaf() {
    //     let mut test_tree = get_test_tree().0;
    //     test_tree.nodes[0] = None;
    //
    //     let hash = (0, None::<&Leaf>).get_hash(&test_tree).unwrap();
    //
    //     let expected = hex!("8855508aade16ec573d21e6a485dfd0a7624085c1a14b5ecdd6485de0c6839a4");
    //
    //     assert_eq!(expected, hash)
    // }
    //
    // // Sanity check test to verify the input to the hash function isn't changing between releases
    // // This is done with a mock hash that returns its input as output
    // #[test]
    // fn test_parent_hash() {
    //     let mut test_tree = get_test_tree().0;
    //     let test_key_packages = get_test_key_packages();
    //     test_tree
    //         .add_nodes(vec![test_key_packages[0].clone()])
    //         .unwrap();
    //
    //     let test_parent = Parent {
    //         public_key: vec![0u8; 2],
    //         parent_hash: ParentHash::from(vec![1u8; 2]),
    //         unmerged_leaves: vec![LeafIndex(2)],
    //     };
    //
    //     test_tree.nodes[1] = Some(Node::Parent(test_parent.clone()));
    //
    //     let hash = (1, Some(&test_parent)).get_hash(&test_tree).unwrap();
    //
    //     let expected = hex!("413c6bfce4aae0ca5ea11e0717c1776e17d3c7222973abc502f818c71fd0c9b6");
    //
    //     assert_eq!(hash, expected)
    // }
    //
    // #[test]
    // fn test_empty_parent() {
    //     let mut test_tree = get_test_tree().0;
    //     let test_key_packages = get_test_key_packages();
    //     test_tree
    //         .add_nodes(vec![test_key_packages[0].clone()])
    //         .unwrap();
    //
    //     let hash = (1, None::<&Parent>).get_hash(&test_tree).unwrap();
    //
    //     let expected = hex!("6ab23496612c266ccf7222bb7e3e21255574393e91d89ba0efd9f9147d5851d6");
    //     assert_eq!(hash, expected)
    // }
    //
    // // Sanity check test to verify the input to the hash function isn't changing between releases
    // // This is done with a mock hash that returns its input as output
    // #[test]
    // fn test_tree_hash() {
    //     let mut test_tree = get_test_tree().0;
    //     let test_key_packages = get_test_key_packages();
    //     test_tree
    //         .add_nodes(vec![test_key_packages[0].clone()])
    //         .unwrap();
    //
    //     let hash = test_tree.tree_hash().unwrap();
    //
    //     let expected = hex!("6ab23496612c266ccf7222bb7e3e21255574393e91d89ba0efd9f9147d5851d6");
    //
    //     assert_eq!(hash, expected)
    // }

    //TODO: Re-Enable these tests for each cipher suite once TLS encoding is done and proper test vectors can be generated
}
