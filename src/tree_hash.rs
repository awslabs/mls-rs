use crate::ratchet_tree::{RatchetTree, RatchetTreeError};
use crate::key_package::KeyPackage;
use crate::tree_node::{Leaf, Node, Parent, NodeIndex, NodeTypeResolver};
use serde::{Serialize, Deserialize};
use crate::tree_math;

#[derive(Serialize, Deserialize)]
struct LeafNodeHashInput {
    node_index: u32,
    key_package: Option<KeyPackage>
}

#[derive(Serialize, Deserialize)]
struct ParentNodeTreeHashInput {
    node_index: u32,
    parent_node: Option<Parent>,
    left_hash: Vec<u8>,
    right_hash: Vec<u8>
}

trait TreeHashable {
    fn get_hash(&self, tree: &RatchetTree) -> Result<Vec<u8>, RatchetTreeError>;
}

impl TreeHashable for (NodeIndex, &Option<Node>) {
    fn get_hash(&self, tree: &RatchetTree) -> Result<Vec<u8>, RatchetTreeError> {
        match self.1 {
            None => {
                if self.0 % 2 == 0 {
                    (self.0, None::<&Leaf>).get_hash(tree)
                } else {
                    (self.0, None::<&Parent>).get_hash(tree)
                }
            },
            Some(_) => {
                if self.0 % 2 == 0 {
                    (self.0, Some(self.1.as_leaf()?)).get_hash(tree)
                } else {
                    (self.0, Some(self.1.as_parent()?)).get_hash(tree)
                }
            }
        }
    }
}

impl TreeHashable for (NodeIndex, Option<&Leaf>) {
    fn get_hash(&self, tree: &RatchetTree) -> Result<Vec<u8>, RatchetTreeError> {
        let input = LeafNodeHashInput {
            node_index: self.0 as u32,
            key_package: self.1.map(|l| l.key_package.clone())
        };
        tree.cipher_suite
            .hash(&bincode::serialize(&input)?)
            .map_err(|e| e.into())
    }
}

impl TreeHashable for (NodeIndex, Option<&Parent>) {
    fn get_hash(&self, tree: &RatchetTree) -> Result<Vec<u8>, RatchetTreeError> {
        let left = tree_math::left(self.0)?;
        let right = tree_math::right(self.0, tree.leaf_count())?;
        let left_hash = (left, &tree.nodes[left]).get_hash(tree)?;
        let right_hash = (right, &tree.nodes[right]).get_hash(tree)?;

        let input = ParentNodeTreeHashInput {
            node_index: self.0 as u32,
            parent_node: self.1.cloned(),
            left_hash,
            right_hash
        };

        tree.cipher_suite
            .hash(&bincode::serialize(&input)?)
            .map_err(|e| e.into())
    }
}

impl RatchetTree {
    pub fn tree_hash(&self) -> Result<Vec<u8>, RatchetTreeError> {
        let root = tree_math::root(self.leaf_count());
        (root, &self.nodes[root]).get_hash(self)
    }
}

#[cfg(test)]
mod test {
    use crate::tree_node::{Leaf, NodeTypeResolver, Parent, Node, LeafIndex};
    use crate::tree_hash::TreeHashable;

    use crate::ratchet_tree::test::{
        get_test_tree,
        get_test_key_packages
    };

    // Sanity check test to verify the input to the hash function isn't changing between releases
    // This is done with a mock hash that returns its input as output
    #[test]
    fn test_leaf_hash() {
        let test_tree = get_test_tree().0;
        let leaf = test_tree.nodes[0].as_leaf().unwrap();

        let hash = (0, Some(leaf)).get_hash(&test_tree).unwrap();
        let expected = hex!("0000000001ff2a0003000000000000006261720000000002000000000000\
                                      0034320300000000000000666f6f42000100000000000000010002000000\
                                      00000000181802000000000000002a2a");

        assert_eq!(expected, hash)
    }

    #[test]
    fn test_empty_leaf() {
        let mut test_tree = get_test_tree().0;
        test_tree.nodes[0] = None;

        let hash = (0, None::<&Leaf>).get_hash(&test_tree).unwrap();
        let expected = hex!("0000000000");

        assert_eq!(expected, hash)
    }

    // Sanity check test to verify the input to the hash function isn't changing between releases
    // This is done with a mock hash that returns its input as output
    #[test]
    fn test_parent_hash() {
        let mut test_tree = get_test_tree().0;
        let test_key_packages = get_test_key_packages();
        test_tree.add_nodes(vec![test_key_packages[0].clone()]).unwrap();

        let test_parent = Parent {
            public_key: vec![0u8;2],
            parent_hash: vec![1u8;2],
            unmerged_leaves: vec![LeafIndex(2)]
        };

        test_tree.nodes[1] = Some(Node::Parent(test_parent.clone()));

        let hash = (1, Some(&test_parent)).get_hash(&test_tree).unwrap();
        let expected = hex!("010000000102000000000000000000020000000000000001010100000000\
                                      00000002000000000000004c000000000000000000000001ff2a00030000\
                                      000000000062617200000000020000000000000034320300000000000000\
                                      666f6f420001000000000000000100020000000000000018180200000000\
                                      0000002a2a4b000000000000000200000001ff2a00040000000000000066\
                                      6f6f41000000000200000000000000343201000000000000004142000100\
                                      00000000000001000200000000000000181802000000000000002a2a");

        assert_eq!(hash, expected)
    }

    #[test]
    fn test_empty_parent() {
        let mut test_tree = get_test_tree().0;
        let test_key_packages = get_test_key_packages();
        test_tree.add_nodes(vec![test_key_packages[0].clone()]).unwrap();

        let hash = (1, None::<&Parent>).get_hash(&test_tree).unwrap();
        let expected = hex!("01000000004c000000000000000000000001ff2a00030000000000000062\
                                      617200000000020000000000000034320300000000000000666f6f420001\
                                      0000000000000001000200000000000000181802000000000000002a2a4b\
                                      000000000000000200000001ff2a000400000000000000666f6f41000000\
                                      000200000000000000343201000000000000004142000100000000000000\
                                      01000200000000000000181802000000000000002a2a");
        assert_eq!(hash, expected)
    }

    // Sanity check test to verify the input to the hash function isn't changing between releases
    // This is done with a mock hash that returns its input as output
    #[test]
    fn test_tree_hash() {
        let mut test_tree = get_test_tree().0;
        let test_key_packages = get_test_key_packages();
        test_tree.add_nodes(vec![test_key_packages[0].clone()]).unwrap();

        let hash =  test_tree.tree_hash().unwrap();
        let expected = hex!("01000000004c000000000000000000000001ff2a00030000000000000062\
                                      617200000000020000000000000034320300000000000000666f6f420001\
                                      0000000000000001000200000000000000181802000000000000002a2a4b\
                                      000000000000000200000001ff2a000400000000000000666f6f41000000\
                                      000200000000000000343201000000000000004142000100000000000000\
                                      01000200000000000000181802000000000000002a2a");

        assert_eq!(hash, expected)
    }
}