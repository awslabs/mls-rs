// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// Copyright by contributors to this project.
// SPDX-License-Identifier: (Apache-2.0 OR MIT)

use alloc::{borrow::Cow, vec::Vec};
use mls_rs_codec::{MlsDecode, MlsEncode, MlsSize};

use crate::{
    client::MlsError,
    tree_kem::{
        leaf_node::LeafNode,
        node::{LeafIndex, Node, NodeIndex, NodeVec, Parent},
    },
};

use super::Roster;

#[derive(Debug, MlsSize, MlsEncode, MlsDecode, PartialEq, Clone)]
pub struct ExportedTree<'a>(pub(crate) Cow<'a, NodeVec>);

impl<'a> ExportedTree<'a> {
    pub(crate) fn new(node_data: NodeVec) -> Self {
        Self(Cow::Owned(node_data))
    }

    pub(crate) fn new_borrowed(node_data: &'a NodeVec) -> Self {
        Self(Cow::Borrowed(node_data))
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, MlsError> {
        self.mls_encode_to_vec().map_err(Into::into)
    }

    pub fn byte_size(&self) -> usize {
        self.mls_encoded_len()
    }

    pub fn into_owned(self) -> ExportedTree<'static> {
        ExportedTree(Cow::Owned(self.0.into_owned()))
    }

    pub fn roster(&'a self) -> Roster<'a> {
        Roster {
            public_tree: &self.0,
        }
    }

    /// Returns a reference to the underlying vector of nodes in the tree.
    ///
    /// Each element is `None` for a blank node, or `Some(Node)` for an
    /// occupied leaf or parent node. Nodes are indexed by `NodeIndex` where
    /// even indices are leaves and odd indices are parent nodes.
    pub fn nodes(&self) -> &[Option<Node>] {
        &self.0
    }

    /// Returns the filtered direct path for a given leaf index as a vector
    /// of `Option<&Parent>` nodes.
    ///
    /// Per RFC 9420 Section 8.4, the filtered direct path removes all nodes
    /// whose child on the copath has an empty resolution. Each entry is `None`
    /// if the parent node at that position is blank, or `Some(&Parent)` if
    /// it is populated.
    pub fn filtered_direct_path(&self, index: LeafIndex) -> Result<Vec<Option<&Parent>>, MlsError> {
        let direct_copath = self.0.direct_copath(index);
        let filtered = self.0.filtered(index)?;

        let path = direct_copath
            .into_iter()
            .zip(filtered)
            .filter_map(|(cp, is_filtered)| {
                (!is_filtered).then(|| {
                    self.0
                        .get(cp.path as usize)
                        .and_then(Option::as_ref)
                        .and_then(|n| match n {
                            Node::Parent(p) => Some(p),
                            Node::Leaf(_) => None,
                        })
                })
            })
            .collect();

        Ok(path)
    }

    /// Returns the parent node at the given `NodeIndex`, or `None` if the
    /// node is blank or is a leaf node. Returns an error if the index is
    /// out of range.
    pub fn get_parent(&self, index: NodeIndex) -> Result<Option<&Parent>, MlsError> {
        let parent = self.0.borrow_node(index)?.as_ref().and_then(|n| match n {
            Node::Parent(p) => Some(p),
            Node::Leaf(_) => None,
        });

        Ok(parent)
    }

    /// Returns the leaf node at the given `LeafIndex`, or `None` if the
    /// leaf slot is blank. Returns an error if the index is out of range.
    pub fn get_leaf(&self, index: LeafIndex) -> Result<Option<&LeafNode>, MlsError> {
        let leaf = self
            .0
            .borrow_node(index.into())?
            .as_ref()
            .and_then(|n| match n {
                Node::Leaf(l) => Some(l),
                Node::Parent(_) => None,
            });

        Ok(leaf)
    }
}

impl ExportedTree<'static> {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, MlsError> {
        Self::mls_decode(&mut &*bytes).map_err(Into::into)
    }
}

impl From<ExportedTree<'_>> for NodeVec {
    fn from(value: ExportedTree) -> Self {
        value.0.into_owned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tree_kem::node::{test_utils::get_test_node_vec, NodeTypeResolver};

    #[maybe_async::test(not(mls_build_async), async(mls_build_async, crate::futures_test))]
    async fn test_exported_tree_accessors() {
        // The test tree (7 nodes, 4 leaf slots):
        //
        //        3
        //       / \
        //      1   5
        //     / \ / \
        //    0  2 4  6
        //    A  _  C  D
        //
        // Node 0: Leaf "A"
        // Node 1: None (blank parent)
        // Node 2: None (blank leaf)
        // Node 3: None (blank root)
        // Node 4: Leaf "C"
        // Node 5: Parent { key: "CD", unmerged_leaves: [2] }
        // Node 6: Leaf "D"
        let nodes = get_test_node_vec().await;
        let tree = ExportedTree::new(nodes.clone());

        assert_eq!(tree.nodes().len(), nodes.len());

        let leaf_a = tree.get_leaf(LeafIndex::unchecked(0)).unwrap().unwrap();
        assert_eq!(leaf_a, nodes[0].as_leaf().unwrap());

        // get_leaf for blank leaf
        let leaf_b = tree.get_leaf(LeafIndex::unchecked(1)).unwrap();
        assert!(leaf_b.is_none());

        // get_parent for occupied parent (node index 5)
        let parent = tree.get_parent(5).unwrap().unwrap();
        assert_eq!(parent, nodes[5].as_parent().unwrap());

        // get_parent for blank parent (node index 1)
        let blank_parent = tree.get_parent(1).unwrap();
        assert!(blank_parent.is_none());

        // get_parent on a leaf node returns None
        let not_parent = tree.get_parent(0).unwrap();
        assert!(not_parent.is_none());

        // filtered_direct_path for leaf 0:
        // Direct path is [1, 3], copath is [2, 5].
        // Node at index 1 is filtered out (copath node 2 has empty resolution).
        // Node at index 3 is kept (copath node 5 has non-empty resolution).
        // Node 3 is blank, so result is [None].
        let fdp = tree.filtered_direct_path(LeafIndex::unchecked(0)).unwrap();
        assert_eq!(fdp.len(), 1);
        assert!(fdp[0].is_none()); // node 3 is blank

        // filtered_direct_path for leaf 2 (node index 4, leaf "C"):
        // Direct path is [5, 3], copath is [6, 1].
        // Node 6 is leaf "D" (non-empty resolution) → node 5 kept.
        // Node 1 is blank, but leaf 0 "A" is in resolution of subtree → check.
        // Actually copath of node 3 is node 1, resolution of node 1 is [0] (leaf A).
        // So node 3 is NOT filtered. Both path nodes kept.
        let fdp2 = tree.filtered_direct_path(LeafIndex::unchecked(2)).unwrap();
        assert_eq!(fdp2.len(), 2);
        // Node 5 is the occupied parent
        assert_eq!(fdp2[0].unwrap().public_key.as_ref(), b"CD");
        // Node 3 is blank
        assert!(fdp2[1].is_none());
    }
}
