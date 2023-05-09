use super::leaf_node::LeafNode;
use crate::client::MlsError;
use crate::crypto::HpkePublicKey;
use crate::tree_kem::math as tree_math;
use crate::tree_kem::parent_hash::ParentHash;
use alloc::vec;
use alloc::vec::Vec;
use aws_mls_codec::{MlsDecode, MlsEncode, MlsSize};
use core::hash::Hash;
use core::ops::{Deref, DerefMut};
use serde_with::serde_as;

#[cfg(feature = "std")]
use std::collections::HashSet;

#[cfg(not(feature = "std"))]
use alloc::collections::BTreeSet;

#[serde_as]
#[derive(
    Clone, Debug, PartialEq, MlsSize, MlsEncode, MlsDecode, serde::Deserialize, serde::Serialize,
)]
pub(crate) struct Parent {
    pub public_key: HpkePublicKey,
    pub parent_hash: ParentHash,
    pub unmerged_leaves: Vec<LeafIndex>,
}

#[derive(
    Clone,
    Copy,
    Debug,
    Ord,
    PartialEq,
    PartialOrd,
    Hash,
    Eq,
    MlsSize,
    MlsEncode,
    MlsDecode,
    serde::Deserialize,
    serde::Serialize,
)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct LeafIndex(pub(crate) u32);

impl LeafIndex {
    pub fn new(i: u32) -> Self {
        Self(i)
    }
}

impl Deref for LeafIndex {
    type Target = u32;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl From<&LeafIndex> for NodeIndex {
    fn from(leaf_index: &LeafIndex) -> Self {
        leaf_index.0 * 2
    }
}

impl From<LeafIndex> for NodeIndex {
    fn from(leaf_index: LeafIndex) -> Self {
        leaf_index.0 * 2
    }
}

impl LeafIndex {
    pub(crate) fn direct_path(&self, leaf_count: u32) -> Result<Vec<NodeIndex>, MlsError> {
        tree_math::direct_path(NodeIndex::from(self), leaf_count)
    }

    fn copath(&self, leaf_count: u32) -> Result<Vec<NodeIndex>, MlsError> {
        tree_math::copath(NodeIndex::from(self), leaf_count)
    }
}

pub(crate) type NodeIndex = u32;

#[derive(
    Clone, Debug, PartialEq, MlsSize, MlsEncode, MlsDecode, serde::Deserialize, serde::Serialize,
)]
#[allow(clippy::large_enum_variant)]
#[repr(u8)]
//TODO: Research if this should actually be a Box<Leaf> for memory / performance reasons
pub(crate) enum Node {
    Leaf(LeafNode) = 1u8,
    Parent(Parent) = 2u8,
}

impl Node {
    pub fn public_key(&self) -> &HpkePublicKey {
        match self {
            Node::Parent(p) => &p.public_key,
            Node::Leaf(l) => &l.public_key,
        }
    }
}

impl From<Parent> for Option<Node> {
    fn from(p: Parent) -> Self {
        Node::from(p).into()
    }
}

impl From<LeafNode> for Option<Node> {
    fn from(l: LeafNode) -> Self {
        Node::from(l).into()
    }
}

impl From<Parent> for Node {
    fn from(p: Parent) -> Self {
        Node::Parent(p)
    }
}

impl From<LeafNode> for Node {
    fn from(l: LeafNode) -> Self {
        Node::Leaf(l)
    }
}

pub(crate) trait NodeTypeResolver {
    fn as_parent(&self) -> Result<&Parent, MlsError>;
    fn as_parent_mut(&mut self) -> Result<&mut Parent, MlsError>;
    fn as_leaf(&self) -> Result<&LeafNode, MlsError>;
    fn as_leaf_mut(&mut self) -> Result<&mut LeafNode, MlsError>;
    fn as_non_empty(&self) -> Result<&Node, MlsError>;
}

impl NodeTypeResolver for Option<Node> {
    fn as_parent(&self) -> Result<&Parent, MlsError> {
        self.as_ref()
            .and_then(|n| match n {
                Node::Parent(p) => Some(p),
                Node::Leaf(_) => None,
            })
            .ok_or(MlsError::ExpectedParentNode)
    }

    fn as_parent_mut(&mut self) -> Result<&mut Parent, MlsError> {
        self.as_mut()
            .and_then(|n| match n {
                Node::Parent(p) => Some(p),
                Node::Leaf(_) => None,
            })
            .ok_or(MlsError::ExpectedParentNode)
    }

    fn as_leaf(&self) -> Result<&LeafNode, MlsError> {
        self.as_ref()
            .and_then(|n| match n {
                Node::Parent(_) => None,
                Node::Leaf(l) => Some(l),
            })
            .ok_or(MlsError::ExpectedLeafNode)
    }

    fn as_leaf_mut(&mut self) -> Result<&mut LeafNode, MlsError> {
        self.as_mut()
            .and_then(|n| match n {
                Node::Parent(_) => None,
                Node::Leaf(l) => Some(l),
            })
            .ok_or(MlsError::ExpectedLeafNode)
    }

    fn as_non_empty(&self) -> Result<&Node, MlsError> {
        self.as_ref().ok_or(MlsError::UnexpectedEmptyNode)
    }
}

#[derive(
    Clone,
    Debug,
    PartialEq,
    MlsSize,
    MlsEncode,
    MlsDecode,
    Default,
    serde::Deserialize,
    serde::Serialize,
)]
pub(crate) struct NodeVec(Vec<Option<Node>>);

impl From<Vec<Option<Node>>> for NodeVec {
    fn from(x: Vec<Option<Node>>) -> Self {
        NodeVec(x)
    }
}

impl Deref for NodeVec {
    type Target = Vec<Option<Node>>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for NodeVec {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl NodeVec {
    #[cfg(any(test, feature = "custom_proposal", feature = "tree_index"))]
    pub fn occupied_leaf_count(&self) -> u32 {
        self.non_empty_leaves().count() as u32
    }

    pub fn total_leaf_count(&self) -> u32 {
        (self.len() as u32 / 2 + 1).next_power_of_two()
    }

    #[inline]
    pub fn borrow_node(&self, index: NodeIndex) -> Result<&Option<Node>, MlsError> {
        Ok(self.get(self.validate_index(index)?).unwrap_or(&None))
    }

    fn validate_index(&self, index: NodeIndex) -> Result<usize, MlsError> {
        if (index as usize) >= self.len().next_power_of_two() {
            Err(MlsError::InvalidNodeIndex(index))
        } else {
            Ok(index as usize)
        }
    }

    fn empty_leaves_from(
        &mut self,
        start: LeafIndex,
    ) -> impl Iterator<Item = (LeafIndex, &mut Option<Node>)> {
        self.iter_mut()
            .step_by(2)
            .enumerate()
            .skip(start.0 as usize)
            .filter(|(_, n)| n.is_none())
            .map(|(i, n)| (LeafIndex(i as u32), n))
    }

    #[cfg(test)]
    fn empty_leaves(&mut self) -> impl Iterator<Item = (LeafIndex, &mut Option<Node>)> {
        self.empty_leaves_from(LeafIndex(0))
    }

    pub fn non_empty_leaves(&self) -> impl Iterator<Item = (LeafIndex, &LeafNode)> + '_ {
        self.iter()
            .enumerate()
            .step_by(2)
            .map(|(i, n)| (LeafIndex(i as u32 / 2), n))
            .filter_map(|(i, n)| n.as_leaf().ok().map(|l| (i, l)))
    }

    pub fn non_empty_parents(&self) -> impl Iterator<Item = (NodeIndex, &Parent)> + '_ {
        self.iter()
            .enumerate()
            .skip(1)
            .step_by(2)
            .map(|(i, n)| (i as NodeIndex, n))
            .filter_map(|(i, n)| n.as_parent().ok().map(|p| (i, p)))
    }

    #[inline]
    pub fn direct_path(&self, index: LeafIndex) -> Result<Vec<NodeIndex>, MlsError> {
        // Direct path from leaf to root
        index.direct_path(self.total_leaf_count())
    }

    pub fn filtered_direct_path(&self, index: LeafIndex) -> Result<Vec<NodeIndex>, MlsError> {
        Ok(self
            .filtered_direct_path_co_path(index)?
            .into_iter()
            .map(|(dp, _)| dp)
            .collect())
    }

    // Section 8.4
    // The filtered direct path of a node is obtained from the node's direct path by removing
    // all nodes whose child on the nodes's copath has an empty resolution
    pub fn filtered_direct_path_co_path(
        &self,
        index: LeafIndex,
    ) -> Result<Vec<(NodeIndex, NodeIndex)>, MlsError> {
        index
            .direct_path(self.total_leaf_count())?
            .into_iter()
            .zip(index.copath(self.total_leaf_count())?)
            .filter_map(|(dp, cp)| {
                if self.is_resolution_empty(cp) {
                    None
                } else {
                    Some(Ok((dp, cp)))
                }
            })
            .collect()
    }

    #[inline]
    pub fn is_blank(&self, index: NodeIndex) -> Result<bool, MlsError> {
        self.borrow_node(index).map(|n| n.is_none())
    }

    #[inline]
    pub fn is_leaf(&self, index: NodeIndex) -> bool {
        index % 2 == 0
    }

    // Blank a previously filled leaf node, and return the existing leaf
    pub fn blank_leaf_node(&mut self, leaf_index: LeafIndex) -> Result<Option<LeafNode>, MlsError> {
        let node_index = NodeIndex::from(leaf_index);
        let blanked_leaf = self.blank_node(node_index)?.and_then(|node| match node {
            Node::Leaf(l) => Some(l),
            Node::Parent(_) => None,
        });

        Ok(blanked_leaf)
    }

    pub fn blank_node(&mut self, node_index: NodeIndex) -> Result<Option<Node>, MlsError> {
        let index = self.validate_index(node_index)?;
        Ok(self.get_mut(index).and_then(Option::take))
    }

    pub fn blank_direct_path(&mut self, leaf: LeafIndex) -> Result<Vec<Option<Node>>, MlsError> {
        self.direct_path(leaf)?
            .iter()
            .map(|&index| self.blank_node(index))
            .collect()
    }

    // Remove elements until the last leaf is non-blank
    pub fn trim(&mut self) {
        // Find the last full leaf
        let last_full = self
            .iter()
            .enumerate()
            .rev()
            .step_by(2)
            .find(|(_, node)| node.is_some())
            .map(|r| r.0);

        // Truncate the node vector to the last full leaf
        if let Some(last_full) = last_full {
            self.truncate(last_full + 1)
        }
    }

    pub fn borrow_as_parent(&self, node_index: NodeIndex) -> Result<&Parent, MlsError> {
        self.borrow_node(node_index).and_then(|n| n.as_parent())
    }

    pub fn borrow_as_parent_mut(&mut self, node_index: NodeIndex) -> Result<&mut Parent, MlsError> {
        let index = self.validate_index(node_index)?;

        self.get_mut(index)
            .ok_or(MlsError::InvalidNodeIndex(node_index))?
            .as_parent_mut()
    }

    pub fn borrow_as_leaf_mut(&mut self, index: LeafIndex) -> Result<&mut LeafNode, MlsError> {
        let node_index = NodeIndex::from(index);
        let index = self.validate_index(node_index)?;

        self.get_mut(index)
            .ok_or(MlsError::InvalidNodeIndex(node_index))?
            .as_leaf_mut()
    }

    pub fn borrow_as_leaf(&self, index: LeafIndex) -> Result<&LeafNode, MlsError> {
        let node_index = NodeIndex::from(index);
        self.borrow_node(node_index).and_then(|n| n.as_leaf())
    }

    pub fn borrow_or_fill_node_as_parent(
        &mut self,
        node_index: NodeIndex,
        public_key: &HpkePublicKey,
    ) -> Result<&mut Parent, MlsError> {
        let index = self.validate_index(node_index)?;

        while self.len() <= index {
            self.push(None);
        }

        self.get_mut(index)
            .ok_or(MlsError::InvalidNodeIndex(node_index))
            .and_then(|n| {
                if n.is_none() {
                    *n = Parent {
                        public_key: public_key.clone(),
                        parent_hash: ParentHash::empty(),
                        unmerged_leaves: vec![],
                    }
                    .into();
                }
                n.as_parent_mut()
            })
    }

    pub fn get_resolution_index(&self, index: NodeIndex) -> Result<Vec<NodeIndex>, MlsError> {
        match self.get(index as usize) {
            None | Some(None) => {
                // This node is blank
                if tree_math::level(index) == 0 {
                    // Node is a leaf {
                    Ok(Vec::new()) // Resolution of a blank leaf node is empty list
                } else {
                    // Resolution of a blank intermediate is is the result of concatenating the
                    // resolution of its left and right children
                    Ok([
                        self.get_resolution_index(tree_math::left(index)?)?,
                        self.get_resolution_index(tree_math::right(index)?)?,
                    ]
                    .concat())
                }
            }
            Some(Some(node)) => {
                // Resolution of a non blank node comprises the node itself + unmerged leaves
                match node {
                    Node::Parent(parent) => {
                        let mut ret = vec![index];
                        let unmerged = parent.unmerged_leaves.iter().map(NodeIndex::from);
                        ret.extend(unmerged);
                        Ok(ret)
                    }
                    Node::Leaf(_) => Ok(vec![index]),
                }
            }
        }
    }

    pub fn get_resolution(
        &self,
        node_index: NodeIndex,
        excluding: &[LeafIndex],
    ) -> Result<Vec<&Node>, MlsError> {
        let excluding = excluding.iter().map(NodeIndex::from);

        #[cfg(feature = "std")]
        let excluding = excluding.collect::<HashSet<NodeIndex>>();
        #[cfg(not(feature = "std"))]
        let excluding = excluding.collect::<BTreeSet<NodeIndex>>();

        self.get_resolution_index(node_index)?
            .into_iter()
            .filter(|i| !excluding.contains(i))
            .map(|i| self.borrow_node(i).and_then(|n| n.as_non_empty()))
            .collect()
    }

    pub fn is_resolution_empty(&self, index: NodeIndex) -> bool {
        match self.get(index as usize) {
            Some(Some(_)) => false,
            _ if self.is_leaf(index) => true,
            _ => {
                // Left and right return an error only if `index` is a leaf, so it's safe to unwrap.
                self.is_resolution_empty(tree_math::left(index).unwrap())
                    && self.is_resolution_empty(tree_math::right(index).unwrap())
            }
        }
    }

    /// If `start` is a valid leaf index for the current tree, inserts a leaf at the first blank
    /// leaf at or after `start`, extending the tree if necessary.
    ///
    /// If `start` is larger than or equal to the current number of leaves, inserts a leaf after the
    /// last leaf.
    pub fn insert_leaf(&mut self, start: LeafIndex, leaf: LeafNode) -> LeafIndex {
        if let Some((i, node)) = self.empty_leaves_from(start).next() {
            *node = Some(leaf.into());
            return i;
        }

        if !self.is_empty() {
            self.push(None);
        }

        self.push(Some(leaf.into()));
        LeafIndex(self.len() as u32 / 2)
    }
}

#[cfg(test)]
pub(crate) mod test_utils {
    use super::*;
    use crate::{
        client::test_utils::TEST_CIPHER_SUITE, tree_kem::leaf_node::test_utils::get_basic_test_node,
    };

    pub(crate) async fn get_test_node_vec() -> NodeVec {
        let nodes: Vec<Option<Node>> = vec![
            get_basic_test_node(TEST_CIPHER_SUITE, "A").await.into(),
            None,
            None,
            None,
            get_basic_test_node(TEST_CIPHER_SUITE, "C").await.into(),
            Parent {
                public_key: b"CD".to_vec().into(),
                parent_hash: ParentHash::empty(),
                unmerged_leaves: vec![LeafIndex(2)],
            }
            .into(),
            get_basic_test_node(TEST_CIPHER_SUITE, "D").await.into(),
        ];

        NodeVec::from(nodes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        client::test_utils::TEST_CIPHER_SUITE,
        tree_kem::{
            leaf_node::test_utils::get_basic_test_node, node::test_utils::get_test_node_vec,
        },
    };

    #[cfg(target_arch = "wasm32")]
    use wasm_bindgen_test::wasm_bindgen_test as test;

    #[cfg(not(target_arch = "wasm32"))]
    use futures_test::test;

    #[test]
    async fn node_key_getters() {
        let test_node_parent: Node = Parent {
            public_key: b"pub".to_vec().into(),
            parent_hash: ParentHash::empty(),
            unmerged_leaves: vec![],
        }
        .into();

        let test_leaf = get_basic_test_node(TEST_CIPHER_SUITE, "B").await;
        let test_node_leaf: Node = test_leaf.clone().into();

        assert_eq!(test_node_parent.public_key().as_ref(), b"pub");
        assert_eq!(test_node_leaf.public_key(), &test_leaf.public_key);
    }

    #[test]
    async fn test_empty_leaves() {
        let mut test_vec = get_test_node_vec().await;
        let mut test_vec_clone = get_test_node_vec().await;
        let empty_leaves: Vec<(LeafIndex, &mut Option<Node>)> = test_vec.empty_leaves().collect();
        assert_eq!(
            [(LeafIndex(1), &mut test_vec_clone[2])].as_ref(),
            empty_leaves.as_slice()
        );
    }

    #[test]
    async fn test_direct_path() {
        let test_vec = get_test_node_vec().await;
        // Tree math is already tested in that module, just ensure equality
        let expected = tree_math::direct_path(0, 4).unwrap();
        let actual = test_vec.direct_path(LeafIndex(0)).unwrap();
        assert_eq!(actual, expected);
    }

    #[test]
    async fn test_filtered_direct_path() {
        let test_vec = get_test_node_vec().await;
        let expected = [3];
        let actual = test_vec.filtered_direct_path(LeafIndex(0)).unwrap();
        assert_eq!(actual, expected);
    }

    #[test]
    async fn test_filtered_direct_path_co_path() {
        let test_vec = get_test_node_vec().await;
        let expected = [(3, 5)];
        let actual = test_vec.filtered_direct_path_co_path(LeafIndex(0)).unwrap();
        assert_eq!(actual, expected);
    }

    #[test]
    async fn test_get_parent_node() {
        let mut test_vec = get_test_node_vec().await;

        // If the node is a leaf it should fail
        assert!(test_vec.borrow_as_parent_mut(0).is_err());

        // If the node index is out of range it should fail
        assert!(test_vec
            .borrow_as_parent_mut(test_vec.len() as u32)
            .is_err());

        // Otherwise it should succeed
        let mut expected = Parent {
            public_key: b"CD".to_vec().into(),
            parent_hash: ParentHash::empty(),
            unmerged_leaves: vec![LeafIndex(2)],
        };

        assert_eq!(test_vec.borrow_as_parent_mut(5).unwrap(), &mut expected);
    }

    #[test]
    async fn test_get_resolution() {
        let test_vec = get_test_node_vec().await;

        let resolution_node_5 = test_vec.get_resolution(5, &[]).unwrap();
        let resolution_node_2 = test_vec.get_resolution(2, &[]).unwrap();
        let resolution_node_3 = test_vec.get_resolution(3, &[]).unwrap();

        let expected_5: Vec<Node> = [
            test_vec[5].as_ref().unwrap().clone(),
            test_vec[4].as_ref().unwrap().clone(),
        ]
        .to_vec();

        let expected_2: Vec<&Node> = [].to_vec();

        let expected_3: Vec<Node> = [
            test_vec[0].as_ref().unwrap().clone(),
            test_vec[5].as_ref().unwrap().clone(),
            test_vec[4].as_ref().unwrap().clone(),
        ]
        .to_vec();

        assert_eq!(resolution_node_5, expected_5.iter().collect::<Vec<&Node>>());
        assert_eq!(resolution_node_2, expected_2);
        assert_eq!(resolution_node_3, expected_3.iter().collect::<Vec<&Node>>());
    }

    #[test]
    async fn test_resolution_filter() {
        let test_vec = get_test_node_vec().await;
        let resolution_node_5 = test_vec.get_resolution(5, &[LeafIndex(2)]).unwrap();
        let expected_5: Vec<Node> = [test_vec[5].as_ref().unwrap().clone()].to_vec();

        assert_eq!(resolution_node_5, expected_5.iter().collect::<Vec<&Node>>());
    }

    #[test]
    async fn test_get_or_fill_existing() {
        let mut test_vec = get_test_node_vec().await;
        let mut test_vec2 = test_vec.clone();

        let expected = test_vec[5].as_parent_mut().unwrap();
        let actual = test_vec2
            .borrow_or_fill_node_as_parent(5, &Vec::new().into())
            .unwrap();

        assert_eq!(actual, expected);
    }

    #[test]
    async fn test_get_or_fill_empty() {
        let mut test_vec = get_test_node_vec().await;

        let mut expected = Parent {
            public_key: vec![0u8; 4].into(),
            parent_hash: ParentHash::empty(),
            unmerged_leaves: vec![],
        };

        let actual = test_vec
            .borrow_or_fill_node_as_parent(1, &vec![0u8; 4].into())
            .unwrap();

        assert_eq!(actual, &mut expected);
    }

    #[test]
    async fn test_leaf_count() {
        let test_vec = get_test_node_vec().await;
        assert_eq!(test_vec.len(), 7);
        assert_eq!(test_vec.occupied_leaf_count(), 3);
        assert_eq!(
            test_vec.non_empty_leaves().count(),
            test_vec.occupied_leaf_count() as usize
        );
    }

    #[test]
    async fn test_total_leaf_count() {
        let test_vec = get_test_node_vec().await;
        assert_eq!(test_vec.occupied_leaf_count(), 3);
        assert_eq!(test_vec.total_leaf_count(), 4);
    }
}
