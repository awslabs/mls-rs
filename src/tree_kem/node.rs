use crate::key_package::ValidatedKeyPackage;
use crate::tree_kem::math as tree_math;
use crate::tree_kem::math::TreeMathError;
use crate::tree_kem::parent_hash::ParentHash;
use ferriscrypt::hpke::kem::HpkePublicKey;
use std::convert::TryFrom;
use std::hash::Hash;
use std::ops::{Deref, DerefMut};
use thiserror::Error;
use tls_codec_derive::{TlsDeserialize, TlsSerialize, TlsSize};

#[derive(Clone, Debug, PartialEq, TlsDeserialize, TlsSerialize, TlsSize)]
pub(crate) struct Leaf {
    pub key_package: ValidatedKeyPackage,
}

#[derive(Clone, Debug, PartialEq, TlsDeserialize, TlsSerialize, TlsSize)]
pub(crate) struct Parent {
    #[tls_codec(with = "crate::tls::ByteVec::<u32>")]
    pub public_key: HpkePublicKey,
    pub parent_hash: ParentHash,
    #[tls_codec(with = "crate::tls::DefVec::<u32>")]
    pub unmerged_leaves: Vec<LeafIndex>,
}

impl From<Vec<u8>> for Parent {
    fn from(pk: Vec<u8>) -> Self {
        Self {
            public_key: pk.into(),
            parent_hash: ParentHash::empty(),
            unmerged_leaves: vec![],
        }
    }
}

#[derive(
    Clone, Copy, Debug, Ord, PartialEq, PartialOrd, Hash, Eq, TlsDeserialize, TlsSerialize, TlsSize,
)]
pub struct LeafIndex(pub(crate) u32);

impl TryFrom<NodeIndex> for LeafIndex {
    type Error = TreeMathError;

    fn try_from(value: NodeIndex) -> Result<Self, Self::Error> {
        if value % 2 == 0 {
            Ok(Self(value / 2))
        } else {
            Err(TreeMathError::InvalidIndex)
        }
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
    pub(crate) fn direct_path(&self, leaf_count: u32) -> Result<Vec<NodeIndex>, TreeMathError> {
        tree_math::direct_path(NodeIndex::from(self), leaf_count)
    }

    fn copath(&self, leaf_count: u32) -> Result<Vec<NodeIndex>, TreeMathError> {
        tree_math::copath(NodeIndex::from(self), leaf_count)
    }
}

pub(crate) type NodeIndex = u32;

#[derive(Error, Debug)]
pub enum NodeVecError {
    #[error(transparent)]
    TreeMathError(#[from] TreeMathError),
    #[error("not a parent")]
    NotParentNode,
    #[error("not a leaf")]
    NotLeafNode,
    #[error("node index is out of bounds {0}")]
    InvalidNodeIndex(NodeIndex),
    #[error("unexpected empty node found")]
    UnexpectedEmptyNode,
}

#[derive(Clone, Debug, PartialEq, TlsDeserialize, TlsSerialize, TlsSize)]
#[allow(clippy::large_enum_variant)]
#[repr(u8)]
//TODO: Research if this should actually be a Box<Leaf> for memory / performance reasons
pub(crate) enum Node {
    #[tls_codec(discriminant = 1)]
    Leaf(Leaf),
    Parent(Parent),
}

impl Node {
    pub fn public_key(&self) -> &HpkePublicKey {
        match self {
            Node::Parent(p) => &p.public_key,
            Node::Leaf(l) => &l.key_package.hpke_init_key,
        }
    }
}

impl From<Parent> for Option<Node> {
    fn from(p: Parent) -> Self {
        Node::from(p).into()
    }
}

impl From<Leaf> for Option<Node> {
    fn from(l: Leaf) -> Self {
        Node::from(l).into()
    }
}

impl From<Parent> for Node {
    fn from(p: Parent) -> Self {
        Node::Parent(p)
    }
}

impl From<Leaf> for Node {
    fn from(l: Leaf) -> Self {
        Node::Leaf(l)
    }
}

impl From<ValidatedKeyPackage> for Option<Node> {
    fn from(kp: ValidatedKeyPackage) -> Self {
        Option::from(Leaf::from(kp))
    }
}

impl From<ValidatedKeyPackage> for Leaf {
    fn from(key_package: ValidatedKeyPackage) -> Self {
        Leaf { key_package }
    }
}

impl From<ValidatedKeyPackage> for Node {
    fn from(key_package: ValidatedKeyPackage) -> Self {
        Node::Leaf(key_package.into())
    }
}

pub(crate) trait NodeTypeResolver {
    fn as_parent(&self) -> Result<&Parent, NodeVecError>;
    fn as_parent_mut(&mut self) -> Result<&mut Parent, NodeVecError>;
    fn as_leaf(&self) -> Result<&Leaf, NodeVecError>;
    fn as_leaf_mut(&mut self) -> Result<&mut Leaf, NodeVecError>;
    fn as_non_empty(&self) -> Result<&Node, NodeVecError>;
}

impl NodeTypeResolver for Option<Node> {
    fn as_parent(&self) -> Result<&Parent, NodeVecError> {
        self.as_ref()
            .and_then(|n| match n {
                Node::Parent(p) => Some(p),
                Node::Leaf(_) => None,
            })
            .ok_or(NodeVecError::NotParentNode)
    }

    fn as_parent_mut(&mut self) -> Result<&mut Parent, NodeVecError> {
        self.as_mut()
            .and_then(|n| match n {
                Node::Parent(p) => Some(p),
                Node::Leaf(_) => None,
            })
            .ok_or(NodeVecError::NotParentNode)
    }

    fn as_leaf(&self) -> Result<&Leaf, NodeVecError> {
        self.as_ref()
            .and_then(|n| match n {
                Node::Parent(_) => None,
                Node::Leaf(l) => Some(l),
            })
            .ok_or(NodeVecError::NotLeafNode)
    }

    fn as_leaf_mut(&mut self) -> Result<&mut Leaf, NodeVecError> {
        self.as_mut()
            .and_then(|n| match n {
                Node::Parent(_) => None,
                Node::Leaf(l) => Some(l),
            })
            .ok_or(NodeVecError::NotLeafNode)
    }

    fn as_non_empty(&self) -> Result<&Node, NodeVecError> {
        self.as_ref().ok_or(NodeVecError::UnexpectedEmptyNode)
    }
}

#[derive(Clone, Debug, PartialEq, TlsDeserialize, TlsSerialize, TlsSize, Default)]
pub(crate) struct NodeVec(#[tls_codec(with = "crate::tls::DefVec::<u32>")] Vec<Option<Node>>);

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
    pub fn leaf_count(&self) -> u32 {
        self.non_empty_leaves().count() as u32
    }

    #[inline]
    pub fn borrow_node(&self, index: NodeIndex) -> Result<&Option<Node>, NodeVecError> {
        self.get(index as usize)
            .ok_or(NodeVecError::InvalidNodeIndex(index))
    }

    #[inline]
    pub fn borrow_node_mut(&mut self, index: NodeIndex) -> Result<&mut Option<Node>, NodeVecError> {
        self.get_mut(index as usize)
            .ok_or(NodeVecError::InvalidNodeIndex(index))
    }

    pub fn empty_leaves(&mut self) -> impl Iterator<Item = (LeafIndex, &mut Option<Node>)> + '_ {
        // List of empty leaves from left to right
        self.iter_mut()
            .enumerate()
            .step_by(2)
            .filter(|(_, n)| n.is_none())
            .map(|(i, n)| (LeafIndex(i as u32 / 2), n))
    }

    pub fn non_empty_leaves(&self) -> impl Iterator<Item = (LeafIndex, &Leaf)> + '_ {
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
    pub fn direct_path(&self, index: LeafIndex) -> Result<Vec<NodeIndex>, TreeMathError> {
        // Direct path from leaf to root
        index.direct_path((self.len() / 2 + 1) as u32)
    }

    #[inline]
    pub fn copath(&self, index: LeafIndex) -> Result<Vec<NodeIndex>, TreeMathError> {
        // Co path from leaf to root
        index.copath((self.len() / 2 + 1) as u32)
    }

    #[inline]
    pub fn is_blank(&self, index: NodeIndex) -> Result<bool, NodeVecError> {
        self.borrow_node(index).map(|n| n.is_none())
    }

    #[inline]
    pub fn is_leaf(&self, index: NodeIndex) -> bool {
        index % 2 == 0
    }

    // Blank a previously filled leaf node, and return the existing leaf
    pub fn blank_leaf_node(&mut self, leaf_index: LeafIndex) -> Result<Option<Leaf>, NodeVecError> {
        let node_index = NodeIndex::from(leaf_index);
        let blanked_leaf = self.blank_node(node_index)?.and_then(|node| match node {
            Node::Leaf(l) => Some(l),
            Node::Parent(_) => None,
        });

        Ok(blanked_leaf)
    }

    pub fn blank_node(&mut self, node_index: NodeIndex) -> Result<Option<Node>, NodeVecError> {
        self.borrow_node_mut(node_index).map(|node| {
            let res = node.clone();
            *node = None;
            res
        })
    }

    pub fn blank_direct_path(
        &mut self,
        leaf: LeafIndex,
    ) -> Result<Vec<Option<Node>>, NodeVecError> {
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

    pub fn borrow_as_parent(&self, node_index: NodeIndex) -> Result<&Parent, NodeVecError> {
        self.borrow_node(node_index).and_then(|n| n.as_parent())
    }

    pub fn borrow_as_parent_mut(
        &mut self,
        node_index: NodeIndex,
    ) -> Result<&mut Parent, NodeVecError> {
        self.borrow_node_mut(node_index)
            .and_then(|n| n.as_parent_mut())
    }

    pub fn borrow_as_leaf_mut(&mut self, index: LeafIndex) -> Result<&mut Leaf, NodeVecError> {
        let node_index = NodeIndex::from(index);
        self.borrow_node_mut(node_index)
            .and_then(|n| n.as_leaf_mut())
    }

    pub fn borrow_as_leaf(&self, index: LeafIndex) -> Result<&Leaf, NodeVecError> {
        let node_index = NodeIndex::from(index);
        self.borrow_node(node_index).and_then(|n| n.as_leaf())
    }

    pub fn borrow_or_fill_node_as_parent(
        &mut self,
        node_index: NodeIndex,
        public_key: &HpkePublicKey,
    ) -> Result<&mut Parent, NodeVecError> {
        self.borrow_node_mut(node_index).and_then(|n| {
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

    pub fn get_resolution_index(&self, index: NodeIndex) -> Result<Vec<NodeIndex>, NodeVecError> {
        if let Some(node) = self.get(index as usize) {
            match node {
                None => {
                    // This node is blank
                    if LeafIndex::try_from(index).is_ok() {
                        // Node is a leaf {
                        Ok(Vec::new()) // Resolution of a blank leaf node is empty list
                    } else {
                        // Resolution of a blank intermediate is is the result of concatenating the
                        // resolution of its left and right children
                        Ok([
                            self.get_resolution_index(tree_math::left(index)?)?,
                            self.get_resolution_index(tree_math::right(
                                index,
                                (self.len() / 2 + 1) as u32,
                            )?)?,
                        ]
                        .concat())
                    }
                }
                Some(node) => {
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
        } else {
            Err(TreeMathError::InvalidIndex.into())
        }
    }

    pub fn get_resolution(
        &self,
        node_index: NodeIndex,
        excluding: &[NodeIndex],
    ) -> Result<Vec<&Node>, NodeVecError> {
        self.get_resolution_index(node_index)?
            .iter()
            .filter(|i| !excluding.contains(i))
            .map(|&i| self.borrow_node(i).and_then(|n| n.as_non_empty()))
            .collect()
    }

    pub fn direct_path_copath_resolution(
        &self,
        index: LeafIndex,
        excluding: &[LeafIndex],
    ) -> Result<Vec<(NodeIndex, Vec<&Node>)>, NodeVecError> {
        let excluding = excluding
            .iter()
            .map(NodeIndex::from)
            .collect::<Vec<NodeIndex>>();

        self.direct_path(index)?
            .iter()
            .zip(self.copath(index)?)
            .map(|(&dp, cp)| self.get_resolution(cp, &excluding).map(|r| (dp, r)))
            .collect()
    }
}

#[cfg(test)]
pub mod test {
    use super::*;
    use crate::cipher_suite::CipherSuite;
    use crate::client::Client;
    use crate::client_config::DefaultClientConfig;
    use crate::extension::LifetimeExt;

    #[cfg(target_arch = "wasm32")]
    use wasm_bindgen_test::{wasm_bindgen_test as test, wasm_bindgen_test_configure};

    #[cfg(target_arch = "wasm32")]
    wasm_bindgen_test_configure!(run_in_browser);

    fn get_test_key_package(id: Vec<u8>) -> ValidatedKeyPackage {
        let client = Client::generate_basic(
            CipherSuite::Curve25519Aes128V1,
            id,
            DefaultClientConfig::default(),
        )
        .unwrap();

        client
            .gen_key_package(LifetimeExt::years(1).unwrap())
            .unwrap()
            .key_package
    }

    pub(crate) fn get_test_node_vec() -> NodeVec {
        let nodes = [
            Leaf {
                key_package: get_test_key_package(b"A".to_vec()),
            }
            .into(),
            None,
            None,
            None,
            Leaf {
                key_package: get_test_key_package(b"C".to_vec()),
            }
            .into(),
            Parent {
                public_key: b"CD".to_vec().into(),
                parent_hash: ParentHash::empty(),
                unmerged_leaves: vec![LeafIndex(2)],
            }
            .into(),
            Leaf {
                key_package: get_test_key_package(b"D".to_vec()),
            }
            .into(),
        ];

        NodeVec::from(nodes.to_vec())
    }

    #[test]
    fn node_key_getters() {
        let test_node_parent: Node = Parent {
            public_key: b"pub".to_vec().into(),
            parent_hash: ParentHash::empty(),
            unmerged_leaves: vec![],
        }
        .into();

        let mut test_key_package = get_test_key_package(b"B".to_vec());
        test_key_package.hpke_init_key = b"pub_leaf".to_vec().into();

        let test_node_leaf: Node = Leaf {
            key_package: test_key_package,
        }
        .into();

        assert_eq!(test_node_parent.public_key().as_ref(), b"pub");
        assert_eq!(test_node_leaf.public_key().as_ref(), b"pub_leaf");
    }

    #[test]
    fn test_empty_leaves() {
        let mut test_vec = get_test_node_vec();
        let mut test_vec_clone = get_test_node_vec();
        let empty_leaves: Vec<(LeafIndex, &mut Option<Node>)> = test_vec.empty_leaves().collect();
        assert_eq!(
            [(LeafIndex(1), &mut test_vec_clone[2])].as_ref(),
            empty_leaves.as_slice()
        );
    }

    #[test]
    fn test_direct_path() {
        let test_vec = get_test_node_vec();
        // Tree math is already tested in that module, just ensure equality
        let expected = tree_math::direct_path(0, 4).unwrap();
        let actual = test_vec.direct_path(LeafIndex(0)).unwrap();
        assert_eq!(actual, expected);
    }

    #[test]
    fn test_copath() {
        let test_vec = get_test_node_vec();
        // Tree math is already tested in that module, just ensure equality
        let expected = tree_math::copath(0, 4).unwrap();
        let actual = test_vec.copath(LeafIndex(0)).unwrap();
        assert_eq!(actual, expected);
    }

    #[test]
    fn test_get_parent_node() {
        let mut test_vec = get_test_node_vec();

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
    fn test_get_resolution() {
        let test_vec = get_test_node_vec();

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
    fn test_resolution_filter() {
        let test_vec = get_test_node_vec();
        let resolution_node_5 = test_vec.get_resolution(5, &[4]).unwrap();
        let expected_5: Vec<Node> = [test_vec[5].as_ref().unwrap().clone()].to_vec();

        assert_eq!(resolution_node_5, expected_5.iter().collect::<Vec<&Node>>());
    }

    #[test]
    fn test_copath_resolution() {
        let test_vec = get_test_node_vec();

        let expected: Vec<(NodeIndex, Vec<Node>)> = [
            (1, [].to_vec()),
            (
                3,
                [
                    test_vec[5].as_ref().unwrap().clone(),
                    test_vec[4].as_ref().unwrap().clone(),
                ]
                .to_vec(),
            ),
        ]
        .to_vec();

        let copath_resolution = test_vec
            .direct_path_copath_resolution(LeafIndex(0), &[])
            .unwrap();

        let expected: Vec<(NodeIndex, Vec<&Node>)> = expected
            .iter()
            .map(|(i, n)| (*i, n.iter().collect()))
            .collect();

        assert_eq!(expected, copath_resolution)
    }

    #[test]
    fn test_copath_resolution_filter() {
        let test_vec = get_test_node_vec();

        let expected: Vec<(NodeIndex, Vec<Node>)> = [
            (1, [].to_vec()),
            (3, [test_vec[5].as_ref().unwrap().clone()].to_vec()),
        ]
        .to_vec();

        let copath_resolution = test_vec
            .direct_path_copath_resolution(LeafIndex(0), &[LeafIndex(2)])
            .unwrap();

        let expected: Vec<(NodeIndex, Vec<&Node>)> = expected
            .iter()
            .map(|(i, n)| (*i, n.iter().collect()))
            .collect();

        assert_eq!(expected, copath_resolution)
    }

    #[test]
    fn test_get_or_fill_existing() {
        let mut test_vec = get_test_node_vec();
        let mut test_vec2 = test_vec.clone();

        let expected = test_vec[5].as_parent_mut().unwrap();
        let actual = test_vec2
            .borrow_or_fill_node_as_parent(5, &Vec::new().into())
            .unwrap();

        assert_eq!(actual, expected);
    }

    #[test]
    fn test_get_or_fill_empty() {
        let mut test_vec = get_test_node_vec();

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
    fn test_leaf_count() {
        let test_vec = get_test_node_vec();
        assert_eq!(test_vec.len(), 7);
        assert_eq!(test_vec.leaf_count(), 3);
        assert_eq!(
            test_vec.non_empty_leaves().count(),
            test_vec.leaf_count() as usize
        );
    }
}
