use crate::cipher_suite::CipherSuite;
use crate::extension::{ExtensionError, ParentHashExt};
use crate::tree_kem::math as tree_math;
use crate::tree_kem::math::TreeMathError;
use crate::tree_kem::node::{LeafIndex, Node, NodeIndex, NodeVec, NodeVecError, Parent};
use crate::tree_kem::RatchetTreeError;
use crate::tree_kem::TreeKemPublic;
use ferriscrypt::hpke::kem::HpkePublicKey;
use std::collections::HashMap;
use std::ops::Deref;
use thiserror::Error;
use tls_codec::Serialize;
use tls_codec_derive::{TlsDeserialize, TlsSerialize, TlsSize};

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
    #[tls_codec(with = "crate::tls::ByteVec::<u32>")]
    public_key: &'a HpkePublicKey,
    #[tls_codec(with = "crate::tls::ByteVec::<u32>")]
    parent_hash: &'a [u8],
    #[tls_codec(with = "crate::tls::Vector::<u32, crate::tls::ByteVec>")]
    original_child_resolution: Vec<&'a HpkePublicKey>,
}

#[derive(Clone, Debug, PartialEq, TlsDeserialize, TlsSerialize, TlsSize)]
pub struct ParentHash(#[tls_codec(with = "crate::tls::ByteVec::<u8>")] Vec<u8>);

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
    pub fn new(
        cipher_suite: CipherSuite,
        public_key: &HpkePublicKey,
        parent_hash: &ParentHash,
        original_child_resolution: Vec<&HpkePublicKey>,
    ) -> Result<Self, ParentHashError> {
        let input = ParentHashInput {
            public_key,
            parent_hash,
            original_child_resolution,
        };

        let input_bytes = input.tls_serialize_detached()?;
        let hash = cipher_suite.hash_function().digest(&input_bytes);
        Ok(Self(hash))
    }

    pub fn empty() -> Self {
        ParentHash(Vec::new())
    }

    pub fn matches(&self, hash: ParentHash) -> bool {
        //TODO: Constant time equals
        &hash == self
    }
}

impl Node {
    fn get_parent_hash(&self) -> Result<Option<ParentHash>, ExtensionError> {
        match self {
            Node::Parent(p) => Ok(Some(p.parent_hash.clone())),
            Node::Leaf(l) => Ok(l
                .key_package
                .extensions
                .get_extension::<ParentHashExt>()?
                .map(|ext| ext.parent_hash)),
        }
    }
}

impl NodeVec {
    fn original_child_resolution(
        &self,
        parent: &Parent,
        index: NodeIndex,
    ) -> Result<Vec<&HpkePublicKey>, NodeVecError> {
        let unmerged_leaves: Vec<NodeIndex> =
            parent.unmerged_leaves.iter().map(NodeIndex::from).collect();

        Ok(self
            .get_resolution(index, &unmerged_leaves)?
            .iter()
            .map(|n| n.public_key())
            .collect())
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
        let ocr = self
            .nodes
            .original_child_resolution(node, co_path_child_index)?;
        ParentHash::new(self.cipher_suite, &node.public_key, parent_parent_hash, ocr)
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

        let direct_path = self.nodes.direct_path(index)?;
        let copath = self.nodes.copath(index)?;

        // Calculate all the parent hash values along the direct path from root to leaf
        direct_path.iter().zip(copath.iter()).rev().try_fold(
            ParentHash::empty(),
            |last_hash, (&index, &sibling_index)| {
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
            let received_parent_hash = update_path
                .leaf_key_package
                .extensions
                .get_extension::<ParentHashExt>()?
                .ok_or(RatchetTreeError::ParentHashNotFound)?;

            if !leaf_hash.matches(received_parent_hash.parent_hash) {
                return Err(RatchetTreeError::ParentHashMismatch);
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
            if l_node.get_parent_hash()? == Some(parent_hash_right) {
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
            if r_node.get_parent_hash()? == Some(parent_hash_left) {
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
mod test {
    use super::*;
    use crate::extension::ParentHashExt;
    use crate::tree_kem::node::test::get_test_node_vec;
    use crate::tree_kem::test::{get_test_key_package, get_test_key_packages, get_test_tree};
    use crate::ProtocolVersion;

    #[cfg(target_arch = "wasm32")]
    use wasm_bindgen_test::{wasm_bindgen_test as test, wasm_bindgen_test_configure};

    #[cfg(target_arch = "wasm32")]
    wasm_bindgen_test_configure!(run_in_browser);

    fn get_phash_test_tree(
        protocol_version: ProtocolVersion,
        cipher_suite: CipherSuite,
    ) -> TreeKemPublic {
        let (mut tree, _, _) = get_test_tree(protocol_version, cipher_suite);
        let key_packages = get_test_key_packages(protocol_version, cipher_suite);
        tree.add_leaves(key_packages).unwrap();

        // Fill in parent nodes
        for i in 0..tree.total_leaf_count() - 1 {
            tree.nodes
                .borrow_node_mut(i * 2 + 1)
                .map(|node| {
                    *node = Some(Node::Parent(Parent {
                        public_key: vec![i as u8].into(),
                        parent_hash: ParentHash::empty(),
                        unmerged_leaves: vec![],
                    }))
                })
                .unwrap()
        }

        tree
    }

    #[test]
    fn test_original_child_resolution() {
        let node_vec = get_test_node_vec();
        let expected = HpkePublicKey::from(vec![67u8, 68u8]);
        let parent = node_vec.borrow_as_parent(5).unwrap();
        let child_resolution = node_vec.original_child_resolution(parent, 5).unwrap();
        assert_eq!(vec![&expected], child_resolution);
    }

    #[test]
    fn test_missing_parent_hash() {
        let protocol_version = ProtocolVersion::Mls10;
        let cipher_suite = CipherSuite::Curve25519Aes128V1;

        let mut test_tree = get_phash_test_tree(protocol_version, cipher_suite);
        let test_key_package =
            get_test_key_package(protocol_version, cipher_suite, b"foo".to_vec());

        let test_update_path = ValidatedUpdatePath {
            leaf_key_package: test_key_package.key_package,
            nodes: vec![],
        };

        let missing_parent_hash_res =
            test_tree.update_parent_hashes(LeafIndex(0), Some(&test_update_path));

        assert!(missing_parent_hash_res.is_err());
    }

    #[test]
    fn test_invalid_parent_hash() {
        let protocol_version = ProtocolVersion::Mls10;
        let cipher_suite = CipherSuite::Curve25519Aes128V1;

        let mut test_tree = get_phash_test_tree(protocol_version, cipher_suite);
        let test_key_package =
            get_test_key_package(protocol_version, cipher_suite, b"foo".to_vec());

        let mut test_update_path = ValidatedUpdatePath {
            leaf_key_package: test_key_package.key_package,
            nodes: vec![],
        };

        let unexpected_parent_hash = ParentHashExt::from(ParentHash::from(hex!("f00d")));

        test_update_path
            .leaf_key_package
            .extensions
            .set_extension(unexpected_parent_hash)
            .unwrap();

        let invalid_parent_hash_res =
            test_tree.update_parent_hashes(LeafIndex(0), Some(&test_update_path));

        assert!(invalid_parent_hash_res.is_err());
    }

    //TODO: Tests based on test vectors once TLS encoding is implemented
}
