use std::collections::{HashMap, HashSet};

use crate::provider::crypto::CipherSuiteProvider;
use crate::tree_kem::math as tree_math;
use crate::{
    extension::RequiredCapabilitiesExt,
    provider::identity::IdentityProvider,
    tree_kem::{
        leaf_node_validator::{LeafNodeValidationError, LeafNodeValidator},
        RatchetTreeError, TreeKemPublic,
    },
};
use thiserror::Error;

use super::node::{LeafIndex, NodeIndex, NodeVecError};

#[derive(Debug, Error)]
pub enum TreeValidationError {
    #[error(transparent)]
    RatchetTreeError(#[from] RatchetTreeError),
    #[error(transparent)]
    NodeVecError(#[from] NodeVecError),
    #[error(transparent)]
    LeafNodeValidationError(#[from] LeafNodeValidationError),
    #[error("tree hash mismatch, expected: {0} found: {1}")]
    TreeHashMismatch(String, String),
    #[error("invalid node parent hash found")]
    ParentHashMismatch,
    #[error("unexpected pattern of unmerged leaves")]
    UnmergedLeavesMismatch,
}

pub(crate) struct TreeValidator<'a, C, CSP>
where
    C: IdentityProvider,
    CSP: CipherSuiteProvider,
{
    expected_tree_hash: &'a [u8],
    leaf_node_validator: LeafNodeValidator<'a, C, CSP>,
    group_id: &'a [u8],
}

impl<'a, C: IdentityProvider, CSP: CipherSuiteProvider> TreeValidator<'a, C, CSP> {
    pub fn new(
        cipher_suite_provider: &'a CSP,
        group_id: &'a [u8],
        tree_hash: &'a [u8],
        required_capabilities: Option<&'a RequiredCapabilitiesExt>,
        identity_provider: C,
    ) -> Self {
        TreeValidator {
            expected_tree_hash: tree_hash,
            leaf_node_validator: LeafNodeValidator::new(
                cipher_suite_provider,
                required_capabilities,
                identity_provider,
            ),
            group_id,
        }
    }

    pub fn validate(&self, tree: &mut TreeKemPublic) -> Result<(), TreeValidationError> {
        self.validate_tree_hash(tree)
            .and(
                tree.validate_parent_hashes()
                    .map_err(|_| TreeValidationError::ParentHashMismatch),
            )
            .and(self.validate_leaves(tree))
            .and(validate_unmerged(tree))
    }

    fn validate_tree_hash(&self, tree: &mut TreeKemPublic) -> Result<(), TreeValidationError> {
        //Verify that the tree hash of the ratchet tree matches the tree_hash field in the GroupInfo.
        let tree_hash = tree.tree_hash()?;

        if tree_hash != self.expected_tree_hash {
            return Err(TreeValidationError::TreeHashMismatch(
                hex::encode(self.expected_tree_hash),
                hex::encode(tree_hash),
            ));
        }

        Ok(())
    }

    fn validate_leaves(&self, tree: &TreeKemPublic) -> Result<(), TreeValidationError> {
        // For each non-empty leaf node, verify the signature on the LeafNode.
        tree.nodes
            .non_empty_leaves()
            .try_for_each(|(li, ln)| self.leaf_node_validator.revalidate(ln, self.group_id, *li))
            .map_err(Into::into)
    }
}

fn validate_unmerged(tree: &TreeKemPublic) -> Result<(), TreeValidationError> {
    let mut unmerged_sets: HashMap<u32, HashSet<LeafIndex>> = tree
        .nodes
        .non_empty_parents()
        .map(|(i, n)| (i, HashSet::from_iter(n.unmerged_leaves.iter().cloned())))
        .collect();

    // For each leaf L, we search for the longest prefix P[1], P[2], ..., P[k] of the direct path of L
    // such that for each i=1..k, either L is in the unmerged leaves of P[i], or P[i] is blank. We will
    // then check that L is unmerged at each P[1], ..., P[k] and no other node.
    for (index, _) in tree.nodes.non_empty_leaves() {
        let mut n = NodeIndex::from(index);

        while let Ok(parent) = tree_math::parent(n, tree.total_leaf_count()) {
            if tree.nodes.is_blank(parent)? {
                n = parent;
                continue;
            }

            let parent_node = tree.nodes.borrow_as_parent(parent)?;

            if parent_node.unmerged_leaves.contains(&index) {
                unmerged_sets.get_mut(&parent).unwrap().remove(&index);
                n = parent;
            } else {
                break;
            }
        }
    }

    unmerged_sets
        .values()
        .all(HashSet::is_empty)
        .then_some(())
        .ok_or(TreeValidationError::UnmergedLeavesMismatch)
}

#[cfg(test)]
mod tests {
    use assert_matches::assert_matches;
    use ferriscrypt::rand::SecureRng;

    use super::*;
    use crate::{
        cipher_suite::CipherSuite,
        group::test_utils::get_test_group_context,
        provider::{
            crypto::test_utils::test_cipher_suite_provider, identity::BasicIdentityProvider,
        },
        tree_kem::{
            kem::TreeKem,
            leaf_node::test_utils::{default_properties, get_basic_test_node},
            node::{LeafIndex, Node, Parent},
            parent_hash::{test_utils::get_test_tree_fig_12, ParentHash},
            test_utils::get_test_tree,
        },
    };

    #[cfg(target_arch = "wasm32")]
    use wasm_bindgen_test::wasm_bindgen_test as test;

    fn test_parent_node(cipher_suite: CipherSuite) -> Parent {
        let (_, public_key) = test_cipher_suite_provider(cipher_suite)
            .kem_generate()
            .unwrap();

        Parent {
            public_key,
            parent_hash: ParentHash::empty(),
            unmerged_leaves: vec![],
        }
    }

    fn get_valid_tree(cipher_suite: CipherSuite) -> TreeKemPublic {
        let mut test_tree = get_test_tree(cipher_suite);

        let leaf1 = get_basic_test_node(cipher_suite, "leaf1");
        let leaf2 = get_basic_test_node(cipher_suite, "leaf2");

        test_tree
            .public
            .add_leaves(vec![leaf1, leaf2], BasicIdentityProvider)
            .unwrap();

        test_tree.public.nodes[1] = Some(Node::Parent(test_parent_node(cipher_suite)));
        test_tree.public.nodes[3] = Some(Node::Parent(test_parent_node(cipher_suite)));

        TreeKem::new(&mut test_tree.public, &mut test_tree.private)
            .encap(
                &mut get_test_group_context(42, cipher_suite),
                &[LeafIndex(1), LeafIndex(2)],
                &test_tree.creator_signing_key,
                default_properties(),
                None,
                BasicIdentityProvider,
                &test_cipher_suite_provider(cipher_suite),
                #[cfg(test)]
                &Default::default(),
            )
            .unwrap();

        test_tree.public
    }

    #[test]
    fn test_valid_tree() {
        for cipher_suite in CipherSuite::all() {
            println!("Checking cipher suite: {cipher_suite:?}");
            let mut test_tree = get_valid_tree(cipher_suite);
            let expected_tree_hash = test_tree.tree_hash().unwrap();

            let cipher_suite_provider = test_cipher_suite_provider(cipher_suite);

            let validator = TreeValidator::new(
                &cipher_suite_provider,
                b"",
                &expected_tree_hash,
                None,
                BasicIdentityProvider::new(),
            );

            validator.validate(&mut test_tree).unwrap();
        }
    }

    #[test]
    fn test_tree_hash_mismatch() {
        for cipher_suite in CipherSuite::all() {
            let mut test_tree = get_valid_tree(cipher_suite);
            let expected_tree_hash = SecureRng::gen(32).unwrap();

            let cipher_suite_provider = test_cipher_suite_provider(cipher_suite);

            let validator = TreeValidator::new(
                &cipher_suite_provider,
                b"",
                &expected_tree_hash,
                None,
                BasicIdentityProvider::new(),
            );

            assert_matches!(
                validator.validate(&mut test_tree),
                Err(TreeValidationError::TreeHashMismatch(_, _))
            );
        }
    }

    #[test]
    fn test_parent_hash_mismatch() {
        for cipher_suite in CipherSuite::all() {
            let mut test_tree = get_valid_tree(cipher_suite);

            let parent_node = test_tree.nodes.borrow_as_parent_mut(1).unwrap();
            parent_node.parent_hash = ParentHash::from(SecureRng::gen(32).unwrap());

            let expected_tree_hash = test_tree.tree_hash().unwrap();

            let cipher_suite_provider = test_cipher_suite_provider(cipher_suite);

            let validator = TreeValidator::new(
                &cipher_suite_provider,
                b"",
                &expected_tree_hash,
                None,
                BasicIdentityProvider::new(),
            );

            assert_matches!(
                validator.validate(&mut test_tree),
                Err(TreeValidationError::ParentHashMismatch)
            );
        }
    }

    #[test]
    fn test_key_package_validation_failure() {
        for cipher_suite in CipherSuite::all() {
            let mut test_tree = get_valid_tree(cipher_suite);

            test_tree
                .nodes
                .borrow_as_leaf_mut(LeafIndex(0))
                .unwrap()
                .signature = SecureRng::gen(32).unwrap();

            let expected_tree_hash = test_tree.tree_hash().unwrap();

            let cipher_suite_provider = test_cipher_suite_provider(cipher_suite);

            let validator = TreeValidator::new(
                &cipher_suite_provider,
                b"",
                &expected_tree_hash,
                None,
                BasicIdentityProvider::new(),
            );

            assert_matches!(
                validator.validate(&mut test_tree),
                Err(TreeValidationError::LeafNodeValidationError(_))
            );
        }
    }

    #[test]
    fn verify_unmerged_with_correct_tree() {
        let tree = get_test_tree_fig_12(CipherSuite::Curve25519Aes128);
        validate_unmerged(&tree).unwrap();
    }

    #[test]
    fn verify_unmerged_with_blank_leaf() {
        let mut tree = get_test_tree_fig_12(CipherSuite::Curve25519Aes128);

        // Blank leaf D unmerged at nodes 3, 7
        tree.nodes.blank_node(6).unwrap();

        assert_matches!(
            validate_unmerged(&tree),
            Err(TreeValidationError::UnmergedLeavesMismatch)
        );
    }

    #[test]
    fn verify_unmerged_with_broken_path() {
        let mut tree = get_test_tree_fig_12(CipherSuite::Curve25519Aes128);

        // Make D with direct path [3, 7] unmerged at 7 but not 3
        tree.nodes.borrow_as_parent_mut(3).unwrap().unmerged_leaves = vec![];

        assert_matches!(
            validate_unmerged(&tree),
            Err(TreeValidationError::UnmergedLeavesMismatch)
        );
    }

    #[test]
    fn verify_unmerged_with_leaf_outside_tree() {
        let mut tree = get_test_tree_fig_12(CipherSuite::Curve25519Aes128);

        // Add leaf E from the right subtree of the root to unmerged leaves of node 1 on the left
        tree.nodes.borrow_as_parent_mut(1).unwrap().unmerged_leaves = vec![LeafIndex(4)];

        assert_matches!(
            validate_unmerged(&tree),
            Err(TreeValidationError::UnmergedLeavesMismatch)
        );
    }
}
