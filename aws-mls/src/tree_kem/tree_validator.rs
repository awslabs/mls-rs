use std::collections::{HashMap, HashSet};

use crate::provider::crypto::CipherSuiteProvider;
use crate::tree_kem::math as tree_math;
use crate::{
    extension::RequiredCapabilitiesExt,
    tree_kem::{
        leaf_node_validator::{LeafNodeValidationError, LeafNodeValidator},
        RatchetTreeError, TreeKemPublic,
    },
};
use aws_mls_core::identity::IdentityProvider;
use futures::TryStreamExt;
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
    cipher_suite_provider: &'a CSP,
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
            cipher_suite_provider,
        }
    }

    pub async fn validate(&self, tree: &mut TreeKemPublic) -> Result<(), TreeValidationError> {
        self.validate_tree_hash(tree)?;
        tree.validate_parent_hashes(self.cipher_suite_provider)
            .map_err(|_| TreeValidationError::ParentHashMismatch)?;
        self.validate_leaves(tree).await?;
        validate_unmerged(tree)
    }

    fn validate_tree_hash(&self, tree: &mut TreeKemPublic) -> Result<(), TreeValidationError> {
        //Verify that the tree hash of the ratchet tree matches the tree_hash field in the GroupInfo.
        let tree_hash = tree.tree_hash(self.cipher_suite_provider)?;

        if tree_hash != self.expected_tree_hash {
            return Err(TreeValidationError::TreeHashMismatch(
                hex::encode(self.expected_tree_hash),
                hex::encode(tree_hash),
            ));
        }

        Ok(())
    }

    async fn validate_leaves(&self, tree: &TreeKemPublic) -> Result<(), TreeValidationError> {
        // For each non-empty leaf node, verify the signature on the LeafNode.
        futures::stream::iter(tree.nodes.non_empty_leaves().map(Ok))
            .try_for_each(|(li, ln)| self.leaf_node_validator.revalidate(ln, self.group_id, *li))
            .await
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

    use super::*;
    use crate::{
        cipher_suite::CipherSuite,
        group::test_utils::{get_test_group_context, random_bytes, TEST_GROUP},
        provider::{
            crypto::test_utils::test_cipher_suite_provider, crypto::test_utils::TestCryptoProvider,
            identity::BasicIdentityProvider,
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

    async fn get_valid_tree(cipher_suite: CipherSuite) -> TreeKemPublic {
        let cipher_suite_provider = test_cipher_suite_provider(cipher_suite);

        let mut test_tree = get_test_tree(cipher_suite).await;

        let leaf1 = get_basic_test_node(cipher_suite, "leaf1").await;
        let leaf2 = get_basic_test_node(cipher_suite, "leaf2").await;

        test_tree
            .public
            .add_leaves(
                vec![leaf1, leaf2],
                BasicIdentityProvider,
                &cipher_suite_provider,
            )
            .await
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
                &cipher_suite_provider,
                #[cfg(test)]
                &Default::default(),
            )
            .await
            .unwrap();

        test_tree.public
    }

    #[futures_test::test]
    async fn test_valid_tree() {
        for cipher_suite in TestCryptoProvider::all_supported_cipher_suites() {
            println!("Checking cipher suite: {cipher_suite:?}");
            let cipher_suite_provider = test_cipher_suite_provider(cipher_suite);

            let mut test_tree = get_valid_tree(cipher_suite).await;
            let expected_tree_hash = test_tree.tree_hash(&cipher_suite_provider).unwrap();

            let validator = TreeValidator::new(
                &cipher_suite_provider,
                TEST_GROUP,
                &expected_tree_hash,
                None,
                BasicIdentityProvider::new(),
            );

            validator.validate(&mut test_tree).await.unwrap();
        }
    }

    #[futures_test::test]
    async fn test_tree_hash_mismatch() {
        for cipher_suite in TestCryptoProvider::all_supported_cipher_suites() {
            let mut test_tree = get_valid_tree(cipher_suite).await;
            let expected_tree_hash = random_bytes(32);

            let cipher_suite_provider = test_cipher_suite_provider(cipher_suite);

            let validator = TreeValidator::new(
                &cipher_suite_provider,
                b"",
                &expected_tree_hash,
                None,
                BasicIdentityProvider::new(),
            );

            assert_matches!(
                validator.validate(&mut test_tree).await,
                Err(TreeValidationError::TreeHashMismatch(_, _))
            );
        }
    }

    #[futures_test::test]
    async fn test_parent_hash_mismatch() {
        for cipher_suite in TestCryptoProvider::all_supported_cipher_suites() {
            let mut test_tree = get_valid_tree(cipher_suite).await;

            let parent_node = test_tree.nodes.borrow_as_parent_mut(1).unwrap();
            parent_node.parent_hash = ParentHash::from(random_bytes(32));

            let cipher_suite_provider = test_cipher_suite_provider(cipher_suite);
            let expected_tree_hash = test_tree.tree_hash(&cipher_suite_provider).unwrap();

            let validator = TreeValidator::new(
                &cipher_suite_provider,
                b"",
                &expected_tree_hash,
                None,
                BasicIdentityProvider::new(),
            );

            assert_matches!(
                validator.validate(&mut test_tree).await,
                Err(TreeValidationError::ParentHashMismatch)
            );
        }
    }

    #[futures_test::test]
    async fn test_key_package_validation_failure() {
        for cipher_suite in TestCryptoProvider::all_supported_cipher_suites() {
            let mut test_tree = get_valid_tree(cipher_suite).await;

            test_tree
                .nodes
                .borrow_as_leaf_mut(LeafIndex(0))
                .unwrap()
                .signature = random_bytes(32);

            let cipher_suite_provider = test_cipher_suite_provider(cipher_suite);
            let expected_tree_hash = test_tree.tree_hash(&cipher_suite_provider).unwrap();

            let validator = TreeValidator::new(
                &cipher_suite_provider,
                b"",
                &expected_tree_hash,
                None,
                BasicIdentityProvider::new(),
            );

            assert_matches!(
                validator.validate(&mut test_tree).await,
                Err(TreeValidationError::LeafNodeValidationError(_))
            );
        }
    }

    #[futures_test::test]
    async fn verify_unmerged_with_correct_tree() {
        let tree = get_test_tree_fig_12(CipherSuite::Curve25519Aes128).await;
        validate_unmerged(&tree).unwrap();
    }

    #[futures_test::test]
    async fn verify_unmerged_with_blank_leaf() {
        let mut tree = get_test_tree_fig_12(CipherSuite::Curve25519Aes128).await;

        // Blank leaf D unmerged at nodes 3, 7
        tree.nodes.blank_node(6).unwrap();

        assert_matches!(
            validate_unmerged(&tree),
            Err(TreeValidationError::UnmergedLeavesMismatch)
        );
    }

    #[futures_test::test]
    async fn verify_unmerged_with_broken_path() {
        let mut tree = get_test_tree_fig_12(CipherSuite::Curve25519Aes128).await;

        // Make D with direct path [3, 7] unmerged at 7 but not 3
        tree.nodes.borrow_as_parent_mut(3).unwrap().unmerged_leaves = vec![];

        assert_matches!(
            validate_unmerged(&tree),
            Err(TreeValidationError::UnmergedLeavesMismatch)
        );
    }

    #[futures_test::test]
    async fn verify_unmerged_with_leaf_outside_tree() {
        let mut tree = get_test_tree_fig_12(CipherSuite::Curve25519Aes128).await;

        // Add leaf E from the right subtree of the root to unmerged leaves of node 1 on the left
        tree.nodes.borrow_as_parent_mut(1).unwrap().unmerged_leaves = vec![LeafIndex(4)];

        assert_matches!(
            validate_unmerged(&tree),
            Err(TreeValidationError::UnmergedLeavesMismatch)
        );
    }
}
