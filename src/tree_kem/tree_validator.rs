use super::{
    leaf_node_validator::{LeafNodeValidationError, LeafNodeValidator},
    RatchetTreeError, TreeKemPublic,
};
use crate::client_config::CredentialValidator;
use crate::{cipher_suite::CipherSuite, extension::RequiredCapabilitiesExt};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum TreeValidationError {
    #[error(transparent)]
    RatchetTreeError(#[from] RatchetTreeError),
    #[error(transparent)]
    LeafNodeValidationError(#[from] LeafNodeValidationError),
    #[error("tree hash mismatch, expected: {0} found: {1}")]
    TreeHashMismatch(String, String),
    #[error("invalid node parent hash found")]
    ParentHashMismatch,
}

pub(crate) struct TreeValidator<'a, C>
where
    C: CredentialValidator,
{
    expected_tree_hash: &'a [u8],
    leaf_node_validator: LeafNodeValidator<'a, C>,
    group_id: &'a [u8],
}

impl<'a, C: CredentialValidator> TreeValidator<'a, C> {
    pub fn new(
        cipher_suite: CipherSuite,
        group_id: &'a [u8],
        tree_hash: &'a [u8],
        required_capabilities: Option<&'a RequiredCapabilitiesExt>,
        credential_validator: C,
    ) -> Self {
        TreeValidator {
            expected_tree_hash: tree_hash,
            leaf_node_validator: LeafNodeValidator::new(
                cipher_suite,
                required_capabilities,
                credential_validator,
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
            .try_for_each(|(_, ln)| self.leaf_node_validator.revalidate(ln, self.group_id))
            .map_err(Into::into)
    }
}

#[cfg(test)]
mod tests {
    use assert_matches::assert_matches;
    use ferriscrypt::{asym::ec_key::SecretKey, hpke::kem::HpkePublicKey, rand::SecureRng};

    use super::*;
    use crate::{
        group::test_utils::get_test_group_context,
        tree_kem::{
            kem::TreeKem,
            leaf_node::test_utils::get_basic_test_node_sig_key,
            node::{LeafIndex, Node, Parent},
            parent_hash::ParentHash,
            test_utils::get_test_tree,
        },
    };

    use crate::client_config::PassthroughCredentialValidator;
    #[cfg(target_arch = "wasm32")]
    use wasm_bindgen_test::wasm_bindgen_test as test;

    fn test_parent_node(cipher_suite: CipherSuite) -> Parent {
        let public_key = SecretKey::generate(cipher_suite.kem_type().curve())
            .unwrap()
            .to_public()
            .unwrap();

        Parent {
            public_key: HpkePublicKey::from(public_key.to_uncompressed_bytes().unwrap()),
            parent_hash: ParentHash::empty(),
            unmerged_leaves: vec![],
        }
    }

    fn get_valid_tree(cipher_suite: CipherSuite) -> TreeKemPublic {
        let mut test_tree = get_test_tree(cipher_suite);

        let (leaf1, _, leaf1_signer) = get_basic_test_node_sig_key(cipher_suite, "leaf1");

        test_tree.public.add_leaves(vec![leaf1]).unwrap();

        test_tree.public.nodes[1] = Some(Node::Parent(test_parent_node(cipher_suite)));

        let signers = [&test_tree.creator_signing_key, &leaf1_signer];

        TreeKem::new(&mut test_tree.public, &mut test_tree.private)
            .encap(
                b"test_group",
                &mut get_test_group_context(42, cipher_suite),
                &[LeafIndex(1)],
                signers[0],
                None,
                None,
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

            let validator = TreeValidator::new(
                cipher_suite,
                b"test_group",
                &expected_tree_hash,
                None,
                PassthroughCredentialValidator::new(),
            );

            validator.validate(&mut test_tree).unwrap();
        }
    }

    #[test]
    fn test_tree_hash_mismatch() {
        for cipher_suite in CipherSuite::all() {
            let mut test_tree = get_valid_tree(cipher_suite);
            let expected_tree_hash = SecureRng::gen(32).unwrap();

            let validator = TreeValidator::new(
                cipher_suite,
                b"test_group",
                &expected_tree_hash,
                None,
                PassthroughCredentialValidator::new(),
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

            let validator = TreeValidator::new(
                cipher_suite,
                b"test_troup",
                &expected_tree_hash,
                None,
                PassthroughCredentialValidator::new(),
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

            let validator = TreeValidator::new(
                cipher_suite,
                b"test_group",
                &expected_tree_hash,
                None,
                PassthroughCredentialValidator::new(),
            );

            assert_matches!(
                validator.validate(&mut test_tree),
                Err(TreeValidationError::LeafNodeValidationError(_))
            );
        }
    }
}
