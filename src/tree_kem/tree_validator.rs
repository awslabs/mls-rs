use super::{RatchetTreeError, TreeKemPublic};
use std::collections::HashSet;
use thiserror::Error;

use crate::{
    cipher_suite::CipherSuite,
    extension::RequiredCapabilitiesExt,
    key_package::{KeyPackageValidationError, KeyPackageValidationOptions, KeyPackageValidator},
    ProtocolVersion,
};

#[derive(Debug, Error)]
pub enum TreeValidationError {
    #[error(transparent)]
    RatchetTreeError(#[from] RatchetTreeError),
    #[error(transparent)]
    KeyPackageValidationError(#[from] KeyPackageValidationError),
    #[error("tree hash mismatch, expected: {0} found: {1}")]
    TreeHashMismatch(String, String),
    #[error("invalid node parent hash found")]
    ParentHashMismatch,
}

pub struct TreeValidator<'a> {
    expected_tree_hash: &'a [u8],
    key_package_validator: KeyPackageValidator<'a>,
}

impl<'a> TreeValidator<'a> {
    pub fn new(
        protocol_version: ProtocolVersion,
        cipher_suite: CipherSuite,
        tree_hash: &'a [u8],
        required_capabilities: Option<&'a RequiredCapabilitiesExt>,
    ) -> Self {
        TreeValidator {
            expected_tree_hash: tree_hash,
            key_package_validator: KeyPackageValidator {
                protocol_version,
                cipher_suite,
                required_capabilities,
                options: HashSet::from([KeyPackageValidationOptions::SkipLifetimeCheck]),
            },
        }
    }

    pub fn validate(&self, tree: &TreeKemPublic) -> Result<(), TreeValidationError> {
        self.validate_tree_hash(tree)
            .and(self.validate_parent_hashes(tree))
            .and(self.validate_leaves(tree))
    }

    fn validate_tree_hash(&self, tree: &TreeKemPublic) -> Result<(), TreeValidationError> {
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
        // For each non-empty leaf node, verify the signature on the KeyPackage.
        tree.nodes
            .non_empty_leaves()
            .map(|l| &l.1.key_package)
            .try_for_each(|kp| self.key_package_validator.check_signature(kp))
            .map_err(Into::into)
    }

    fn validate_parent_hashes(&self, tree: &TreeKemPublic) -> Result<(), TreeValidationError> {
        //For each non-empty parent node, verify that exactly one of the node's children are
        // non-empty and have the hash of this node set as their parent_hash value (if the child
        // is another parent) or has a parent_hash extension in the KeyPackage containing the same
        // value (if the child is a leaf). If either of the node's children is empty, and in
        // particular does not have a parent hash, then its respective children's
        // values have to be considered instead.
        tree.nodes
            .non_empty_parents()
            .try_for_each(|(node_index, node)| tree.validate_parent_hash(node_index, node))
            .map_err(|_| TreeValidationError::ParentHashMismatch)
    }
}

#[cfg(test)]
mod test {
    use assert_matches::assert_matches;
    use ferriscrypt::{hpke::kem::HpkePublicKey, rand::SecureRng};

    use super::*;
    use crate::{
        extension::ParentHashExt,
        key_package::KeyPackageGenerator,
        tree_kem::{
            node::{LeafIndex, Node, Parent},
            parent_hash::ParentHash,
            test::{get_test_key_package_sig_key, get_test_tree_with_signer},
        },
    };

    fn test_parent_node(cipher_suite: CipherSuite) -> Parent {
        let public_key = cipher_suite
            .generate_secret_key()
            .unwrap()
            .to_public()
            .unwrap();

        Parent {
            public_key: HpkePublicKey::try_from(public_key).unwrap(),
            parent_hash: ParentHash::empty(),
            unmerged_leaves: vec![],
        }
    }

    fn get_valid_tree(
        cipher_suite: CipherSuite,
        protocol_version: ProtocolVersion,
    ) -> TreeKemPublic {
        let leaf0_signer = cipher_suite.generate_secret_key().unwrap();

        let (mut public_tree, _, _) =
            get_test_tree_with_signer(protocol_version, cipher_suite, &leaf0_signer);

        let leaf1_signer = cipher_suite.generate_secret_key().unwrap();

        let key_package = get_test_key_package_sig_key(
            protocol_version,
            cipher_suite,
            b"user".to_vec(),
            &leaf1_signer,
        );

        public_tree
            .add_leaves(vec![key_package.key_package])
            .unwrap();

        public_tree.nodes[1] = Some(Node::Parent(test_parent_node(cipher_suite)));

        for (index, _) in public_tree.clone().nodes.non_empty_leaves() {
            let parent_hash = public_tree.update_parent_hashes(index, None).unwrap();

            let package = public_tree.nodes.borrow_as_leaf_mut(index).unwrap();

            package
                .key_package
                .extensions
                .set_extension(ParentHashExt::from(parent_hash))
                .unwrap();

            let signer = if index.0 == 0 {
                &leaf0_signer
            } else {
                &leaf1_signer
            };

            let signer = KeyPackageGenerator {
                protocol_version,
                cipher_suite,
                credential: &package.key_package.credential.clone(),
                extensions: &package.key_package.extensions.clone(),
                signing_key: signer,
            };

            signer.sign(&mut package.key_package).unwrap();
        }

        public_tree
    }

    #[test]
    fn test_valid_tree() {
        for (protocol_version, cipher_suite) in
            ProtocolVersion::all().flat_map(|p| CipherSuite::all().map(move |cs| (p, cs)))
        {
            let test_tree = get_valid_tree(cipher_suite, protocol_version);
            let expected_tree_hash = test_tree.tree_hash().unwrap();

            let validator =
                TreeValidator::new(protocol_version, cipher_suite, &expected_tree_hash, None);

            validator.validate(&test_tree).unwrap();
        }
    }

    #[test]
    fn test_tree_hash_mismatch() {
        for (protocol_version, cipher_suite) in
            ProtocolVersion::all().flat_map(|p| CipherSuite::all().map(move |cs| (p, cs)))
        {
            let test_tree = get_valid_tree(cipher_suite, protocol_version);
            let expected_tree_hash = SecureRng::gen(32).unwrap();

            let validator =
                TreeValidator::new(protocol_version, cipher_suite, &expected_tree_hash, None);

            assert_matches!(
                validator.validate(&test_tree),
                Err(TreeValidationError::TreeHashMismatch(_, _))
            );
        }
    }

    #[test]
    fn test_parent_hash_mismatch() {
        for (protocol_version, cipher_suite) in
            ProtocolVersion::all().flat_map(|p| CipherSuite::all().map(move |cs| (p, cs)))
        {
            let mut test_tree = get_valid_tree(cipher_suite, protocol_version);

            let parent_node = test_tree.nodes.borrow_as_parent_mut(1).unwrap();
            parent_node.parent_hash = ParentHash::from(SecureRng::gen(32).unwrap());

            let expected_tree_hash = test_tree.tree_hash().unwrap();

            let validator =
                TreeValidator::new(protocol_version, cipher_suite, &expected_tree_hash, None);

            assert_matches!(
                validator.validate(&test_tree),
                Err(TreeValidationError::ParentHashMismatch)
            );
        }
    }

    #[test]
    fn test_key_package_validation_failure() {
        for (protocol_version, cipher_suite) in
            ProtocolVersion::all().flat_map(|p| CipherSuite::all().map(move |cs| (p, cs)))
        {
            let mut test_tree = get_valid_tree(cipher_suite, protocol_version);

            test_tree
                .nodes
                .borrow_as_leaf_mut(LeafIndex(0))
                .unwrap()
                .key_package
                .signature = SecureRng::gen(32).unwrap();

            let expected_tree_hash = test_tree.tree_hash().unwrap();

            let validator =
                TreeValidator::new(protocol_version, cipher_suite, &expected_tree_hash, None);

            assert_matches!(
                validator.validate(&test_tree),
                Err(TreeValidationError::KeyPackageValidationError(_))
            );
        }
    }
}
