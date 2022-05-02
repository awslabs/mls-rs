use ferriscrypt::hpke::kem::HpkePublicKey;
use thiserror::Error;
use tls_codec_derive::{TlsDeserialize, TlsSerialize, TlsSize};

use crate::cipher_suite::HpkeCiphertext;
use crate::client_config::CredentialValidator;

use super::{
    leaf_node::LeafNode,
    leaf_node_validator::{
        LeafNodeValidationError, LeafNodeValidator, ValidatedLeafNode, ValidationContext,
    },
};

#[derive(Clone, Debug, PartialEq, TlsDeserialize, TlsSerialize, TlsSize)]
pub struct UpdatePathNode {
    #[tls_codec(with = "crate::tls::ByteVec")]
    pub public_key: HpkePublicKey,
    #[tls_codec(with = "crate::tls::DefVec")]
    pub encrypted_path_secret: Vec<HpkeCiphertext>,
}

#[derive(Clone, Debug, PartialEq, TlsDeserialize, TlsSerialize, TlsSize)]
pub struct UpdatePath {
    pub leaf_node: LeafNode,
    #[tls_codec(with = "crate::tls::DefVec")]
    pub nodes: Vec<UpdatePathNode>,
}

#[derive(Debug, Error)]
pub enum UpdatePathValidationError {
    #[error(transparent)]
    LeafNodeValidationError(#[from] LeafNodeValidationError),
}

#[derive(Clone, Debug, PartialEq)]
pub struct ValidatedUpdatePath {
    pub leaf_node: ValidatedLeafNode,
    pub nodes: Vec<UpdatePathNode>,
}

pub struct UpdatePathValidator<'a, C: CredentialValidator>(LeafNodeValidator<'a, C>);

impl<'a, C: CredentialValidator> UpdatePathValidator<'a, C> {
    pub fn new(validator: LeafNodeValidator<'a, C>) -> Self {
        Self(validator)
    }
}

impl<'a, C: CredentialValidator> UpdatePathValidator<'a, C> {
    pub fn validate(
        &self,
        path: UpdatePath,
        group_id: &[u8],
    ) -> Result<ValidatedUpdatePath, UpdatePathValidationError> {
        let validated_key_package = self
            .0
            .validate(path.leaf_node, ValidationContext::Commit(group_id))?;

        Ok(ValidatedUpdatePath {
            leaf_node: validated_key_package,
            nodes: path.nodes,
        })
    }
}

#[cfg(test)]
mod tests {
    use assert_matches::assert_matches;

    use ferriscrypt::{hpke::kem::HpkePublicKey, rand::SecureRng};

    use crate::tree_kem::{
        leaf_node::{test_utils::get_basic_test_node_sig_key, LeafNode},
        leaf_node_validator::LeafNodeValidator,
        parent_hash::ParentHash,
    };

    use super::{UpdatePath, UpdatePathNode, UpdatePathValidator};
    use crate::{cipher_suite::CipherSuite, tree_kem::UpdatePathValidationError};

    use crate::client_config::{CredentialValidator, PassthroughCredentialValidator};

    #[cfg(target_arch = "wasm32")]
    use wasm_bindgen_test::wasm_bindgen_test as test;

    const TEST_GROUP_ID: &[u8] = b"GROUP";

    fn test_update_path(cipher_suite: CipherSuite) -> UpdatePath {
        let (mut leaf_node, _, signer) = get_basic_test_node_sig_key(cipher_suite, "foo");

        leaf_node
            .commit(cipher_suite, TEST_GROUP_ID, None, None, &signer, |_| {
                Ok(ParentHash::empty())
            })
            .unwrap();

        let ciphertext = ferriscrypt::hpke::HpkeCiphertext {
            enc: SecureRng::gen(32).unwrap(),
            ciphertext: SecureRng::gen(32).unwrap(),
        }
        .into();

        UpdatePath {
            leaf_node,
            nodes: vec![UpdatePathNode {
                public_key: HpkePublicKey::from(SecureRng::gen(32).unwrap()),
                encrypted_path_secret: vec![ciphertext],
            }],
        }
    }

    fn test_validator<'a, C: CredentialValidator>(
        cipher_suite: CipherSuite,
        credential_validator: C,
    ) -> UpdatePathValidator<'a, C> {
        UpdatePathValidator(LeafNodeValidator::new(
            cipher_suite,
            None,
            credential_validator,
        ))
    }

    #[test]
    fn test_valid_leaf_node() {
        let cipher_suite = CipherSuite::Curve25519Aes128;
        let update_path = test_update_path(cipher_suite);

        let validator = test_validator(cipher_suite, PassthroughCredentialValidator::new());

        let validated = validator
            .validate(update_path.clone(), TEST_GROUP_ID)
            .unwrap();

        assert_eq!(validated.nodes, update_path.nodes);
        assert_eq!(LeafNode::from(validated.leaf_node), update_path.leaf_node);
    }

    #[test]
    fn test_invalid_key_package() {
        let cipher_suite = CipherSuite::Curve25519Aes128;
        let mut update_path = test_update_path(cipher_suite);
        update_path.leaf_node.signature = SecureRng::gen(32).unwrap();

        let validator = test_validator(cipher_suite, PassthroughCredentialValidator::new());
        let validated = validator.validate(update_path, TEST_GROUP_ID);

        assert_matches!(
            validated,
            Err(UpdatePathValidationError::LeafNodeValidationError(_))
        );
    }
}
