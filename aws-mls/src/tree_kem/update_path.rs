use alloc::{vec, vec::Vec};
use aws_mls_codec::{MlsDecode, MlsEncode, MlsSize};
use aws_mls_core::{error::IntoAnyError, extension::ExtensionList, identity::IdentityProvider};

use super::{
    leaf_node::LeafNode,
    leaf_node_validator::{LeafNodeValidator, ValidationContext},
    node::LeafIndex,
};
use crate::{
    client::MlsError,
    crypto::{CipherSuiteProvider, HpkeCiphertext, HpkePublicKey},
};
use crate::{group::message_processor::ProvisionalState, time::MlsTime};

#[derive(Clone, Debug, PartialEq, Eq, MlsSize, MlsEncode, MlsDecode)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct UpdatePathNode {
    pub public_key: HpkePublicKey,
    pub encrypted_path_secret: Vec<HpkeCiphertext>,
}

#[derive(Clone, Debug, PartialEq, MlsSize, MlsEncode, MlsDecode)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct UpdatePath {
    pub leaf_node: LeafNode,
    pub nodes: Vec<UpdatePathNode>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct ValidatedUpdatePath {
    pub leaf_node: LeafNode,
    pub nodes: Vec<Option<UpdatePathNode>>,
}

#[maybe_async::maybe_async]
pub(crate) async fn validate_update_path<C: IdentityProvider, CSP: CipherSuiteProvider>(
    identity_provider: &C,
    cipher_suite_provider: &CSP,
    path: &UpdatePath,
    state: &ProvisionalState,
    sender: LeafIndex,
    commit_time: Option<MlsTime>,
    group_context_extensions: &ExtensionList,
) -> Result<ValidatedUpdatePath, MlsError> {
    let required_capabilities = state.group_context.extensions.get_as()?;

    let leaf_validator = LeafNodeValidator::new(
        cipher_suite_provider,
        required_capabilities.as_ref(),
        identity_provider,
        Some(group_context_extensions),
    );

    leaf_validator
        .check_if_valid(
            &path.leaf_node,
            ValidationContext::Commit((&state.group_context.group_id, *sender, commit_time)),
        )
        .await?;

    #[cfg(feature = "external_commit")]
    let check_identity_eq = state.applied_proposals.external_initializations.is_empty();

    #[cfg(not(feature = "external_commit"))]
    let check_identity_eq = true;

    if check_identity_eq {
        let existing_leaf = state.public_tree.nodes.borrow_as_leaf(sender)?;
        let original_leaf_node = existing_leaf.clone();

        let original_identity = identity_provider
            .identity(&original_leaf_node.signing_identity)
            .await
            .map_err(|e| MlsError::IdentityProviderError(e.into_any_error()))?;

        let updated_identity = identity_provider
            .identity(&path.leaf_node.signing_identity)
            .await
            .map_err(|e| MlsError::IdentityProviderError(e.into_any_error()))?;

        (original_identity == updated_identity)
            .then_some(())
            .ok_or(MlsError::DifferentIdentityInUpdate(*sender))?;

        (existing_leaf.public_key != path.leaf_node.public_key)
            .then_some(())
            .ok_or(MlsError::SameHpkeKey(*sender))?;
    }

    // Unfilter the update path
    let filtered = state.public_tree.nodes.filtered(sender)?;
    let num_filtered = filtered.iter().filter(|v| !**v).count();

    (path.nodes.len() == num_filtered)
        .then_some(())
        .ok_or(MlsError::WrongPathLen)?;

    let mut unfiltered_nodes = vec![None; filtered.len()];
    let filtered_iter = filtered.into_iter().enumerate().filter(|(_, f)| !*f);

    // TODO can we avoid clone?
    for ((i, _), node) in filtered_iter.zip(path.nodes.iter()) {
        unfiltered_nodes[i] = Some(node.clone());
    }

    Ok(ValidatedUpdatePath {
        leaf_node: path.leaf_node.clone(),
        nodes: unfiltered_nodes,
    })
}

#[cfg(test)]
mod tests {
    use alloc::vec;
    use assert_matches::assert_matches;
    use aws_mls_core::extension::ExtensionList;

    use crate::client::test_utils::TEST_CIPHER_SUITE;
    use crate::crypto::test_utils::test_cipher_suite_provider;
    use crate::crypto::HpkeCiphertext;
    use crate::group::message_processor::ProvisionalState;
    use crate::group::test_utils::{get_test_group_context, random_bytes, TEST_GROUP};
    use crate::identity::basic::BasicIdentityProvider;
    use crate::tree_kem::leaf_node::test_utils::default_properties;
    use crate::tree_kem::node::LeafIndex;
    use crate::tree_kem::test_utils::{get_test_leaf_nodes, get_test_tree};
    use crate::tree_kem::validate_update_path;
    use crate::tree_kem::{
        leaf_node::test_utils::get_basic_test_node_sig_key, parent_hash::ParentHash,
    };

    use super::{UpdatePath, UpdatePathNode};
    use crate::{cipher_suite::CipherSuite, tree_kem::MlsError};

    #[cfg(target_arch = "wasm32")]
    use wasm_bindgen_test::wasm_bindgen_test as test;

    #[maybe_async::maybe_async]
    async fn test_update_path(cipher_suite: CipherSuite, cred: &str) -> UpdatePath {
        let (mut leaf_node, _, signer) = get_basic_test_node_sig_key(cipher_suite, cred).await;

        leaf_node
            .commit(
                &test_cipher_suite_provider(cipher_suite),
                TEST_GROUP,
                0,
                default_properties(),
                None,
                &signer,
                ParentHash::empty(),
            )
            .unwrap();

        let node = UpdatePathNode {
            public_key: random_bytes(32).into(),
            encrypted_path_secret: vec![HpkeCiphertext {
                kem_output: random_bytes(32),
                ciphertext: random_bytes(32),
            }],
        };

        UpdatePath {
            leaf_node,
            nodes: vec![node.clone(), node],
        }
    }

    #[maybe_async::maybe_async]
    async fn test_provisional_state(cipher_suite: CipherSuite) -> ProvisionalState {
        let mut tree = get_test_tree(cipher_suite).await.public;
        let leaf_nodes = get_test_leaf_nodes(cipher_suite).await;

        tree.add_leaves(
            leaf_nodes,
            &BasicIdentityProvider,
            &test_cipher_suite_provider(cipher_suite),
        )
        .await
        .unwrap();

        ProvisionalState {
            public_tree: tree,
            applied_proposals: Default::default(),
            group_context: get_test_group_context(1, cipher_suite),
            indexes_of_added_kpkgs: vec![],
            #[cfg(feature = "external_commit")]
            external_init_index: None,
            #[cfg(feature = "state_update")]
            rejected_proposals: vec![],
        }
    }

    #[maybe_async::test(sync, async(not(sync), futures_test::test))]
    async fn test_valid_leaf_node() {
        let cipher_suite_provider = test_cipher_suite_provider(TEST_CIPHER_SUITE);
        let update_path = test_update_path(TEST_CIPHER_SUITE, "creator").await;

        let validated = validate_update_path(
            &BasicIdentityProvider,
            &cipher_suite_provider,
            &update_path,
            &test_provisional_state(TEST_CIPHER_SUITE).await,
            LeafIndex(0),
            None,
            &ExtensionList::new(),
        )
        .await
        .unwrap();

        let expected = update_path.nodes.into_iter().map(Some).collect::<Vec<_>>();

        assert_eq!(validated.nodes, expected);
        assert_eq!(validated.leaf_node, update_path.leaf_node);
    }

    #[maybe_async::test(sync, async(not(sync), futures_test::test))]
    async fn test_invalid_key_package() {
        let cipher_suite_provider = test_cipher_suite_provider(TEST_CIPHER_SUITE);
        let mut update_path = test_update_path(TEST_CIPHER_SUITE, "creator").await;
        update_path.leaf_node.signature = random_bytes(32);

        let validated = validate_update_path(
            &BasicIdentityProvider,
            &cipher_suite_provider,
            &update_path,
            &test_provisional_state(TEST_CIPHER_SUITE).await,
            LeafIndex(0),
            None,
            &ExtensionList::new(),
        )
        .await;

        assert_matches!(validated, Err(MlsError::InvalidSignature));
    }

    #[maybe_async::test(sync, async(not(sync), futures_test::test))]
    async fn validating_path_fails_with_different_identity() {
        let cipher_suite_provider = test_cipher_suite_provider(TEST_CIPHER_SUITE);
        let cipher_suite = TEST_CIPHER_SUITE;
        let update_path = test_update_path(cipher_suite, "foobar").await;

        let validated = validate_update_path(
            &BasicIdentityProvider,
            &cipher_suite_provider,
            &update_path,
            &test_provisional_state(cipher_suite).await,
            LeafIndex(0),
            None,
            &ExtensionList::new(),
        )
        .await;

        assert_matches!(validated, Err(MlsError::DifferentIdentityInUpdate(_)));
    }

    #[maybe_async::test(sync, async(not(sync), futures_test::test))]
    async fn validating_path_fails_with_same_hpke_key() {
        let cipher_suite_provider = test_cipher_suite_provider(TEST_CIPHER_SUITE);
        let update_path = test_update_path(TEST_CIPHER_SUITE, "creator").await;
        let mut state = test_provisional_state(TEST_CIPHER_SUITE).await;

        state
            .public_tree
            .nodes
            .borrow_as_leaf_mut(LeafIndex(0))
            .unwrap()
            .public_key = update_path.leaf_node.public_key.clone();

        let validated = validate_update_path(
            &BasicIdentityProvider,
            &cipher_suite_provider,
            &update_path,
            &state,
            LeafIndex(0),
            None,
            &ExtensionList::new(),
        )
        .await;

        assert_matches!(validated, Err(MlsError::SameHpkeKey(_)));
    }
}
