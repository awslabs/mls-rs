use aws_mls_codec::{MlsDecode, MlsEncode, MlsSize};

use aws_mls_core::crypto::{
    CipherSuiteProvider, CryptoProvider, HpkeSecretKey, SignatureSecretKey,
};
use aws_mls_core::protocol_version::ProtocolVersion;

use crate::cipher_suite::CipherSuite;
use crate::crypto::test_utils::test_cipher_suite_provider;
use crate::group::{ConfirmedTranscriptHash, GroupContext};
use crate::identity::basic::BasicIdentityProvider;
use crate::identity::SigningIdentity;
use crate::tree_kem::leaf_node::LeafNode;
use crate::tree_kem::node::LeafIndex;
use crate::tree_kem::{TreeKemPrivate, TreeKemPublic};
use crate::ExtensionList;
use std::collections::HashMap;

use super::group_functions::MlsCryptoProvider;

pub const PROTOCOL_VERSION: ProtocolVersion = ProtocolVersion::MLS_10;

#[derive(Debug, MlsSize, MlsDecode, MlsEncode)]
pub struct TestCase {
    pub private_keys: Vec<TreeKemPrivate>,
    pub test_tree: TreeKemPublic,
    pub encap_tree: TreeKemPublic,
    pub encap_private_key: TreeKemPrivate,
    pub encap_signer: SignatureSecretKey,
    pub group_context: GroupContext,
    pub encap_identity: SigningIdentity,
}

#[maybe_async::maybe_async]
async fn generate_test_cases(cipher_suite: CipherSuite) -> HashMap<u32, TestCase> {
    let mut cases = HashMap::new();

    for length in [100, 1000, 10000] {
        cases.insert(length, create_stage(cipher_suite, length).await);
    }

    cases
}

#[maybe_async::async_impl]
pub async fn load_test_cases(cipher_suite: CipherSuite) -> HashMap<u32, TestCase> {
    load_test_case_mls!(empty_trees, generate_test_cases(cipher_suite).await, to_vec)
}

#[maybe_async::sync_impl]
pub fn load_test_cases(cipher_suite: CipherSuite) -> HashMap<u32, TestCase> {
    load_test_case_mls!(empty_trees, generate_test_cases(cipher_suite), to_vec)
}

// Used code from kem.rs to create empty test trees and to begin doing encap/decap
#[maybe_async::maybe_async]
pub async fn create_stage(cipher_suite: CipherSuite, size: u32) -> TestCase {
    // Generate signing keys and key package generations, and private keys for multiple
    // participants in order to set up state

    let mut leaf_nodes = Vec::new();
    let mut private_keys = Vec::new();

    for index in 1..size {
        let (leaf_node, hpke_secret, _) = make_leaf(cipher_suite, &format!("{index}")).await;

        let private_key = TreeKemPrivate::new_self_leaf(LeafIndex::new(index), hpke_secret);

        leaf_nodes.push(leaf_node);
        private_keys.push(private_key)
    }

    let (encap_node, encap_hpke_secret, encap_signer) = make_leaf(cipher_suite, "encap").await;

    let encap_identity = encap_node.signing_identity.clone();

    let cipher_suite_provider = test_cipher_suite_provider(cipher_suite);

    // Build a test tree we can clone for all leaf nodes
    let (mut test_tree, encap_private_key) =
        TreeKemPublic::derive(encap_node, encap_hpke_secret, &BasicIdentityProvider)
            .await
            .unwrap();

    test_tree
        .add_leaves(leaf_nodes, &BasicIdentityProvider, &cipher_suite_provider)
        .await
        .unwrap();

    // Clone the tree for the first leaf, generate a new key package for that leaf
    let encap_tree = test_tree.clone();

    let group_context = GroupContext {
        protocol_version: PROTOCOL_VERSION,
        cipher_suite,
        group_id: b"test_group".to_vec(),
        epoch: 42,
        tree_hash: vec![0u8; cipher_suite_provider.kdf_extract_size()],
        confirmed_transcript_hash: ConfirmedTranscriptHash::from(vec![
            0u8;
            cipher_suite_provider
                .kdf_extract_size()
        ]),
        extensions: ExtensionList::new(),
    };

    TestCase {
        private_keys,
        test_tree,
        encap_tree,
        encap_private_key,
        encap_signer,
        group_context,
        encap_identity,
    }
}

#[maybe_async::maybe_async]
async fn make_leaf(cs: CipherSuite, name: &str) -> (LeafNode, HpkeSecretKey, SignatureSecretKey) {
    let cs = MlsCryptoProvider::new().cipher_suite_provider(cs).unwrap();
    LeafNode::generate_default(&cs, name).await
}
