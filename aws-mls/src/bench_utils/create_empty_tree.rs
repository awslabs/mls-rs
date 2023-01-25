use aws_mls_core::crypto::CipherSuiteProvider;

use crate::cipher_suite::CipherSuite;
use crate::extension::ExtensionList;
use crate::group::{ConfirmedTranscriptHash, GroupContext};
use crate::identity::SigningIdentity;
use crate::protocol_version::ProtocolVersion;
use crate::provider::crypto::test_utils::test_cipher_suite_provider;
use crate::provider::crypto::SignatureSecretKey;
use crate::provider::identity::BasicIdentityProvider;
use crate::tree_kem::leaf_node::test_utils::get_basic_test_node_sig_key;
use crate::tree_kem::node::LeafIndex;
use crate::tree_kem::{TreeKemPrivate, TreeKemPublic};
use futures::StreamExt;
use std::collections::HashMap;

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct TestCase {
    pub private_keys: Vec<TreeKemPrivate>,
    pub test_tree: TreeKemPublic,
    pub encap_tree: TreeKemPublic,
    pub encap_private_key: TreeKemPrivate,
    pub encap_signer: SignatureSecretKey,
    pub group_context: GroupContext,
    pub encap_identity: SigningIdentity,
}

async fn generate_test_cases() -> HashMap<usize, TestCase> {
    let cipher_suite = CipherSuite::Curve25519Aes128;

    futures::stream::iter([100, 1000, 10000])
        .then(|length| async move { (length, create_stage(cipher_suite, length).await) })
        .collect::<HashMap<_, _>>()
        .await
}

pub async fn load_test_cases() -> HashMap<usize, TestCase> {
    load_test_cases!(empty_trees, generate_test_cases().await, to_vec)
}

// Used code from kem.rs to create empty test trees and to begin doing encap/decap
pub async fn create_stage(cipher_suite: CipherSuite, size: usize) -> TestCase {
    // Generate signing keys and key package generations, and private keys for multiple
    // participants in order to set up state
    let (leaf_nodes, private_keys): (_, Vec<TreeKemPrivate>) = futures::stream::iter(1..size)
        .then(|index| async move {
            let (leaf_node, hpke_secret, _) =
                get_basic_test_node_sig_key(cipher_suite, &format!("{}", index)).await;

            let private_key =
                TreeKemPrivate::new_self_leaf(LeafIndex::new(index as u32), hpke_secret);

            (leaf_node, private_key)
        })
        .unzip()
        .await;

    let (encap_node, encap_hpke_secret, encap_signer) =
        get_basic_test_node_sig_key(cipher_suite, "encap").await;

    let encap_identity = encap_node.signing_identity.clone();

    let cipher_suite_provider = test_cipher_suite_provider(cipher_suite);

    // Build a test tree we can clone for all leaf nodes
    let (mut test_tree, encap_private_key) = TreeKemPublic::derive(
        encap_node,
        encap_hpke_secret,
        BasicIdentityProvider,
        &cipher_suite_provider,
    )
    .await
    .unwrap();

    test_tree
        .add_leaves(leaf_nodes, BasicIdentityProvider, &cipher_suite_provider)
        .await
        .unwrap();

    // Clone the tree for the first leaf, generate a new key package for that leaf
    let encap_tree = test_tree.clone();

    let group_context = GroupContext {
        protocol_version: ProtocolVersion::Mls10,
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
