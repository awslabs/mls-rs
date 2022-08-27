use crate::cipher_suite::CipherSuite;
use crate::credential::PassthroughCredentialValidator;
use crate::extension::ExtensionList;
use crate::ferriscrypt::asym::ec_key::SecretKey;
use crate::group::{ConfirmedTranscriptHash, GroupContext};
use crate::protocol_version::ProtocolVersion;
use crate::tree_kem::leaf_node::test_utils::get_basic_test_node_sig_key;
use crate::tree_kem::node::LeafIndex;
use crate::tree_kem::{TreeKemPrivate, TreeKemPublic};
use std::collections::HashMap;

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct TestCase {
    pub private_keys: Vec<TreeKemPrivate>,
    pub test_tree: TreeKemPublic,
    pub encap_tree: TreeKemPublic,
    pub encap_private_key: TreeKemPrivate,
    pub encap_signer: SecretKey,
    pub group_context: GroupContext,
}

fn generate_test_cases() -> HashMap<usize, TestCase> {
    let cipher_suite = CipherSuite::Curve25519Aes128;

    [100, 1000, 10000]
        .into_iter()
        .map(|length| (length, create_stage(cipher_suite, length)))
        .collect::<HashMap<_, _>>()
}

pub fn load_test_cases() -> HashMap<usize, TestCase> {
    load_test_cases!(empty_trees, generate_test_cases, to_vec)
}

// Used code from kem.rs to create empty test trees and to begin doing encap/decap
pub fn create_stage(cipher_suite: CipherSuite, size: usize) -> TestCase {
    // Generate signing keys and key package generations, and private keys for multiple
    // participants in order to set up state
    let (leaf_nodes, private_keys): (_, Vec<TreeKemPrivate>) = (1..size)
        .map(|index| {
            let (leaf_node, hpke_secret, _) =
                get_basic_test_node_sig_key(cipher_suite, &format!("{}", index));

            let private_key =
                TreeKemPrivate::new_self_leaf(LeafIndex::new(index as u32), hpke_secret);

            (leaf_node, private_key)
        })
        .unzip();

    let (encap_node, encap_hpke_secret, encap_signer) =
        get_basic_test_node_sig_key(cipher_suite, "encap");

    // Build a test tree we can clone for all leaf nodes
    let (mut test_tree, encap_private_key) = TreeKemPublic::derive(
        cipher_suite,
        encap_node,
        encap_hpke_secret,
        PassthroughCredentialValidator,
    )
    .unwrap();

    test_tree
        .add_leaves(leaf_nodes, PassthroughCredentialValidator)
        .unwrap();

    // Clone the tree for the first leaf, generate a new key package for that leaf
    let encap_tree = test_tree.clone();

    let group_context = GroupContext {
        protocol_version: ProtocolVersion::Mls10,
        cipher_suite,
        group_id: b"test_group".to_vec(),
        epoch: 42,
        tree_hash: vec![0u8; cipher_suite.hash_function().digest_size()],
        confirmed_transcript_hash: ConfirmedTranscriptHash::from(vec![
            0u8;
            cipher_suite
                .hash_function()
                .digest_size()
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
    }
}
