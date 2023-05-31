use alloc::vec;
use alloc::vec::Vec;
use aws_mls_codec::{MlsDecode, MlsEncode};

use crate::{
    client::test_utils::{TEST_CIPHER_SUITE, TEST_PROTOCOL_VERSION},
    crypto::test_utils::test_cipher_suite_provider,
    group::{
        internal::{LeafIndex, TreeKemPublic},
        proposal::{AddProposal, Proposal, ProposalOrRef, RemoveProposal, UpdateProposal},
        proposal_cache::test_utils::CommitReceiver,
        proposal_ref::ProposalRef,
        test_utils::TEST_GROUP,
        Sender,
    },
    key_package::test_utils::test_key_package,
    tree_kem::{
        leaf_node::test_utils::default_properties, node::NodeVec, test_utils::TreeWithSigners,
    },
};

#[cfg(feature = "tree_index")]
use crate::identity::basic::BasicIdentityProvider;

#[derive(serde::Serialize, serde::Deserialize, Debug, Default, Clone)]
struct TreeModsTestCase {
    #[serde(with = "hex::serde")]
    pub tree_before: Vec<u8>,
    #[serde(with = "hex::serde")]
    pub proposal: Vec<u8>,
    pub proposal_sender: u32,
    #[serde(with = "hex::serde")]
    pub tree_after: Vec<u8>,
}

impl TreeModsTestCase {
    #[maybe_async::maybe_async]
    async fn new(tree_before: TreeKemPublic, proposal: Proposal, proposal_sender: u32) -> Self {
        let tree_after = apply_proposal(proposal.clone(), proposal_sender, &tree_before).await;

        Self {
            tree_before: tree_before.nodes.mls_encode_to_vec().unwrap(),
            proposal: proposal.mls_encode_to_vec().unwrap(),
            tree_after: tree_after.nodes.mls_encode_to_vec().unwrap(),
            proposal_sender,
        }
    }
}

#[maybe_async::maybe_async]
async fn generate_tree_mods_tests() -> Vec<TreeModsTestCase> {
    let mut test_vector = vec![];
    let cs = test_cipher_suite_provider(TEST_CIPHER_SUITE);

    // Update
    let tree_before = TreeWithSigners::make_full_tree(8, &cs).await;
    let update = generate_update(6, &tree_before).await;
    test_vector.push(TreeModsTestCase::new(tree_before.tree, update, 6).await);

    // Add in the middle
    let mut tree_before = TreeWithSigners::make_full_tree(6, &cs).await;
    tree_before.remove_member(3);
    test_vector.push(TreeModsTestCase::new(tree_before.tree, generate_add().await, 2).await);

    // Add at the end
    let tree_before = TreeWithSigners::make_full_tree(6, &cs).await;
    test_vector.push(TreeModsTestCase::new(tree_before.tree, generate_add().await, 2).await);

    // Add at the end, tree grows
    let tree_before = TreeWithSigners::make_full_tree(8, &cs).await;
    test_vector.push(TreeModsTestCase::new(tree_before.tree, generate_add().await, 2).await);

    // Remove in the middle
    let tree_before = TreeWithSigners::make_full_tree(8, &cs).await;
    test_vector.push(TreeModsTestCase::new(tree_before.tree, generate_remove(2), 2).await);

    // Remove at the end
    let tree_before = TreeWithSigners::make_full_tree(8, &cs).await;
    test_vector.push(TreeModsTestCase::new(tree_before.tree, generate_remove(7), 2).await);

    // Remove at the end, tree shrinks
    let tree_before = TreeWithSigners::make_full_tree(9, &cs).await;
    test_vector.push(TreeModsTestCase::new(tree_before.tree, generate_remove(8), 2).await);

    test_vector
}

#[maybe_async::test(sync, async(not(sync), futures_test::test))]
async fn tree_modifications_interop() {
    // The test vector can be found here https://github.com/mlswg/mls-implementations/blob/main/test-vectors/tree-operations.json
    #[cfg(sync)]
    let test_cases: Vec<TreeModsTestCase> =
        load_test_case_json!(tree_modifications_interop, generate_tree_mods_tests());

    #[cfg(not(sync))]
    let test_cases: Vec<TreeModsTestCase> =
        load_test_case_json!(tree_modifications_interop, generate_tree_mods_tests().await);

    for test_case in test_cases.into_iter() {
        let nodes = NodeVec::mls_decode(&mut &*test_case.tree_before).unwrap();

        let tree_before = TreeKemPublic::import_node_data(
            nodes,
            #[cfg(feature = "tree_index")]
            &BasicIdentityProvider,
        )
        .await
        .unwrap();

        let proposal = Proposal::mls_decode(&mut &*test_case.proposal).unwrap();

        let tree_after = apply_proposal(proposal, test_case.proposal_sender, &tree_before).await;

        let tree_after = tree_after.export_node_data().mls_encode_to_vec().unwrap();

        assert_eq!(tree_after, test_case.tree_after);
    }
}

#[maybe_async::maybe_async]
async fn apply_proposal(
    proposal: Proposal,
    sender: u32,
    tree_before: &TreeKemPublic,
) -> TreeKemPublic {
    let cs = test_cipher_suite_provider(TEST_CIPHER_SUITE);
    let p_ref = ProposalRef::new_fake(b"fake ref".to_vec());

    CommitReceiver::new(tree_before, Sender::Member(0), LeafIndex(1), cs)
        .cache(p_ref.clone(), proposal, Sender::Member(sender))
        .receive(vec![ProposalOrRef::Reference(p_ref)])
        .await
        .unwrap()
        .public_tree
}

#[maybe_async::maybe_async]
async fn generate_add() -> Proposal {
    let key_package = test_key_package(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE, "Roger").await;
    Proposal::Add(AddProposal { key_package })
}

fn generate_remove(i: u32) -> Proposal {
    let to_remove = LeafIndex(i);
    Proposal::Remove(RemoveProposal { to_remove })
}

#[maybe_async::maybe_async]
async fn generate_update(i: u32, tree: &TreeWithSigners) -> Proposal {
    let signer = tree.signers[i as usize].as_ref().unwrap();
    let mut leaf_node = tree.tree.get_leaf_node(LeafIndex(i)).unwrap().clone();

    leaf_node
        .update(
            &test_cipher_suite_provider(TEST_CIPHER_SUITE),
            TEST_GROUP,
            i,
            default_properties(),
            None,
            signer,
        )
        .unwrap();

    Proposal::Update(UpdateProposal { leaf_node })
}
