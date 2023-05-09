use alloc::vec;
use alloc::vec::Vec;
use aws_mls_codec::{MlsDecode, MlsEncode};
use aws_mls_core::{
    crypto::{CipherSuite, CipherSuiteProvider},
    extension::ExtensionList,
};

use itertools::Itertools;

use crate::{
    crypto::test_utils::try_test_cipher_suite_provider, identity::basic::BasicIdentityProvider,
};

use super::{
    node::NodeVec, test_utils::TreeWithSigners, tree_validator::TreeValidator, TreeKemPublic,
};

#[cfg(target_arch = "wasm32")]
use wasm_bindgen_test::wasm_bindgen_test as test;

#[cfg(not(target_arch = "wasm32"))]
use futures_test::test;

#[derive(serde::Serialize, serde::Deserialize, Debug, Default, Clone)]
struct ValidationTestCase {
    pub cipher_suite: u16,

    #[serde(with = "hex::serde")]
    pub tree: Vec<u8>,
    #[serde(with = "hex::serde")]
    pub group_id: Vec<u8>,
    pub tree_hashes: Vec<TreeHash>,
    pub resolutions: Vec<Vec<u32>>,
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Default, Clone)]
struct TreeHash(#[serde(with = "hex::serde")] pub Vec<u8>);

impl ValidationTestCase {
    fn new<P: CipherSuiteProvider>(tree: TreeKemPublic, group_id: &[u8], cs: &P) -> Self {
        let tree_size = tree.total_leaf_count() * 2 - 1;

        assert!(
            tree.tree_hashes.current.len() == tree_size as usize,
            "hashes not initialized"
        );

        let resolutions = (0..tree_size)
            .map(|i| tree.nodes.get_resolution_index(i).unwrap())
            .collect();

        Self {
            cipher_suite: cs.cipher_suite().into(),
            tree: tree.export_node_data().mls_encode_to_vec().unwrap(),
            tree_hashes: tree.tree_hashes.current.into_iter().map(TreeHash).collect(),
            group_id: group_id.to_vec(),
            resolutions,
        }
    }
}

#[test]
async fn validation() {
    let test_cases: Vec<ValidationTestCase> = load_test_cases!(
        interop_tree_validation,
        generate_validation_test_vector().await
    );

    for test_case in test_cases.into_iter() {
        let Some(cs) = try_test_cipher_suite_provider(test_case.cipher_suite) else {
            continue;
        };

        let mut tree = TreeKemPublic::import_node_data(
            NodeVec::mls_decode(&mut &*test_case.tree).unwrap(),
            #[cfg(feature = "tree_index")]
            &BasicIdentityProvider,
        )
        .await
        .unwrap();

        let tree_hash = tree.tree_hash(&cs).unwrap();

        tree.tree_hashes
            .current
            .iter()
            .zip_eq(test_case.tree_hashes.iter())
            .for_each(|(l, r)| assert_eq!(l, &r.0));

        test_case
            .resolutions
            .iter()
            .enumerate()
            .for_each(|(i, res)| {
                assert_eq!(&tree.nodes.get_resolution_index(i as u32).unwrap(), res)
            });

        TreeValidator::new(
            &cs,
            &test_case.group_id,
            &tree_hash,
            None,
            &ExtensionList::new(),
            &BasicIdentityProvider,
        )
        .validate(&mut tree)
        .await
        .unwrap();
    }
}

async fn generate_validation_test_vector() -> Vec<ValidationTestCase> {
    let mut test_cases = vec![];

    for cs in CipherSuite::all() {
        let Some(cs) = try_test_cipher_suite_provider(*cs) else {
            continue;
        };

        let mut trees = vec![];

        // Generate trees with increasing complexity. Start: full complete trees
        for n_leaves in [2, 4, 8, 32] {
            trees.push(TreeWithSigners::make_full_tree(n_leaves, &cs).await);
        }

        // Internal blanks, no skipping : 8 leaves, 0 commits removing 2, 3 and adding new member
        let mut tree = TreeWithSigners::make_full_tree(8, &cs).await;
        tree.remove_member(2);
        tree.remove_member(3);
        tree.add_member("Bob", &cs).await;
        tree.update_committer_path(0, &cs).await;
        trees.push(tree);

        // Blanks at the end, no skipping
        for n_leaves in [3, 5, 7, 33] {
            trees.push(TreeWithSigners::make_full_tree(n_leaves, &cs).await);
        }

        // Internal blanks, with skipping : 8 leaves, 0 commits removing 1, 2, 3
        let mut tree = TreeWithSigners::make_full_tree(8, &cs).await;
        [1, 2, 3].into_iter().for_each(|i| tree.remove_member(i));
        tree.update_committer_path(0, &cs).await;
        trees.push(tree);

        // Blanks at the end, with skipping
        for n_leaves in [6, 34] {
            trees.push(TreeWithSigners::make_full_tree(n_leaves, &cs).await);
        }

        // Unmerged leaves, no skipping : 7 leaves; 0 commits adding a member
        let mut tree = TreeWithSigners::make_full_tree(7, &cs).await;
        tree.add_member("Bob", &cs).await;
        tree.update_committer_path(0, &cs).await;
        trees.push(tree);

        // Unmerged leaves, with skipping : figure 20 in the RFC
        let mut tree = TreeWithSigners::make_full_tree(7, &cs).await;
        tree.remove_member(5);
        tree.update_committer_path(0, &cs).await;
        tree.update_committer_path(4, &cs).await;
        tree.add_member("Bob", &cs).await;
        tree.tree.tree_hashes.current = vec![];
        tree.tree.tree_hashes.original = vec![];
        tree.tree.tree_hash(&cs).unwrap();
        trees.push(tree);

        // Generate tests
        trees.into_iter().for_each(|tree| {
            test_cases.push(ValidationTestCase::new(tree.tree, &tree.group_id, &cs))
        });
    }

    test_cases
}
