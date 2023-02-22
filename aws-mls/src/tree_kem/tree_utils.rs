use std::borrow::BorrowMut;

use debug_tree::TreeBuilder;

use super::node::NodeIndex;
use super::NodeVecError;
use super::{math::root, node::NodeVec};
use crate::tree_kem::math::{left, right};

pub(crate) fn build_tree(
    tree: &mut TreeBuilder,
    nodes: &NodeVec,
    idx: NodeIndex,
) -> Result<(), NodeVecError> {
    let blank_tag = if nodes.is_blank(idx)? { "Blank " } else { "" };

    // Leaf Node
    if nodes.is_leaf(idx) {
        let leaf_tag = format!("{blank_tag}Leaf ({idx})");
        tree.add_leaf(&leaf_tag);
        return Ok(());
    }

    // Parent Leaf
    let mut parent_tag = format!("{blank_tag}Parent ({idx})");

    if root(nodes.total_leaf_count()) == idx {
        parent_tag = format!("{blank_tag}Root ({idx})");
    }

    // Add unmerged leaves indexes
    let unmerged_leaves_idxs = match nodes.borrow_as_parent(idx) {
        Ok(parent) => parent
            .unmerged_leaves
            .iter()
            .map(|leaf_idx| format!("{}", leaf_idx.0))
            .collect(),
        Err(_) => {
            // Empty parent nodes throw `NotParent` error when borrow as Parent
            vec![]
        }
    };

    if !unmerged_leaves_idxs.is_empty() {
        let unmerged_leaves_tag =
            format!(" unmerged leaves idxs: {}", unmerged_leaves_idxs.join(","));
        parent_tag.push_str(&unmerged_leaves_tag);
    }

    let mut branch = tree.add_branch(&parent_tag);

    build_tree(tree, nodes, left(idx)?)?;
    build_tree(tree, nodes, right(idx)?)?;

    branch.release();

    Ok(())
}

pub(crate) fn build_ascii_tree(nodes: &NodeVec) -> String {
    let leaves_count: u32 = nodes.total_leaf_count();
    let mut tree = TreeBuilder::new();
    build_tree(tree.borrow_mut(), nodes, root(leaves_count)).unwrap();
    tree.string()
}

#[cfg(test)]
pub(crate) mod test_utils {
    use aws_mls_core::{
        crypto::{CipherSuiteProvider, SignatureSecretKey},
        group::Capabilities,
        identity::BasicCredential,
    };

    use crate::{
        crypto::test_utils::TestCryptoProvider,
        identity::{basic::BasicIdentityProvider, test_utils::get_test_signing_identity},
        signer::Signable,
        tree_kem::{
            leaf_node::{ConfigProperties, LeafNode, LeafNodeSigningContext, LeafNodeSource},
            node::LeafIndex,
            Lifetime, TreeKemPublic,
        },
    };

    #[derive(Debug, Clone)]
    pub struct TreeWithSigners {
        pub tree: TreeKemPublic,
        pub signers: Vec<Option<SignatureSecretKey>>,
        pub group_id: Vec<u8>,
    }

    impl TreeWithSigners {
        pub async fn make_full_tree<P: CipherSuiteProvider>(
            n_leaves: u32,
            cs: &P,
        ) -> TreeWithSigners {
            let mut tree = TreeWithSigners {
                tree: TreeKemPublic::new(),
                signers: vec![],
                group_id: cs.random_bytes_vec(cs.kdf_extract_size()).unwrap(),
            };

            tree.add_member("Alice", cs).await;

            // A adds B, B adds C, C adds D etc.
            for i in 1..n_leaves {
                tree.add_member(&format!("Alice{i}"), cs).await;
                tree.update_committer_path(i - 1, cs).await;
            }

            tree
        }

        pub async fn add_member<P: CipherSuiteProvider>(&mut self, name: &str, cs: &P) {
            let (leaf, signer) = make_leaf(name, cs).await;
            let index = self.tree.nodes.insert_leaf(LeafIndex(0), leaf);
            self.tree.update_unmerged(index).unwrap();
            let index = *index as usize;

            match self.signers.len() {
                l if l == index => self.signers.push(Some(signer)),
                l if l > index => self.signers[index] = Some(signer),
                _ => panic!("signer tree size mismatch"),
            }
        }

        pub fn remove_member(&mut self, member: u32) {
            self.tree
                .nodes
                .blank_direct_path(LeafIndex(member))
                .unwrap();

            self.tree.nodes.blank_leaf_node(LeafIndex(member)).unwrap();

            *self
                .signers
                .get_mut(member as usize)
                .expect("signer tree size mismatch") = None;
        }

        pub async fn update_committer_path<P: CipherSuiteProvider>(
            &mut self,
            committer: u32,
            cs: &P,
        ) {
            let path = self
                .tree
                .nodes
                .filtered_direct_path(LeafIndex(committer))
                .unwrap();

            for i in path.into_iter() {
                self.tree
                    .update_node(cs.kem_generate().unwrap().1, i)
                    .unwrap();
            }

            self.tree.tree_hashes.current = vec![];
            self.tree.tree_hashes.original = vec![];
            self.tree.tree_hash(cs).unwrap();

            let parent_hash = self
                .tree
                .update_parent_hashes(LeafIndex(committer), None, cs)
                .unwrap();

            self.tree
                .nodes
                .borrow_as_leaf_mut(LeafIndex(committer))
                .unwrap()
                .leaf_node_source = LeafNodeSource::Commit(parent_hash);

            self.tree.tree_hashes.current = vec![];
            self.tree.tree_hashes.original = vec![];
            self.tree.tree_hash(cs).unwrap();

            let context = LeafNodeSigningContext {
                group_id: Some(&self.group_id),
                leaf_index: Some(committer),
            };

            let signer = self.signers[committer as usize].as_ref().unwrap();

            self.tree
                .nodes
                .borrow_as_leaf_mut(LeafIndex(committer))
                .unwrap()
                .sign(cs, signer, &context)
                .unwrap();

            self.tree.tree_hashes.current = vec![];
            self.tree.tree_hashes.original = vec![];
            self.tree.tree_hash(cs).unwrap();
        }
    }

    pub async fn make_leaf<P: CipherSuiteProvider>(
        name: &str,
        cs: &P,
    ) -> (LeafNode, SignatureSecretKey) {
        let (signing_identity, signature_key) =
            get_test_signing_identity(cs.cipher_suite(), name.as_bytes().to_vec());

        let capabilities = Capabilities {
            credentials: vec![BasicCredential::credential_type()],
            cipher_suites: TestCryptoProvider::all_supported_cipher_suites(),
            ..Default::default()
        };

        let properties = ConfigProperties {
            capabilities,
            extensions: Default::default(),
        };

        let (leaf, _) = LeafNode::generate(
            cs,
            properties,
            signing_identity,
            &signature_key,
            Lifetime::years(1).unwrap(),
            &BasicIdentityProvider::new(),
        )
        .await
        .unwrap();

        (leaf, signature_key)
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        client::test_utils::TEST_CIPHER_SUITE,
        crypto::test_utils::test_cipher_suite_provider,
        identity::basic::BasicIdentityProvider,
        tree_kem::{
            node::Parent,
            parent_hash::ParentHash,
            test_utils::{get_test_leaf_nodes, get_test_tree},
        },
    };

    use super::build_ascii_tree;

    #[futures_test::test]
    async fn print_fully_populated_tree() {
        let cipher_suite_provider = test_cipher_suite_provider(TEST_CIPHER_SUITE);

        // Create a tree
        let mut tree = get_test_tree(TEST_CIPHER_SUITE).await.public;
        let key_packages = get_test_leaf_nodes(TEST_CIPHER_SUITE).await;

        tree.add_leaves(key_packages, BasicIdentityProvider, &cipher_suite_provider)
            .await
            .unwrap();

        let tree_str = concat!(
            "Blank Root (3)\n",
            "├╼ Blank Parent (1)\n",
            "│ ├╼ Leaf (0)\n",
            "│ └╼ Leaf (2)\n",
            "└╼ Blank Parent (5)\n",
            "  ├╼ Leaf (4)\n",
            "  └╼ Leaf (6)",
        );

        assert_eq!(tree_str, build_ascii_tree(&tree.nodes));
    }

    #[futures_test::test]
    async fn print_tree_blank_leaves() {
        let cipher_suite_provider = test_cipher_suite_provider(TEST_CIPHER_SUITE);

        // Create a tree
        let mut tree = get_test_tree(TEST_CIPHER_SUITE).await.public;
        let key_packages = get_test_leaf_nodes(TEST_CIPHER_SUITE).await;

        let to_remove = tree
            .add_leaves(key_packages, BasicIdentityProvider, &cipher_suite_provider)
            .await
            .unwrap()[0];

        tree.remove_leaves(
            vec![to_remove],
            BasicIdentityProvider,
            &cipher_suite_provider,
        )
        .await
        .unwrap();

        let tree_str = concat!(
            "Blank Root (3)\n",
            "├╼ Blank Parent (1)\n",
            "│ ├╼ Leaf (0)\n",
            "│ └╼ Blank Leaf (2)\n",
            "└╼ Blank Parent (5)\n",
            "  ├╼ Leaf (4)\n",
            "  └╼ Leaf (6)",
        );

        assert_eq!(tree_str, build_ascii_tree(&tree.nodes));
    }

    #[futures_test::test]
    async fn print_tree_unmerged_leaves_on_parent() {
        let cipher_suite_provider = test_cipher_suite_provider(TEST_CIPHER_SUITE);

        // Create a tree
        let mut tree = get_test_tree(TEST_CIPHER_SUITE).await.public;
        let key_packages = get_test_leaf_nodes(TEST_CIPHER_SUITE).await;

        tree.add_leaves(
            [key_packages[0].clone(), key_packages[1].clone()].to_vec(),
            BasicIdentityProvider,
            &cipher_suite_provider,
        )
        .await
        .unwrap();

        tree.nodes[3] = Parent {
            public_key: vec![].into(),
            parent_hash: ParentHash::empty(),
            unmerged_leaves: vec![],
        }
        .into();

        tree.add_leaves(
            [key_packages[2].clone()].to_vec(),
            BasicIdentityProvider,
            &cipher_suite_provider,
        )
        .await
        .unwrap();

        let tree_str = concat!(
            "Root (3) unmerged leaves idxs: 3\n",
            "├╼ Blank Parent (1)\n",
            "│ ├╼ Leaf (0)\n",
            "│ └╼ Leaf (2)\n",
            "└╼ Blank Parent (5)\n",
            "  ├╼ Leaf (4)\n",
            "  └╼ Leaf (6)",
        );

        assert_eq!(tree_str, build_ascii_tree(&tree.nodes));
    }
}
