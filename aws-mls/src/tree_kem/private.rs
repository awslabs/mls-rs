use serde::{Deserialize, Serialize};
use serde_with::serde_as;

use crate::crypto::CipherSuiteProvider;

use super::*;

#[serde_as]
#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[non_exhaustive]
pub struct TreeKemPrivate {
    pub self_index: LeafIndex,
    #[cfg(feature = "std")]
    #[serde_as(as = "Vec<(_,_)>")]
    pub secret_keys: HashMap<NodeIndex, HpkeSecretKey>,
    #[cfg(not(feature = "std"))]
    #[serde_as(as = "Vec<(_,_)>")]
    pub secret_keys: BTreeMap<NodeIndex, HpkeSecretKey>,
}

impl TreeKemPrivate {
    pub fn new_self_leaf(self_index: LeafIndex, leaf_secret: HpkeSecretKey) -> Self {
        TreeKemPrivate {
            self_index,
            secret_keys: [(NodeIndex::from(self_index), leaf_secret)]
                .into_iter()
                .collect(),
        }
    }

    #[cfg(feature = "external_commit")]
    pub fn new_for_external() -> Self {
        TreeKemPrivate {
            self_index: LeafIndex(0),
            secret_keys: Default::default(),
        }
    }

    pub fn update_secrets<P: CipherSuiteProvider>(
        &mut self,
        cipher_suite_provider: &P,
        signer_index: LeafIndex,
        path_secret: PathSecret,
        public_tree: &TreeKemPublic,
    ) -> Result<(), MlsError> {
        // Identify the lowest common
        // ancestor of the leaves at index and at GroupInfo.signer_index. Set the private key
        // for this node to the private key derived from the path_secret.
        let lca = tree_math::common_ancestor_direct(signer_index.into(), self.self_index.into());

        // For each parent of the common ancestor, up to the root of the tree, derive a new
        // path secret and set the private key for the node to the private key derived from the
        // path secret. The private key MUST be the private key that corresponds to the public
        // key in the node.

        let path_secret_gen =
            PathSecretGenerator::starting_with(cipher_suite_provider, path_secret);

        public_tree
            .nodes
            .filtered_direct_path(self.self_index)?
            .iter()
            .skip_while(|&&i| i != lca)
            .zip(path_secret_gen)
            .try_for_each(|(&index, secret_generation)| {
                let expected_pub_key = public_tree
                    .nodes
                    .borrow_node(index)?
                    .as_ref()
                    .map(|n| n.public_key())
                    .ok_or(MlsError::PubKeyMismatch)?;

                let (secret_key, public_key) = secret_generation?.to_hpke_key_pair()?;

                if expected_pub_key != &public_key {
                    return Err(MlsError::PubKeyMismatch);
                }

                self.secret_keys.insert(index, secret_key);
                Ok::<_, MlsError>(())
            })?;

        Ok(())
    }

    pub fn update_leaf(
        &mut self,
        num_leaves: u32,
        new_leaf: HpkeSecretKey,
    ) -> Result<(), MlsError> {
        self.secret_keys
            .insert(NodeIndex::from(self.self_index), new_leaf);

        self.self_index
            .direct_path(num_leaves)?
            .iter()
            .for_each(|i| {
                self.secret_keys.remove(i);
            });

        Ok(())
    }

    pub fn remove_leaf(&mut self, num_leaves: u32, index: LeafIndex) -> Result<(), MlsError> {
        self.secret_keys.remove(&NodeIndex::from(index));

        index.direct_path(num_leaves)?.iter().for_each(|i| {
            self.secret_keys.remove(i);
        });

        Ok(())
    }
}

#[cfg(test)]
impl TreeKemPrivate {
    pub fn new(self_index: LeafIndex) -> Self {
        TreeKemPrivate {
            self_index,
            secret_keys: Default::default(),
        }
    }
}

#[cfg(test)]
mod tests {
    use assert_matches::assert_matches;

    use crate::{
        cipher_suite::CipherSuite,
        client::test_utils::TEST_CIPHER_SUITE,
        crypto::test_utils::test_cipher_suite_provider,
        group::test_utils::{get_test_group_context, random_bytes},
        identity::basic::BasicIdentityProvider,
        tree_kem::{
            kem::TreeKem,
            leaf_node::test_utils::{
                default_properties, get_basic_test_node, get_basic_test_node_sig_key,
            },
            node::LeafIndex,
        },
    };

    use super::*;

    #[cfg(target_arch = "wasm32")]
    use wasm_bindgen_test::wasm_bindgen_test as test;

    #[cfg(not(target_arch = "wasm32"))]
    use futures_test::test;

    #[cfg(feature = "std")]
    use std::collections::HashSet;

    #[cfg(not(feature = "std"))]
    use alloc::collections::BTreeSet;

    fn random_hpke_secret_key() -> HpkeSecretKey {
        let (secret, _) = test_cipher_suite_provider(TEST_CIPHER_SUITE)
            .kem_derive(&random_bytes(32))
            .unwrap();

        secret
    }

    #[test]
    async fn test_create_self_leaf() {
        let secret = random_hpke_secret_key();

        let self_index = LeafIndex(42);

        let private_key = TreeKemPrivate::new_self_leaf(self_index, secret.clone());

        assert_eq!(private_key.self_index, self_index);
        assert_eq!(private_key.secret_keys.len(), 1);
        assert_eq!(
            private_key.secret_keys.get(&self_index.into()).unwrap(),
            &secret
        )
    }

    // Create a ratchet tree for Alice, Bob and Charlie. Alice generates an update path for
    // Charlie. Return (Public Tree, Charlie's private key, update path, path secret)
    // The ratchet tree returned has leaf indexes as [alice, bob, charlie]
    async fn update_secrets_setup(
        cipher_suite: CipherSuite,
    ) -> (TreeKemPublic, TreeKemPrivate, TreeKemPrivate, PathSecret) {
        let cipher_suite_provider = test_cipher_suite_provider(cipher_suite);

        let (alice_leaf, alice_hpke_secret, alice_signing) =
            get_basic_test_node_sig_key(cipher_suite, "alice").await;

        let bob_leaf = get_basic_test_node(cipher_suite, "bob").await;

        let (charlie_leaf, charlie_hpke_secret, _charlie_signing) =
            get_basic_test_node_sig_key(cipher_suite, "charlie").await;

        // Create a new public tree with Alice
        let (mut public_tree, mut alice_private) = TreeKemPublic::derive(
            alice_leaf,
            alice_hpke_secret,
            &BasicIdentityProvider,
            &cipher_suite_provider,
        )
        .await
        .unwrap();

        // Add bob and charlie to the tree
        public_tree
            .add_leaves(
                vec![bob_leaf, charlie_leaf],
                &BasicIdentityProvider,
                &cipher_suite_provider,
            )
            .await
            .unwrap();

        // Generate an update path for Alice
        let encap_gen = TreeKem::new(&mut public_tree, &mut alice_private)
            .encap(
                &mut get_test_group_context(42, cipher_suite),
                &[],
                &alice_signing,
                default_properties(),
                None,
                BasicIdentityProvider,
                &cipher_suite_provider,
                #[cfg(test)]
                &Default::default(),
            )
            .await
            .unwrap();

        // Get a path secret from Alice for Charlie
        let path_secret = encap_gen.path_secrets[1].clone().unwrap();

        // Private key for Charlie
        let charlie_private = TreeKemPrivate::new_self_leaf(LeafIndex(2), charlie_hpke_secret);

        (public_tree, charlie_private, alice_private, path_secret)
    }

    #[test]
    async fn test_update_secrets() {
        let cipher_suite = TEST_CIPHER_SUITE;

        let (public_tree, mut charlie_private, alice_private, path_secret) =
            update_secrets_setup(cipher_suite).await;

        let existing_private = charlie_private
            .secret_keys
            .get(&charlie_private.self_index)
            .cloned();

        // Add the secrets for Charlie to his private key
        charlie_private
            .update_secrets(
                &test_cipher_suite_provider(cipher_suite),
                LeafIndex(0),
                path_secret,
                &public_tree,
            )
            .unwrap();

        // Determine the private key values that should now match between Alice and Charlie
        #[cfg(feature = "std")]
        let alice_path: HashSet<u32> = HashSet::from_iter(LeafIndex(0).direct_path(4).unwrap());
        #[cfg(feature = "std")]
        let charlie_path: HashSet<u32> = HashSet::from_iter(LeafIndex(2).direct_path(4).unwrap());

        #[cfg(not(feature = "std"))]
        let alice_path: BTreeSet<u32> = BTreeSet::from_iter(LeafIndex(0).direct_path(4).unwrap());
        #[cfg(not(feature = "std"))]
        let charlie_path: BTreeSet<u32> = BTreeSet::from_iter(LeafIndex(2).direct_path(4).unwrap());

        let intersection = alice_path
            .intersection(&charlie_path)
            .collect::<Vec<&u32>>();

        for one_index in intersection.iter() {
            assert_eq!(
                alice_private.secret_keys.get(one_index).unwrap(),
                charlie_private.secret_keys.get(one_index).unwrap()
            );
        }

        // Make sure that Charlie's private key didn't lose keys
        assert_eq!(charlie_private.secret_keys.len(), intersection.len() + 1);

        assert_eq!(
            charlie_private.secret_keys.get(&charlie_private.self_index),
            existing_private.as_ref()
        );
    }

    #[test]
    async fn test_update_secrets_key_mismatch() {
        let cipher_suite = TEST_CIPHER_SUITE;

        let (mut public_tree, mut charlie_private, _, path_secret) =
            update_secrets_setup(cipher_suite).await;

        // Sabotage the public tree
        public_tree
            .nodes
            .borrow_as_parent_mut(tree_math::root(public_tree.total_leaf_count()))
            .unwrap()
            .public_key = random_bytes(32).into();

        // Add the secrets for Charlie to his private key
        let res = charlie_private.update_secrets(
            &test_cipher_suite_provider(cipher_suite),
            LeafIndex(0),
            path_secret,
            &public_tree,
        );

        assert_matches!(res, Err(MlsError::PubKeyMismatch));
    }

    fn setup_direct_path(self_index: LeafIndex, leaf_count: u32) -> TreeKemPrivate {
        let secret = random_hpke_secret_key();

        let mut private_key = TreeKemPrivate::new_self_leaf(self_index, secret);

        self_index
            .direct_path(leaf_count)
            .unwrap()
            .into_iter()
            .for_each(|i| {
                let secret = random_hpke_secret_key();
                private_key.secret_keys.insert(i, secret);
            });

        private_key
    }

    #[test]
    async fn test_update_leaf() {
        let self_leaf = LeafIndex(42);
        let mut private_key = setup_direct_path(self_leaf, 128);

        let new_secret = random_hpke_secret_key();

        private_key.update_leaf(128, new_secret.clone()).unwrap();

        // The update operation should have removed all the other keys in our direct path we
        // previously added
        assert_eq!(private_key.secret_keys.len(), 1);

        // The secret key for our leaf should have been updated accordingly
        assert_eq!(
            private_key.secret_keys.get(&self_leaf.into()).unwrap(),
            &new_secret
        );
    }

    #[test]
    async fn test_remove_leaf() {
        let self_leaf = LeafIndex(42);
        let mut private_key = setup_direct_path(self_leaf, 128);

        private_key.remove_leaf(128, self_leaf).unwrap();

        // Removing a leaf should remove the key for the leaf, as well as all the other keys on the
        // direct path
        assert_eq!(private_key.secret_keys.len(), 0);
    }
}
