use super::*;

#[derive(Clone, Debug, TlsDeserialize, TlsSerialize, TlsSize)]
pub struct TreeKemPrivate {
    pub self_index: LeafIndex,
    pub key_package_ref: KeyPackageRef,
    #[tls_codec(with = "crate::tls::Map::<crate::tls::DefaultSer, crate::tls::ByteVec::<u32>>")]
    pub secret_keys: HashMap<NodeIndex, HpkeSecretKey>,
}

impl TreeKemPrivate {
    pub fn new_self_leaf(
        self_index: LeafIndex,
        key_package_ref: KeyPackageRef,
        leaf_secret: HpkeSecretKey,
    ) -> Self {
        TreeKemPrivate {
            self_index,
            secret_keys: HashMap::from([(NodeIndex::from(self_index), leaf_secret)]),
            key_package_ref,
        }
    }

    pub fn update_secrets(
        &mut self,
        cipher_suite: CipherSuite,
        signer_index: LeafIndex,
        path_secret: Vec<u8>,
        public_tree: &TreeKemPublic,
    ) -> Result<(), RatchetTreeError> {
        // Identify the lowest common
        // ancestor of the leaves at index and at GroupInfo.signer_index. Set the private key
        // for this node to the private key derived from the path_secret.
        let lca = tree_math::common_ancestor_direct(signer_index.into(), self.self_index.into());

        // For each parent of the common ancestor, up to the root of the tree, derive a new
        // path secret and set the private key for the node to the private key derived from the
        // path secret. The private key MUST be the private key that corresponds to the public
        // key in the node.
        let path_gen = NodeSecretGenerator::new_from_path_secret(cipher_suite, path_secret);

        self.self_index
            .direct_path(public_tree.leaf_count())?
            .iter()
            .skip_while(|&&i| i != lca)
            .zip(path_gen)
            .try_for_each(|(&index, secrets)| {
                let public_key = public_tree
                    .nodes
                    .borrow_node(index)?
                    .as_ref()
                    .map(|n| n.public_key())
                    .ok_or(RatchetTreeError::PubKeyMismatch)?;

                let secrets = secrets?;

                if public_key != &secrets.public_key {
                    return Err(RatchetTreeError::PubKeyMismatch);
                }

                self.secret_keys.insert(index, secrets.secret_key);
                Ok::<_, RatchetTreeError>(())
            })?;

        Ok(())
    }

    pub fn update_leaf(
        &mut self,
        num_leaves: u32,
        key_package_ref: KeyPackageRef,
        new_leaf: HpkeSecretKey,
    ) -> Result<(), RatchetTreeError> {
        self.secret_keys
            .insert(NodeIndex::from(self.self_index), new_leaf);

        self.self_index
            .direct_path(num_leaves)?
            .iter()
            .for_each(|i| {
                self.secret_keys.remove(i);
            });

        self.key_package_ref = key_package_ref;

        Ok(())
    }

    pub fn remove_leaf(
        &mut self,
        num_leaves: u32,
        index: LeafIndex,
    ) -> Result<(), RatchetTreeError> {
        self.secret_keys.remove(&NodeIndex::from(index));

        index.direct_path(num_leaves)?.iter().for_each(|i| {
            self.secret_keys.remove(i);
        });

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use std::collections::HashSet;

    use ferriscrypt::{
        asym::ec_key::{Curve, SecretKey},
        hpke::kem::HpkeSecretKey,
        rand::SecureRng,
    };

    use crate::tree_kem::{
        node::LeafIndex,
        test::{get_test_key_package, get_test_key_package_sig_key},
    };

    use super::*;

    #[test]
    fn test_create_self_leaf() {
        let secret = HpkeSecretKey::try_from(SecretKey::generate(Curve::Ed25519).unwrap()).unwrap();
        let self_index = LeafIndex(42);
        let mut key_package_ref_data = [0u8; 16];
        SecureRng::fill(&mut key_package_ref_data).unwrap();

        let key_package_ref = KeyPackageRef::from(key_package_ref_data);

        let private_key =
            TreeKemPrivate::new_self_leaf(self_index, key_package_ref.clone(), secret.clone());

        assert_eq!(private_key.self_index, self_index);
        assert_eq!(private_key.key_package_ref, key_package_ref);
        assert_eq!(private_key.secret_keys.len(), 1);
        assert_eq!(
            private_key.secret_keys.get(&self_index.into()).unwrap(),
            &secret
        )
    }

    // Create a ratchet tree for Alice, Bob and Charlie. Alice generates an update path for
    // Charlie. Return (Public Tree, Charlie's private key, update path, path secret)
    // The ratchet tree returned has leaf indexes as [alice, bob, charlie]
    fn update_secrets_setup(
        cipher_suite: CipherSuite,
    ) -> (TreeKemPublic, TreeKemPrivate, UpdatePathGeneration, Vec<u8>) {
        let alice_signing =
            SecretKey::generate(Curve::from(cipher_suite.signature_scheme())).unwrap();

        let alice_key_package =
            get_test_key_package_sig_key(cipher_suite, b"alice".to_vec(), &alice_signing);
        let bob_key_package = get_test_key_package(cipher_suite, b"bob".to_vec());
        let charlie_key_package = get_test_key_package(cipher_suite, b"charlie".to_vec());

        // Create a new public tree with Alice
        let (mut public_tree, alice_private) = TreeKemPublic::derive(alice_key_package).unwrap();

        // Add bob and charlie to the tree
        public_tree
            .add_leaves(vec![
                bob_key_package.key_package,
                charlie_key_package.key_package.clone(),
            ])
            .unwrap();

        // Generate an update path for Alice
        let update_path_gen = public_tree
            .encap(&alice_private, &alice_signing, &[], &[])
            .unwrap();

        // Get a path secret from Alice for Charlie
        let path_secret = update_path_gen
            .get_common_path_secret(LeafIndex(2))
            .unwrap();

        // Private key for Charlie
        let charlie_private = TreeKemPrivate::new_self_leaf(
            LeafIndex(2),
            charlie_key_package.key_package.to_reference().unwrap(),
            charlie_key_package.secret_key,
        );

        (public_tree, charlie_private, update_path_gen, path_secret)
    }

    #[test]
    fn test_update_secrets() {
        let cipher_suite =
            crate::cipher_suite::CipherSuite::Mls10128Dhkemx25519Aes128gcmSha256Ed25519;

        let (public_tree, mut charlie_private, update_path_gen, path_secret) =
            update_secrets_setup(cipher_suite);

        let existing_private = charlie_private
            .secret_keys
            .get(&charlie_private.self_index)
            .cloned();

        // Add the secrets for Charlie to his private key
        charlie_private
            .update_secrets(cipher_suite, LeafIndex(0), path_secret, &public_tree)
            .unwrap();

        // Determine the private key values that should now match between Alice and Charlie
        let alice_path: HashSet<u32> = HashSet::from_iter(LeafIndex(0).direct_path(3).unwrap());
        let charlie_path: HashSet<u32> = HashSet::from_iter(LeafIndex(2).direct_path(3).unwrap());

        let intersection = alice_path
            .intersection(&charlie_path)
            .collect::<Vec<&u32>>();

        for one_index in intersection.iter() {
            assert_eq!(
                update_path_gen
                    .secrets
                    .private_key
                    .secret_keys
                    .get(one_index)
                    .unwrap(),
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
    fn test_update_secrets_key_mismatch() {
        let cipher_suite =
            crate::cipher_suite::CipherSuite::Mls10128Dhkemx25519Aes128gcmSha256Ed25519;

        let (mut public_tree, mut charlie_private, _, path_secret) =
            update_secrets_setup(cipher_suite);

        // Sabotage the public tree
        public_tree
            .nodes
            .borrow_as_parent_mut(tree_math::root(public_tree.leaf_count()))
            .unwrap()
            .public_key = HpkePublicKey::from(SecureRng::gen(32).unwrap());

        // Add the secrets for Charlie to his private key
        let res =
            charlie_private.update_secrets(cipher_suite, LeafIndex(0), path_secret, &public_tree);

        assert!(matches!(res, Err(RatchetTreeError::PubKeyMismatch)));
    }

    fn setup_direct_path(self_index: LeafIndex, leaf_count: u32) -> TreeKemPrivate {
        let secret = HpkeSecretKey::try_from(SecretKey::generate(Curve::Ed25519).unwrap()).unwrap();

        let mut private_key =
            TreeKemPrivate::new_self_leaf(self_index, KeyPackageRef::from([0u8; 16]), secret);

        self_index
            .direct_path(leaf_count)
            .unwrap()
            .into_iter()
            .for_each(|i| {
                let secret =
                    HpkeSecretKey::try_from(SecretKey::generate(Curve::Ed25519).unwrap()).unwrap();
                private_key.secret_keys.insert(i, secret);
            });

        private_key
    }

    #[test]
    fn test_update_leaf() {
        let self_leaf = LeafIndex(42);
        let mut private_key = setup_direct_path(self_leaf, 128);

        let new_secret =
            HpkeSecretKey::try_from(SecretKey::generate(Curve::Ed25519).unwrap()).unwrap();

        let new_key_package_ref = KeyPackageRef::from([0u8; 16]);

        private_key
            .update_leaf(128, new_key_package_ref.clone(), new_secret.clone())
            .unwrap();

        // The update operation should have removed all the other keys in our direct path we
        // previously added
        assert_eq!(private_key.secret_keys.len(), 1);

        // The secret key for our leaf should have been updated accordingly
        assert_eq!(
            private_key.secret_keys.get(&self_leaf.into()).unwrap(),
            &new_secret
        );

        assert_eq!(private_key.key_package_ref, new_key_package_ref);
    }

    #[test]
    fn test_remove_leaf() {
        let self_leaf = LeafIndex(42);
        let mut private_key = setup_direct_path(self_leaf, 128);

        private_key.remove_leaf(128, self_leaf).unwrap();

        // Removing a leaf should remove the key for the leaf, as well as all the other keys on the
        // direct path
        assert_eq!(private_key.secret_keys.len(), 0);
    }
}
