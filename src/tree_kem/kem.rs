use std::collections::HashMap;

use ferriscrypt::hpke::kem::HpkePublicKey;
use tls_codec::Serialize;

use crate::extension::ExtensionList;
use crate::signer::Signer;
use crate::tree_kem::math as tree_math;
use crate::GroupContext;

use super::node::Node;
use super::Capabilities;
use super::{
    node::{LeafIndex, NodeIndex},
    path_secret::{PathSecret, PathSecretGeneration, PathSecretGenerator},
    RatchetTreeError, SecretPath, TreeKemPrivate, TreeKemPublic, TreeSecrets, UpdatePath,
    UpdatePathGeneration, UpdatePathNode, ValidatedUpdatePath,
};

use crate::cipher_suite::HpkeCiphertext;

pub struct TreeKem<'a> {
    tree_kem_public: &'a mut TreeKemPublic,
    private_key: TreeKemPrivate,
}

impl<'a> TreeKem<'a> {
    pub fn new(tree_kem_public: &'a mut TreeKemPublic, private_key: TreeKemPrivate) -> Self {
        TreeKem {
            tree_kem_public,
            private_key,
        }
    }

    // TODO: Make UpdatePathGeneration not return a private key to simplify this function
    pub fn encap<S: Signer>(
        self,
        group_id: &[u8],
        context: &mut GroupContext,
        excluding: &[LeafIndex],
        signer: &S,
        update_capabilities: Option<Capabilities>,
        update_extensions: Option<ExtensionList>,
    ) -> Result<UpdatePathGeneration, RatchetTreeError> {
        let secret_generator = PathSecretGenerator::new(self.tree_kem_public.cipher_suite);

        // Generate all the new path secrets and and public keys
        let mut root_secret = None;

        // This avoids computing the filtered path many times. Can be expensive with large resolutions.
        let filtered_direct_path_copath = self
            .tree_kem_public
            .nodes
            .filtered_direct_path_co_path(self.private_key.self_index)?;

        let (node_secrets, updated_pks): (
            HashMap<NodeIndex, PathSecretGeneration>,
            Vec<HpkePublicKey>,
        ) = secret_generator
            .zip(&filtered_direct_path_copath)
            .try_fold(
                (HashMap::new(), Vec::new()),
                |(mut secrets, mut updated_pks), (path_secret, (index, _))| {
                    let path_secret = path_secret?;
                    root_secret = Some(path_secret.path_secret.clone());
                    let (_, public_key) = path_secret.to_hpke_key_pair()?;
                    secrets.insert(*index, path_secret);
                    updated_pks.push(public_key);
                    Ok::<_, RatchetTreeError>((secrets, updated_pks))
                },
            )?;

        // If the committer is the only group member and doesn't add anyone, there may be no path secrets.
        // In such case, we choose a random root secret.
        let root_secret = root_secret.unwrap_or(
            PathSecretGeneration::random(self.tree_kem_public.cipher_suite)?.path_secret,
        );

        // Update the private key with the new keys
        let mut private_key = self.private_key.clone();

        for (index, path_secret) in &node_secrets {
            private_key
                .secret_keys
                .insert(*index, path_secret.to_hpke_key_pair()?.0);
        }

        let secret_path = SecretPath {
            path_secrets: node_secrets
                .iter()
                .map(|(index, ps)| (*index, ps.path_secret.clone()))
                .collect(),
            root_secret,
        };

        let mut own_leaf_copy = self
            .tree_kem_public
            .nodes
            .borrow_as_leaf(private_key.self_index)?
            .clone();

        // Remove the original leaf from the index
        self.tree_kem_public.index.remove(&own_leaf_copy)?;

        // Apply parent node updates to the tree to aid with the parent hash calculation
        self.tree_kem_public.apply_parent_node_updates(
            updated_pks.iter().collect(),
            &filtered_direct_path_copath,
        )?;

        // Evolve your leaf forward
        let secret_key = own_leaf_copy.commit(
            self.tree_kem_public.cipher_suite,
            group_id,
            update_capabilities,
            update_extensions,
            signer,
            |_| {
                self.tree_kem_public
                    .update_parent_hashes(private_key.self_index, None)
                    .map_err(Into::into)
            },
        )?;

        let own_leaf = self
            .tree_kem_public
            .nodes
            .borrow_as_leaf_mut(private_key.self_index)?;

        *own_leaf = own_leaf_copy;
        let own_leaf = own_leaf.clone();

        self.tree_kem_public
            .index
            .insert(private_key.self_index, &own_leaf)?;

        let own_leaf = own_leaf.clone();

        private_key
            .secret_keys
            .insert(NodeIndex::from(private_key.self_index), secret_key);

        // Tree modifications are all done so we can update the tree hash and encrypt with the new context
        self.tree_kem_public
            .update_hashes(&mut vec![private_key.self_index], &[])?;

        context.tree_hash = self.tree_kem_public.tree_hash()?;
        let context_bytes = context.tls_serialize_detached()?;

        let excluding = excluding
            .iter()
            .map(NodeIndex::from)
            .collect::<Vec<NodeIndex>>();

        let node_updates = updated_pks
            .into_iter()
            .zip(&filtered_direct_path_copath)
            .map(|(public_key, (node, copath_child))| {
                let encrypted_path_secret = encrypt_copath_node_resolution(
                    self.tree_kem_public,
                    &node_secrets[node],
                    self.tree_kem_public
                        .nodes
                        .get_resolution(*copath_child, &excluding)?,
                    &context_bytes,
                )?;
                Ok(UpdatePathNode {
                    public_key,
                    encrypted_path_secret,
                })
            })
            .collect::<Result<Vec<_>, RatchetTreeError>>()?;

        // Create an update path with the new node and parent node updates
        let update_path = UpdatePath {
            leaf_node: own_leaf,
            nodes: node_updates,
        };

        Ok(UpdatePathGeneration {
            update_path,
            secrets: TreeSecrets {
                private_key,
                secret_path,
            },
        })
    }

    pub fn decap(
        self,
        sender_index: LeafIndex,
        update_path: &ValidatedUpdatePath,
        added_leaves: &[LeafIndex],
        context: &mut GroupContext,
    ) -> Result<TreeSecrets, RatchetTreeError> {
        // Exclude newly added leaf indexes
        let excluding = added_leaves
            .iter()
            .map(NodeIndex::from)
            .collect::<Vec<NodeIndex>>();

        // Find the least common ancestor shared by us and the sender
        let lca = tree_math::common_ancestor_direct(
            self.private_key.self_index.into(),
            sender_index.into(),
        );

        let filtered_direct_path_co_path = self
            .tree_kem_public
            .nodes
            .filtered_direct_path_co_path(sender_index)?;

        let removed_key_package = self.tree_kem_public.apply_update_path(
            sender_index,
            update_path,
            &filtered_direct_path_co_path,
        )?;

        self.tree_kem_public.index.remove(&removed_key_package)?;

        self.tree_kem_public
            .index
            .insert(sender_index, &update_path.leaf_node)?;

        // Verify the parent hash of the new sender leaf node and update the parent hash values
        // in the local tree
        self.tree_kem_public
            .update_parent_hashes(sender_index, Some(update_path))?;

        // Update the tree hash to get context for decryption
        context.tree_hash = self.tree_kem_public.tree_hash()?;
        let context_bytes = context.tls_serialize_detached()?;

        let lca_path_secret = filtered_direct_path_co_path
            .iter()
            .zip(&update_path.nodes)
            .find_map(|((direct_path_index, co_path_index), update_path_node)| {
                if *direct_path_index == lca {
                    decrypt_parent_path_secret(
                        self.tree_kem_public,
                        &self.private_key,
                        update_path_node,
                        *co_path_index,
                        &excluding,
                        &context_bytes,
                    )
                    .into()
                } else {
                    None
                }
            })
            .ok_or(RatchetTreeError::LcaNotFoundInDirectPath)??;
        // Derive the rest of the secrets for the tree and assign to the proper nodes
        let node_secret_gen =
            PathSecretGenerator::starting_with(self.tree_kem_public.cipher_suite, lca_path_secret);

        // Update secrets based on the decrypted path secret in the update
        let (root_secret, private_key, path_secrets) = filtered_direct_path_co_path
            .iter()
            .zip(update_path.nodes.iter())
            .skip_while(|((index, _), _)| *index != lca)
            .zip(node_secret_gen)
            .try_fold(
                (None, self.private_key, HashMap::new()),
                |(_, mut private_key, mut path_secrets), ((&(index, _), update), secret)| {
                    let secret = secret?;
                    // Verify the private key we calculated properly matches the public key we inserted into the tree. This guarantees
                    // that we will be able to decrypt later.
                    let (hpke_private, hpke_public) = secret.to_hpke_key_pair()?;

                    if hpke_public != update.public_key {
                        return Err(RatchetTreeError::PubKeyMismatch);
                    }

                    private_key.secret_keys.insert(index, hpke_private);
                    path_secrets.insert(index, secret.path_secret.clone());
                    Ok((Some(secret.path_secret), private_key, path_secrets))
                },
            )?;

        // The only situation in which there are no path secrets is when the committer is alone in the
        // group and doesn't add anyone. In such case, he should process pending commit instead of
        // decrypting.
        let root_secret = root_secret.ok_or(RatchetTreeError::DecryptFromSelf)?;

        // actially path secrets aren't needed in this output.
        let tree_secrets = TreeSecrets {
            private_key,
            secret_path: SecretPath {
                path_secrets,
                root_secret,
            },
        };

        Ok(tree_secrets)
    }
}

fn encrypt_copath_node_resolution(
    tree_kem_public: &TreeKemPublic,
    path_secret: &PathSecretGeneration,
    copath_node_resolution: Vec<&Node>,
    context: &[u8],
) -> Result<Vec<HpkeCiphertext>, RatchetTreeError> {
    Ok(copath_node_resolution
        .iter()
        .map(|&copath_node| {
            tree_kem_public
                .cipher_suite
                .hpke()
                .seal(
                    copath_node.public_key(),
                    context,
                    None,
                    None,
                    &path_secret.path_secret,
                )
                .map(HpkeCiphertext::from)
        })
        .collect::<Result<Vec<HpkeCiphertext>, _>>()?)
}

fn decrypt_parent_path_secret(
    tree_kem_public: &mut TreeKemPublic,
    private_key: &TreeKemPrivate,
    update_node: &UpdatePathNode,
    lca_direct_path_child: NodeIndex,
    excluding: &[NodeIndex],
    context: &[u8],
) -> Result<PathSecret, RatchetTreeError> {
    tree_kem_public
        .nodes
        .get_resolution_index(lca_direct_path_child)? // Resolution of the lca child node
        .iter()
        .filter(|i| !excluding.contains(i)) // Match up the nodes with their ciphertexts
        .zip(update_node.encrypted_path_secret.iter())
        .find_map(|(i, ct)| private_key.secret_keys.get(i).map(|sk| (sk, ct)))
        .ok_or(RatchetTreeError::UpdateErrorNoSecretKey)
        .and_then(|(sk, ct)| {
            // Decrypt the path secret
            tree_kem_public
                .cipher_suite
                .hpke()
                .open(&ct.clone().into(), sk, context, None, None)
                .map_err(|_| RatchetTreeError::HPKEDecryptionError)
        })
        .map(PathSecret::from)
}

#[cfg(test)]
mod tests {
    use ferriscrypt::hpke::kem::HpkePublicKey;

    use crate::{
        cipher_suite::CipherSuite,
        extension::{test_utils::TestExtension, ExtensionList},
        group::test_utils::get_test_group_context,
        tree_kem::{
            leaf_node::test_utils::get_basic_test_node_sig_key, node::LeafIndex, Capabilities,
            TreeKemPrivate, TreeKemPublic, UpdatePath, ValidatedUpdatePath,
        },
    };

    use super::{tree_math, TreeKem};

    use ferriscrypt::asym::ec_key::SecretKey;

    // Verify that the tree is in the correct state after generating an update path
    fn verify_tree_update_path(
        tree: &TreeKemPublic,
        update_path: &UpdatePath,
        index: LeafIndex,
        capabilities: Option<Capabilities>,
        extensions: Option<ExtensionList>,
    ) {
        // Make sure the update path is based on the direct path of the sender
        let direct_path = tree.nodes.direct_path(index).unwrap();
        for (i, &dpi) in direct_path.iter().enumerate() {
            assert_eq!(
                *tree
                    .nodes
                    .borrow_node(dpi)
                    .unwrap()
                    .as_ref()
                    .unwrap()
                    .public_key(),
                update_path.nodes[i].public_key
            );
        }

        // Verify that the leaf from the update path has been installed
        assert_eq!(
            tree.nodes.borrow_as_leaf(index).unwrap(),
            &update_path.leaf_node
        );

        // Verify that updated capabilities were installed
        if let Some(capabilities) = capabilities {
            assert_eq!(update_path.leaf_node.capabilities, capabilities);
        }

        // Verify that update extensions were installed
        if let Some(extensions) = extensions {
            assert_eq!(update_path.leaf_node.extensions, extensions);
        }

        // Verify that we have a public keys up to the root
        let root = tree_math::root(tree.total_leaf_count());
        assert!(tree.nodes.borrow_node(root).unwrap().is_some());
    }

    fn verify_tree_private_path(
        cipher_suite: &CipherSuite,
        public_tree: &TreeKemPublic,
        private_tree: &TreeKemPrivate,
        index: LeafIndex,
    ) {
        assert_eq!(private_tree.self_index, index);
        // Make sure we have private values along the direct path, and the public keys match
        for one_index in public_tree.nodes.direct_path(index).unwrap() {
            let secret_key = private_tree.secret_keys.get(&one_index).unwrap();
            let public_key = public_tree
                .nodes
                .borrow_node(one_index)
                .unwrap()
                .as_ref()
                .unwrap()
                .public_key();
            let secret_key =
                SecretKey::from_bytes(secret_key.as_ref(), cipher_suite.kem_type().curve())
                    .unwrap();
            assert_eq!(
                HpkePublicKey::from(
                    secret_key
                        .to_public()
                        .unwrap()
                        .to_uncompressed_bytes()
                        .unwrap()
                ),
                *public_key
            );
        }
    }

    fn encap_decap(
        cipher_suite: CipherSuite,
        size: usize,
        capabilities: Option<Capabilities>,
        extensions: Option<ExtensionList>,
    ) {
        // Generate signing keys and key package generations, and private keys for multiple
        // participants in order to set up state
        let (leaf_nodes, private_keys): (_, Vec<TreeKemPrivate>) = (1..size)
            .map(|index| {
                let (leaf_node, hpke_secret, _) =
                    get_basic_test_node_sig_key(cipher_suite, &format!("{}", index));

                let private_key =
                    TreeKemPrivate::new_self_leaf(LeafIndex(index as u32), hpke_secret);

                (leaf_node, private_key)
            })
            .unzip();

        let (encap_node, encap_hpke_secret, encap_signer) =
            get_basic_test_node_sig_key(cipher_suite, "encap");

        // Build a test tree we can clone for all leaf nodes
        let (mut test_tree, encap_private_key) =
            TreeKemPublic::derive(cipher_suite, encap_node, encap_hpke_secret).unwrap();

        test_tree.add_leaves(leaf_nodes).unwrap();

        // Clone the tree for the first leaf, generate a new key package for that leaf
        let mut encap_tree = test_tree.clone();

        // Perform the encap function
        let update_path_gen = TreeKem::new(&mut encap_tree, encap_private_key)
            .encap(
                b"test_group",
                &mut get_test_group_context(42, cipher_suite),
                &[],
                &encap_signer,
                capabilities.clone(),
                extensions.clone(),
            )
            .unwrap();

        // Verify that the state of the tree matches the produced update path
        verify_tree_update_path(
            &encap_tree,
            &update_path_gen.update_path,
            LeafIndex(0),
            capabilities,
            extensions,
        );

        // Verify that the private key matches the data in the public key
        verify_tree_private_path(
            &cipher_suite,
            &encap_tree,
            &update_path_gen.secrets.private_key,
            LeafIndex(0),
        );

        // Apply the update path to the rest of the leaf nodes using the decap function
        let validated_update_path = ValidatedUpdatePath {
            leaf_node: update_path_gen.update_path.leaf_node,
            nodes: update_path_gen.update_path.nodes,
        };

        encap_tree
            .update_hashes(&mut vec![LeafIndex(0)], &[])
            .unwrap();

        let mut receiver_trees: Vec<TreeKemPublic> = (1..size).map(|_| test_tree.clone()).collect();

        for (i, tree) in receiver_trees.iter_mut().enumerate() {
            println!("Decap for {:?}, user: {:?}", i, private_keys[i].self_index);
            let secrets = TreeKem::new(tree, private_keys[i].clone())
                .decap(
                    LeafIndex(0),
                    &validated_update_path,
                    &[],
                    &mut get_test_group_context(42, cipher_suite),
                )
                .unwrap();

            tree.update_hashes(&mut vec![LeafIndex(0)], &[]).unwrap();

            assert_eq!(tree, &encap_tree);

            assert_eq!(
                secrets.secret_path.root_secret,
                update_path_gen.secrets.secret_path.root_secret
            );
        }
    }

    #[test]
    fn test_encap_decap() {
        for cipher_suite in CipherSuite::all() {
            println!("Testing Tree KEM encap / decap for: {cipher_suite:?}");
            encap_decap(cipher_suite, 10, None, None);
        }
    }

    #[test]
    fn test_encap_capabilities() {
        let cipher_suite = CipherSuite::Curve25519Aes128;
        let mut capabilities = Capabilities::default();
        capabilities.extensions.push(42);

        encap_decap(cipher_suite, 10, Some(capabilities.clone()), None);
    }

    #[test]
    fn test_encap_extensions() {
        let cipher_suite = CipherSuite::Curve25519Aes128;
        let mut extensions = ExtensionList::default();
        extensions.set_extension(TestExtension { foo: 10 }).unwrap();

        encap_decap(cipher_suite, 10, None, Some(extensions));
    }

    #[test]
    fn test_encap_capabilities_extensions() {
        let cipher_suite = CipherSuite::Curve25519Aes128;
        let mut capabilities = Capabilities::default();
        capabilities.extensions.push(42);

        let mut extensions = ExtensionList::default();
        extensions.set_extension(TestExtension { foo: 10 }).unwrap();

        encap_decap(cipher_suite, 10, Some(capabilities), Some(extensions));
    }
}
