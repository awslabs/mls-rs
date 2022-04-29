use std::collections::HashMap;

use ferriscrypt::hpke::HpkeError;

use crate::tree_kem::math as tree_math;
use crate::{signer::Signer, LeafNodeRef};

use super::node::Node;
use super::EncryptedResolution;
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
        context: &[u8],
        excluding: &[LeafNodeRef],
        signer: &S,
    ) -> Result<UpdatePathGeneration, RatchetTreeError> {
        let secret_generator = PathSecretGenerator::new(self.tree_kem_public.cipher_suite);

        let excluding: Vec<LeafIndex> = excluding
            .iter()
            .flat_map(|reference| self.tree_kem_public.leaf_node_index(reference))
            .collect();

        // Generate all the new path secrets and encrypt them to their copath node resolutions
        let (node_secrets, node_updates): (
            HashMap<NodeIndex, PathSecretGeneration>,
            Vec<UpdatePathNode>,
        ) = secret_generator
            .zip(
                self.tree_kem_public
                    .nodes
                    .direct_path_copath_resolution(self.private_key.self_index, &excluding)?,
            )
            .map(|(path_secret, (index, copath_nodes))| {
                encrypt_copath_node_resolution(
                    self.tree_kem_public,
                    path_secret?,
                    index,
                    copath_nodes,
                    context,
                )
            })
            .try_fold(
                (HashMap::new(), Vec::new()),
                |(mut secrets, mut updates), resolution| {
                    let encrypted_resolution = resolution?;
                    secrets.insert(encrypted_resolution.index, encrypted_resolution.path_secret);
                    updates.push(encrypted_resolution.update_path_node);
                    Ok::<_, RatchetTreeError>((secrets, updates))
                },
            )?;

        let root_secret = node_secrets
            .get(&tree_math::root(
                self.tree_kem_public.nodes.total_leaf_count(),
            ))
            .cloned()
            .map(Ok)
            .unwrap_or_else(|| PathSecretGeneration::random(self.tree_kem_public.cipher_suite))?
            .path_secret;

        // Update the private key with the new keys
        let mut private_key = self.private_key.clone();

        for (index, path_secret) in &node_secrets {
            private_key
                .secret_keys
                .insert(*index, path_secret.to_hpke_key_pair()?.0);
        }

        let secret_path = SecretPath {
            path_secrets: node_secrets
                .into_iter()
                .map(|(index, ps)| (index, ps.path_secret))
                .collect(),
            root_secret,
        };

        let mut own_leaf_copy = self
            .tree_kem_public
            .nodes
            .borrow_as_leaf(private_key.self_index)?
            .clone();

        // Remove the original leaf from the index
        self.tree_kem_public
            .index
            .remove(&private_key.leaf_node_ref, &own_leaf_copy)?;

        // Apply parent node updates to the tree to aid with the parent hash calculation
        self.tree_kem_public
            .apply_parent_node_updates(private_key.self_index, &node_updates)?;

        // Evolve your leaf forward
        // TODO: Support updating extensions and capabilities at this point
        let secret_key = own_leaf_copy.commit(
            self.tree_kem_public.cipher_suite,
            group_id,
            None,
            None,
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
        let new_leaf_ref = own_leaf_copy.to_reference(self.tree_kem_public.cipher_suite)?;
        *own_leaf = own_leaf_copy;

        self.tree_kem_public.index.insert(
            new_leaf_ref.clone(),
            private_key.self_index,
            own_leaf,
        )?;

        private_key
            .secret_keys
            .insert(NodeIndex::from(private_key.self_index), secret_key);

        private_key.leaf_node_ref = new_leaf_ref;

        // Create an update path with the new node and parent node updates
        let update_path = UpdatePath {
            leaf_node: own_leaf.clone().into(),
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
        sender: &LeafNodeRef,
        update_path: &ValidatedUpdatePath,
        added_leaves: &[LeafNodeRef],
        context: &[u8],
    ) -> Result<TreeSecrets, RatchetTreeError> {
        let sender_index = self.tree_kem_public.leaf_node_index(sender)?;

        // Exclude newly added leaf indexes
        let excluding = added_leaves
            .iter()
            .flat_map(|index| self.tree_kem_public.leaf_node_index(index).map(Into::into))
            .collect::<Vec<NodeIndex>>();

        // Find the least common ancestor shared by us and the sender
        let lca = tree_math::common_ancestor_direct(
            self.private_key.self_index.into(),
            sender_index.into(),
        );

        let lca_path_secret = self
            .tree_kem_public
            .nodes
            .filtered_direct_path_co_path(sender_index)?
            .into_iter()
            .zip(&update_path.nodes)
            .find_map(|((direct_path_index, co_path_index), update_path_node)| {
                if direct_path_index == lca {
                    decrypt_parent_path_secret(
                        self.tree_kem_public,
                        &self.private_key,
                        update_path_node,
                        co_path_index,
                        &excluding,
                        context,
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
        let (path_secrets, private_key) = node_secret_gen
            .zip(
                // Get a pairing of direct path index + associated update
                // This will help us verify that the calculated public key is the expected one
                self.tree_kem_public
                    .nodes
                    .filtered_direct_path(sender_index)?
                    .iter()
                    .zip(update_path.nodes.iter())
                    .skip_while(|(dp, _)| **dp != lca),
            )
            .try_fold(
                (HashMap::new(), self.private_key),
                |(mut path_secrets, mut private_key), (secret, (&index, update))| {
                    let secret = secret?;
                    // Verify the private key we calculated properly matches the public key we were
                    // expecting
                    let (hpke_private, hpke_public) = secret.to_hpke_key_pair()?;

                    if hpke_public != update.public_key {
                        return Err(RatchetTreeError::PubKeyMismatch);
                    }

                    private_key.secret_keys.insert(index, hpke_private);
                    path_secrets.insert(index, secret.path_secret);

                    Ok((path_secrets, private_key))
                },
            )?;

        let root_secret = path_secrets
            .get(&tree_math::root(self.tree_kem_public.total_leaf_count()))
            .cloned()
            .map(Ok)
            .unwrap_or_else(|| PathSecret::random(self.tree_kem_public.cipher_suite))?;

        let tree_secrets = TreeSecrets {
            private_key,
            secret_path: SecretPath {
                path_secrets,
                root_secret,
            },
        };

        let removed_key_package = self
            .tree_kem_public
            .apply_update_path(sender_index, update_path)?;
        self.tree_kem_public
            .index
            .remove(sender, &removed_key_package)?;

        self.tree_kem_public.index.insert(
            update_path
                .leaf_node
                .to_reference(self.tree_kem_public.cipher_suite)?,
            sender_index,
            &update_path.leaf_node,
        )?;

        // Verify the parent hash of the new sender leaf node and update the parent hash values
        // in the local tree
        self.tree_kem_public
            .update_parent_hashes(sender_index, Some(update_path))?;

        Ok(tree_secrets)
    }
}

fn encrypt_copath_node_resolution(
    tree_kem_public: &TreeKemPublic,
    path_secret: PathSecretGeneration,
    index: NodeIndex,
    copath_node_resolution: Vec<&Node>,
    context: &[u8],
) -> Result<EncryptedResolution, RatchetTreeError> {
    let ciphertext = copath_node_resolution
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
        .collect::<Result<Vec<HpkeCiphertext>, HpkeError>>()?;

    let (_, public_key) = path_secret.to_hpke_key_pair()?;

    let update_path_node = UpdatePathNode {
        public_key,
        encrypted_path_secret: ciphertext,
    };

    Ok(EncryptedResolution {
        path_secret,
        index,
        update_path_node,
    })
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
        .zip(update_node.encrypted_path_secret.iter())
        .filter(|(i, _)| !excluding.contains(i)) // Match up the nodes with their ciphertexts
        .find_map(|(i, ct)| private_key.secret_keys.get(i).map(|sk| (sk, ct)))
        .ok_or(RatchetTreeError::UpdateErrorNoSecretKey)
        .and_then(|(sk, ct)| {
            // Decrypt the path secret
            tree_kem_public
                .cipher_suite
                .hpke()
                .open(&ct.clone().into(), sk, context, None, None)
                .map_err(Into::into)
        })
        .map(PathSecret::from)
}

#[cfg(test)]
mod tests {
    use ferriscrypt::hpke::kem::HpkePublicKey;

    use crate::{
        cipher_suite::CipherSuite,
        tree_kem::{
            leaf_node::test_utils::get_basic_test_node_sig_key,
            leaf_node_validator::ValidatedLeafNode, node::LeafIndex, TreeKemPrivate, TreeKemPublic,
            UpdatePath, ValidatedUpdatePath,
        },
    };

    use super::{tree_math, TreeKem};

    use ferriscrypt::asym::ec_key::SecretKey;

    // Verify that the tree is in the correct state after generating an update path
    fn verify_tree_update_path(tree: &TreeKemPublic, update_path: &UpdatePath, index: LeafIndex) {
        // Make sure the update path is based on the direct path of the sender
        let direct_path = tree.nodes.direct_path(index).unwrap();
        for (i, &dpi) in direct_path.iter().enumerate() {
            assert_eq!(
                *tree.nodes[dpi as usize].as_ref().unwrap().public_key(),
                update_path.nodes[i].public_key
            );
        }

        // Verify that the leaf from the update path has been installed
        assert_eq!(
            tree.leaf_node_index(
                &update_path
                    .leaf_node
                    .to_reference(tree.cipher_suite)
                    .unwrap()
            )
            .unwrap(),
            index
        );

        // Verify that we have a public keys up to the root
        assert!(tree.nodes[tree_math::root(tree.total_leaf_count()) as usize].is_some());
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
            let public_key = public_tree.nodes[one_index as usize]
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

    fn encap_decap(cipher_suite: CipherSuite, size: usize) {
        // Generate signing keys and key package generations, and private keys for multiple
        // participants in order to set up state
        let (leaf_nodes, private_keys): (_, Vec<TreeKemPrivate>) = (1..size)
            .map(|index| {
                let (leaf_node, hpke_secret, _) =
                    get_basic_test_node_sig_key(cipher_suite, &format!("{}", index));

                let private_key = TreeKemPrivate::new_self_leaf(
                    LeafIndex(index as u32),
                    leaf_node.to_reference(cipher_suite).unwrap(),
                    hpke_secret,
                );

                (ValidatedLeafNode::from(leaf_node), private_key)
            })
            .unzip();

        let (encap_node, encap_hpke_secret, encap_signer) =
            get_basic_test_node_sig_key(cipher_suite, "encap");

        // Build a test tree we can clone for all leaf nodes
        let (mut test_tree, encap_private_key) =
            TreeKemPublic::derive(cipher_suite, encap_node.clone().into(), encap_hpke_secret)
                .unwrap();

        test_tree.add_leaves(leaf_nodes).unwrap();

        // Clone the tree for the first leaf, generate a new key package for that leaf
        let mut encap_tree = test_tree.clone();

        // Perform the encap function
        let update_path_gen = TreeKem::new(&mut encap_tree, encap_private_key)
            .encap(b"test_group", b"test_ctx", &[], &encap_signer)
            .unwrap();

        // Verify that the state of the tree matches the produced update path
        verify_tree_update_path(&encap_tree, &update_path_gen.update_path, LeafIndex(0));

        // Verify that the private key matches the data in the public key
        verify_tree_private_path(
            &cipher_suite,
            &encap_tree,
            &update_path_gen.secrets.private_key,
            LeafIndex(0),
        );

        // Apply the update path to the rest of the leaf nodes using the decap function
        let validated_update_path = ValidatedUpdatePath {
            leaf_node: ValidatedLeafNode::from(update_path_gen.update_path.leaf_node),
            nodes: update_path_gen.update_path.nodes,
        };

        let mut receiver_trees: Vec<TreeKemPublic> = (1..size).map(|_| test_tree.clone()).collect();

        for (i, tree) in receiver_trees.iter_mut().enumerate() {
            println!("Decap for {:?}, user: {:?}", i, private_keys[i].self_index);
            let secrets = TreeKem::new(tree, private_keys[i].clone())
                .decap(
                    &encap_node.to_reference(cipher_suite).unwrap(),
                    &validated_update_path,
                    &[],
                    b"test_ctx".as_ref(),
                )
                .unwrap();

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
            encap_decap(cipher_suite, 10);
        }
    }
}
