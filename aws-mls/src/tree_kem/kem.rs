use crate::client::MlsError;
use crate::crypto::{CipherSuiteProvider, HpkeCiphertext, SignatureSecretKey};
use crate::group::GroupContext;
use crate::identity::SigningIdentity;
use crate::tree_kem::math as tree_math;
use alloc::vec;
use alloc::vec::Vec;
use aws_mls_codec::MlsEncode;
use aws_mls_core::{error::IntoAnyError, identity::IdentityProvider};
use cfg_if::cfg_if;

#[cfg(feature = "rayon")]
use rayon::prelude::*;

use super::hpke_encryption::HpkeEncryptable;
use super::leaf_node::ConfigProperties;
use super::node::Node;
use super::{
    node::{LeafIndex, NodeIndex},
    path_secret::{PathSecret, PathSecretGeneration, PathSecretGenerator},
    TreeKemPrivate, TreeKemPublic, UpdatePath, UpdatePathNode, ValidatedUpdatePath,
};

#[cfg(test)]
use crate::group::CommitModifiers;

pub struct TreeKem<'a> {
    tree_kem_public: &'a mut TreeKemPublic,
    private_key: &'a mut TreeKemPrivate,
}

pub struct EncapGeneration {
    pub update_path: UpdatePath,
    pub path_secrets: Vec<Option<PathSecret>>,
    pub root_secret: PathSecret,
}

impl<'a> TreeKem<'a> {
    pub fn new(
        tree_kem_public: &'a mut TreeKemPublic,
        private_key: &'a mut TreeKemPrivate,
    ) -> Self {
        TreeKem {
            tree_kem_public,
            private_key,
        }
    }

    #[allow(clippy::too_many_arguments)]
    #[maybe_async::maybe_async]
    pub async fn encap<C, P>(
        self,
        context: &mut GroupContext,
        excluding: &[LeafIndex],
        signer: &SignatureSecretKey,
        update_leaf_properties: ConfigProperties,
        signing_identity: Option<SigningIdentity>,
        identity_provider: C,
        cipher_suite_provider: &P,
        #[cfg(test)] commit_modifiers: &CommitModifiers<P>,
    ) -> Result<EncapGeneration, MlsError>
    where
        C: IdentityProvider,
        P: CipherSuiteProvider + Send + Sync,
    {
        let num_leaves = self.tree_kem_public.nodes.total_leaf_count();
        let self_index = self.private_key.self_index;
        let path = self.tree_kem_public.nodes.direct_path_copath(self_index)?;
        let filtered = self.tree_kem_public.nodes.filtered(self_index)?;

        self.private_key.secret_keys.resize(path.len() + 1, None);

        let mut secret_generator = PathSecretGenerator::new(cipher_suite_provider);
        let mut path_secrets = vec![];

        for (i, ((dp, _), f)) in path.iter().zip(&filtered).enumerate() {
            if !f {
                let secret = secret_generator.next_secret()?;
                let (secret_key, public_key) = secret.to_hpke_key_pair()?;
                self.private_key.secret_keys[i + 1] = Some(secret_key);
                self.tree_kem_public.update_node(public_key, *dp)?;
                path_secrets.push(Some(secret.path_secret));
            } else {
                self.private_key.secret_keys[i + 1] = None;
                path_secrets.push(None);
            }
        }

        #[cfg(test)]
        (commit_modifiers.modify_tree)(self.tree_kem_public);

        let mut own_leaf_copy = self
            .tree_kem_public
            .nodes
            .borrow_as_leaf(self_index)?
            .clone();

        let parent_hash =
            self.tree_kem_public
                .update_parent_hashes(self_index, None, cipher_suite_provider)?;

        self.private_key.secret_keys[0] = Some(own_leaf_copy.commit(
            cipher_suite_provider,
            &context.group_id,
            *self_index,
            update_leaf_properties,
            signing_identity,
            signer,
            parent_hash,
        )?);

        self.tree_kem_public
            .rekey_leaf(self_index, own_leaf_copy.clone(), identity_provider)
            .await?;

        #[cfg(test)]
        {
            (commit_modifiers.modify_leaf)(&mut own_leaf_copy, signer, cipher_suite_provider);
            *self
                .tree_kem_public
                .nodes
                .borrow_as_leaf_mut(self_index)
                .unwrap() = own_leaf_copy.clone();
        }

        // Tree modifications are all done so we can update the tree hash and encrypt with the new context
        self.tree_kem_public
            .update_hashes(&mut vec![self_index], &[], cipher_suite_provider)?;

        context.tree_hash = self.tree_kem_public.tree_hash(cipher_suite_provider)?;

        let context_bytes = context.mls_encode_to_vec()?;

        cfg_if! {
            if #[cfg(feature = "rayon")] {
                let copath_iter = path.into_par_iter().zip(path_secrets.par_iter());
            } else {
                let copath_iter = path.into_iter().zip(path_secrets.iter());
            }
        }

        let node_updates = copath_iter
            .filter_map(|((_, copath_index), path_secret)| {
                path_secret.as_ref().map(|path_secret| {
                    let encrypted_path_secret = encrypt_copath_node_resolution(
                        cipher_suite_provider,
                        path_secret,
                        self.tree_kem_public
                            .nodes
                            .get_resolution(copath_index, excluding)?,
                        &context_bytes,
                    )?;

                    let path_index = tree_math::parent(copath_index, num_leaves)?;

                    Ok(UpdatePathNode {
                        public_key: self
                            .tree_kem_public
                            .nodes
                            .borrow_as_parent(path_index)?
                            .public_key
                            .clone(),
                        encrypted_path_secret,
                    })
                })
            })
            .collect::<Result<Vec<_>, MlsError>>()?;

        #[cfg(test)]
        let node_updates = (commit_modifiers.modify_path)(node_updates);

        // Create an update path with the new node and parent node updates
        let update_path = UpdatePath {
            leaf_node: own_leaf_copy,
            nodes: node_updates,
        };

        // If the committer is the only group member and doesn't add anyone, there may be no path secrets.
        // In such case, we choose a random root secret.
        let root_secret = path_secrets
            .iter()
            .rev()
            .cloned()
            .find_map(|secret| secret)
            .unwrap_or(PathSecretGeneration::random(cipher_suite_provider)?.path_secret);

        Ok(EncapGeneration {
            update_path,
            path_secrets,
            root_secret,
        })
    }

    #[maybe_async::maybe_async]
    pub async fn decap<IP, CP>(
        self,
        sender_index: LeafIndex,
        update_path: ValidatedUpdatePath,
        added_leaves: &[LeafIndex],
        context: &mut GroupContext,
        identity_provider: IP,
        cipher_suite_provider: &CP,
    ) -> Result<PathSecret, MlsError>
    where
        IP: IdentityProvider,
        CP: CipherSuiteProvider,
    {
        // Exclude newly added leaf indexes
        let excluding = added_leaves
            .iter()
            .map(NodeIndex::from)
            .collect::<Vec<NodeIndex>>();

        self.tree_kem_public
            .apply_update_path(
                sender_index,
                &update_path,
                identity_provider,
                cipher_suite_provider,
            )
            .await?;

        // Update the tree hash to get context for decryption
        context.tree_hash = self.tree_kem_public.tree_hash(cipher_suite_provider)?;

        let context_bytes = context.mls_encode_to_vec()?;

        let self_index = self.private_key.self_index;

        let lca_index =
            tree_math::leaf_lca_level(self_index.into(), sender_index.into()) as usize - 2;

        let lca_node = update_path.nodes[lca_index]
            .as_ref()
            .ok_or(MlsError::LcaNotFoundInDirectPath)?;

        let direct_path_copath = self
            .tree_kem_public
            .nodes
            .direct_path_copath(sender_index)?;

        let lca_path_secret = decrypt_parent_path_secret(
            cipher_suite_provider,
            self.tree_kem_public,
            self.private_key,
            lca_node,
            direct_path_copath[lca_index].1,
            &excluding,
            &context_bytes,
        )?;

        // Derive the rest of the secrets for the tree and assign to the proper nodes
        let mut node_secret_gen =
            PathSecretGenerator::starting_with(cipher_suite_provider, lca_path_secret);

        // Update secrets based on the decrypted path secret in the update
        let mut root_secret = None;
        self.private_key
            .secret_keys
            .resize(direct_path_copath.len() + 1, None);

        for (i, update) in update_path.nodes.iter().enumerate().skip(lca_index) {
            if let Some(update) = update {
                let secret = node_secret_gen
                    .next()
                    .ok_or(MlsError::FailedGeneratingPathSecret)??;

                // Verify the private key we calculated properly matches the public key we inserted into the tree. This guarantees
                // that we will be able to decrypt later.
                let (hpke_private, hpke_public) = secret.to_hpke_key_pair()?;

                if hpke_public != update.public_key {
                    return Err(MlsError::PubKeyMismatch);
                }

                self.private_key.secret_keys[i + 1] = Some(hpke_private);

                root_secret = Some(secret.path_secret);
            } else {
                self.private_key.secret_keys[i + 1] = None;
            }
        }

        // The only situation in which there are no path secrets is when the committer is alone in the
        // group and doesn't add anyone. In such case, he should process pending commit instead of
        // decrypting.
        root_secret.ok_or(MlsError::CantProcessMessageFromSelf)
    }
}

fn encrypt_copath_node_resolution<P: CipherSuiteProvider>(
    cipher_suite_provider: &P,
    path_secret: &PathSecret,
    resolution: Vec<&Node>,
    context: &[u8],
) -> Result<Vec<HpkeCiphertext>, MlsError> {
    resolution
        .iter()
        .map(|&copath_node| {
            path_secret.encrypt(cipher_suite_provider, copath_node.public_key(), context)
        })
        .collect::<Result<Vec<HpkeCiphertext>, _>>()
        .map_err(|e| MlsError::CryptoProviderError(e.into_any_error()))
}

fn decrypt_parent_path_secret<P: CipherSuiteProvider>(
    cipher_suite_provider: &P,
    tree_kem_public: &mut TreeKemPublic,
    private_key: &TreeKemPrivate,
    update_node: &UpdatePathNode,
    lca_direct_path_child: NodeIndex,
    excluding: &[NodeIndex],
    context: &[u8],
) -> Result<PathSecret, MlsError> {
    // Find the node in the resolution of the copath child that is above the sender
    let self_index = 2 * *private_key.self_index;

    let resolution = tree_kem_public
        .nodes
        .get_resolution_index(lca_direct_path_child)?;

    let (resolved, ct) = resolution
        .iter()
        .filter(|i| !excluding.contains(i))
        .zip(&update_node.encrypted_path_secret)
        .find(|(i, _)| {
            let l = tree_math::level(**i) + 1;
            *i >> l == self_index >> l
        })
        .ok_or(MlsError::UpdateErrorNoSecretKey)?;

    let secret_key = private_key
        .secret_keys
        .get(tree_math::level(*resolved) as usize)
        .ok_or(MlsError::UpdateErrorNoSecretKey)?
        .as_ref();

    // If the sender didn't find the key, then it must be an unmerged leaf of the found node.
    let (secret_key, ct) = match secret_key {
        Some(secret_key) => (secret_key, ct),
        None => {
            let secret_key = private_key
                .secret_keys
                .first()
                .and_then(Option::as_ref)
                .ok_or(MlsError::UpdateErrorNoSecretKey)?;

            let ct = resolution
                .iter()
                .filter(|i| !excluding.contains(i))
                .zip(&update_node.encrypted_path_secret)
                .find_map(|(i, ct)| (i == &self_index).then_some(ct));

            (secret_key, ct.ok_or(MlsError::UpdateErrorNoSecretKey)?)
        }
    };

    PathSecret::decrypt(cipher_suite_provider, secret_key, context, ct)
}

#[cfg(test)]
mod tests {
    use super::{tree_math, TreeKem};
    use crate::{
        cipher_suite::CipherSuite,
        client::test_utils::TEST_CIPHER_SUITE,
        crypto::test_utils::{test_cipher_suite_provider, TestCryptoProvider},
        extension::test_utils::TestExtension,
        group::test_utils::{get_test_group_context, random_bytes},
        identity::basic::BasicIdentityProvider,
        tree_kem::{
            leaf_node::{
                test_utils::{get_basic_test_node_sig_key, get_test_capabilities},
                ConfigProperties,
            },
            node::LeafIndex,
            Capabilities, TreeKemPrivate, TreeKemPublic, UpdatePath, ValidatedUpdatePath,
        },
        ExtensionList,
    };
    use alloc::{format, vec, vec::Vec};
    use aws_mls_core::crypto::CipherSuiteProvider;

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
        let provider = test_cipher_suite_provider(*cipher_suite);

        assert_eq!(private_tree.self_index, index);

        // Make sure we have private values along the direct path, and the public keys match
        let path_iter = public_tree
            .nodes
            .direct_path(index)
            .unwrap()
            .into_iter()
            .enumerate();

        for (i, dp) in path_iter {
            let secret_key = private_tree.secret_keys[i + 1].as_ref().unwrap();

            let public_key = public_tree
                .nodes
                .borrow_node(dp)
                .unwrap()
                .as_ref()
                .unwrap()
                .public_key();

            let test_data = random_bytes(32);
            let sealed = provider
                .hpke_seal(public_key, &[], None, &test_data)
                .unwrap();

            let opened = provider.hpke_open(&sealed, secret_key, &[], None).unwrap();
            assert_eq!(test_data, opened);
        }
    }

    #[maybe_async::maybe_async]
    async fn encap_decap(
        cipher_suite: CipherSuite,
        size: usize,
        capabilities: Option<Capabilities>,
        extensions: Option<ExtensionList>,
    ) {
        let cipher_suite_provider = test_cipher_suite_provider(cipher_suite);

        // Generate signing keys and key package generations, and private keys for multiple
        // participants in order to set up state

        let mut leaf_nodes = Vec::new();
        let mut private_keys = Vec::new();

        for index in 1..size {
            let (leaf_node, hpke_secret, _) =
                get_basic_test_node_sig_key(cipher_suite, &format!("{index}")).await;

            let private_key = TreeKemPrivate::new_self_leaf(LeafIndex(index as u32), hpke_secret);

            leaf_nodes.push(leaf_node);
            private_keys.push(private_key);
        }

        let (encap_node, encap_hpke_secret, encap_signer) =
            get_basic_test_node_sig_key(cipher_suite, "encap").await;

        // Build a test tree we can clone for all leaf nodes
        let (mut test_tree, mut encap_private_key) = TreeKemPublic::derive(
            encap_node,
            encap_hpke_secret,
            &BasicIdentityProvider,
            &cipher_suite_provider,
        )
        .await
        .unwrap();

        test_tree
            .add_leaves(leaf_nodes, &BasicIdentityProvider, &cipher_suite_provider)
            .await
            .unwrap();

        // Clone the tree for the first leaf, generate a new key package for that leaf
        let mut encap_tree = test_tree.clone();

        let update_leaf_properties = ConfigProperties {
            capabilities: capabilities.clone().unwrap_or_else(get_test_capabilities),
            extensions: extensions.clone().unwrap_or_default(),
        };

        // Perform the encap function
        let encap_gen = TreeKem::new(&mut encap_tree, &mut encap_private_key)
            .encap(
                &mut get_test_group_context(42, cipher_suite),
                &[],
                &encap_signer,
                update_leaf_properties,
                None,
                BasicIdentityProvider,
                &cipher_suite_provider,
                #[cfg(test)]
                &Default::default(),
            )
            .await
            .unwrap();

        // Verify that the state of the tree matches the produced update path
        verify_tree_update_path(
            &encap_tree,
            &encap_gen.update_path,
            LeafIndex(0),
            capabilities,
            extensions,
        );

        // Verify that the private key matches the data in the public key
        verify_tree_private_path(&cipher_suite, &encap_tree, &encap_private_key, LeafIndex(0));

        let filtered = test_tree.nodes.filtered(LeafIndex(0)).unwrap();
        let mut unfiltered_nodes = vec![None; filtered.len()];
        filtered
            .into_iter()
            .enumerate()
            .filter(|(_, f)| !*f)
            .zip(encap_gen.update_path.nodes.iter())
            .for_each(|((i, _), node)| {
                unfiltered_nodes[i] = Some(node.clone());
            });

        // Apply the update path to the rest of the leaf nodes using the decap function
        let validated_update_path = ValidatedUpdatePath {
            leaf_node: encap_gen.update_path.leaf_node,
            nodes: unfiltered_nodes,
        };

        encap_tree
            .update_hashes(&mut vec![LeafIndex(0)], &[], &cipher_suite_provider)
            .unwrap();

        let mut receiver_trees: Vec<TreeKemPublic> = (1..size).map(|_| test_tree.clone()).collect();

        for (i, tree) in receiver_trees.iter_mut().enumerate() {
            TreeKem::new(tree, &mut private_keys[i])
                .decap(
                    LeafIndex(0),
                    validated_update_path.clone(),
                    &[],
                    &mut get_test_group_context(42, cipher_suite),
                    BasicIdentityProvider,
                    &cipher_suite_provider,
                )
                .await
                .unwrap();

            tree.update_hashes(&mut vec![LeafIndex(0)], &[], &cipher_suite_provider)
                .unwrap();

            assert_eq!(tree, &encap_tree);
        }
    }

    #[maybe_async::test(sync, async(not(sync), futures_test::test))]
    async fn test_encap_decap() {
        for cipher_suite in TestCryptoProvider::all_supported_cipher_suites() {
            encap_decap(cipher_suite, 10, None, None).await;
        }
    }

    #[maybe_async::test(sync, async(not(sync), futures_test::test))]
    async fn test_encap_capabilities() {
        let cipher_suite = TEST_CIPHER_SUITE;
        let mut capabilities = get_test_capabilities();
        capabilities.extensions.push(42.into());

        encap_decap(cipher_suite, 10, Some(capabilities.clone()), None).await;
    }

    #[maybe_async::test(sync, async(not(sync), futures_test::test))]
    async fn test_encap_extensions() {
        let cipher_suite = TEST_CIPHER_SUITE;
        let mut extensions = ExtensionList::default();
        extensions.set_from(TestExtension { foo: 10 }).unwrap();

        encap_decap(cipher_suite, 10, None, Some(extensions)).await;
    }

    #[maybe_async::test(sync, async(not(sync), futures_test::test))]
    async fn test_encap_capabilities_extensions() {
        let cipher_suite = TEST_CIPHER_SUITE;
        let mut capabilities = get_test_capabilities();
        capabilities.extensions.push(42.into());

        let mut extensions = ExtensionList::default();
        extensions.set_from(TestExtension { foo: 10 }).unwrap();

        encap_decap(cipher_suite, 10, Some(capabilities), Some(extensions)).await;
    }
}
