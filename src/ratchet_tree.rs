use crate::ciphersuite::{CipherSuiteError};
use rand_core::{CryptoRng, RngCore};
use thiserror::Error;
use crate::key_package::{KeyPackage, KeyPackageGeneration, KeyPackageGenerator, KeyPackageError};
use crate::tree_math;
use crate::tree_math::{TreeMathError};
use cfg_if::cfg_if;
use crate::hpke::HPKECiphertext;
use crate::tree_path::{NodeSecretGenerator, NodeSecrets};
use crate::signature::{SignatureError};
use crate::tree_node::{NodeIndex, Node, NodeVecError, LeafIndex, Leaf, NodeVec};
use serde::{Serialize, Deserialize};
use std::collections::HashMap;
use crate::group::GroupSecrets;

cfg_if! {
    if #[cfg(test)] {
        use crate::ciphersuite::test_util::MockCipherSuite as CipherSuite;
    } else {
        use crate::ciphersuite::{CipherSuite};
    }
}

#[derive(Error, Debug)]
pub enum RatchetTreeError {
    #[error(transparent)]
    CipherSuiteError(#[from] CipherSuiteError),
    #[error(transparent)]
    TreeMathError(#[from] TreeMathError),
    #[error(transparent)]
    KeyPackageError(#[from] KeyPackageError),
    #[error(transparent)]
    SignatureError(#[from] SignatureError),
    #[error(transparent)]
    NodeVecError(#[from] NodeVecError),
    #[error(transparent)]
    BincodeError(#[from] bincode::Error),
    #[error("invalid update path signature")]
    InvalidUpdatePathSignature,
    #[error("update path pub key mismatch")]
    PubKeyMismatch,
    #[error("bad update: no suitable secret key")]
    UpdateErrorNoSecretKey,
    #[error("bad state: missing own credential")]
    MissingSelfCredential,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct RatchetTree {
    pub cipher_suite: CipherSuite,
    pub (crate) nodes: NodeVec,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct TreeKemPrivate {
    pub self_index: LeafIndex,
    pub secret_keys: HashMap<NodeIndex, Vec<u8>>
}

impl From<KeyPackageGeneration> for TreeKemPrivate {
    fn from(kg: KeyPackageGeneration) -> Self {
        Self::from(kg.secret_key)
    }
}

impl TreeKemPrivate {
    pub fn new(self_index: LeafIndex) -> Self {
        TreeKemPrivate {
            self_index,
            secret_keys: Default::default()
        }
    }

    pub fn new_self_leaf(self_index: LeafIndex, leaf_secret: Vec<u8>) -> Self {
        let mut private_key = TreeKemPrivate {
            self_index,
            secret_keys: Default::default()
        };
        private_key.secret_keys.insert(NodeIndex::from(self_index), leaf_secret);
        private_key
    }

    pub fn new_from_secret(
        cipher_suite: &CipherSuite,
        self_index: LeafIndex,
        leaf_secret: Vec<u8>,
        sender_index: LeafIndex,
        leaf_count: usize,
        group_secrets: &GroupSecrets
    ) -> Result<Self, RatchetTreeError> {
        // Update the leaf at index index with the private key corresponding to the public key
        // in the node.
        let mut private_key = TreeKemPrivate::new_self_leaf(self_index, leaf_secret);

        if let Some(path_secret) = &group_secrets.path_secret {
            // If the path_secret value is set in the GroupSecrets object: Identify the lowest common
            // ancestor of the leaves at index and at GroupInfo.signer_index. Set the private key
            // for this node to the private key derived from the path_secret.
            let lca = tree_math::common_ancestor_direct(sender_index.into(),
                                                        self_index.into());

            let path_gen = NodeSecretGenerator::new_from_path_secret(
                cipher_suite.clone(),
                path_secret.path_secret.clone()
            ).flatten(); //TODO: This is skipping errors
            
            // For each parent of the common ancestor, up to the root of the tree, derive a new
            // path secret and set the private key for the node to the private key derived from the
            // path secret. The private key MUST be the private key that corresponds to the public
            // key in the node.
            self_index.direct_path(leaf_count)?
                .iter()
                .skip_while(|&&i| i != lca )
                .zip(path_gen)
                .for_each(|(&i, secret)| {
                    private_key.secret_keys.insert(i, secret.key_pair.secret_key);
                });
        }

        Ok(private_key)
    }
}

impl From<Vec<u8>> for TreeKemPrivate {
    fn from(secret_key: Vec<u8>) -> Self {
        let mut secret_keys = HashMap::new();
        secret_keys.insert(0usize, secret_key);

        TreeKemPrivate {
            self_index: LeafIndex(0),
            secret_keys,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SecretPath {
    pub root_secret: Vec<u8>,
    path_secrets: HashMap<NodeIndex, Vec<u8>>
}

impl SecretPath {
    pub fn get_path_secret(&self, index: NodeIndex) -> Option<Vec<u8>> {
        self.path_secrets.get(&index).cloned()
    }
}

impl Default for SecretPath {
    fn default() -> Self {
        SecretPath {
            root_secret: vec![],
            path_secrets: Default::default()
        }
    }
}

impl From<Vec<IndexedNodeSecrets>> for SecretPath {
    fn from(path_secrets: Vec<IndexedNodeSecrets>) -> Self {
        let mut secrets = HashMap::new();
        let root_secret = path_secrets.iter().fold(Vec::new(), | _, secret| {
            secrets.insert(secret.index, secret.secrets.path_secret.clone());
            secret.secrets.path_secret.clone()
        });
        SecretPath {
            root_secret,
            path_secrets: secrets
        }
    }
}

struct IndexedNodeSecrets {
    index: NodeIndex,
    secrets: NodeSecrets
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct UpdatePathGeneration {
    pub update_path: UpdatePath,
    pub secrets: TreeSecrets,
}

impl UpdatePathGeneration {
    pub fn get_common_path_secret(&self, leaf: LeafIndex) -> Option<Vec<u8>> {
        let lca = tree_math::common_ancestor_direct(
            self.secrets.private_key.self_index.into(),
            leaf.into()
        );

        self.secrets.secret_path.get_path_secret(lca)
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct TreeSecrets {
    pub private_key: TreeKemPrivate,
    pub secret_path: SecretPath,
}

impl TreeSecrets {
    fn new(private_key: TreeKemPrivate) -> TreeSecrets {
        TreeSecrets {
            private_key,
            secret_path: Default::default()
        }
    }
}

impl RatchetTree {
    pub fn new(key_package: KeyPackageGeneration)
        -> Result<(RatchetTree, TreeKemPrivate), RatchetTreeError> {
        let cipher_suite = key_package.key_package.cipher_suite.clone();

        let public_tree = RatchetTree {
            cipher_suite,
            nodes: vec![Leaf::from(key_package.key_package.clone()).into()].into(),
        };

        let private_tree = TreeKemPrivate::from(key_package);

        Ok((public_tree, private_tree))
    }

    pub fn leaf_count(&self) -> usize {
        self.nodes.leaf_count()
    }

    pub fn find_leaf(&self, key_package: &KeyPackage) -> Option<LeafIndex> {
        self.nodes
            .non_empty_leaves()
            .find(|(_, leaf)| &leaf.key_package == key_package)
            .map(|r| r.0)
    }

    pub fn get_key_package(&self, leaf: LeafIndex) -> Result<&KeyPackage, RatchetTreeError> {
        self.nodes
            .get_leaf_node(leaf)
            .map(|l| &l.key_package)
            .map_err(|e| e.into())
    }

    pub fn is_valid(&self, expected_tree_hash: &Vec<u8>) -> Result<bool, RatchetTreeError> {
        //Verify that the tree hash of the ratchet tree matches the tree_hash field in the GroupInfo.
        if &self.tree_hash()? != expected_tree_hash {
            return Ok(false);
        }

        //For each non-empty parent node, verify that exactly one of the node's children are
        // non-empty and have the hash of this node set as their parent_hash value (if the child
        // is another parent) or has a parent_hash extension in the KeyPackage containing the same
        // value (if the child is a leaf). If either of the node's children is empty, and in
        // particular does not have a parent hash, then its respective children's
        // values have to be considered instead.
        // TODO: Parent hash calculation / validation

        // For each non-empty leaf node, verify the signature on the KeyPackage.
        for one_leaf in self.nodes.non_empty_leaves().map(|l| l.1) {
            if one_leaf.key_package.has_valid_signature() == false {
                return Ok(false)
            }
        }

        Ok(true)
    }

    fn update_unmerged(&mut self, index: LeafIndex) -> Result<(), RatchetTreeError> {
        // For a given leaf index, find parent nodes and add the leaf to the unmerged leaf
        self.nodes.direct_path(index)?
            .iter()
            .try_for_each(|&i| {
                self.nodes.get_parent_node_mut(i).ok()
                    .and_then(|p| Some(p.unmerged_leaves.push(index) ));
                Ok(())
            })
    }

    fn fill_empty_leaves(&mut self, nodes: &Vec<Node>) -> Vec<LeafIndex> {
        // Fill a set of empty leaves given a particular array, return the amount of
        // nodes consumed
        self.nodes.empty_leaves()
            .zip(nodes.iter())
            .fold(Vec::new(), |mut indexs, ((index, empty_node), new_node)| {
                *empty_node = Some(new_node.clone());
                indexs.push(index);
                indexs
            })
    }

    pub fn add_nodes(&mut self, key_packages: Vec<KeyPackage>) -> Result<Vec<LeafIndex>, RatchetTreeError> {
        // Convert all the key packaes into nodes
        let new_nodes: Vec<Node> = key_packages
            .iter()
            .map(|n| Node::from(n.clone()))
            .collect();

        // Fill empty leaves first, then add the remaining nodes by extending
        // the tree to the right
        let mut added_leaf_index = self.fill_empty_leaves(&new_nodes);

        new_nodes
            .iter()
            .skip(added_leaf_index.len())
            .for_each(|n| {
                self.nodes.push(None);
                self.nodes.push(n.clone().into());
                added_leaf_index.push(LeafIndex(self.nodes.len() / 2))
            });

        added_leaf_index
            .iter()
            .try_for_each(|&i| { self.update_unmerged(i) })?;

        Ok(added_leaf_index)
    }

    fn encrypt_copath_node_resolution<RNG: CryptoRng + RngCore + 'static>(
        &self,
        rng: &mut RNG,
        path_secret: &NodeSecrets,
        index: NodeIndex,
        copath_node_resolution: Vec<&Node>,
        context: &[u8]
    ) -> Result<(IndexedNodeSecrets, UpdatePathNode), RatchetTreeError> {
        let ciphertext = copath_node_resolution
            .iter()
            .map(|&copath_node| {
                self.cipher_suite.hpke_seal(rng, &copath_node.get_public_key(),
                                            context, &path_secret.path_secret).unwrap()
            })
            .collect();

        let update_path_node = UpdatePathNode {
            public_key: path_secret.key_pair.public_key.clone(),
            encrypted_path_secret: ciphertext
        };

        let indexed_node_secrets = IndexedNodeSecrets {
            index,
            secrets: path_secret.clone()
        };

        Ok((indexed_node_secrets, update_path_node))
    }

    // TODO: This can be expressed as one method with apply_secret_update_path,
    // we wind up cloning the tree anyways during the commit process
    pub fn gen_update_path<RNG: CryptoRng + RngCore + 'static, KPG: KeyPackageGenerator>(
        &self,
        from: LeafIndex,
        rng: &mut RNG,
        key_generator: &KPG,
        context: &[u8],
        excluding: &Vec<LeafIndex>
    ) -> Result<UpdatePathGeneration, RatchetTreeError> {
        // random leaf secret
        let leaf_secret = self.cipher_suite.generate_leaf_secret(rng)?;

        let mut secret_generator = NodeSecretGenerator::new_from_path_secret(self.cipher_suite.clone(), leaf_secret);

        // new leaf keypair
        let leaf_keypair = secret_generator.next_secret()?.key_pair;
        // new key package
        let leaf_key_package = key_generator.package_from_pub_key(&self.cipher_suite,
                                                                  leaf_keypair.public_key)?;

        // Generate all the new path secrets and encrypt them to their copath node resolutions
        let (node_secrets, node_updates): (Vec<IndexedNodeSecrets>, Vec<UpdatePathNode>) =
            secret_generator
                .flatten() //TODO: Remove flatmap + flatten
                .zip(self.nodes.direct_path_copath_resolution(from, excluding)?)
                .flat_map(|(path_secret, (index, copath_nodes))| {
                    self.encrypt_copath_node_resolution(rng,
                                                        &path_secret,
                                                        index,
                                                        copath_nodes,
                                                        &context)
                })
                .unzip();

        let mut private_key = TreeKemPrivate::from(leaf_keypair.secret_key);
        node_secrets.iter().for_each(|ps| {
            private_key.secret_keys.insert(ps.index, ps.secrets.key_pair.secret_key.clone());
        });

        let secret_path = SecretPath::from(node_secrets);

        let update_path = UpdatePath {
            leaf_key_package,
            nodes: node_updates
        };

        Ok(UpdatePathGeneration {
            update_path,
            secrets: TreeSecrets {
                private_key,
                secret_path,
            }
        })
    }

    fn decrypt_parent_path_secret(
        &self, private_key: &TreeKemPrivate,
        update_node: &UpdatePathNode,
        lca_direct_path_child: NodeIndex,
        excluding: &Vec<NodeIndex>,
        context: &[u8]
    ) -> Result<Vec<u8>, RatchetTreeError> {
        self.nodes
            .get_resolution_index(lca_direct_path_child)? // Resolution of the lca child node
            .iter()
            .zip(update_node.encrypted_path_secret.iter())
            .filter(|(i, _)| !excluding.contains(i))// Match up the nodes with their ciphertexts
            .find_map(|(i,ct)| {
                private_key.secret_keys.get(i).map_or(None, |sk| Some((sk, ct)))
            })
            .ok_or(RatchetTreeError::UpdateErrorNoSecretKey)
            .and_then(|(sk, ct)| { // Decrypt the path secret
                self.cipher_suite.hpke_open(ct, &sk, context)
                    .map_err(|e| e.into())
            })
    }

    fn update_node(&mut self, pub_key: Vec<u8>, index: NodeIndex) -> Result<(), RatchetTreeError> {
        self.nodes
            .get_or_fill_parent_node(index,
                                     &pub_key)
            .map_err(|e| e.into())
            .and_then(|p| {
                p.public_key = pub_key;
                p.unmerged_leaves = vec![];
                Ok(())
            })
    }

    pub fn apply_update_path(
        &mut self,
        sender: LeafIndex,
        update_path: &UpdatePath
    ) -> Result<(), RatchetTreeError> {
        self.nodes.get_leaf_node_mut(NodeIndex::from(sender))
            .map_err(|e| RatchetTreeError::NodeVecError(e))
            .and_then(|l| {
                l.key_package = update_path.leaf_key_package.clone();
                Ok(())
            })?;


        update_path.nodes
            .iter()
            .zip(self.nodes.direct_path(sender)?)
            .try_for_each(|(one_node, node_index)| {
                self.update_node(one_node.public_key.clone(), node_index)
            })
    }

    pub fn refresh_private_key(
        &self,
        private_key: &TreeKemPrivate,
        sender: LeafIndex,
        update_path: &UpdatePath,
        excluding: Vec<LeafIndex>,
        context: &[u8]
    ) -> Result<TreeSecrets, RatchetTreeError> {
        // Exclude newly added leaf indexes
        let excluding = excluding
            .iter()
            .map(|i| NodeIndex::from(i)).collect();

        // Find the least common ancestor shared by us and the sender
        let lca = tree_math::common_ancestor_direct(private_key.self_index.into(),
                                                    sender.into());

        let sender_direct = self.nodes.direct_path(sender)?;
        let sender_co = self.nodes.copath(sender)?;

        let lca_path_secret = sender_direct
            .iter()
            .zip(sender_co.iter().zip(&update_path.nodes))
            .find_map(|(&direct_path_index, (&co_path_index, update_path_node))| {
                if direct_path_index == lca {
                    self.decrypt_parent_path_secret(private_key,
                                                    update_path_node,
                                                    co_path_index,
                                                    &excluding,
                                                    context).into()
                } else {
                    None
                }
        }).ok_or(RatchetTreeError::UpdateErrorNoSecretKey)??;

        // Derive the rest of the secrets for the tree and assign to the proper nodes
        let node_secret_gen = NodeSecretGenerator::new_from_path_secret(
            self.cipher_suite.clone(),
            lca_path_secret
        );

        // Update secrets based on the decrypted path secret in the update
        let tree_secrets = node_secret_gen
            .flatten() //TODO: Remove flatten
            .zip(
                // Get a pairing of direct path index + associated update
                // This will help us verify that the calculated public key is the expected one
                self.nodes
                    .direct_path(sender)?
                    .iter()
                    .zip(update_path.nodes.iter())
                    .skip_while(|(dp, _)|**dp != lca)
            )
            .try_fold(TreeSecrets::new(private_key.clone()), |mut secrets, (secret, (&index, update))| {
                // Verify the private key we calculated properly matches the public key we were
                // expecting
                if secret.key_pair.public_key != update.public_key {
                    return Err(RatchetTreeError::PubKeyMismatch);
                }
                secrets.private_key.secret_keys.insert(index, secret.key_pair.secret_key);
                secrets.secret_path.root_secret = secret.path_secret.clone();
                secrets.secret_path.path_secrets.insert(index, secret.path_secret);
                Ok(secrets)
            })?;

        Ok(tree_secrets)
    }

}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct UpdatePathNode {
    pub public_key: Vec<u8>,
    pub encrypted_path_secret: Vec<HPKECiphertext>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct UpdatePath {
    pub leaf_key_package: KeyPackage,
    pub nodes: Vec<UpdatePathNode>
}

#[cfg(test)]
pub (crate) mod test {
    use super::RatchetTree;
    use crate::ciphersuite::test_util::MockCipherSuite;
    use crate::tree_node::{LeafIndex, NodeVec, NodeTypeResolver};
    use crate::tree_node::Leaf;
    use crate::key_package::{KeyPackage, KeyPackageGeneration};
    use crate::protocol_version::ProtocolVersion;
    use crate::credential::{BasicCredential, CredentialConvertable};
    use crate::tree_node::Parent;
    use crate::rand::test_rng::ZerosRng;
    use crate::ciphersuite::KemKeyPair;
    use crate::hpke::HPKECiphertext;
    use crate::signature::test_utils::{ MockTestSignatureScheme, MockVerifier };
    use crate::key_package::test_util::MockKeyPackageGenerator;
    use crate::ratchet_tree::TreeKemPrivate;
    use std::collections::HashMap;
    use crate::extension::{Extension, ExtensionId};

    pub fn get_mock_cipher_suite() -> MockCipherSuite {
        let mut cipher_suite = MockCipherSuite::new();
        cipher_suite.expect_clone().returning_st(move|| { get_mock_cipher_suite() });
        cipher_suite.expect_get_id().returning_st(move || 42);
        cipher_suite.expect_generate_leaf_secret().returning_st(move |_: &ZerosRng| { Ok(vec![0u8; 32]) });
        cipher_suite.expect_derive_secret().returning_st(move |secret, label| {
            Ok([secret, label.to_string().as_bytes()].concat())
        });
        cipher_suite.expect_derive_kem_key_pair().returning_st(move |ikm| {
            let mut ikm_clone = ikm.clone().to_vec();
            ikm_clone.reverse();

            Ok(KemKeyPair {
               public_key: ikm_clone,
               secret_key: ikm.to_vec().clone()
           })
        });
        cipher_suite.expect_hpke_seal().returning_st(move |_rng: &mut ZerosRng, pk, aad, pt| {
            let mut ct = pt.clone().to_vec();
            ct.reverse();

            Ok(HPKECiphertext {
                kem_output: [pk, aad, pt].concat(),
                ciphertext: ct
            })
        });
        cipher_suite.expect_hpke_open().returning_st(move |ct, _secret_key,
                                                           _aad| {
            let mut pt = ct.ciphertext.clone().to_vec();
            pt.reverse();

            Ok(pt)
        });
        cipher_suite.expect_hash().returning_st(move |input| {
            Ok(input.to_vec())
        });
        cipher_suite
    }

    pub fn get_test_key_package(id: Vec<u8>, pk: Vec<u8>) -> KeyPackage {

        let mut test_verifier = MockVerifier::new();
        test_verifier.expect_to_bytes().returning_st(move || Ok(b"42".to_vec()));
        let mut signature_scheme = MockTestSignatureScheme::new();
        signature_scheme.expect_get_verifier().return_const(test_verifier);

        KeyPackage {
            version: ProtocolVersion::Test,
            cipher_suite: get_mock_cipher_suite(),
            hpke_init_key: pk,
            credential: BasicCredential::new(id, signature_scheme).unwrap().to_credential(),
            extensions: vec![Extension {
                extension_id: ExtensionId::Capabilities,
                data: vec![24u8;2]
            }],
            signature: vec![42u8;2]
        }
    }

    pub fn get_test_tree() -> RatchetTree {
        let self_leaf = Leaf {
            key_package: get_test_key_package(b"foo".to_vec(), b"bar".to_vec()),
        };

        RatchetTree {
            cipher_suite: get_mock_cipher_suite(),
            nodes: NodeVec::from(vec![Some(self_leaf.into())]),
        }
    }

    #[test]
    fn test_tree_constructor() {
        let test_key_package = KeyPackageGeneration {
            key_package: get_test_key_package(b"foo".to_vec(), b"bar".to_vec()),
            secret_key: b"foobar".to_vec(),
            key_package_hash: vec![]
        };

        let (public, private) = RatchetTree::new(test_key_package).unwrap();
        assert_eq!(public, get_test_tree());
        assert_eq!(private.self_index, LeafIndex(0));
        assert_eq!(private.secret_keys[&0], b"foobar".to_vec())
    }

    pub fn get_test_key_packages() -> Vec<KeyPackage> {
        [
            get_test_key_package(b"A".to_vec(), b"fooA".to_vec()),
            get_test_key_package(b"B".to_vec(), b"fooB".to_vec()),
            get_test_key_package(b"C".to_vec(), b"fooC".to_vec())
        ].to_vec()
    }

    #[test]
    fn test_add_node_new_tree() {
        let mut tree = get_test_tree();

        let key_packages = get_test_key_packages();

        tree.add_nodes(key_packages.clone()).unwrap();

        assert_eq!(tree.nodes.len(), 7);
        assert_eq!(tree.nodes[1], None);
        assert_eq!(tree.nodes[2], Leaf {
            key_package: key_packages[0].clone(),
        }.into());
        assert_eq!(tree.nodes[3], None);
        assert_eq!(tree.nodes[4], Leaf {
            key_package: key_packages[1].clone(),
        }.into());
        assert_eq!(tree.nodes[5], None);
        assert_eq!(tree.nodes[6], Leaf {
            key_package: key_packages[2].clone(),
        }.into());
    }

    #[test]
    fn test_add_node_empty_leaf() {
        let mut tree = get_test_tree();
        let key_packages = get_test_key_packages();

        tree.add_nodes([key_packages[0].clone()].to_vec()).unwrap();
        tree.nodes[0] = None; // Set the original first node to none
        tree.add_nodes([key_packages[1].clone()].to_vec()).unwrap();

        assert_eq!(tree.nodes[0], Leaf::from(key_packages[1].clone()).into());
        assert_eq!(tree.nodes[1], None);
        assert_eq!(tree.nodes[2], Leaf::from(key_packages[0].clone()).into());
        assert_eq!(tree.nodes.len(), 3)
    }

    #[test]
    fn test_add_node_unmerged() {
        let mut tree = get_test_tree();

        let key_packages = get_test_key_packages();

        tree.add_nodes([key_packages[0].clone(), key_packages[1].clone()].to_vec()).unwrap();

        tree.nodes[3] = Parent {
            public_key: vec![],
            parent_hash: vec![],
            unmerged_leaves: vec![]
        }.into();

        tree.add_nodes([key_packages[2].clone()].to_vec()).unwrap();

        assert_eq!(tree.nodes[3].as_parent().unwrap().unmerged_leaves, vec![LeafIndex(3)])
    }

    #[test]
    fn test_update_path() {
        let mut tree = get_test_tree();
        tree.add_nodes(get_test_key_packages()).unwrap();

        let mut receiver_tree = tree.clone();

        let test_ctx = b"group_ctx".to_vec();
        let mut kpg = MockKeyPackageGenerator::new();

        let test_leaf = get_test_key_package(b"A".to_vec(), b"fooA".to_vec());
        let test_leaf_clone = test_leaf.clone();

        kpg.expect_package_from_pub_key().returning_st(move |_cipher_suite, _pub_key| {
            Ok(test_leaf_clone.clone())
        });

        // Create a new update path with corresponding private key
        let update_path = tree.gen_update_path(LeafIndex(0),
                                               &mut ZerosRng,
                                               &kpg,
                                               &test_ctx,
                                               &vec![]).unwrap();

        // Apply the generated update path
        tree.apply_update_path(LeafIndex(0), &update_path.update_path).unwrap();

        // This test just exercises the code with basic sanity checking, actual algorithm
        // testing is done via integration tests
        assert_eq!(update_path.update_path.leaf_key_package, test_leaf);
        assert_eq!(update_path.secrets.private_key.self_index, LeafIndex(0));

        let root_node = crate::tree_math::root(tree.leaf_count());
        assert_eq!(update_path.secrets.secret_path.root_secret,
                   update_path.secrets.secret_path.path_secrets.get(&root_node).cloned().unwrap());
        assert_eq!(update_path.secrets.private_key.secret_keys.len(),
                   update_path.secrets.secret_path.path_secrets.len() + 1);
        assert_eq!(update_path.update_path.nodes.len(), update_path.secrets.secret_path.path_secrets.len());

        // Verify that we have all the secrets in our direct path
        tree.nodes.direct_path(LeafIndex(0)).unwrap().iter().for_each(|i| {
            assert!(update_path.secrets.private_key.secret_keys.get(i).is_some());
            assert!(update_path.secrets.secret_path.path_secrets.get(i).is_some());
        });

        // Apply the update path and ensure that the tree was updated properly
        let mut receiver_secrets = HashMap::new();
        receiver_secrets.insert(2, Vec::new());

        let receiver_private_key = TreeKemPrivate {
            self_index: LeafIndex(1),
            secret_keys: receiver_secrets
        };

        let tree_secrets = receiver_tree.refresh_private_key(&receiver_private_key,
                                                           LeafIndex(0),
                                                           &update_path.update_path,
                                                           vec![],
                                                           &test_ctx).unwrap();

        assert_eq!(tree_secrets.private_key.self_index, LeafIndex(1));
        assert_eq!(tree_secrets.secret_path.root_secret, update_path.secrets.secret_path.root_secret);
        assert_eq!(tree_secrets.secret_path.path_secrets.len() + 1,
                   tree_secrets.private_key.secret_keys.len());

        // verify the receiver has all the secrets in their direct path
        // Verify that we have all the secrets in our direct path
        receiver_tree.nodes.direct_path(LeafIndex(0)).unwrap().iter().for_each(|i| {
            assert!(tree_secrets.private_key.secret_keys.get(i).is_some());
            assert!(tree_secrets.secret_path.path_secrets.get(i).is_some());
        });

        // Apply the public update path
        receiver_tree.apply_update_path(LeafIndex(0), &update_path.update_path).unwrap();
        assert_eq!(receiver_tree, tree)

    }

    #[test]
    fn test_tree_hash() {
        let mut test_tree = get_test_tree();
        test_tree.add_nodes(get_test_key_packages()).unwrap();

        let tree_hash = test_tree.tree_hash().unwrap();
        println!("{:?}", tree_hash);
    }
}