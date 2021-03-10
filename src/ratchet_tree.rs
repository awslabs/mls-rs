use crate::ciphersuite::{CipherSuiteError};
use rand_core::{CryptoRng, RngCore};
use thiserror::Error;
use crate::key_package::{KeyPackage, KeyPackageGeneration, KeyPackageGenerator, KeyPackageError};
use crate::tree_math;
use crate::tree_math::{TreeMathError, parent};
use std::convert::TryFrom;
use cfg_if::cfg_if;
use crate::hpke::HPKECiphertext;
use crate::tree_path::{NodeSecretGenerator, NodeSecrets};
use crate::signature::{Verifier, SignatureError};
use crate::tree_node::{NodeIndex, Node, NodeVecError, LeafIndex, Leaf, Parent, NodeVec};

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
    #[error("invalid update path signature")]
    InvalidUpdatePathSignature,
    #[error("update path pub key mismatch")]
    PubKeyMismatch,
    #[error("bad update: no suitable secret key")]
    UpdateErrorNoSecretKey,
}

#[derive(Clone, Debug, PartialEq)]
pub struct RatchetTree {
    cipher_suite: CipherSuite,
    nodes: NodeVec,
    self_index: LeafIndex
}

impl RatchetTree {
    fn new(key_package: KeyPackageGeneration) -> Result<RatchetTree, RatchetTreeError> {

        let cipher_suite = key_package.key_package.data.cipher_suite.clone();

        let leaf_node = Leaf {
            secret_key: Some(key_package.secret_key),
            key_package: key_package.key_package
        };

        Ok(RatchetTree {
            cipher_suite,
            nodes: vec![Some(Node::Leaf(leaf_node))].into(),
            self_index: LeafIndex::try_from(0)?
        })
    }

    fn update_unmerged(&mut self, index: LeafIndex) -> Result<(), RatchetTreeError> {
        // For a given leaf index, find parent nodes and add the leaf to the unmerged leaf
        self.nodes.direct_path(index)?
            .iter()
            .try_for_each(|&i| {
                self.nodes.get_parent_node_mut(i).ok()
                    .and_then(|p| Some(p.unmerged.push(index) ));
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

    pub fn add_nodes(&mut self, key_packages: Vec<KeyPackage>) -> Result<(), RatchetTreeError> {
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
            .try_for_each(|&i| { self.update_unmerged(i) })
    }

    fn encrypt_copath_node_resolution<RNG: CryptoRng + RngCore + 'static>(&self, rng: &mut RNG, path_secret: &NodeSecrets, copath_node_resolution: Vec<&Node>, context: &[u8]) -> Result<(NodeSecrets, UpdatePathNode), RatchetTreeError> {
        let ciphertext = copath_node_resolution
            .iter()
            .flat_map(|&copath_node| {
                self.cipher_suite.hpke_seal(rng, &copath_node.get_public_key(),
                                            context, &path_secret.path_secret)
            })
            .collect();

        let update_path_node = UpdatePathNode {
            public_key: path_secret.key_pair.public_key.clone(),
            encrypted_path_secret: ciphertext
        };

        Ok((path_secret.clone(), update_path_node))
    }

    pub fn gen_secret_update_path<RNG: CryptoRng + RngCore + 'static, KPG: KeyPackageGenerator>(&self, rng: &mut RNG, key_generator: &KPG, context: &[u8]) -> Result<SecretUpdatePath, RatchetTreeError> {
        // random leaf secret
        let leaf_secret = self.cipher_suite.generate_leaf_secret(rng)?;

        let mut secret_generator = NodeSecretGenerator::new_from_path_secret(self.cipher_suite.clone(), leaf_secret);

        // new leaf keypair
        let leaf_keypair = secret_generator.next_secret()?.key_pair;
        // new key package
        let leaf_key_package = key_generator.package_from_pub_key(&self.cipher_suite,
                                                                  leaf_keypair.public_key)?;

        // Generate all the new path secrets and encrypt them to their copath node resolutions
        let (update_secrets, node_updates) =
            secret_generator
                .flatten()
                .zip(self.nodes.copath_resolution(self.self_index)?)
                .flat_map(|(path_secret, copath_nodes)| {
                    self.encrypt_copath_node_resolution(rng,
                                                        &path_secret,
                                                        copath_nodes,
                                                        &context)
                })
                .unzip();

        Ok(SecretUpdatePath {
            leaf: Leaf {
                key_package: leaf_key_package.clone(),
                secret_key: Some(leaf_keypair.secret_key)
            },
            update_path: UpdatePath {
                leaf_key_package,
                nodes: node_updates
            },
            update_secrets
        })
    }

    // Apply a pending path update and return the root node path secret
    pub fn apply_secret_update_path(&mut self, pending: &SecretUpdatePath) -> Result<Vec<u8>, RatchetTreeError> {
        // Update leaf secret key
        self.nodes.get_mut(NodeIndex::from(self.self_index))
            .ok_or(TreeMathError::InvalidIndex)
            .and_then(|n| Ok(*n = Some(Node::Leaf(pending.leaf.clone()))))?;

        // Iterate through the update secrets and apply them to their nodes
        self.nodes.direct_path(self.self_index)?
            .iter()
            .zip(pending.update_secrets.iter())
            .try_fold(Vec::new(), |_, (&i, secret)| {
                self.update_node_secret(&secret, i)
                    .and_then(|_| Ok(secret.path_secret.clone()))
            })
            .map_err(|e| e.into())
    }

    fn decrypt_parent_path_secret(&self, update_node: &UpdatePathNode, lca_direct_path_child: NodeIndex, context: &[u8]) -> Result<Vec<u8>, RatchetTreeError> {
        self.nodes
            .get_resolution(lca_direct_path_child)? // Resolution of the lca child node
            .iter()
            .zip(update_node.encrypted_path_secret.iter()) // Match up the nodes with their ciphertexts
            .find_map(|(i,ct)| {
                i.get_secret_key().as_ref().map_or(None, |sk| Some((sk, ct)))
            })
            .ok_or(RatchetTreeError::UpdateErrorNoSecretKey)
            .and_then(|(sk, ct)| { // Decrypt the path secret
                self.cipher_suite.hpke_open(ct, &sk, context)
                    .map_err(|e| e.into())
            })
    }

    fn update_node_secret(&mut self, secret: &NodeSecrets, index: NodeIndex) -> Result<(), RatchetTreeError> {
        self.nodes
            .get_or_fill_parent_node(index,
                                     &secret.key_pair.public_key,
                                     Some(&secret.key_pair.secret_key))
            .map_err(|e| e.into())
            .and_then(|p| {
                // It is important to make sure the keys we derived agree with our expectations
                if p.public_key != secret.key_pair.public_key {
                    Err(RatchetTreeError::PubKeyMismatch)
                } else {
                    // Update the values on the node, TODO: this is redundant on a new node
                    p.secret_key = Some(secret.key_pair.secret_key.clone());
                    p.public_key = secret.key_pair.public_key.clone();
                    p.unmerged = vec![];
                    Ok(())
                }
            })
    }

    pub fn apply_update_path(&mut self, sender: LeafIndex, update_path: &UpdatePath, context: &[u8]) -> Result<Vec<u8>, RatchetTreeError> {
        // Find the least common ancestor shared by us and the sender
        let lca = tree_math::common_ancestor_direct(self.self_index.into(), sender.into());

        let lca_children = [
            tree_math::left(lca)?,
            tree_math::right(lca, self.nodes.leaf_count())?
        ];

        // Find the path secret of the parent node of the lca child on our direct path
        // Also returns the position in the direct path we were able to decrypt
        let (direct_path_index, path_secret) = self.nodes
            .direct_path_with_leaf(self.self_index)?
            .iter()
            .enumerate()
            .zip(&update_path.nodes)
            .find_map(|((index, &i), update_node)| {
                lca_children // Wait until we find one of the lca children in our direct path
                    .iter()
                    .find(|&&x|x == i)
                    .and_then(|&i| { // Attempt to decrypt the path secret at that node
                        self.decrypt_parent_path_secret(update_node, i, context)
                            .map(|r| (index + 1, r))
                            .into()
                    })
            })
            .ok_or(RatchetTreeError::UpdateErrorNoSecretKey)??;

        // Derive the rest of the secrets for the tree and assign to the proper nodes
        // NOTE: Direct path is stateful, so it is already sitting at the correct index from
        // the prior call above. Return the path secret of the tree root

        let node_secret_gen = NodeSecretGenerator::new_from_path_secret(
            self.cipher_suite.clone(),
            path_secret
        );

        let root_path_secret = node_secret_gen
            .flatten()
            .zip(
                self.nodes.direct_path_with_leaf(self.self_index)?
                .iter()
                .skip(direct_path_index)
            )
            .try_fold(Vec::new(), | _, (secret, &i)| {
                self.update_node_secret(&secret, i)
                    .and_then(|_| Ok(secret.path_secret.clone()))
            })?;

        // Update leaf value
        self.nodes.get_leaf_node_mut(NodeIndex::from(sender))
            .map_err(|e| RatchetTreeError::NodeVecError(e))
            .and_then(|l| {
                l.key_package = update_path.leaf_key_package.clone();
                Ok(())
            })?;

        // Apply the new public values from the update path
        self.nodes.direct_path(sender)?
            .iter()
            .zip(update_path.nodes.iter())
            .try_for_each(|(&i, update)| {
                self.nodes
                    .get_or_fill_parent_node(i,
                                             &update.public_key,
                                             None)
                    .map_err(|e| RatchetTreeError::NodeVecError(e))
                    .and_then(|n| {
                        n.public_key = update.public_key.clone();
                        n.unmerged = vec![];
                        Ok(())
                    })
            })?;

        // Return the path secret of the root node
        Ok(root_path_secret)
    }

}

pub struct SecretUpdatePath {
    leaf: Leaf,
    update_path: UpdatePath,
    update_secrets: Vec<NodeSecrets>
}

pub struct UpdatePathNode {
    pub public_key: Vec<u8>,
    pub encrypted_path_secret: Vec<HPKECiphertext>,
}

pub struct UpdatePath {
    pub leaf_key_package: KeyPackage,
    pub nodes: Vec<UpdatePathNode>
}

#[cfg(test)]
mod test {
    use super::RatchetTree;
    use crate::ciphersuite::test_util::MockCipherSuite;
    use crate::tree_node::{LeafIndex, NodeVec, NodeTypeResolver, Node};
    use crate::tree_node::Leaf;
    use crate::key_package::{KeyPackage, KeyPackageData, KeyPackageGeneration, KeyPackageGenerator, KeyPackageError};
    use crate::protocol_version::ProtocolVersion;
    use crate::credential::{BasicCredential, CredentialConvertable};
    use crate::signature::SignatureSchemeId;
    use crate::tree_node::Parent;
    use crate::rand::test_rng::ZerosRng;
    use crate::key_package::test_util::MockKeyPackageGenerator;
    use crate::ciphersuite::KemKeyPair;
    use crate::hpke::HPKECiphertext;
    use crate::ratchet_tree::SecretUpdatePath;
    use crate::signature::test_utils::{ MockTestSignatureScheme, MockVerifier };

    fn get_mock_cipher_suite() -> MockCipherSuite {
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
        cipher_suite.expect_hpke_seal().returning_st(move |rng: &mut ZerosRng, pk, aad, pt| {
            let mut ct = pt.clone().to_vec();
            ct.reverse();

            Ok(HPKECiphertext {
                kem_output: [pk, aad, pt].concat(),
                ciphertext: ct
            })
        });
        cipher_suite.expect_hpke_open().returning_st(move |ct, secret_key,
                                                           aad| {
            let mut pt = ct.ciphertext.clone().to_vec();
            pt.reverse();

            Ok(pt)
        });
        cipher_suite
    }

    fn get_test_key_package(id: Vec<u8>, pk: Vec<u8>) -> KeyPackage {

        let mut test_verifier = MockVerifier::new();
        test_verifier.expect_to_bytes().returning_st(move || Ok(b"42".to_vec()));
        let mut signature_scheme = MockTestSignatureScheme::new();
        signature_scheme.expect_get_verifier().return_const(test_verifier);

        KeyPackage { data: KeyPackageData {
            version: ProtocolVersion::Test,
            cipher_suite: get_mock_cipher_suite(),
            hpke_init_key: pk,
            credential: BasicCredential::new(id, signature_scheme).unwrap().to_credential(),
            extensions: vec![]
        }, signature: vec![] }
    }

    fn get_test_tree() -> RatchetTree {
        let self_leaf = Leaf {
            key_package: get_test_key_package(b"foo".to_vec(), b"bar".to_vec()),
            secret_key: Some(b"foobar".to_vec())
        };

        RatchetTree {
            cipher_suite: get_mock_cipher_suite(),
            nodes: NodeVec::from(vec![Some(self_leaf.into())]),
            self_index: LeafIndex(0)
        }
    }

    #[test]
    fn test_tree_constructor() {
        let test_key_package = KeyPackageGeneration {
            key_package: get_test_key_package(b"foo".to_vec(), b"bar".to_vec()),
            secret_key: b"foobar".to_vec()
        };

        let tree = RatchetTree::new(test_key_package).unwrap();
        assert_eq!(tree, get_test_tree())
    }

    fn get_test_key_packages() -> Vec<KeyPackage> {
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
            secret_key: None
        }.into());
        assert_eq!(tree.nodes[3], None);
        assert_eq!(tree.nodes[4], Leaf {
            key_package: key_packages[1].clone(),
            secret_key: None
        }.into());
        assert_eq!(tree.nodes[5], None);
        assert_eq!(tree.nodes[6], Leaf {
            key_package: key_packages[2].clone(),
            secret_key: None
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
            secret_key: None,
            unmerged: vec![]
        }.into();

        tree.add_nodes([key_packages[2].clone()].to_vec()).unwrap();

        assert_eq!(tree.nodes[3].as_parent().unwrap().unmerged, vec![LeafIndex(3)])
    }

    fn generate_update_path() -> (RatchetTree, SecretUpdatePath) {
        let mut tree = get_test_tree();
        let key_packages = get_test_key_packages();
        tree.add_nodes(key_packages.clone()).unwrap();

        let ctx = b"foo".to_vec();

        let mut key_package_gen = MockKeyPackageGenerator::new();
        key_package_gen.expect_package_from_pub_key().returning_st(move |_, pk| {
            Ok(get_test_key_package(b"NEW".to_vec(), pk.clone()))
        });

        let update_path = tree.gen_secret_update_path(&mut ZerosRng{},
                                                      &key_package_gen,
                                                      &ctx).unwrap();

        (tree, update_path)
    }

    #[test]
    fn test_gen_apply_update_path() {
        let (mut tree, update_path) = generate_update_path();

        let root_secret = tree.apply_secret_update_path(&update_path).unwrap();
        assert_eq!(root_secret, update_path.update_secrets.iter().last().unwrap().path_secret);

        let current_keypairs: Vec<KemKeyPair> = tree.nodes
            .direct_path(tree.self_index)
            .unwrap()
            .iter()
            .map(|n| tree.nodes[*n].as_parent().unwrap())
            .map(|p| KemKeyPair {
                public_key: p.public_key.clone(),
                secret_key: p.secret_key.clone().unwrap()
            }).collect();

        let expected_keypairs: Vec<KemKeyPair> = update_path
            .update_secrets
            .iter()
            .map(|s| s.key_pair.clone())
            .collect();

        assert_eq!(current_keypairs, expected_keypairs);
    }

    #[test]
    fn test_apply_update_path() {
        let (_, update_path) = generate_update_path();

        let mut receiver_tree = get_test_tree();
        receiver_tree.add_nodes(get_test_key_packages()).unwrap();

        let public_leaf = Leaf { key_package: get_test_key_package(b"A".to_vec(), vec![]), secret_key: None };
        receiver_tree.nodes[0] = public_leaf.into();
        receiver_tree.self_index = LeafIndex(1);
        receiver_tree.nodes[2] = Leaf { key_package: get_test_key_package(b"B".to_vec(), vec![]), secret_key: Some(b"bar".to_vec()) }.into();

        let root_secret = receiver_tree.apply_update_path(LeafIndex(0), &update_path.update_path, &b"foo".to_vec()).unwrap();

        assert_eq!(update_path.update_secrets.last().unwrap().path_secret, root_secret);
        assert_eq!(update_path.update_path.leaf_key_package,
                   receiver_tree.nodes.get_leaf_node_mut(0).unwrap().key_package);

        // Make sure all the public values were updated
        receiver_tree.nodes
            .direct_path(LeafIndex(0))
            .unwrap()
            .iter()
            .enumerate()
            .for_each(|(i, &n)| {
                let one_node = receiver_tree.nodes.get(n).unwrap().is_some();

                let parent_node = receiver_tree.nodes.get_parent_node_mut(n)
                    .unwrap();
                assert_eq!(parent_node.public_key, update_path.update_path.nodes[i].public_key);
                assert_eq!(parent_node.unmerged, vec![])
        });

        // Make sure that our entire direct path has secret keys
        receiver_tree.nodes.direct_path(LeafIndex(1)).unwrap().iter().for_each(|&i| {
            let parent_node = receiver_tree.nodes.get_parent_node_mut(i)
                .unwrap();
            assert_eq!(parent_node.secret_key.is_some(), true);
        })
    }
}