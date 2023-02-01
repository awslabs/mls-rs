use crate::provider::crypto::CipherSuiteProvider;
use crate::serde_utils::vec_u8_as_base64::VecAsBase64;
use crate::tree_kem::math as tree_math;
use crate::tree_kem::math::TreeMathError;
use crate::tree_kem::node::{LeafIndex, NodeIndex};
use serde_with::serde_as;
use std::collections::HashMap;
use std::ops::{Deref, DerefMut};
use thiserror::Error;
use tls_codec::Serialize;
use zeroize::Zeroize;

use super::key_schedule::kdf_expand_with_label;

pub(crate) const MAX_RATCHET_BACK_HISTORY: u32 = 1024;

#[derive(Error, Debug)]
pub enum SecretTreeError {
    #[error(transparent)]
    TreeMathError(#[from] TreeMathError),
    #[error("requested invalid index")]
    InvalidIndex,
    #[error("attempted to consume an already consumed node")]
    InvalidNodeConsumption,
    #[error("leaf secret already consumed")]
    InvalidLeafConsumption,
    #[error("key not available, invalid generation {0}")]
    KeyMissing(u32),
    #[error("requested generation {0} is too far ahead of current generation {1}")]
    InvalidFutureGeneration(u32, u32),
    #[error(transparent)]
    CipherSuiteProviderError(Box<dyn std::error::Error + Send + Sync + 'static>),
    #[error(transparent)]
    TlsCodecError(#[from] tls_codec::Error),
}

#[derive(Clone, Debug, PartialEq, serde::Deserialize, serde::Serialize)]
#[repr(u8)]
enum SecretTreeNode {
    Secret(TreeSecret),
    Ratchet(SecretRatchets),
}

impl SecretTreeNode {
    fn into_ratchet(self) -> Option<SecretRatchets> {
        if let SecretTreeNode::Ratchet(ratchets) = self {
            Some(ratchets)
        } else {
            None
        }
    }

    fn into_secret(self) -> Option<TreeSecret> {
        if let SecretTreeNode::Secret(secret) = self {
            Some(secret)
        } else {
            None
        }
    }
}

#[serde_as]
#[derive(Zeroize)]
#[zeroize(drop)]
#[derive(Clone, Debug, PartialEq, serde::Deserialize, serde::Serialize)]
struct TreeSecret(#[serde_as(as = "VecAsBase64")] Vec<u8>);

impl Deref for TreeSecret {
    type Target = Vec<u8>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for TreeSecret {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl AsRef<[u8]> for TreeSecret {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl From<Vec<u8>> for TreeSecret {
    fn from(vec: Vec<u8>) -> Self {
        TreeSecret(vec)
    }
}

#[derive(Clone, Debug, PartialEq, serde::Deserialize, serde::Serialize)]
struct TreeSecretsVec(Vec<Option<SecretTreeNode>>);

impl Deref for TreeSecretsVec {
    type Target = Vec<Option<SecretTreeNode>>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for TreeSecretsVec {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl TreeSecretsVec {
    fn replace_node(
        &mut self,
        index: NodeIndex,
        value: Option<SecretTreeNode>,
    ) -> Result<(), SecretTreeError> {
        self.get_mut(index as usize)
            .ok_or(SecretTreeError::InvalidIndex)
            .map(|n| *n = value)
    }

    fn get_secret(&self, index: NodeIndex) -> Option<SecretTreeNode> {
        self.get(index as usize).and_then(|n| n.clone())
    }

    fn total_leaf_count(&self) -> u32 {
        ((self.len() / 2 + 1) as u32).next_power_of_two()
    }
}

#[derive(Clone, Debug, PartialEq, serde::Deserialize, serde::Serialize)]
pub struct SecretTree {
    known_secrets: TreeSecretsVec,
    leaf_count: u32,
}

impl SecretTree {
    pub(crate) fn empty() -> SecretTree {
        SecretTree {
            known_secrets: TreeSecretsVec(vec![]),
            leaf_count: 0,
        }
    }
}

#[derive(Clone, Debug, PartialEq, serde::Deserialize, serde::Serialize)]
pub struct SecretRatchets {
    pub application: SecretKeyRatchet,
    pub handshake: SecretKeyRatchet,
}

impl SecretRatchets {
    pub fn message_key_generation<P: CipherSuiteProvider>(
        &mut self,
        cipher_suite_provider: &P,
        generation: u32,
        key_type: KeyType,
    ) -> Result<MessageKeyData, SecretTreeError> {
        match key_type {
            KeyType::Handshake => self
                .handshake
                .get_message_key(cipher_suite_provider, generation),
            KeyType::Application => self
                .application
                .get_message_key(cipher_suite_provider, generation),
        }
    }

    pub fn next_message_key<P: CipherSuiteProvider>(
        &mut self,
        cipher_suite_provider: &P,
        key_type: KeyType,
    ) -> Result<(MessageKeyData, u32), SecretTreeError> {
        match key_type {
            KeyType::Handshake => self.handshake.next_message_key(cipher_suite_provider),
            KeyType::Application => self.application.next_message_key(cipher_suite_provider),
        }
    }
}

impl SecretTree {
    pub fn new(leaf_count: u32, encryption_secret: Vec<u8>) -> SecretTree {
        let mut known_secrets = TreeSecretsVec(vec![None; (leaf_count * 2 - 1) as usize]);

        known_secrets[tree_math::root(leaf_count) as usize] =
            Some(SecretTreeNode::Secret(TreeSecret::from(encryption_secret)));

        Self {
            known_secrets,
            leaf_count,
        }
    }

    fn consume_node<P: CipherSuiteProvider>(
        &mut self,
        cipher_suite_provider: &P,
        index: NodeIndex,
    ) -> Result<(), SecretTreeError> {
        if let Some(secret) = self.read_node(index)?.and_then(|n| n.into_secret()) {
            let left_index = tree_math::left(index)?;
            let right_index = tree_math::right(index)?;

            let left_secret =
                kdf_expand_with_label(cipher_suite_provider, &secret, "tree", b"left", None)
                    .map_err(|e| SecretTreeError::CipherSuiteProviderError(e.into()))?;

            let right_secret =
                kdf_expand_with_label(cipher_suite_provider, &secret, "tree", b"right", None)
                    .map_err(|e| SecretTreeError::CipherSuiteProviderError(e.into()))?;

            self.write_node(left_index, Some(SecretTreeNode::Secret(left_secret.into())))?;
            self.write_node(
                right_index,
                Some(SecretTreeNode::Secret(right_secret.into())),
            )?;
            self.write_node(index, None)
        } else {
            Ok(()) // If the node is empty we can just skip it
        }
    }

    fn read_node(&self, index: NodeIndex) -> Result<Option<SecretTreeNode>, SecretTreeError> {
        Ok(self.known_secrets.get_secret(index))
    }

    fn write_node(
        &mut self,
        index: NodeIndex,
        value: Option<SecretTreeNode>,
    ) -> Result<(), SecretTreeError> {
        self.known_secrets.replace_node(index, value)
    }

    // Start at the root node and work your way down consuming any intermediates needed
    fn leaf_secret_ratchets<P: CipherSuiteProvider>(
        &mut self,
        cipher_suite_provider: &P,
        leaf_index: LeafIndex,
    ) -> Result<SecretRatchets, SecretTreeError> {
        if let Some(ratchet) = self
            .read_node(leaf_index.into())?
            .and_then(|n| n.into_ratchet())
        {
            return Ok(ratchet);
        }

        leaf_index
            .direct_path(self.known_secrets.total_leaf_count())?
            .iter()
            .rev()
            .try_for_each(|&i| self.consume_node(cipher_suite_provider, i))?;

        let secret = self
            .read_node(leaf_index.into())?
            .and_then(|n| n.into_secret())
            .ok_or(SecretTreeError::InvalidLeafConsumption)?;

        self.write_node(leaf_index.into(), None)?;

        Ok(SecretRatchets {
            application: SecretKeyRatchet::new(
                cipher_suite_provider,
                leaf_index,
                &secret,
                KeyType::Application,
            )?,
            handshake: SecretKeyRatchet::new(
                cipher_suite_provider,
                leaf_index,
                &secret,
                KeyType::Handshake,
            )?,
        })
    }

    pub fn next_message_key<P: CipherSuiteProvider>(
        &mut self,
        cipher_suite_provider: &P,
        leaf_index: LeafIndex,
        key_type: KeyType,
    ) -> Result<(MessageKeyData, u32), SecretTreeError> {
        self.message_key(cipher_suite_provider, leaf_index, |ratchet| {
            ratchet.next_message_key(cipher_suite_provider, key_type)
        })
    }

    pub fn message_key_generation<P: CipherSuiteProvider>(
        &mut self,
        cipher_suite_provider: &P,
        leaf_index: LeafIndex,
        key_type: KeyType,
        generation: u32,
    ) -> Result<MessageKeyData, SecretTreeError> {
        self.message_key(cipher_suite_provider, leaf_index, |ratchet| {
            ratchet.message_key_generation(cipher_suite_provider, generation, key_type)
        })
    }

    fn message_key<T, F, P>(
        &mut self,
        cipher_suite_provider: &P,
        leaf_index: LeafIndex,
        mut op: F,
    ) -> Result<T, SecretTreeError>
    where
        F: FnMut(&mut SecretRatchets) -> Result<T, SecretTreeError>,
        P: CipherSuiteProvider,
    {
        let mut ratchet = self.leaf_secret_ratchets(cipher_suite_provider, leaf_index)?;
        let res = op(&mut ratchet)?;

        self.write_node(leaf_index.into(), Some(SecretTreeNode::Ratchet(ratchet)))?;

        Ok(res)
    }
}

#[derive(Clone, Copy)]
pub enum KeyType {
    Handshake,
    Application,
}

impl ToString for KeyType {
    fn to_string(&self) -> String {
        match self {
            Self::Handshake => "handshake".to_string(),
            Self::Application => "application".to_string(),
        }
    }
}

#[serde_as]
#[derive(Debug, Clone, PartialEq, Eq, Zeroize, serde::Deserialize, serde::Serialize)]
#[zeroize(drop)]
pub struct MessageKeyData {
    #[serde_as(as = "VecAsBase64")]
    pub nonce: Vec<u8>,
    #[serde_as(as = "VecAsBase64")]
    pub key: Vec<u8>,
}

#[serde_as]
#[derive(Debug, Clone, PartialEq, serde::Deserialize, serde::Serialize)]
pub struct SecretKeyRatchet {
    secret: TreeSecret,
    #[serde_as(as = "Vec<(_,_)>")]
    history: HashMap<u32, MessageKeyData>,
    node_index: NodeIndex,
    generation: u32,
}

impl SecretKeyRatchet {
    fn new<P: CipherSuiteProvider>(
        cipher_suite_provider: &P,
        leaf: LeafIndex,
        secret: &[u8],
        key_type: KeyType,
    ) -> Result<Self, SecretTreeError> {
        let secret = kdf_expand_with_label(
            cipher_suite_provider,
            secret,
            &key_type.to_string(),
            &[],
            None,
        )
        .map_err(|e| SecretTreeError::CipherSuiteProviderError(e.into()))?;

        Ok(Self {
            secret: TreeSecret::from(secret),
            node_index: leaf.into(),
            generation: 0,
            history: Default::default(),
        })
    }

    fn get_message_key<P: CipherSuiteProvider>(
        &mut self,
        cipher_suite_provider: &P,
        generation: u32,
    ) -> Result<MessageKeyData, SecretTreeError> {
        if generation < self.generation {
            self.history
                .remove_entry(&generation)
                .map(|(_, mk)| mk)
                .ok_or(SecretTreeError::KeyMissing(generation))
        } else {
            let max_generation_allowed = self.generation + MAX_RATCHET_BACK_HISTORY;

            if generation > max_generation_allowed {
                return Err(SecretTreeError::InvalidFutureGeneration(
                    generation,
                    max_generation_allowed,
                ));
            }

            while self.generation < generation {
                let (key_data, generation) = self.next_message_key(cipher_suite_provider)?;
                self.history.insert(generation, key_data);
            }

            self.next_message_key(cipher_suite_provider).map(|r| r.0)
        }
    }

    fn next_message_key<P: CipherSuiteProvider>(
        &mut self,
        cipher_suite_provider: &P,
    ) -> Result<(MessageKeyData, u32), SecretTreeError> {
        let generation = self.generation;

        let key = MessageKeyData {
            nonce: self.derive_secret(
                cipher_suite_provider,
                "nonce",
                cipher_suite_provider.aead_nonce_size(),
            )?,
            key: self.derive_secret(
                cipher_suite_provider,
                "key",
                cipher_suite_provider.aead_key_size(),
            )?,
        };

        self.secret = TreeSecret::from(self.derive_secret(
            cipher_suite_provider,
            "secret",
            cipher_suite_provider.kdf_extract_size(),
        )?);

        self.generation = generation + 1;

        Ok((key, generation))
    }

    fn derive_secret<P: CipherSuiteProvider>(
        &self,
        cipher_suite_provider: &P,
        label: &str,
        len: usize,
    ) -> Result<Vec<u8>, SecretTreeError> {
        kdf_expand_with_label(
            cipher_suite_provider,
            self.secret.as_ref(),
            label,
            &(self.node_index, self.generation).tls_serialize_detached()?,
            Some(len),
        )
        .map_err(|e| SecretTreeError::CipherSuiteProviderError(e.into()))
    }
}

#[cfg(test)]
pub(crate) mod test_utils {
    use crate::tree_kem;

    use super::SecretTree;

    pub(crate) fn get_test_tree(secret: Vec<u8>, leaf_count: u32) -> SecretTree {
        SecretTree::new(leaf_count, secret)
    }

    impl SecretTree {
        pub(crate) fn get_root_secret(&self) -> Vec<u8> {
            self.read_node(tree_kem::math::root(self.leaf_count))
                .unwrap()
                .unwrap()
                .into_secret()
                .unwrap()
                .0
                .to_vec()
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        cipher_suite::CipherSuite,
        client::test_utils::TEST_CIPHER_SUITE,
        group::test_utils::random_bytes,
        provider::crypto::test_utils::{
            test_cipher_suite_provider, try_test_cipher_suite_provider, TestCryptoProvider,
        },
    };

    use super::{test_utils::get_test_tree, *};

    use assert_matches::assert_matches;

    #[cfg(target_arch = "wasm32")]
    use wasm_bindgen_test::wasm_bindgen_test as test;

    #[test]
    fn test_secret_tree() {
        for cipher_suite in TestCryptoProvider::all_supported_cipher_suites() {
            println!("Running secret tree derivation for {cipher_suite:?}");

            let cs_provider = test_cipher_suite_provider(cipher_suite);

            let test_secret = vec![0u8; cs_provider.kdf_extract_size()];

            let mut test_tree = get_test_tree(test_secret.clone(), 16);

            let mut secrets: Vec<SecretRatchets> = (0..16)
                .into_iter()
                .map(|i| {
                    test_tree
                        .leaf_secret_ratchets(
                            &test_cipher_suite_provider(cipher_suite),
                            LeafIndex(i),
                        )
                        .unwrap()
                })
                .collect();

            // Verify the tree is now completely empty
            let full = test_tree
                .known_secrets
                .iter()
                .filter(|n| n.is_some())
                .count();
            assert_eq!(full, 0);

            // Verify that all the secrets are unique
            let count = secrets.len();
            secrets.dedup();
            assert_eq!(count, secrets.len());
        }
    }

    #[test]
    fn test_secret_key_ratchet() {
        for cipher_suite in TestCryptoProvider::all_supported_cipher_suites() {
            println!("Running secret tree ratchet for {cipher_suite:?}");

            let provider = test_cipher_suite_provider(cipher_suite);

            let mut app_ratchet = SecretKeyRatchet::new(
                &provider,
                LeafIndex(42),
                &vec![0u8; provider.kdf_extract_size()],
                KeyType::Application,
            )
            .unwrap();

            let mut handshake_ratchet = SecretKeyRatchet::new(
                &provider,
                LeafIndex(42),
                &vec![0u8; provider.kdf_extract_size()],
                KeyType::Handshake,
            )
            .unwrap();

            let app_keys: Vec<(MessageKeyData, u32)> = vec![
                app_ratchet.next_message_key(&provider).unwrap(),
                app_ratchet.next_message_key(&provider).unwrap(),
            ];

            let handshake_keys: Vec<(MessageKeyData, u32)> = vec![
                handshake_ratchet.next_message_key(&provider).unwrap(),
                handshake_ratchet.next_message_key(&provider).unwrap(),
            ];

            // Verify that the keys have different outcomes due to their different labels
            assert_ne!(app_keys, handshake_keys);

            // Verify that the keys at each generation are different
            assert_ne!(handshake_keys[0], handshake_keys[1]);
        }
    }

    #[test]
    fn test_get_key() {
        for cipher_suite in TestCryptoProvider::all_supported_cipher_suites() {
            println!("Running secret tree get key for {cipher_suite:?}");

            let provider = test_cipher_suite_provider(cipher_suite);

            let mut ratchet = SecretKeyRatchet::new(
                &test_cipher_suite_provider(cipher_suite),
                LeafIndex(42),
                &vec![0u8; provider.kdf_extract_size()],
                KeyType::Application,
            )
            .unwrap();

            let mut ratchet_clone = ratchet.clone();

            // This will generate keys 0 and 1 in ratchet_clone
            let _ = ratchet_clone.next_message_key(&provider).unwrap();
            let clone_2 = ratchet_clone.next_message_key(&provider).unwrap();

            // Going back in time should result in an error
            assert!(ratchet_clone.get_message_key(&provider, 0).is_err());

            // Calling get key should be the same as calling next until hitting the desired generation
            let second_key = ratchet
                .get_message_key(&provider, ratchet_clone.generation - 1)
                .unwrap();

            assert_eq!(clone_2.0, second_key)
        }
    }

    #[test]
    fn test_secret_ratchet() {
        for cipher_suite in TestCryptoProvider::all_supported_cipher_suites() {
            println!("Running secret tree secret ratchet {cipher_suite:?}");

            let provider = test_cipher_suite_provider(cipher_suite);

            let mut ratchet = SecretKeyRatchet::new(
                &provider,
                LeafIndex(42),
                &vec![0u8; provider.kdf_extract_size()],
                KeyType::Application,
            )
            .unwrap();

            let original_secret = ratchet.secret.clone();
            let _ = ratchet.next_message_key(&provider).unwrap();
            let new_secret = ratchet.secret;
            assert_ne!(original_secret, new_secret)
        }
    }

    #[test]
    fn test_out_of_order_keys() {
        let cipher_suite = TEST_CIPHER_SUITE;
        let provider = test_cipher_suite_provider(cipher_suite);

        let mut ratchet =
            SecretKeyRatchet::new(&provider, LeafIndex(42), &[0u8; 32], KeyType::Handshake)
                .unwrap();

        let mut ratchet_clone = ratchet.clone();

        // Ask for all the keys in order from the original ratchet
        let ordered_keys = (0..=MAX_RATCHET_BACK_HISTORY)
            .map(|i| ratchet.get_message_key(&provider, i).unwrap())
            .collect::<Vec<MessageKeyData>>();

        // Ask for a key at index MAX_RATCHET_BACK_HISTORY in the clone
        let last_key = ratchet_clone
            .get_message_key(&provider, MAX_RATCHET_BACK_HISTORY)
            .unwrap();

        assert_eq!(last_key, ordered_keys[ordered_keys.len() - 1]);

        // Get all the other keys
        let back_history_keys = (0..MAX_RATCHET_BACK_HISTORY - 1)
            .map(|i| ratchet_clone.get_message_key(&provider, i).unwrap())
            .collect::<Vec<MessageKeyData>>();

        assert_eq!(
            back_history_keys,
            ordered_keys[..(MAX_RATCHET_BACK_HISTORY as usize) - 1]
        );
    }

    #[test]
    fn test_too_out_of_order() {
        let cipher_suite = TEST_CIPHER_SUITE;
        let provider = test_cipher_suite_provider(cipher_suite);

        let mut ratchet =
            SecretKeyRatchet::new(&provider, LeafIndex(42), &[0u8; 32], KeyType::Handshake)
                .unwrap();

        let res = ratchet.get_message_key(&provider, MAX_RATCHET_BACK_HISTORY + 1);
        let invalid_generation = MAX_RATCHET_BACK_HISTORY + 1;

        assert_matches!(
            res,
            Err(SecretTreeError::InvalidFutureGeneration(
                invalid,
                expected
            ))
            if invalid == invalid_generation && expected == MAX_RATCHET_BACK_HISTORY
        )
    }

    #[derive(Debug, PartialEq, serde::Serialize, serde::Deserialize)]
    struct Ratchet {
        application_keys: Vec<(MessageKeyData, u32)>,
        handshake_keys: Vec<(MessageKeyData, u32)>,
    }

    #[derive(Debug, serde::Serialize, serde::Deserialize)]
    struct TestCase {
        cipher_suite: u16,
        #[serde(with = "hex::serde")]
        encryption_secret: Vec<u8>,
        ratchets: Vec<Ratchet>,
    }

    fn get_ratchet_data(secret_tree: &mut SecretTree, cipher_suite: CipherSuite) -> Vec<Ratchet> {
        let provider = test_cipher_suite_provider(cipher_suite);
        (0..16)
            .map(|index| {
                let mut ratchets = secret_tree
                    .leaf_secret_ratchets(&provider, LeafIndex(index))
                    .unwrap();

                let application_keys = (0..20)
                    .map(|_| ratchets.handshake.next_message_key(&provider).unwrap())
                    .collect();

                let handshake_keys = (0..20)
                    .map(|_| ratchets.handshake.next_message_key(&provider).unwrap())
                    .collect();

                Ratchet {
                    application_keys,
                    handshake_keys,
                }
            })
            .collect()
    }

    fn generate_secret_tree_test_vectors() -> Vec<TestCase> {
        CipherSuite::all()
            .map(|cipher_suite| {
                let provider = test_cipher_suite_provider(cipher_suite);
                let encryption_secret = random_bytes(provider.kdf_extract_size());
                let mut secret_tree = SecretTree::new(16, encryption_secret.clone());

                TestCase {
                    cipher_suite: cipher_suite.into(),
                    encryption_secret,
                    ratchets: get_ratchet_data(&mut secret_tree, cipher_suite),
                }
            })
            .collect()
    }

    fn load_test_cases() -> Vec<TestCase> {
        load_test_cases!(secret_tree, generate_secret_tree_test_vectors())
    }

    #[test]
    fn test_secret_tree_test_vectors() {
        let test_cases = load_test_cases();

        for case in test_cases {
            let Some(cs_provider) = try_test_cipher_suite_provider(case.cipher_suite) else {
                continue;
            };

            let mut secret_tree = SecretTree::new(16, case.encryption_secret);
            let ratchet_data = get_ratchet_data(&mut secret_tree, cs_provider.cipher_suite());

            assert_eq!(ratchet_data, case.ratchets);
        }
    }
}
