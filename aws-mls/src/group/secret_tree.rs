use crate::client::MlsError;
use crate::serde_utils::vec_u8_as_base64::VecAsBase64;
use crate::tree_kem::math as tree_math;
use crate::tree_kem::node::{LeafIndex, NodeIndex};
use crate::CipherSuiteProvider;
use alloc::string::{String, ToString};
use alloc::vec;
use alloc::vec::Vec;
use core::ops::{Deref, DerefMut};
use serde_with::serde_as;
use zeroize::Zeroizing;

#[cfg(feature = "std")]
use std::collections::HashMap;

#[cfg(not(feature = "std"))]
use alloc::collections::BTreeMap;

use super::key_schedule::kdf_expand_with_label;

pub(crate) const MAX_RATCHET_BACK_HISTORY: u32 = 1024;

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
#[derive(Clone, Debug, PartialEq, serde::Deserialize, serde::Serialize)]
struct TreeSecret(#[serde_as(as = "VecAsBase64")] Zeroizing<Vec<u8>>);

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
        TreeSecret(Zeroizing::new(vec))
    }
}

impl From<Zeroizing<Vec<u8>>> for TreeSecret {
    fn from(vec: Zeroizing<Vec<u8>>) -> Self {
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
    ) -> Result<(), MlsError> {
        self.get_mut(index as usize)
            .ok_or(MlsError::InvalidNodeIndex(index))
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

#[cfg(feature = "external_commit")]
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
    ) -> Result<MessageKeyData, MlsError> {
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
    ) -> Result<MessageKeyData, MlsError> {
        match key_type {
            KeyType::Handshake => self.handshake.next_message_key(cipher_suite_provider),
            KeyType::Application => self.application.next_message_key(cipher_suite_provider),
        }
    }
}

impl SecretTree {
    pub fn new(leaf_count: u32, encryption_secret: Zeroizing<Vec<u8>>) -> SecretTree {
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
    ) -> Result<(), MlsError> {
        if let Some(secret) = self.read_node(index)?.and_then(|n| n.into_secret()) {
            let left_index = tree_math::left(index)?;
            let right_index = tree_math::right(index)?;

            let left_secret =
                kdf_expand_with_label(cipher_suite_provider, &secret, "tree", b"left", None)
                    .map_err(|e| MlsError::CryptoProviderError(e.into()))?;

            let right_secret =
                kdf_expand_with_label(cipher_suite_provider, &secret, "tree", b"right", None)
                    .map_err(|e| MlsError::CryptoProviderError(e.into()))?;

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

    fn read_node(&self, index: NodeIndex) -> Result<Option<SecretTreeNode>, MlsError> {
        Ok(self.known_secrets.get_secret(index))
    }

    fn write_node(
        &mut self,
        index: NodeIndex,
        value: Option<SecretTreeNode>,
    ) -> Result<(), MlsError> {
        self.known_secrets.replace_node(index, value)
    }

    // Start at the root node and work your way down consuming any intermediates needed
    fn leaf_secret_ratchets<P: CipherSuiteProvider>(
        &mut self,
        cipher_suite_provider: &P,
        leaf_index: LeafIndex,
    ) -> Result<SecretRatchets, MlsError> {
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
            .ok_or(MlsError::InvalidLeafConsumption)?;

        self.write_node(leaf_index.into(), None)?;

        Ok(SecretRatchets {
            application: SecretKeyRatchet::new(
                cipher_suite_provider,
                &secret,
                KeyType::Application,
            )?,
            handshake: SecretKeyRatchet::new(cipher_suite_provider, &secret, KeyType::Handshake)?,
        })
    }

    pub fn next_message_key<P: CipherSuiteProvider>(
        &mut self,
        cipher_suite_provider: &P,
        leaf_index: LeafIndex,
        key_type: KeyType,
    ) -> Result<MessageKeyData, MlsError> {
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
    ) -> Result<MessageKeyData, MlsError> {
        self.message_key(cipher_suite_provider, leaf_index, |ratchet| {
            ratchet.message_key_generation(cipher_suite_provider, generation, key_type)
        })
    }

    fn message_key<T, F, P>(
        &mut self,
        cipher_suite_provider: &P,
        leaf_index: LeafIndex,
        mut op: F,
    ) -> Result<T, MlsError>
    where
        F: FnMut(&mut SecretRatchets) -> Result<T, MlsError>,
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
#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
/// AEAD key derived by the MLS secret tree.
pub struct MessageKeyData {
    #[serde_as(as = "VecAsBase64")]
    pub(crate) nonce: Zeroizing<Vec<u8>>,
    #[serde_as(as = "VecAsBase64")]
    pub(crate) key: Zeroizing<Vec<u8>>,
    pub(crate) generation: u32,
}

impl MessageKeyData {
    /// AEAD nonce.
    #[cfg_attr(not(feature = "secret_tree_access"), allow(dead_code))]
    pub fn nonce(&self) -> &[u8] {
        &self.nonce
    }

    /// AEAD key.
    #[cfg_attr(not(feature = "secret_tree_access"), allow(dead_code))]
    pub fn key(&self) -> &[u8] {
        &self.key
    }

    /// Generation of this key within the key schedule.
    #[cfg_attr(not(feature = "secret_tree_access"), allow(dead_code))]
    pub fn generation(&self) -> u32 {
        self.generation
    }
}

#[serde_as]
#[derive(Debug, Clone, PartialEq, serde::Deserialize, serde::Serialize)]
pub struct SecretKeyRatchet {
    secret: TreeSecret,
    #[cfg(feature = "std")]
    #[serde_as(as = "Vec<(_,_)>")]
    history: HashMap<u32, MessageKeyData>,
    #[cfg(not(feature = "std"))]
    #[serde_as(as = "Vec<(_,_)>")]
    history: BTreeMap<u32, MessageKeyData>,
    generation: u32,
}

impl SecretKeyRatchet {
    fn new<P: CipherSuiteProvider>(
        cipher_suite_provider: &P,
        secret: &[u8],
        key_type: KeyType,
    ) -> Result<Self, MlsError> {
        let secret = kdf_expand_with_label(
            cipher_suite_provider,
            secret,
            &key_type.to_string(),
            &[],
            None,
        )
        .map_err(|e| MlsError::CryptoProviderError(e.into()))?;

        Ok(Self {
            secret: TreeSecret::from(secret),
            generation: 0,
            history: Default::default(),
        })
    }

    fn get_message_key<P: CipherSuiteProvider>(
        &mut self,
        cipher_suite_provider: &P,
        generation: u32,
    ) -> Result<MessageKeyData, MlsError> {
        if generation < self.generation {
            self.history
                .remove_entry(&generation)
                .map(|(_, mk)| mk)
                .ok_or(MlsError::KeyMissing(generation))
        } else {
            let max_generation_allowed = self.generation + MAX_RATCHET_BACK_HISTORY;

            if generation > max_generation_allowed {
                return Err(MlsError::InvalidFutureGeneration(
                    generation,
                    max_generation_allowed,
                ));
            }

            while self.generation < generation {
                let key_data = self.next_message_key(cipher_suite_provider)?;
                self.history.insert(key_data.generation, key_data);
            }

            self.next_message_key(cipher_suite_provider)
        }
    }

    fn next_message_key<P: CipherSuiteProvider>(
        &mut self,
        cipher_suite_provider: &P,
    ) -> Result<MessageKeyData, MlsError> {
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
            generation,
        };

        self.secret = TreeSecret::from(self.derive_secret(
            cipher_suite_provider,
            "secret",
            cipher_suite_provider.kdf_extract_size(),
        )?);

        self.generation = generation + 1;

        Ok(key)
    }

    fn derive_secret<P: CipherSuiteProvider>(
        &self,
        cipher_suite_provider: &P,
        label: &str,
        len: usize,
    ) -> Result<Zeroizing<Vec<u8>>, MlsError> {
        kdf_expand_with_label(
            cipher_suite_provider,
            self.secret.as_ref(),
            label,
            &self.generation.to_be_bytes(),
            Some(len),
        )
        .map_err(|e| MlsError::CryptoProviderError(e.into()))
    }
}

#[cfg(test)]
pub(crate) mod test_utils {
    use alloc::{string::String, vec::Vec};
    use aws_mls_core::crypto::CipherSuiteProvider;
    use zeroize::Zeroizing;

    use crate::{crypto::test_utils::try_test_cipher_suite_provider, tree_kem};

    use super::{KeyType, SecretKeyRatchet, SecretTree};

    pub(crate) fn get_test_tree(secret: Vec<u8>, leaf_count: u32) -> SecretTree {
        SecretTree::new(leaf_count, Zeroizing::new(secret))
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

    #[derive(Debug, serde::Serialize, serde::Deserialize)]
    pub struct RatchetInteropTestCase {
        #[serde(with = "hex::serde")]
        secret: Vec<u8>,
        label: String,
        generation: u32,
        length: usize,
        #[serde(with = "hex::serde")]
        out: Vec<u8>,
    }

    #[derive(Debug, serde::Serialize, serde::Deserialize)]
    pub struct InteropTestCase {
        cipher_suite: u16,
        derive_tree_secret: RatchetInteropTestCase,
    }

    #[test]
    fn test_basic_crypto_test_vectors() {
        let test_cases: Vec<InteropTestCase> =
            load_test_cases!(basic_crypto, Vec::<InteropTestCase>::new());

        test_cases.into_iter().for_each(|test_case| {
            if let Some(cs) = try_test_cipher_suite_provider(test_case.cipher_suite) {
                test_case.derive_tree_secret.verify(&cs)
            }
        })
    }

    impl RatchetInteropTestCase {
        pub fn verify<P: CipherSuiteProvider>(&self, cs: &P) {
            let mut ratchet =
                SecretKeyRatchet::new(cs, &self.secret, KeyType::Application).unwrap();

            ratchet.secret = self.secret.clone().into();
            ratchet.generation = self.generation;
            let computed = ratchet.derive_secret(cs, &self.label, self.length).unwrap();

            assert_eq!(&computed.to_vec(), &self.out);
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        cipher_suite::CipherSuite,
        client::test_utils::TEST_CIPHER_SUITE,
        crypto::test_utils::{
            test_cipher_suite_provider, try_test_cipher_suite_provider, TestCryptoProvider,
        },
        group::{ciphertext_processor::InteropSenderData, test_utils::random_bytes},
    };

    use super::{test_utils::get_test_tree, *};

    use assert_matches::assert_matches;

    #[cfg(target_arch = "wasm32")]
    use wasm_bindgen_test::wasm_bindgen_test as test;

    #[test]
    fn test_secret_tree() {
        for cipher_suite in TestCryptoProvider::all_supported_cipher_suites() {
            let cs_provider = test_cipher_suite_provider(cipher_suite);

            let test_secret = vec![0u8; cs_provider.kdf_extract_size()];

            let mut test_tree = get_test_tree(test_secret.clone(), 16);

            let mut secrets: Vec<SecretRatchets> = (0..16)
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
            let provider = test_cipher_suite_provider(cipher_suite);

            let mut app_ratchet = SecretKeyRatchet::new(
                &provider,
                &vec![0u8; provider.kdf_extract_size()],
                KeyType::Application,
            )
            .unwrap();

            let mut handshake_ratchet = SecretKeyRatchet::new(
                &provider,
                &vec![0u8; provider.kdf_extract_size()],
                KeyType::Handshake,
            )
            .unwrap();

            let app_keys: Vec<MessageKeyData> = vec![
                app_ratchet.next_message_key(&provider).unwrap(),
                app_ratchet.next_message_key(&provider).unwrap(),
            ];

            let handshake_keys: Vec<MessageKeyData> = vec![
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
            let provider = test_cipher_suite_provider(cipher_suite);

            let mut ratchet = SecretKeyRatchet::new(
                &test_cipher_suite_provider(cipher_suite),
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

            assert_eq!(clone_2, second_key)
        }
    }

    #[test]
    fn test_secret_ratchet() {
        for cipher_suite in TestCryptoProvider::all_supported_cipher_suites() {
            let provider = test_cipher_suite_provider(cipher_suite);

            let mut ratchet = SecretKeyRatchet::new(
                &provider,
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

        let mut ratchet = SecretKeyRatchet::new(&provider, &[0u8; 32], KeyType::Handshake).unwrap();
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

        let mut ratchet = SecretKeyRatchet::new(&provider, &[0u8; 32], KeyType::Handshake).unwrap();

        let res = ratchet.get_message_key(&provider, MAX_RATCHET_BACK_HISTORY + 1);
        let invalid_generation = MAX_RATCHET_BACK_HISTORY + 1;

        assert_matches!(
            res,
            Err(MlsError::InvalidFutureGeneration(
                invalid,
                expected
            ))
            if invalid == invalid_generation && expected == MAX_RATCHET_BACK_HISTORY
        )
    }

    #[derive(Debug, PartialEq, serde::Serialize, serde::Deserialize)]
    struct Ratchet {
        application_keys: Vec<MessageKeyData>,
        handshake_keys: Vec<MessageKeyData>,
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

                let mut secret_tree =
                    SecretTree::new(16, Zeroizing::new(encryption_secret.clone()));

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

            let mut secret_tree = SecretTree::new(16, Zeroizing::new(case.encryption_secret));
            let ratchet_data = get_ratchet_data(&mut secret_tree, cs_provider.cipher_suite());

            assert_eq!(ratchet_data, case.ratchets);
        }
    }

    #[test]
    fn interop_test_vector() {
        // The test vector can be found here https://github.com/mlswg/mls-implementations/blob/main/test-vectors/secret-tree.json
        let test_cases = load_interop_test_cases();

        for case in test_cases {
            let Some(cs) = try_test_cipher_suite_provider(case.cipher_suite) else {
                continue;
            };

            case.sender_data.verify(&cs);

            let mut tree = SecretTree::new(
                case.leaves.len() as u32,
                Zeroizing::new(case.encryption_secret),
            );

            for (index, leaves) in case.leaves.iter().enumerate() {
                for leaf in leaves.iter() {
                    let key = tree
                        .message_key_generation(
                            &cs,
                            LeafIndex(index as u32),
                            KeyType::Application,
                            leaf.generation,
                        )
                        .unwrap();

                    assert_eq!(key.key.to_vec(), leaf.application_key);
                    assert_eq!(key.nonce.to_vec(), leaf.application_nonce);

                    let key = tree
                        .message_key_generation(
                            &cs,
                            LeafIndex(index as u32),
                            KeyType::Handshake,
                            leaf.generation,
                        )
                        .unwrap();

                    assert_eq!(key.key.to_vec(), leaf.handshake_key);
                    assert_eq!(key.nonce.to_vec(), leaf.handshake_nonce);
                }
            }
        }
    }

    #[derive(Debug, serde::Serialize, serde::Deserialize)]
    struct InteropTestCase {
        cipher_suite: u16,
        #[serde(with = "hex::serde")]
        encryption_secret: Vec<u8>,
        sender_data: InteropSenderData,
        leaves: Vec<Vec<InteropLeaf>>,
    }

    #[derive(Debug, serde::Serialize, serde::Deserialize)]
    struct InteropLeaf {
        generation: u32,
        #[serde(with = "hex::serde")]
        application_key: Vec<u8>,
        #[serde(with = "hex::serde")]
        application_nonce: Vec<u8>,
        #[serde(with = "hex::serde")]
        handshake_key: Vec<u8>,
        #[serde(with = "hex::serde")]
        handshake_nonce: Vec<u8>,
    }

    fn load_interop_test_cases() -> Vec<InteropTestCase> {
        load_test_cases!(secret_tree_interop, generate_interop_test_vectors())
    }

    fn generate_interop_test_vectors() -> Vec<InteropTestCase> {
        let mut test_cases = vec![];

        for cs in CipherSuite::all() {
            let Some(cs) = try_test_cipher_suite_provider(*cs) else {
                continue;
            };

            let gens = [0, 15];
            let tree_sizes = [1, 8, 32];

            for n_leaves in tree_sizes {
                let encryption_secret = cs.random_bytes_vec(cs.kdf_extract_size()).unwrap();

                let mut tree = SecretTree::new(n_leaves, Zeroizing::new(encryption_secret.clone()));

                let leaves = (0..n_leaves)
                    .map(|leaf| {
                        gens.into_iter()
                            .map(|gen| {
                                let index = LeafIndex(leaf);

                                let handshake_key = tree
                                    .message_key_generation(&cs, index, KeyType::Handshake, gen)
                                    .unwrap();

                                let app_key = tree
                                    .message_key_generation(&cs, index, KeyType::Application, gen)
                                    .unwrap();

                                InteropLeaf {
                                    generation: gen,
                                    application_key: app_key.key.to_vec(),
                                    application_nonce: app_key.nonce.to_vec(),
                                    handshake_key: handshake_key.key.to_vec(),
                                    handshake_nonce: handshake_key.nonce.to_vec(),
                                }
                            })
                            .collect()
                    })
                    .collect();

                let case = InteropTestCase {
                    cipher_suite: *cs.cipher_suite(),
                    encryption_secret,
                    sender_data: InteropSenderData::new(&cs),
                    leaves,
                };

                test_cases.push(case);
            }
        }

        test_cases
    }
}
