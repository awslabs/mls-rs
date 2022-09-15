use crate::cipher_suite::CipherSuite;
use crate::group::key_schedule::{KeyScheduleKdf, KeyScheduleKdfError};
use crate::serde_utils::vec_u8_as_base64::VecAsBase64;
use crate::tree_kem::math as tree_math;
use crate::tree_kem::math::TreeMathError;
use crate::tree_kem::node::{LeafIndex, NodeIndex};
use ferriscrypt::cipher::aead::{AeadError, AeadNonce, Key};
use ferriscrypt::cipher::NonceError;
use serde_with::serde_as;
use std::collections::HashMap;
use std::ops::{Deref, DerefMut};
use thiserror::Error;
use tls_codec_derive::{TlsDeserialize, TlsSerialize, TlsSize};
use zeroize::Zeroize;

pub(crate) const MAX_RATCHET_BACK_HISTORY: u32 = 1024;

#[derive(Error, Debug)]
pub enum SecretTreeError {
    #[error(transparent)]
    TreeMathError(#[from] TreeMathError),
    #[error(transparent)]
    KeyScheduleKdfError(#[from] KeyScheduleKdfError),
    #[error(transparent)]
    AeadError(#[from] AeadError),
    #[error(transparent)]
    NonceError(#[from] NonceError),
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
}

#[derive(
    Clone,
    Debug,
    PartialEq,
    TlsDeserialize,
    TlsSerialize,
    TlsSize,
    serde::Deserialize,
    serde::Serialize,
)]
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
#[derive(
    Clone,
    Debug,
    PartialEq,
    TlsDeserialize,
    TlsSerialize,
    TlsSize,
    serde::Deserialize,
    serde::Serialize,
)]
struct TreeSecret(
    #[tls_codec(with = "crate::tls::ByteVec")]
    #[serde_as(as = "VecAsBase64")]
    Vec<u8>,
);

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

#[derive(
    Clone,
    Debug,
    PartialEq,
    TlsDeserialize,
    TlsSerialize,
    TlsSize,
    serde::Deserialize,
    serde::Serialize,
)]
struct TreeSecretsVec(
    #[tls_codec(with = "crate::tls::Vector::<crate::tls::Optional<crate::tls::DefaultSer>>")]
    Vec<Option<SecretTreeNode>>,
);

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

#[derive(
    Clone,
    Debug,
    PartialEq,
    TlsDeserialize,
    TlsSerialize,
    TlsSize,
    serde::Deserialize,
    serde::Serialize,
)]
pub struct SecretTree {
    cipher_suite: CipherSuite,
    known_secrets: TreeSecretsVec,
    leaf_count: u32,
}

impl SecretTree {
    pub(crate) fn empty(cipher_suite: CipherSuite) -> SecretTree {
        SecretTree {
            cipher_suite,
            known_secrets: TreeSecretsVec(vec![]),
            leaf_count: 0,
        }
    }
}

#[derive(TlsDeserialize, TlsSerialize, TlsSize)]
struct TreeContext {
    node: u32,
    generation: u32,
}

#[derive(
    Clone,
    Debug,
    PartialEq,
    TlsDeserialize,
    TlsSerialize,
    TlsSize,
    serde::Deserialize,
    serde::Serialize,
)]
pub struct SecretRatchets {
    pub application: SecretKeyRatchet,
    pub handshake: SecretKeyRatchet,
}

impl SecretRatchets {
    pub fn get_message_key(
        &mut self,
        generation: u32,
        key_type: KeyType,
    ) -> Result<MessageKey, SecretTreeError> {
        match key_type {
            KeyType::Handshake => self.handshake.get_message_key(generation),
            KeyType::Application => self.application.get_message_key(generation),
        }
    }

    pub fn next_message_key(&mut self, key_type: KeyType) -> Result<MessageKey, SecretTreeError> {
        match key_type {
            KeyType::Handshake => self.handshake.next_message_key(),
            KeyType::Application => self.application.next_message_key(),
        }
    }
}

impl SecretTree {
    pub fn new(
        cipher_suite: CipherSuite,
        leaf_count: u32,
        encryption_secret: Vec<u8>,
    ) -> SecretTree {
        let mut known_secrets = TreeSecretsVec(vec![None; (leaf_count * 2 - 1) as usize]);
        known_secrets[tree_math::root(leaf_count) as usize] =
            Some(SecretTreeNode::Secret(TreeSecret::from(encryption_secret)));

        Self {
            cipher_suite,
            known_secrets,
            leaf_count,
        }
    }

    fn consume_node(&mut self, index: NodeIndex) -> Result<(), SecretTreeError> {
        let kdf = KeyScheduleKdf::new(self.cipher_suite.kdf_type());

        if let Some(secret) = self.read_node(index)?.and_then(|n| n.into_secret()) {
            let left_index = tree_math::left(index)?;
            let right_index = tree_math::right(index)?;

            let left_secret = TreeSecret::from(kdf.expand_with_label(
                &secret,
                "tree",
                b"left",
                kdf.extract_size(),
            )?);

            let right_secret = TreeSecret::from(kdf.expand_with_label(
                &secret,
                "tree",
                b"right",
                kdf.extract_size(),
            )?);

            self.write_node(left_index, Some(SecretTreeNode::Secret(left_secret)))?;
            self.write_node(right_index, Some(SecretTreeNode::Secret(right_secret)))?;
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
    fn get_leaf_secret_ratchets(
        &mut self,
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
            .try_for_each(|&i| self.consume_node(i))?;

        let secret = self
            .read_node(leaf_index.into())?
            .and_then(|n| n.into_secret())
            .ok_or(SecretTreeError::InvalidLeafConsumption)?;

        self.write_node(leaf_index.into(), None)?;

        Ok(SecretRatchets {
            application: SecretKeyRatchet::new(
                self.cipher_suite,
                leaf_index,
                &secret,
                KeyType::Application,
            )?,
            handshake: SecretKeyRatchet::new(
                self.cipher_suite,
                leaf_index,
                &secret,
                KeyType::Handshake,
            )?,
        })
    }

    pub fn get_message_key(
        &mut self,
        leaf_index: LeafIndex,
        key_type: KeyType,
        generation: Option<u32>,
    ) -> Result<MessageKey, SecretTreeError> {
        let mut ratchet = self.get_leaf_secret_ratchets(leaf_index)?;

        let message_key = if let Some(generation) = generation {
            ratchet.get_message_key(generation, key_type)?
        } else {
            ratchet.next_message_key(key_type)?
        };

        self.write_node(leaf_index.into(), Some(SecretTreeNode::Ratchet(ratchet)))?;

        Ok(message_key)
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct MessageKey {
    nonce: AeadNonce,
    key: Key,
    pub generation: u32,
}

impl MessageKey {
    fn from_derived(
        cipher_suite: CipherSuite,
        derived_key: DerivedKey,
        generation: u32,
    ) -> Result<MessageKey, SecretTreeError> {
        let nonce = AeadNonce::try_from(derived_key.nonce.clone())?;
        let key = Key::new(cipher_suite.aead_type(), derived_key.key.clone())?;

        Ok(MessageKey {
            nonce,
            key,
            generation,
        })
    }

    fn reuse_safe_nonce(&self, reuse_guard: &[u8; 4]) -> AeadNonce {
        let mut data: Vec<u8> = self
            .nonce
            .iter()
            .zip(reuse_guard.iter())
            .map(|(nonce_byte, &guard_byte)| nonce_byte ^ guard_byte)
            .collect();

        data.append(&mut self.nonce[reuse_guard.len()..self.nonce.len()].to_vec());

        AeadNonce::new(&data).unwrap()
    }

    pub fn encrypt(
        &self,
        data: &[u8],
        aad: &[u8],
        reuse_guard: &[u8; 4],
    ) -> Result<Vec<u8>, AeadError> {
        self.key
            .encrypt_to_vec(data, Some(aad), self.reuse_safe_nonce(reuse_guard))
    }

    pub fn decrypt(
        &self,
        data: &[u8],
        aad: &[u8],
        reuse_guard: &[u8; 4],
    ) -> Result<Vec<u8>, AeadError> {
        self.key
            .decrypt_from_vec(data, Some(aad), self.reuse_safe_nonce(reuse_guard))
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
#[derive(
    Debug,
    Clone,
    PartialEq,
    TlsSize,
    TlsSerialize,
    TlsDeserialize,
    Zeroize,
    serde::Deserialize,
    serde::Serialize,
)]
#[zeroize(drop)]
struct DerivedKey {
    #[tls_codec(with = "crate::tls::ByteVec")]
    #[serde_as(as = "VecAsBase64")]
    nonce: Vec<u8>,
    #[tls_codec(with = "crate::tls::ByteVec")]
    #[serde_as(as = "VecAsBase64")]
    key: Vec<u8>,
}

#[serde_as]
#[derive(
    Debug,
    Clone,
    PartialEq,
    TlsDeserialize,
    TlsSerialize,
    TlsSize,
    serde::Deserialize,
    serde::Serialize,
)]
pub struct SecretKeyRatchet {
    cipher_suite: CipherSuite,
    secret: TreeSecret,
    #[tls_codec(with = "crate::tls::DefMap")]
    #[serde_as(as = "Vec<(_,_)>")]
    history: HashMap<u32, DerivedKey>,
    node_index: NodeIndex,
    generation: u32,
}

impl SecretKeyRatchet {
    pub fn new(
        cipher_suite: CipherSuite,
        leaf: LeafIndex,
        secret: &[u8],
        key_type: KeyType,
    ) -> Result<Self, SecretTreeError> {
        let kdf = KeyScheduleKdf::new(cipher_suite.kdf_type());

        let node_index = NodeIndex::from(leaf);

        let secret =
            kdf.expand_with_label(secret, &key_type.to_string(), &[], kdf.extract_size())?;

        Ok(Self {
            cipher_suite,
            secret: TreeSecret::from(secret),
            node_index,
            generation: 0,
            history: Default::default(),
        })
    }

    pub fn get_message_key(&mut self, generation: u32) -> Result<MessageKey, SecretTreeError> {
        if generation < self.generation {
            self.history
                .remove_entry(&generation)
                .map(|(gen, dk)| MessageKey::from_derived(self.cipher_suite, dk, gen))
                .transpose()?
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
                let (generation, key) = self.ratchet()?;
                self.history.insert(generation, key);
            }

            self.next_message_key()
        }
    }

    pub fn next_message_key(&mut self) -> Result<MessageKey, SecretTreeError> {
        self.ratchet().map(|(generation, derived_key)| {
            MessageKey::from_derived(self.cipher_suite, derived_key, generation)
        })?
    }

    fn ratchet(&mut self) -> Result<(u32, DerivedKey), SecretTreeError> {
        let kdf = KeyScheduleKdf::new(self.cipher_suite.kdf_type());

        let generation = self.generation;

        let key = kdf.derive_tree_secret(
            &self.secret,
            "key",
            self.node_index as u32,
            generation,
            self.cipher_suite.aead_type().key_size(),
        )?;

        let nonce = kdf.derive_tree_secret(
            &self.secret,
            "nonce",
            self.node_index as u32,
            generation,
            self.cipher_suite.aead_type().nonce_size(),
        )?;

        let key = DerivedKey { nonce, key };

        self.secret = TreeSecret::from(kdf.derive_tree_secret(
            &self.secret,
            "secret",
            self.node_index as u32,
            generation,
            kdf.extract_size(),
        )?);

        self.generation = generation + 1;

        Ok((generation, key))
    }
}

#[cfg(test)]
pub(crate) mod test_utils {
    use super::SecretTree;
    use crate::cipher_suite::CipherSuite;

    pub(crate) fn get_test_tree(
        cipher_suite: CipherSuite,
        secret: Vec<u8>,
        leaf_count: u32,
    ) -> SecretTree {
        SecretTree::new(cipher_suite, leaf_count, secret)
    }
}

#[cfg(test)]
mod tests {
    use super::{test_utils::get_test_tree, *};

    use assert_matches::assert_matches;
    use ferriscrypt::rand::SecureRng;

    use num_enum::TryFromPrimitive;
    #[cfg(target_arch = "wasm32")]
    use wasm_bindgen_test::wasm_bindgen_test as test;

    #[test]
    fn test_secret_tree() {
        for one_cipher_suite in CipherSuite::all() {
            println!("Running secret tree derivation for {:?}", one_cipher_suite);

            let test_secret = [0u8; 32].to_vec();
            let mut test_tree = get_test_tree(one_cipher_suite, test_secret.clone(), 16);

            let mut secrets: Vec<SecretRatchets> = (0..16)
                .into_iter()
                .map(|i| test_tree.get_leaf_secret_ratchets(LeafIndex(i)).unwrap())
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
        for one_cipher_suite in CipherSuite::all() {
            println!("Running secret tree ratchet for {:?}", one_cipher_suite);

            let mut app_ratchet = SecretKeyRatchet::new(
                one_cipher_suite,
                LeafIndex(42),
                &[0u8; 32],
                KeyType::Application,
            )
            .unwrap();

            let mut handshake_ratchet = SecretKeyRatchet::new(
                one_cipher_suite,
                LeafIndex(42),
                &[0u8; 32],
                KeyType::Handshake,
            )
            .unwrap();

            let app_keys: Vec<MessageKey> = vec![
                app_ratchet.next_message_key().unwrap(),
                app_ratchet.next_message_key().unwrap(),
            ];

            let handshake_keys: Vec<MessageKey> = vec![
                handshake_ratchet.next_message_key().unwrap(),
                handshake_ratchet.next_message_key().unwrap(),
            ];

            // Verify that the keys have different outcomes due to their different labels
            assert_ne!(app_keys, handshake_keys);

            // Verify that the keys at each generation are different
            assert_ne!(handshake_keys[0], handshake_keys[1]);
        }
    }

    #[test]
    fn test_get_key() {
        for one_cipher_suite in CipherSuite::all() {
            println!("Running secret tree get key for {:?}", one_cipher_suite);

            let mut ratchet = SecretKeyRatchet::new(
                one_cipher_suite,
                LeafIndex(42),
                &[0u8; 32],
                KeyType::Application,
            )
            .unwrap();

            let mut ratchet_clone = ratchet.clone();

            // This will generate keys 0 and 1 in ratchet_clone
            let _ = ratchet_clone.next_message_key().unwrap();
            let clone_2 = ratchet_clone.next_message_key().unwrap();

            // Going back in time should result in an error
            assert!(ratchet_clone.get_message_key(0).is_err());

            // Calling get key should be the same as calling next until hitting the desired generation
            let second_key = ratchet
                .get_message_key(ratchet_clone.generation - 1)
                .unwrap();

            assert_eq!(second_key.generation, ratchet_clone.generation - 1);
            assert_eq!(clone_2, second_key)
        }
    }

    #[test]
    fn test_secret_ratchet() {
        for one_cipher_suite in CipherSuite::all() {
            println!("Running secret tree secret ratchet {:?}", one_cipher_suite);

            let mut ratchet = SecretKeyRatchet::new(
                one_cipher_suite,
                LeafIndex(42),
                &[0u8; 32],
                KeyType::Application,
            )
            .unwrap();

            let original_secret = ratchet.secret.clone();
            let _ = ratchet.next_message_key().unwrap();
            let new_secret = ratchet.secret;
            assert_ne!(original_secret, new_secret)
        }
    }

    #[test]
    fn test_out_of_order_keys() {
        let cipher_suite = CipherSuite::Curve25519Aes128;

        let mut ratchet =
            SecretKeyRatchet::new(cipher_suite, LeafIndex(42), &[0u8; 32], KeyType::Handshake)
                .unwrap();

        let mut ratchet_clone = ratchet.clone();

        // Ask for all the keys in order from the original ratchet
        let ordered_keys = (0..=MAX_RATCHET_BACK_HISTORY)
            .map(|i| ratchet.get_message_key(i).unwrap())
            .collect::<Vec<MessageKey>>();

        // Ask for a key at index MAX_RATCHET_BACK_HISTORY in the clone
        let last_key = ratchet_clone
            .get_message_key(MAX_RATCHET_BACK_HISTORY)
            .unwrap();

        assert_eq!(last_key, ordered_keys[ordered_keys.len() - 1]);

        // Get all the other keys
        let back_history_keys = (0..MAX_RATCHET_BACK_HISTORY - 1)
            .map(|i| ratchet_clone.get_message_key(i).unwrap())
            .collect::<Vec<MessageKey>>();

        assert_eq!(
            back_history_keys,
            ordered_keys[..(MAX_RATCHET_BACK_HISTORY as usize) - 1]
        );
    }

    #[test]
    fn test_too_out_of_order() {
        let cipher_suite = CipherSuite::Curve25519Aes128;

        let mut ratchet =
            SecretKeyRatchet::new(cipher_suite, LeafIndex(42), &[0u8; 32], KeyType::Handshake)
                .unwrap();

        let res = ratchet.get_message_key(MAX_RATCHET_BACK_HISTORY + 1);
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
    struct KeyData {
        #[serde(with = "hex::serde")]
        nonce: Vec<u8>,
        #[serde(with = "hex::serde")]
        key: Vec<u8>,
        generation: u32,
    }

    impl From<MessageKey> for KeyData {
        fn from(key: MessageKey) -> Self {
            KeyData {
                nonce: key.nonce.to_vec(),
                key: key.key.as_ref().to_vec(),
                generation: key.generation,
            }
        }
    }

    #[derive(Debug, PartialEq, serde::Serialize, serde::Deserialize)]
    struct Ratchet {
        application_keys: Vec<KeyData>,
        handshake_keys: Vec<KeyData>,
    }

    #[derive(Debug, serde::Serialize, serde::Deserialize)]
    struct TestCase {
        cipher_suite: u16,
        #[serde(with = "hex::serde")]
        encryption_secret: Vec<u8>,
        ratchets: Vec<Ratchet>,
    }

    fn get_ratchet_data(secret_tree: &mut SecretTree) -> Vec<Ratchet> {
        (0..16)
            .map(|index| {
                let mut ratchets = secret_tree
                    .get_leaf_secret_ratchets(LeafIndex(index))
                    .unwrap();

                let application_keys = (0..20)
                    .map(|_| KeyData::from(ratchets.application.next_message_key().unwrap()))
                    .collect();

                let handshake_keys = (0..20)
                    .map(|_| KeyData::from(ratchets.handshake.next_message_key().unwrap()))
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
                let kdf = KeyScheduleKdf::new(cipher_suite.kdf_type());
                let encryption_secret = SecureRng::gen(kdf.extract_size()).unwrap();

                let mut secret_tree = SecretTree::new(cipher_suite, 16, encryption_secret.clone());
                TestCase {
                    cipher_suite: cipher_suite as u16,
                    encryption_secret,
                    ratchets: get_ratchet_data(&mut secret_tree),
                }
            })
            .collect()
    }

    fn load_test_cases() -> Vec<TestCase> {
        load_test_cases!(secret_tree, generate_secret_tree_test_vectors)
    }

    #[test]
    fn test_secret_tree_test_vectors() {
        let test_cases = load_test_cases();

        for case in test_cases {
            let cipher_suite = CipherSuite::try_from_primitive(case.cipher_suite);

            if cipher_suite.is_err() {
                println!("Skipping test case due to unsupported cipher suite");
                continue;
            }

            let mut secret_tree =
                SecretTree::new(cipher_suite.unwrap(), 16, case.encryption_secret);

            let ratchet_data = get_ratchet_data(&mut secret_tree);

            assert_eq!(ratchet_data, case.ratchets);
            assert_eq!(secret_tree.cipher_suite as u16, case.cipher_suite);
        }
    }
}
