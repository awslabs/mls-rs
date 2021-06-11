use crate::ciphersuite::{CipherSuiteError, ExpandType};
use crate::group::GroupContext;
use crate::secret_tree::{EncryptionKey, KeyType, SecretKeyRatchet, SecretTree, SecretTreeError};
use crate::tree_kem::node::LeafIndex;
use crate::tree_kem::{TreeSecrets, UpdatePathGeneration};
use cfg_if::cfg_if;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::ops::Deref;
use thiserror::Error;

cfg_if! {
    if #[cfg(test)] {
        use crate::ciphersuite::test_util::MockCipherSuite as CipherSuite;
    } else {
        use crate::ciphersuite::{CipherSuite};
    }
}

#[derive(Error, Debug)]
pub enum EpochKeyScheduleError {
    #[error(transparent)]
    CipherSuiteError(#[from] CipherSuiteError),
    #[error(transparent)]
    SecretTreeError(#[from] SecretTreeError),
    #[error(transparent)]
    BincodeError(#[from] bincode::Error),
    #[error("key derivation failure")]
    KeyDerivationFailure,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct EpochKeySchedule {
    pub cipher_suite: CipherSuite,
    pub secret_tree: SecretTree,
    pub self_index: LeafIndex,
    pub sender_data_secret: Vec<u8>,
    pub exporter_secret: Vec<u8>,
    pub authentication_secret: Vec<u8>,
    pub external_secret: Vec<u8>,
    pub confirmation_key: Vec<u8>,
    pub membership_key: Vec<u8>,
    pub resumption_secret: Vec<u8>,
    pub init_secret: Vec<u8>,
    pub handshake_ratchets: HashMap<LeafIndex, SecretKeyRatchet>,
    pub application_ratchets: HashMap<LeafIndex, SecretKeyRatchet>,
}

impl PartialEq for EpochKeySchedule {
    fn eq(&self, other: &Self) -> bool {
        self.cipher_suite == other.cipher_suite
            && self.sender_data_secret == other.sender_data_secret
            && self.exporter_secret == other.exporter_secret
            && self.authentication_secret == other.authentication_secret
            && self.external_secret == other.external_secret
            && self.confirmation_key == other.confirmation_key
            && self.membership_key == other.membership_key
            && self.resumption_secret == other.resumption_secret
            && self.init_secret == other.init_secret
    }
}

pub(crate) struct EpochKeyScheduleDerivation {
    pub key_schedule: EpochKeySchedule,
    pub joiner_secret: Vec<u8>,
}

impl EpochKeySchedule {
    pub fn derive(
        cipher_suite: CipherSuite,
        last_init: &[u8],
        commit_secret: &[u8],
        num_leaves: usize,
        context: &GroupContext,
        self_index: LeafIndex,
    ) -> Result<EpochKeyScheduleDerivation, EpochKeyScheduleError> {
        let joiner_secret = cipher_suite
            .derive_secret(&cipher_suite.extract(last_init, commit_secret)?, "joiner")?;

        let schedule = Self::new_joiner(
            cipher_suite,
            &joiner_secret,
            num_leaves,
            context,
            self_index,
        )?;

        Ok(EpochKeyScheduleDerivation {
            key_schedule: schedule,
            joiner_secret,
        })
    }

    pub fn evolved_from(
        epoch: &EpochKeySchedule,
        commit_secret: &[u8],
        num_leaves: usize,
        context: &GroupContext,
    ) -> Result<EpochKeyScheduleDerivation, EpochKeyScheduleError> {
        Self::derive(
            epoch.cipher_suite.clone(),
            &epoch.init_secret,
            commit_secret,
            num_leaves,
            context,
            epoch.self_index,
        )
    }

    pub fn new_joiner(
        cipher_suite: CipherSuite,
        joiner_secret: &[u8],
        num_leaves: usize,
        context: &GroupContext,
        self_index: LeafIndex,
    ) -> Result<Self, EpochKeyScheduleError> {
        //TODO: PSK is not supported
        let epoch_seed = cipher_suite.extract(joiner_secret, &[])?;

        let epoch_secret = cipher_suite.expand_with_label(
            &epoch_seed,
            "epoch",
            &bincode::serialize(context)?,
            ExpandType::Secret,
        )?;

        // Derive secrets from epoch secret
        let sender_data_secret = cipher_suite.derive_secret(&epoch_secret, "sender data")?;
        let encryption_secret = cipher_suite.derive_secret(&epoch_secret, "encryption")?;
        let exporter_secret = cipher_suite.derive_secret(&epoch_secret, "exporter")?;
        let authentication_secret = cipher_suite.derive_secret(&epoch_secret, "authentication")?;
        let external_secret = cipher_suite.derive_secret(&epoch_secret, "external")?;
        let confirmation_key = cipher_suite.derive_secret(&epoch_secret, "confirm")?;
        let membership_key = cipher_suite.derive_secret(&epoch_secret, "membership")?;
        let resumption_secret = cipher_suite.derive_secret(&epoch_secret, "resumption")?;

        let init_secret = cipher_suite.derive_secret(&epoch_secret, "init")?;

        let secret_tree = SecretTree::new(cipher_suite.clone(), num_leaves, encryption_secret);

        Ok(Self {
            cipher_suite,
            secret_tree,
            sender_data_secret,
            exporter_secret,
            authentication_secret,
            external_secret,
            confirmation_key,
            membership_key,
            resumption_secret,
            init_secret,
            self_index,
            application_ratchets: Default::default(),
            handshake_ratchets: Default::default(),
        })
    }

    #[inline]
    fn get_ratchet(
        &mut self,
        leaf_index: LeafIndex,
        key_type: &KeyType,
    ) -> Option<&mut SecretKeyRatchet> {
        match key_type {
            KeyType::Handshake => self.handshake_ratchets.get_mut(&leaf_index),
            KeyType::Application => self.application_ratchets.get_mut(&leaf_index),
        }
    }

    #[inline]
    fn derive_ratchets(
        &mut self,
        leaf_index: LeafIndex,
        out_type: &KeyType,
    ) -> Result<&mut SecretKeyRatchet, EpochKeyScheduleError> {
        let ratchets = self.secret_tree.get_leaf_secret_ratchets(leaf_index)?;
        self.application_ratchets
            .insert(leaf_index, ratchets.application);
        self.handshake_ratchets
            .insert(leaf_index, ratchets.handshake);
        self.get_ratchet(leaf_index, out_type)
            .ok_or(EpochKeyScheduleError::KeyDerivationFailure)
    }

    #[inline]
    fn get_key(
        &mut self,
        leaf_index: LeafIndex,
        generation: Option<u32>,
        key_type: &KeyType,
    ) -> Result<EncryptionKey, EpochKeyScheduleError> {
        if let Some(ratchet) = self.get_ratchet(leaf_index, key_type) {
            match generation {
                None => ratchet.next_key(),
                Some(gen) => ratchet.get_key(gen),
            }
            .map_err(|e| e.into())
        } else {
            self.derive_ratchets(leaf_index, key_type)
                .and_then(|r| r.next_key().map_err(|e| e.into()))
        }
    }

    pub fn get_encryption_key(
        &mut self,
        key_type: KeyType,
    ) -> Result<EncryptionKey, EpochKeyScheduleError> {
        self.get_key(self.self_index, None, &key_type)
    }

    pub fn get_decryption_key(
        &mut self,
        sender: LeafIndex,
        generation: u32,
        key_type: KeyType,
    ) -> Result<EncryptionKey, EpochKeyScheduleError> {
        self.get_key(sender, Some(generation), &key_type)
    }

    pub fn get_sender_data_params(
        &self,
        ciphertext: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>), EpochKeyScheduleError> {
        // Sample the first extract_size bytes of the ciphertext, and if it is shorter, just use
        // the ciphertext itself
        let ciphertext_sample = if ciphertext.len() <= self.cipher_suite.extract_size() as usize {
            ciphertext
        } else {
            ciphertext
                .get(0..self.cipher_suite.extract_size() as usize)
                .unwrap()
        };

        // Generate a sender data key and nonce using the sender_data_secret from the current
        // epoch's key schedule
        let sender_data_key = self.cipher_suite.expand_with_label(
            &self.sender_data_secret,
            "key",
            ciphertext_sample,
            ExpandType::AeadKey,
        )?;

        let sender_data_nonce = self.cipher_suite.expand_with_label(
            &self.sender_data_secret,
            "nonce",
            ciphertext_sample,
            ExpandType::AeadNonce,
        )?;

        Ok((sender_data_key, sender_data_nonce))
    }
}

pub struct CommitSecret(Vec<u8>);

impl Deref for CommitSecret {
    type Target = Vec<u8>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl CommitSecret {
    // Define commit_secret as the value path_secret[n+1] derived from the path_secret[n] value
    // assigned to the root node.
    pub fn from_update_path(
        cipher_suite: &CipherSuite,
        update_path: Option<&UpdatePathGeneration>,
    ) -> Result<Self, CipherSuiteError> {
        Self::from_tree_secrets(cipher_suite, update_path.map(|up| &up.secrets))
    }

    pub fn from_tree_secrets(
        cipher_suite: &CipherSuite,
        secrets: Option<&TreeSecrets>,
    ) -> Result<Self, CipherSuiteError> {
        match secrets {
            Some(secrets) => {
                let secret =
                    cipher_suite.derive_secret(&secrets.secret_path.root_secret, "path")?;
                Ok(CommitSecret(secret))
            }
            None => Ok(Self::empty(cipher_suite)),
        }
    }

    pub fn empty(cipher_suite: &CipherSuite) -> Self {
        // Define commit_secret as the all-zero vector of the same length as a path_secret
        // value would be
        CommitSecret(vec![0u8; cipher_suite.extract_size() as usize])
    }
}

pub struct WelcomeSecret(Vec<u8>);

impl Deref for WelcomeSecret {
    type Target = Vec<u8>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl WelcomeSecret {
    pub fn from_joiner_secret(
        cipher_suite: &CipherSuite,
        joiner_secret: &[u8],
    ) -> Result<WelcomeSecret, CipherSuiteError> {
        //TODO: PSK is not supported
        let epoch_seed = cipher_suite.extract(joiner_secret, &[])?;

        cipher_suite.derive_secret(&epoch_seed, "welcome").map(Self)
    }

    pub(crate) fn as_nonce(&self, cipher_suite: &CipherSuite) -> Result<Vec<u8>, CipherSuiteError> {
        cipher_suite.expand(self, b"nonce", ExpandType::AeadNonce)
    }

    pub(crate) fn as_key(&self, cipher_suite: &CipherSuite) -> Result<Vec<u8>, CipherSuiteError> {
        cipher_suite.expand(self, b"key", ExpandType::AeadKey)
    }

    pub fn encrypt(
        &self,
        cipher_suite: &CipherSuite,
        plaintext: &[u8],
    ) -> Result<Vec<u8>, CipherSuiteError> {
        let key = self.as_key(cipher_suite)?;
        let nonce = self.as_nonce(cipher_suite)?;
        cipher_suite.aead_encrypt(key, plaintext, &[], &nonce)
    }

    pub fn decrypt(
        &self,
        cipher_suite: &CipherSuite,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, CipherSuiteError> {
        let key = self.as_key(cipher_suite)?;
        let nonce = self.as_nonce(cipher_suite)?;
        cipher_suite.aead_decrypt(key, ciphertext, &[], &nonce)
    }
}

//TODO: Unit tests

#[cfg(test)]
pub mod test_utils {
    use super::*;
    use crate::secret_tree::test::get_test_tree;

    pub(crate) fn get_test_epoch_key_schedule(
        cipher_suite: CipherSuite,
        membership_key: Vec<u8>,
        confirmation_key: Vec<u8>,
    ) -> EpochKeySchedule {
        EpochKeySchedule {
            cipher_suite,
            secret_tree: get_test_tree(vec![], 1),
            self_index: LeafIndex(0),
            sender_data_secret: vec![],
            exporter_secret: vec![],
            authentication_secret: vec![],
            external_secret: vec![],
            confirmation_key,
            membership_key,
            resumption_secret: vec![],
            init_secret: vec![],
            handshake_ratchets: Default::default(),
            application_ratchets: Default::default(),
        }
    }
}
