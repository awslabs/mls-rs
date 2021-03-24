use crate::secret_tree::{SecretTree, KeyType, SecretKeyRatchet, EncryptionKey, SecretTreeError};
use serde::{Serialize, Deserialize};
use thiserror::Error;
use cfg_if::cfg_if;
use crate::ciphersuite::{CipherSuiteError, ExpandType};
use crate::tree_node::LeafIndex;
use std::collections::HashMap;
use crate::group::GroupContext;
use std::ops::Deref;
use crate::ratchet_tree::{UpdatePathGeneration, TreeSecrets};

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
    KeyDerivationFailure
}

#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
pub struct EpochKeySchedule {
    pub cipher_suite: CipherSuite,
    secret_tree: SecretTree,
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
    pub application_ratchets: HashMap<LeafIndex, SecretKeyRatchet>
}

pub struct EpochKeyScheduleDerivation {
    pub key_schedule: EpochKeySchedule,
    pub joiner_secret: Vec<u8>
}

impl EpochKeySchedule {
    pub fn derive(
        cipher_suite: CipherSuite,
        last_init: &[u8],
        commit_secret: &[u8],
        num_leaves: usize,
        context: &GroupContext,
        self_index: LeafIndex
    ) -> Result<EpochKeyScheduleDerivation, EpochKeyScheduleError> {
        let joiner_secret = cipher_suite.derive_secret(
            &cipher_suite.extract(last_init, commit_secret)?,
            "joiner"
        )?;

        let schedule = Self::new_joiner(
            cipher_suite,
            &joiner_secret,
            num_leaves,
            context,
            self_index
        )?;

        Ok(EpochKeyScheduleDerivation {
            key_schedule: schedule,
            joiner_secret
        })
    }

    pub fn evolved_from(
        epoch: &EpochKeySchedule,
        commit_secret: &[u8],
        num_leaves: usize,
        context: &GroupContext
    ) -> Result<EpochKeyScheduleDerivation, EpochKeyScheduleError> {
        Self::derive(epoch.cipher_suite.clone(),
                  &epoch.init_secret,
                  commit_secret,
                  num_leaves,
                  context,
                  epoch.self_index)
    }

    pub fn new_joiner(
        cipher_suite: CipherSuite,
        joiner_secret: &[u8],
        num_leaves: usize,
        context: &GroupContext,
        self_index: LeafIndex
    ) -> Result<Self, EpochKeyScheduleError> {
        //TODO: PSK is not supported
        let epoch_seed = cipher_suite.extract(&joiner_secret, &[])?;

        let epoch_secret = cipher_suite.expand_with_label(&epoch_seed,
                                                 "epoch", &bincode::serialize(context)?,
                                                 ExpandType::Secret)?;

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
    fn get_ratchet(&mut self, leaf_index: LeafIndex, key_type: &KeyType) -> Option<&mut SecretKeyRatchet> {
        match key_type {
            KeyType::Handshake => self.handshake_ratchets.get_mut(&leaf_index),
            KeyType::Application => self.application_ratchets.get_mut(&leaf_index)
        }
    }

    #[inline]
    fn derive_ratchets(&mut self, leaf_index: LeafIndex, out_type: &KeyType) -> Result<&mut SecretKeyRatchet, EpochKeyScheduleError> {
        let ratchets = self.secret_tree.get_leaf_secret_ratchets(leaf_index)?;
        self.application_ratchets.insert(leaf_index, ratchets.application);
        self.handshake_ratchets.insert(leaf_index, ratchets.handshake);
        self.get_ratchet(leaf_index, out_type).ok_or(EpochKeyScheduleError::KeyDerivationFailure)
    }

    #[inline]
    //TODO: Make sure to support out of order / skipped packets by passing in pkt number
    fn get_key(&mut self, leaf_index: LeafIndex, key_type: &KeyType) -> Result<EncryptionKey, EpochKeyScheduleError> {
        if let Some(ratchet) = self.get_ratchet(leaf_index, &key_type) {
            ratchet.next_key().map_err(|e| e.into())
        } else {
            self.derive_ratchets(leaf_index, &key_type).and_then(|r| r.next_key().map_err(|e| e.into()))
        }
    }

    //TODO: Make sure to support out of order / skipped packets by passing in pkt number
    pub fn get_encryption_key(&mut self, key_type: KeyType) -> Result<EncryptionKey, EpochKeyScheduleError> {
        self.get_key(self.self_index, &key_type)
    }

    //TODO: Make sure to support out of order / skipped packets by passing in pkt number
    pub fn get_decryption_key(&mut self, sender: LeafIndex, key_type: KeyType) -> Result<EncryptionKey, EpochKeyScheduleError> {
        self.get_key(sender, &key_type)
    }
}

pub struct CommitSecret();

impl CommitSecret {
    // Define commit_secret as the value path_secret[n+1] derived from the path_secret[n] value
    // assigned to the root node.
    pub fn from_update_path(cipher_suite: &CipherSuite, update_path: Option<&UpdatePathGeneration>) -> Result<Vec<u8>, CipherSuiteError> {
        Self::from_tree_secrets(cipher_suite,
                                update_path.map(|up| &up.secrets))
    }

    pub fn from_tree_secrets(cipher_suite: &CipherSuite, secrets: Option<&TreeSecrets>) -> Result<Vec<u8>, CipherSuiteError> {
        match secrets {
            Some(secrets) => {
                cipher_suite.derive_secret(&secrets.secret_path.root_secret, "path")
            },
            None => Ok(Self::empty(cipher_suite))
        }
    }

    pub fn empty(cipher_suite: &CipherSuite) -> Vec<u8> {
        // Define commit_secret as the all-zero vector of the same length as a path_secret
        // value would be
        vec![0u8; cipher_suite.extract_size() as usize]
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
    pub fn from_joiner_secret(cipher_suite: &CipherSuite, joiner_secret: &[u8]) -> Result<WelcomeSecret, CipherSuiteError> {
        //TODO: PSK is not supported
        let epoch_seed = cipher_suite.extract(&joiner_secret, &[])?;

        cipher_suite.derive_secret(
            &epoch_seed,
            "welcome"
        ).map(|r| Self(r))
    }

    pub(crate) fn as_nonce(&self, cipher_suite: &CipherSuite) -> Result<Vec<u8>, CipherSuiteError> {
        cipher_suite.expand(&self, b"nonce", ExpandType::AeadNonce)
    }

    pub(crate) fn as_key(&self, cipher_suite: &CipherSuite) -> Result<Vec<u8>, CipherSuiteError> {
        cipher_suite.expand(&self, b"key", ExpandType::AeadKey)
    }

    pub fn encrypt(&self, cipher_suite: &CipherSuite, plaintext: &[u8]) -> Result<Vec<u8>, CipherSuiteError> {
        let key = self.as_key(cipher_suite)?;
        let nonce = self.as_nonce(cipher_suite)?;
        cipher_suite.aead_encrypt(key, plaintext, &[], &nonce)
    }

    pub fn decrypt(&self, cipher_suite: &CipherSuite, ciphertext: &[u8]) -> Result<Vec<u8>, CipherSuiteError> {
        let key = self.as_key(cipher_suite)?;
        let nonce = self.as_nonce(cipher_suite)?;
        cipher_suite.aead_decrypt(key, ciphertext, &[], &nonce)
    }
}