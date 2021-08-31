use crate::cipher_suite::CipherSuite;
use crate::group::key_schedule::{KeyScheduleKdf, KeyScheduleKdfError};
use crate::group::secret_tree::{
    EncryptionKey, KeyType, SecretKeyRatchet, SecretTree, SecretTreeError,
};
use crate::group::GroupContext;
use crate::tree_kem::node::LeafIndex;
use crate::tree_kem::{TreeSecrets, UpdatePathGeneration};
use ferriscrypt::cipher::aead::{AeadError, AeadNonce, Key};
use ferriscrypt::cipher::NonceError;
use ferriscrypt::kdf::KdfError;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::ops::Deref;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum EpochKeyScheduleError {
    #[error(transparent)]
    KeyScheduleKdfError(#[from] KeyScheduleKdfError),
    #[error(transparent)]
    KdfError(#[from] KdfError),
    #[error(transparent)]
    SecretTreeError(#[from] SecretTreeError),
    #[error(transparent)]
    BincodeError(#[from] bincode::Error),
    #[error(transparent)]
    AeadError(#[from] AeadError),
    #[error(transparent)]
    NonceError(#[from] NonceError),
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
        let kdf = KeyScheduleKdf::new(cipher_suite.kdf_type());

        let joiner_secret = kdf.derive_secret(&kdf.extract(last_init, commit_secret)?, "joiner")?;

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
            epoch.cipher_suite,
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
        let kdf = KeyScheduleKdf::new(cipher_suite.kdf_type());

        //TODO: PSK is not supported
        let epoch_seed = kdf.extract(joiner_secret, &[])?;

        let epoch_secret = kdf.expand_with_label(
            &epoch_seed,
            "epoch",
            &bincode::serialize(context)?,
            kdf.extract_size(),
        )?;

        // Derive secrets from epoch secret
        let sender_data_secret = kdf.derive_secret(&epoch_secret, "sender data")?;
        let encryption_secret = kdf.derive_secret(&epoch_secret, "encryption")?;
        let exporter_secret = kdf.derive_secret(&epoch_secret, "exporter")?;
        let authentication_secret = kdf.derive_secret(&epoch_secret, "authentication")?;
        let external_secret = kdf.derive_secret(&epoch_secret, "external")?;
        let confirmation_key = kdf.derive_secret(&epoch_secret, "confirm")?;
        let membership_key = kdf.derive_secret(&epoch_secret, "membership")?;
        let resumption_secret = kdf.derive_secret(&epoch_secret, "resumption")?;

        let init_secret = kdf.derive_secret(&epoch_secret, "init")?;

        let secret_tree = SecretTree::new(cipher_suite, num_leaves, encryption_secret);

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
    ) -> Result<(Key, AeadNonce), EpochKeyScheduleError> {
        let kdf = KeyScheduleKdf::new(self.cipher_suite.kdf_type());
        // Sample the first extract_size bytes of the ciphertext, and if it is shorter, just use
        // the ciphertext itself
        let ciphertext_sample = if ciphertext.len() <= kdf.extract_size() as usize {
            ciphertext
        } else {
            ciphertext.get(0..kdf.extract_size() as usize).unwrap()
        };

        // Generate a sender data key and nonce using the sender_data_secret from the current
        // epoch's key schedule
        let sender_data_key = kdf.expand_with_label(
            &self.sender_data_secret,
            "key",
            ciphertext_sample,
            self.cipher_suite.aead_type().key_size(),
        )?;

        let sender_data_nonce = kdf.expand_with_label(
            &self.sender_data_secret,
            "nonce",
            ciphertext_sample,
            self.cipher_suite.aead_type().nonce_size(),
        )?;

        Ok((
            Key::new(self.cipher_suite.aead_type(), sender_data_key)?,
            AeadNonce::new(&sender_data_nonce)?,
        ))
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
    ) -> Result<Self, KeyScheduleKdfError> {
        Self::from_tree_secrets(cipher_suite, update_path.map(|up| &up.secrets))
    }

    pub fn from_tree_secrets(
        cipher_suite: &CipherSuite,
        secrets: Option<&TreeSecrets>,
    ) -> Result<Self, KeyScheduleKdfError> {
        let kdf = KeyScheduleKdf::new(cipher_suite.kdf_type());

        match secrets {
            Some(secrets) => {
                let secret = kdf.derive_secret(&secrets.secret_path.root_secret, "path")?;
                Ok(CommitSecret(secret))
            }
            None => Ok(Self::empty(cipher_suite)),
        }
    }

    pub fn empty(cipher_suite: &CipherSuite) -> Self {
        let kdf = KeyScheduleKdf::new(cipher_suite.kdf_type());
        // Define commit_secret as the all-zero vector of the same length as a path_secret
        // value would be
        CommitSecret(vec![0u8; kdf.extract_size()])
    }
}

pub struct WelcomeSecret {
    pub data: Vec<u8>,
    key: Key,
    nonce: AeadNonce,
}

impl Deref for WelcomeSecret {
    type Target = Vec<u8>;

    fn deref(&self) -> &Self::Target {
        &self.data
    }
}

impl WelcomeSecret {
    pub fn from_joiner_secret(
        cipher_suite: CipherSuite,
        joiner_secret: &[u8],
    ) -> Result<WelcomeSecret, EpochKeyScheduleError> {
        //TODO: PSK is not supported
        let kdf = KeyScheduleKdf::new(cipher_suite.kdf_type());
        let epoch_seed = kdf.extract(joiner_secret, &[])?;
        let data = kdf.derive_secret(&epoch_seed, "welcome")?;

        let aead = cipher_suite.aead_type();

        let mut key_buf = vec![0u8; aead.key_size()];
        kdf.expand(&data, b"key", &mut key_buf)?;
        let key = Key::new(aead, key_buf)?;

        let mut nonce_buf = vec![0u8; aead.nonce_size()];
        kdf.expand(&data, b"nonce", &mut nonce_buf)?;
        let nonce = AeadNonce::new(&nonce_buf)?;

        Ok(WelcomeSecret { data, key, nonce })
    }

    pub fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>, EpochKeyScheduleError> {
        self.key
            .encrypt_to_vec(plaintext, None, self.nonce.clone())
            .map_err(Into::into)
    }

    pub fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>, EpochKeyScheduleError> {
        self.key
            .decrypt_from_vec(ciphertext, None, self.nonce.clone())
            .map_err(Into::into)
    }
}

//TODO: Unit tests

#[cfg(test)]
pub mod test_utils {
    use super::*;
    use crate::group::secret_tree::test::get_test_tree;

    pub(crate) fn get_test_epoch_key_schedule(
        cipher_suite: CipherSuite,
        membership_key: Vec<u8>,
        confirmation_key: Vec<u8>,
    ) -> EpochKeySchedule {
        EpochKeySchedule {
            cipher_suite,
            secret_tree: get_test_tree(cipher_suite, vec![], 1),
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
