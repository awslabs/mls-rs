use crate::cipher_suite::CipherSuite;
use crate::group::key_schedule::{KeyScheduleKdf, KeyScheduleKdfError};
use crate::group::secret_tree::{
    KeyType, MessageKey, SecretKeyRatchet, SecretTree, SecretTreeError,
};
use crate::group::GroupContext;
use crate::tree_kem::node::LeafIndex;
use crate::tree_kem::path_secret::{PathSecret, PathSecretError, PathSecretGenerator};
use crate::tree_kem::{TreeKemPublic, TreeSecrets, UpdatePathGeneration};
use ferriscrypt::asym::ec_key::PublicKey;
use ferriscrypt::cipher::aead::{AeadError, AeadNonce, Key};
use ferriscrypt::cipher::NonceError;
use ferriscrypt::kdf::KdfError;
use std::collections::HashMap;
use std::ops::Deref;
use thiserror::Error;
use zeroize::Zeroize;

#[derive(Error, Debug)]
pub enum EpochError {
    #[error(transparent)]
    KeyScheduleKdfError(#[from] KeyScheduleKdfError),
    #[error(transparent)]
    KdfError(#[from] KdfError),
    #[error(transparent)]
    SecretTreeError(#[from] SecretTreeError),
    #[error(transparent)]
    TlsCodecError(#[from] tls_codec::Error),
    #[error(transparent)]
    AeadError(#[from] AeadError),
    #[error(transparent)]
    NonceError(#[from] NonceError),
    #[error("key derivation failure")]
    KeyDerivationFailure,
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub struct PublicEpoch {
    pub(crate) identifier: u64,
    pub(crate) cipher_suite: CipherSuite,
    pub(crate) public_tree: TreeKemPublic,
}

#[derive(Clone, Debug)]
pub struct Epoch {
    pub context: GroupContext,
    pub self_index: LeafIndex,
    pub resumption_secret: Vec<u8>,
    pub sender_data_secret: Vec<u8>,
    pub secret_tree: SecretTree,
    pub handshake_ratchets: HashMap<LeafIndex, SecretKeyRatchet>,
    pub application_ratchets: HashMap<LeafIndex, SecretKeyRatchet>,
    pub cipher_suite: CipherSuite,
    pub signature_public_keys: HashMap<LeafIndex, PublicKey>,
}

impl PartialEq for Epoch {
    fn eq(&self, other: &Self) -> bool {
        self.context == other.context
            && self.self_index == other.self_index
            && self.resumption_secret == other.resumption_secret
            && self.sender_data_secret == other.sender_data_secret
            && self.cipher_suite == other.cipher_suite
            && self.signature_public_keys == other.signature_public_keys
    }
}

impl Epoch {
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
    ) -> Result<&mut SecretKeyRatchet, EpochError> {
        let ratchets = self.secret_tree.get_leaf_secret_ratchets(leaf_index)?;
        self.application_ratchets
            .insert(leaf_index, ratchets.application);
        self.handshake_ratchets
            .insert(leaf_index, ratchets.handshake);
        self.get_ratchet(leaf_index, out_type)
            .ok_or(EpochError::KeyDerivationFailure)
    }

    #[inline]
    fn get_key(
        &mut self,
        leaf_index: LeafIndex,
        generation: Option<u32>,
        key_type: &KeyType,
    ) -> Result<MessageKey, EpochError> {
        let ratchet = match self.get_ratchet(leaf_index, key_type) {
            Some(ratchet) => ratchet,
            None => self.derive_ratchets(leaf_index, key_type)?,
        };

        match generation {
            None => ratchet.next_message_key(),
            Some(gen) => ratchet.get_message_key(gen),
        }
        .map_err(|e| e.into())
    }

    pub fn get_encryption_key(&mut self, key_type: KeyType) -> Result<MessageKey, EpochError> {
        self.get_key(self.self_index, None, &key_type)
    }

    pub fn get_decryption_key(
        &mut self,
        sender: LeafIndex,
        generation: u32,
        key_type: KeyType,
    ) -> Result<MessageKey, EpochError> {
        self.get_key(sender, Some(generation), &key_type)
    }

    pub fn get_sender_data_params(
        &self,
        ciphertext: &[u8],
    ) -> Result<(Key, AeadNonce), EpochError> {
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

#[derive(Debug, Clone, PartialEq, Zeroize)]
#[zeroize(drop)]
pub struct CommitSecret(PathSecret);

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
        cipher_suite: CipherSuite,
        update_path: Option<&UpdatePathGeneration>,
    ) -> Result<Self, PathSecretError> {
        Self::from_tree_secrets(cipher_suite, update_path.map(|up| &up.secrets))
    }

    pub fn from_tree_secrets(
        cipher_suite: CipherSuite,
        secrets: Option<&TreeSecrets>,
    ) -> Result<Self, PathSecretError> {
        match secrets {
            Some(secrets) => {
                let mut generator = PathSecretGenerator::starting_from(
                    cipher_suite,
                    secrets.secret_path.root_secret.clone(),
                );

                let secret = generator.next_secret()?;
                Ok(CommitSecret(secret.path_secret))
            }
            None => Ok(Self::empty(cipher_suite)),
        }
    }

    pub fn empty(cipher_suite: CipherSuite) -> CommitSecret {
        CommitSecret(PathSecret::empty(cipher_suite))
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
        psk_secret: &[u8],
    ) -> Result<WelcomeSecret, EpochError> {
        let kdf = KeyScheduleKdf::new(cipher_suite.kdf_type());
        let epoch_seed = kdf.extract(psk_secret, joiner_secret)?;
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

    pub fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>, EpochError> {
        self.key
            .encrypt_to_vec(plaintext, None, self.nonce.clone())
            .map_err(Into::into)
    }

    pub fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>, EpochError> {
        self.key
            .decrypt_from_vec(ciphertext, None, self.nonce.clone())
            .map_err(Into::into)
    }
}

#[cfg(test)]
pub mod test_utils {
    use super::*;
    use crate::group::secret_tree::test_utils::get_test_tree;
    use crate::group::test_utils::get_test_group_context;
    use ferriscrypt::kdf::hkdf::Hkdf;

    pub(crate) fn get_test_epoch(cipher_suite: CipherSuite) -> Epoch {
        let secret_tree = get_test_tree(
            cipher_suite,
            vec![0_u8; Hkdf::from(cipher_suite.kdf_type()).extract_size()],
            2,
        );

        Epoch {
            context: get_test_group_context(0),
            self_index: LeafIndex(0),
            resumption_secret: vec![],
            sender_data_secret: vec![],
            secret_tree,
            handshake_ratchets: Default::default(),
            application_ratchets: Default::default(),
            cipher_suite,
            signature_public_keys: Default::default(),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        cipher_suite::CipherSuite,
        group::{epoch::test_utils::get_test_epoch, secret_tree::KeyType},
        tree_kem::node::LeafIndex,
    };

    #[test]
    fn test_get_key() {
        let cipher_suite = CipherSuite::Curve25519Aes128;

        let mut epoch_alice = get_test_epoch(cipher_suite);

        let mut epoch_bob = epoch_alice.clone();
        epoch_bob.self_index = LeafIndex(1);

        for key_type in [KeyType::Application, KeyType::Handshake] {
            let enc_keys =
                std::iter::repeat_with(|| epoch_alice.get_encryption_key(key_type).unwrap())
                    .take(10)
                    .collect::<Vec<_>>();

            let random_permutation: [u32; 10] = [2, 9, 6, 4, 0, 8, 1, 3, 5, 7];

            for i in random_permutation {
                assert_eq!(
                    enc_keys[i as usize],
                    epoch_bob
                        .get_decryption_key(LeafIndex(0), i, key_type)
                        .unwrap()
                );

                assert!(epoch_bob
                    .get_decryption_key(LeafIndex(0), i, key_type)
                    .is_err());
            }
        }
    }
}
