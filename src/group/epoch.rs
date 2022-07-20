use crate::group::key_schedule::{KeyScheduleKdf, KeyScheduleKdfError};
use crate::group::secret_tree::{KeyType, SecretTree, SecretTreeError};
use crate::group::{GroupContext, MLSCiphertext, MLSCiphertextContentAAD};
use crate::psk::{Psk, PskSecretError};
use crate::tree_kem::node::LeafIndex;
use ferriscrypt::asym::ec_key::PublicKey;
use ferriscrypt::cipher::aead::{AeadError, AeadNonce, Key};
use ferriscrypt::cipher::NonceError;
use ferriscrypt::kdf::KdfError;
use std::collections::HashMap;
use thiserror::Error;
use tls_codec::Serialize;
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
    PskSecretError(#[from] PskSecretError),
    #[error(transparent)]
    NonceError(#[from] NonceError),
    #[error("key derivation failure")]
    KeyDerivationFailure,
}

#[derive(Debug, Clone)]
pub(crate) struct Epoch {
    pub context: GroupContext,
    pub self_index: LeafIndex,
    pub(crate) secrets: EpochSecrets,
    pub signature_public_keys: HashMap<LeafIndex, PublicKey>,
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct EpochSecrets {
    pub(crate) resumption_secret: Psk,
    sender_data_secret: SenderDataSecret,
    secret_tree: SecretTree,
}

#[derive(Clone, Debug, PartialEq, Zeroize)]
#[zeroize(drop)]
struct SenderDataSecret(Vec<u8>);

impl From<Vec<u8>> for SenderDataSecret {
    fn from(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }
}

impl PartialEq for Epoch {
    fn eq(&self, other: &Self) -> bool {
        self.context == other.context
            && self.self_index == other.self_index
            && self.secrets == other.secrets
            && self.signature_public_keys == other.signature_public_keys
    }
}

impl Epoch {
    pub fn new(
        context: GroupContext,
        self_index: LeafIndex,
        resumption_secret: Vec<u8>,
        sender_data_secret: Vec<u8>,
        secret_tree: SecretTree,
        signature_public_keys: HashMap<LeafIndex, PublicKey>,
    ) -> Self {
        Self {
            context,
            self_index,
            secrets: EpochSecrets {
                secret_tree,
                resumption_secret: resumption_secret.into(),
                sender_data_secret: sender_data_secret.into(),
            },
            signature_public_keys,
        }
    }

    pub fn encrypt(
        &mut self,
        key_type: KeyType,
        plaintext: &[u8],
        aad: &[u8],
        reuse_guard: &[u8; 4],
    ) -> Result<(Vec<u8>, u32), EpochError> {
        let key = self
            .secrets
            .secret_tree
            .get_message_key(self.self_index, key_type, None)?;

        Ok((key.encrypt(plaintext, aad, reuse_guard)?, key.generation))
    }

    pub fn decrypt(
        &mut self,
        sender: LeafIndex,
        generation: u32,
        key_type: KeyType,
        ciphertext: &MLSCiphertext,
        reuse_guard: &[u8; 4],
    ) -> Result<Vec<u8>, EpochError> {
        let key = self
            .secrets
            .secret_tree
            .get_message_key(sender, key_type, Some(generation))?;

        Ok(key.decrypt(
            &ciphertext.ciphertext,
            &MLSCiphertextContentAAD::from(ciphertext).tls_serialize_detached()?,
            reuse_guard,
        )?)
    }

    pub fn get_sender_data_params(
        &self,
        ciphertext: &[u8],
    ) -> Result<(Key, AeadNonce), EpochError> {
        let kdf = KeyScheduleKdf::new(self.context.cipher_suite.kdf_type());
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
            &self.secrets.sender_data_secret.0,
            "key",
            ciphertext_sample,
            self.context.cipher_suite.aead_type().key_size(),
        )?;

        let sender_data_nonce = kdf.expand_with_label(
            &self.secrets.sender_data_secret.0,
            "nonce",
            ciphertext_sample,
            self.context.cipher_suite.aead_type().nonce_size(),
        )?;

        Ok((
            Key::new(self.context.cipher_suite.aead_type(), sender_data_key)?,
            AeadNonce::new(&sender_data_nonce)?,
        ))
    }

    #[cfg(feature = "benchmark")]
    pub fn get_secret_tree(&self) -> &SecretTree {
        &self.secrets.secret_tree
    }
}

#[cfg(test)]
pub mod test_utils {
    use super::*;
    use crate::cipher_suite::CipherSuite;
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
            context: get_test_group_context(0, cipher_suite),
            self_index: LeafIndex(0),
            secrets: EpochSecrets {
                resumption_secret: vec![].into(),
                sender_data_secret: vec![].into(),
                secret_tree,
            },
            signature_public_keys: Default::default(),
        }
    }
}

#[cfg(test)]
mod tests {
    use tls_codec::Serialize;

    use crate::{
        cipher_suite::CipherSuite,
        group::{
            epoch::test_utils::get_test_epoch,
            framing::{ContentType, MLSCiphertext, MLSCiphertextContentAAD},
            secret_tree::KeyType,
        },
        tree_kem::node::LeafIndex,
    };

    #[test]
    fn test_crypt() {
        let cipher_suite = CipherSuite::Curve25519Aes128;

        let mut epoch_alice = get_test_epoch(cipher_suite);

        let mut epoch_bob = epoch_alice.clone();
        epoch_bob.self_index = LeafIndex(1);

        let aad = MLSCiphertextContentAAD {
            group_id: b"group".to_vec(),
            epoch: 0,
            content_type: ContentType::Application,
            authenticated_data: b"auth data".to_vec(),
        };

        for key_type in [KeyType::Application, KeyType::Handshake] {
            let (ctxts, generations) = std::iter::repeat_with(|| {
                epoch_alice
                    .encrypt(
                        key_type,
                        b"secret message".as_ref(),
                        &aad.tls_serialize_detached().unwrap(),
                        &[1, 2, 3, 4],
                    )
                    .unwrap()
            })
            .take(10)
            .unzip::<_, _, Vec<_>, Vec<_>>();

            assert_eq!(generations, (0..10).collect::<Vec<_>>());

            let random_permutation: [u32; 10] = [2, 9, 6, 4, 0, 8, 1, 3, 5, 7];

            for i in random_permutation {
                let ctxt = MLSCiphertext {
                    group_id: b"group".to_vec(),
                    epoch: 0,
                    content_type: ContentType::Application,
                    authenticated_data: b"auth data".to_vec(),
                    encrypted_sender_data: vec![],
                    ciphertext: ctxts[i as usize].clone(),
                };
                assert_eq!(
                    b"secret message".to_vec(),
                    epoch_bob
                        .decrypt(LeafIndex(0), i, key_type, &ctxt, &[1, 2, 3, 4])
                        .unwrap()
                );

                assert!(epoch_bob
                    .decrypt(LeafIndex(0), i, key_type, &ctxt, &[1, 2, 3, 4])
                    .is_err());
            }
        }
    }
}
