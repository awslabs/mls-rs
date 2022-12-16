use super::{
    epoch::EpochSecrets,
    framing::{
        ContentType, MLSCiphertext, MLSCiphertextContent, MLSCiphertextContentAAD, MLSContent,
        MLSSenderData, MLSSenderDataAAD, Sender, WireFormat,
    },
    key_schedule::{KeyScheduleKdf, KeyScheduleKdfError},
    message_signature::MLSAuthenticatedContent,
    secret_tree::{KeyType, SecretTreeError},
    GroupContext, PaddingMode,
};
use crate::{psk::PskSecretError, tree_kem::node::LeafIndex};
use ferriscrypt::{
    cipher::{
        aead::{AeadError, AeadNonce, Key},
        NonceError,
    },
    kdf::KdfError,
    rand::{SecureRng, SecureRngError},
};
use thiserror::Error;
use tls_codec::{Deserialize, Serialize};
use zeroize::Zeroizing;

#[derive(Error, Debug)]
pub enum CiphertextProcessorError {
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
    #[error(transparent)]
    RngError(#[from] SecureRngError),
    #[error("seal is only supported for self created messages")]
    InvalidSender(Sender),
    #[error("message from self can't be processed")]
    CantProcessMessageFromSelf,
}

pub(crate) trait EpochSecretsProvider {
    fn group_context(&self) -> &GroupContext;
    fn self_index(&self) -> LeafIndex;
    fn epoch_secrets_mut(&mut self) -> &mut EpochSecrets;
    fn epoch_secrets(&self) -> &EpochSecrets;
}

pub(crate) struct CiphertextProcessor<'a, T>(&'a mut T)
where
    T: EpochSecretsProvider;

impl<'a, T> CiphertextProcessor<'a, T>
where
    T: EpochSecretsProvider,
{
    pub fn new(provider: &'a mut T) -> CiphertextProcessor<T> {
        Self(provider)
    }

    fn get_sender_data_params(
        &self,
        ciphertext: &[u8],
    ) -> Result<(Key, AeadNonce), CiphertextProcessorError> {
        let kdf = KeyScheduleKdf::new(self.0.group_context().cipher_suite.kdf_type());
        // Sample the first extract_size bytes of the ciphertext, and if it is shorter, just use
        // the ciphertext itself
        let ciphertext_sample = ciphertext.get(0..kdf.extract_size()).unwrap_or(ciphertext);

        // Generate a sender data key and nonce using the sender_data_secret from the current
        // epoch's key schedule
        let sender_data_key = kdf.expand_with_label(
            &self.0.epoch_secrets().sender_data_secret,
            "key",
            ciphertext_sample,
            self.0.group_context().cipher_suite.aead_type().key_size(),
        )?;

        let sender_data_nonce = kdf.expand_with_label(
            &self.0.epoch_secrets().sender_data_secret,
            "nonce",
            ciphertext_sample,
            self.0.group_context().cipher_suite.aead_type().nonce_size(),
        )?;

        Ok((
            Key::new(
                self.0.group_context().cipher_suite.aead_type(),
                sender_data_key,
            )?,
            AeadNonce::new(&sender_data_nonce)?,
        ))
    }

    pub fn seal(
        &mut self,
        auth_content: MLSAuthenticatedContent,
        padding: PaddingMode,
    ) -> Result<MLSCiphertext, CiphertextProcessorError> {
        if Sender::Member(*self.0.self_index()) != auth_content.content.sender {
            return Err(CiphertextProcessorError::InvalidSender(
                auth_content.content.sender,
            ));
        }

        let content_type = ContentType::from(&auth_content.content.content);
        let authenticated_data = auth_content.content.authenticated_data;

        // Build a ciphertext content using the plaintext content and signature
        let mut ciphertext_content = MLSCiphertextContent {
            content: auth_content.content.content,
            auth: auth_content.auth,
            padding: Vec::new(),
        };

        padding.apply_padding(&mut ciphertext_content);

        // Build ciphertext aad using the plaintext message
        let aad = MLSCiphertextContentAAD {
            group_id: auth_content.content.group_id,
            epoch: auth_content.content.epoch,
            content_type,
            authenticated_data: authenticated_data.clone(),
        };

        // Generate a 4 byte reuse guard
        let mut reuse_guard = [0u8; 4];
        SecureRng::fill(&mut reuse_guard)?;

        // Grab an encryption key from the current epoch's key schedule
        let key_type = match &content_type {
            ContentType::Application => KeyType::Application,
            _ => KeyType::Handshake,
        };

        let ciphertext_content = Zeroizing::new(ciphertext_content.tls_serialize_detached()?);

        // Encrypt the ciphertext content using the encryption key and a nonce that is
        // reuse safe by xor the reuse guard with the first 4 bytes

        let self_index = self.0.self_index();

        let key = self
            .0
            .epoch_secrets_mut()
            .secret_tree
            .get_message_key(self_index, key_type, None)?;

        let ciphertext = key.encrypt(
            &ciphertext_content,
            &aad.tls_serialize_detached()?,
            &reuse_guard,
        )?;

        // Construct an mls sender data struct using the plaintext sender info, the generation
        // of the key schedule encryption key, and the reuse guard used to encrypt ciphertext
        let sender_data = MLSSenderData {
            sender: self_index,
            generation: key.generation,
            reuse_guard,
        };

        let sender_data_aad = MLSSenderDataAAD {
            group_id: self.0.group_context().group_id.clone(),
            epoch: self.0.group_context().epoch,
            content_type,
        };

        // Encrypt the sender data with the derived sender_key and sender_nonce from the current
        // epoch's key schedule
        let (sender_key, sender_nonce) = self.get_sender_data_params(&ciphertext)?;

        let encrypted_sender_data = sender_key.encrypt_to_vec(
            &sender_data.tls_serialize_detached()?,
            Some(&sender_data_aad.tls_serialize_detached()?),
            sender_nonce,
        )?;

        Ok(MLSCiphertext {
            group_id: self.0.group_context().group_id.clone(),
            epoch: self.0.group_context().epoch,
            content_type,
            authenticated_data,
            encrypted_sender_data,
            ciphertext,
        })
    }

    pub fn open(
        &mut self,
        ciphertext: MLSCiphertext,
    ) -> Result<MLSAuthenticatedContent, CiphertextProcessorError> {
        // Decrypt the sender data with the derived sender_key and sender_nonce from the message
        // epoch's key schedule
        let (sender_key, sender_nonce) = self.get_sender_data_params(&ciphertext.ciphertext)?;

        let sender_data_aad = MLSSenderDataAAD {
            group_id: self.0.group_context().group_id.clone(),
            epoch: self.0.group_context().epoch,
            content_type: ciphertext.content_type,
        };

        let decrypted_sender = Zeroizing::new(sender_key.decrypt_from_vec(
            &ciphertext.encrypted_sender_data,
            Some(&sender_data_aad.tls_serialize_detached()?),
            sender_nonce,
        )?);

        let sender_data = MLSSenderData::tls_deserialize(&mut &**decrypted_sender)?;

        if self.0.self_index() == sender_data.sender {
            return Err(CiphertextProcessorError::CantProcessMessageFromSelf);
        }

        // Grab a decryption key from the message epoch's key schedule
        let key_type = match &ciphertext.content_type {
            ContentType::Application => KeyType::Application,
            _ => KeyType::Handshake,
        };

        // Decrypt the content of the message using the grabbed key
        let key = self.0.epoch_secrets_mut().secret_tree.get_message_key(
            sender_data.sender,
            key_type,
            Some(sender_data.generation),
        )?;

        let decrypted_content = Zeroizing::new(key.decrypt(
            &ciphertext.ciphertext,
            &MLSCiphertextContentAAD::from(&ciphertext).tls_serialize_detached()?,
            &sender_data.reuse_guard,
        )?);

        let ciphertext_content = MLSCiphertextContent::tls_deserialize(&mut &**decrypted_content)?;

        // Build the MLS plaintext object and process it
        let auth_content = MLSAuthenticatedContent {
            wire_format: WireFormat::Cipher,
            content: MLSContent {
                group_id: ciphertext.group_id.clone(),
                epoch: ciphertext.epoch,
                sender: Sender::Member(*sender_data.sender),
                authenticated_data: ciphertext.authenticated_data,
                content: ciphertext_content.content,
            },
            auth: ciphertext_content.auth,
        };

        Ok(auth_content)
    }
}

#[cfg(test)]
mod test {
    use ferriscrypt::rand::SecureRng;

    use crate::{
        cipher_suite::CipherSuite,
        client::test_utils::TEST_CIPHER_SUITE,
        group::{
            epoch::{test_utils::get_test_epoch, PriorEpoch},
            framing::{ApplicationData, Content, Sender, WireFormat},
            message_signature::MLSAuthenticatedContent,
            PaddingMode,
        },
        tree_kem::node::LeafIndex,
    };

    use super::{CiphertextProcessor, CiphertextProcessorError};

    use assert_matches::assert_matches;

    #[cfg(target_arch = "wasm32")]
    use wasm_bindgen_test::wasm_bindgen_test as test;

    struct TestData {
        epoch: PriorEpoch,
        content: MLSAuthenticatedContent,
    }

    fn test_data(cipher_suite: CipherSuite) -> TestData {
        let test_epoch = get_test_epoch(cipher_suite);
        let test_signer = cipher_suite.generate_signing_key().unwrap();

        let test_content = MLSAuthenticatedContent::new_signed(
            &test_epoch.context,
            Sender::Member(0),
            Content::Application(ApplicationData::from(b"test".to_vec())),
            &test_signer,
            WireFormat::Cipher,
            vec![],
        )
        .unwrap();

        TestData {
            epoch: test_epoch,
            content: test_content,
        }
    }

    #[test]
    fn test_encrypt_decrypt() {
        CipherSuite::all().for_each(|cipher_suite| {
            let mut test_data = test_data(cipher_suite);
            let mut receiver_epoch = test_data.epoch.clone();

            let mut ciphertext_processor = CiphertextProcessor::new(&mut test_data.epoch);

            let ciphertext = ciphertext_processor
                .seal(test_data.content.clone(), PaddingMode::StepFunction)
                .unwrap();

            receiver_epoch.self_index = LeafIndex::new(1);

            let mut receiver_processor = CiphertextProcessor::new(&mut receiver_epoch);

            let decrypted = receiver_processor.open(ciphertext).unwrap();

            assert_eq!(decrypted, test_data.content);
        })
    }

    #[test]
    fn test_padding_use() {
        let mut test_data = test_data(TEST_CIPHER_SUITE);
        let mut ciphertext_processor = CiphertextProcessor::new(&mut test_data.epoch);

        let ciphertext_step = ciphertext_processor
            .seal(test_data.content.clone(), PaddingMode::StepFunction)
            .unwrap();

        let ciphertext_no_pad = ciphertext_processor
            .seal(test_data.content.clone(), PaddingMode::None)
            .unwrap();

        assert!(ciphertext_step.ciphertext.len() > ciphertext_no_pad.ciphertext.len());
    }

    #[test]
    fn test_invalid_sender() {
        let mut test_data = test_data(TEST_CIPHER_SUITE);
        test_data.content.content.sender = Sender::Member(3);

        let mut ciphertext_processor = CiphertextProcessor::new(&mut test_data.epoch);

        let res = ciphertext_processor.seal(test_data.content, PaddingMode::None);

        assert_matches!(res, Err(CiphertextProcessorError::InvalidSender(_)))
    }

    #[test]
    fn test_cant_process_from_self() {
        let mut test_data = test_data(TEST_CIPHER_SUITE);
        let mut ciphertext_processor = CiphertextProcessor::new(&mut test_data.epoch);

        let ciphertext = ciphertext_processor
            .seal(test_data.content, PaddingMode::None)
            .unwrap();

        let res = ciphertext_processor.open(ciphertext);

        assert_matches!(
            res,
            Err(CiphertextProcessorError::CantProcessMessageFromSelf)
        )
    }

    #[test]
    fn test_decryption_error() {
        let mut test_data = test_data(TEST_CIPHER_SUITE);
        let mut receiver_epoch = test_data.epoch.clone();

        let mut ciphertext_processor = CiphertextProcessor::new(&mut test_data.epoch);

        let mut ciphertext = ciphertext_processor
            .seal(test_data.content.clone(), PaddingMode::StepFunction)
            .unwrap();

        ciphertext.ciphertext = SecureRng::gen(ciphertext.ciphertext.len()).unwrap();
        receiver_epoch.self_index = LeafIndex::new(1);

        let res = ciphertext_processor.open(ciphertext);

        assert!(res.is_err());
    }
}
