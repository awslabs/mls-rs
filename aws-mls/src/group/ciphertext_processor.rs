use self::{
    message_key::MessageKey,
    reuse_guard::ReuseGuard,
    sender_data_key::{MLSSenderData, MLSSenderDataAAD, SenderDataKey},
};

use super::{
    epoch::EpochSecrets,
    framing::{
        ContentType, MLSCiphertext, MLSCiphertextContent, MLSCiphertextContentAAD, MLSContent,
        Sender, WireFormat,
    },
    key_schedule::KeyScheduleError,
    message_signature::MLSAuthenticatedContent,
    secret_tree::{KeyType, SecretTreeError},
    GroupContext, PaddingMode,
};
use crate::{provider::crypto::CipherSuiteProvider, psk::PskError, tree_kem::node::LeafIndex};
use thiserror::Error;
use tls_codec::{Deserialize, Serialize};
use zeroize::Zeroizing;

mod message_key;
mod reuse_guard;
mod sender_data_key;

#[derive(Error, Debug)]
pub enum CiphertextProcessorError {
    #[error(transparent)]
    CipherSuiteProviderError(Box<dyn std::error::Error + Send + Sync + 'static>),
    #[error(transparent)]
    SecretTreeError(#[from] SecretTreeError),
    #[error(transparent)]
    TlsCodecError(#[from] tls_codec::Error),
    #[error(transparent)]
    PskSecretError(#[from] PskError),
    #[error("key derivation failure")]
    KeyDerivationFailure,
    #[error("seal is only supported for self created messages")]
    InvalidSender(Sender),
    #[error("message from self can't be processed")]
    CantProcessMessageFromSelf,
    #[error(transparent)]
    KeyScheduleError(#[from] KeyScheduleError),
}

pub(crate) trait GroupStateProvider {
    fn group_context(&self) -> &GroupContext;
    fn self_index(&self) -> LeafIndex;
    fn epoch_secrets_mut(&mut self) -> &mut EpochSecrets;
    fn epoch_secrets(&self) -> &EpochSecrets;
}

pub(crate) struct CiphertextProcessor<'a, GS, CP>
where
    GS: GroupStateProvider,
    CP: CipherSuiteProvider,
{
    group_state: &'a mut GS,
    cipher_suite_provider: CP,
}

impl<'a, GS, CP> CiphertextProcessor<'a, GS, CP>
where
    GS: GroupStateProvider,
    CP: CipherSuiteProvider,
{
    pub fn new(
        group_state: &'a mut GS,
        cipher_suite_provider: CP,
    ) -> CiphertextProcessor<'a, GS, CP> {
        Self {
            group_state,
            cipher_suite_provider,
        }
    }

    pub fn seal(
        &mut self,
        auth_content: MLSAuthenticatedContent,
        padding: PaddingMode,
    ) -> Result<MLSCiphertext, CiphertextProcessorError> {
        if Sender::Member(*self.group_state.self_index()) != auth_content.content.sender {
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
        let reuse_guard = ReuseGuard::random(&self.cipher_suite_provider)
            .map_err(|e| CiphertextProcessorError::CipherSuiteProviderError(e.into()))?;

        // Grab an encryption key from the current epoch's key schedule
        let key_type = match &content_type {
            ContentType::Application => KeyType::Application,
            _ => KeyType::Handshake,
        };

        let ciphertext_content = Zeroizing::new(ciphertext_content.tls_serialize_detached()?);

        // Encrypt the ciphertext content using the encryption key and a nonce that is
        // reuse safe by xor the reuse guard with the first 4 bytes
        let self_index = self.group_state.self_index();

        let (key_data, generation) = self
            .group_state
            .epoch_secrets_mut()
            .secret_tree
            .next_message_key(&self.cipher_suite_provider, self_index, key_type)?;

        let ciphertext = MessageKey::new(key_data)
            .encrypt(
                &self.cipher_suite_provider,
                &ciphertext_content,
                &aad.tls_serialize_detached()?,
                &reuse_guard,
            )
            .map_err(|e| CiphertextProcessorError::CipherSuiteProviderError(e.into()))?;

        // Construct an mls sender data struct using the plaintext sender info, the generation
        // of the key schedule encryption key, and the reuse guard used to encrypt ciphertext
        let sender_data = MLSSenderData {
            sender: self_index,
            generation,
            reuse_guard,
        };

        let sender_data_aad = MLSSenderDataAAD {
            group_id: self.group_state.group_context().group_id.clone(),
            epoch: self.group_state.group_context().epoch,
            content_type,
        };

        // Encrypt the sender data with the derived sender_key and sender_nonce from the current
        // epoch's key schedule
        let sender_data_key = SenderDataKey::new(
            &self.group_state.epoch_secrets().sender_data_secret,
            &ciphertext,
            &self.cipher_suite_provider,
        )?;

        let encrypted_sender_data = sender_data_key.seal(&sender_data, &sender_data_aad)?;

        Ok(MLSCiphertext {
            group_id: self.group_state.group_context().group_id.clone(),
            epoch: self.group_state.group_context().epoch,
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
        let sender_data_aad = MLSSenderDataAAD {
            group_id: self.group_state.group_context().group_id.clone(),
            epoch: self.group_state.group_context().epoch,
            content_type: ciphertext.content_type,
        };

        let sender_data_key = SenderDataKey::new(
            &self.group_state.epoch_secrets().sender_data_secret,
            &ciphertext.ciphertext,
            &self.cipher_suite_provider,
        )?;

        let sender_data =
            sender_data_key.open(&ciphertext.encrypted_sender_data, &sender_data_aad)?;

        if self.group_state.self_index() == sender_data.sender {
            return Err(CiphertextProcessorError::CantProcessMessageFromSelf);
        }

        // Grab a decryption key from the message epoch's key schedule
        let key_type = match &ciphertext.content_type {
            ContentType::Application => KeyType::Application,
            _ => KeyType::Handshake,
        };

        // Decrypt the content of the message using the grabbed key
        let key = self
            .group_state
            .epoch_secrets_mut()
            .secret_tree
            .message_key_generation(
                &self.cipher_suite_provider,
                sender_data.sender,
                key_type,
                sender_data.generation,
            )?;

        let sender = Sender::Member(*sender_data.sender);

        let decrypted_content = Zeroizing::new(
            MessageKey::new(key)
                .decrypt(
                    &self.cipher_suite_provider,
                    &ciphertext.ciphertext,
                    &MLSCiphertextContentAAD::from(&ciphertext).tls_serialize_detached()?,
                    &sender_data.reuse_guard,
                )
                .map_err(|e| CiphertextProcessorError::CipherSuiteProviderError(e.into()))?,
        );

        let ciphertext_content = MLSCiphertextContent::tls_deserialize(&mut &**decrypted_content)?;

        // Build the MLS plaintext object and process it
        let auth_content = MLSAuthenticatedContent {
            wire_format: WireFormat::Cipher,
            content: MLSContent {
                group_id: ciphertext.group_id.clone(),
                epoch: ciphertext.epoch,
                sender,
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
    use crate::{
        cipher_suite::CipherSuite,
        client::test_utils::TEST_CIPHER_SUITE,
        group::{
            epoch::{test_utils::get_test_epoch, PriorEpoch},
            framing::{ApplicationData, Content, Sender, WireFormat},
            message_signature::MLSAuthenticatedContent,
            test_utils::random_bytes,
            PaddingMode,
        },
        provider::crypto::{
            test_utils::{test_cipher_suite_provider, TestCryptoProvider},
            CipherSuiteProvider,
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

    fn test_processor(
        epoch: &mut PriorEpoch,
        cipher_suite: CipherSuite,
    ) -> CiphertextProcessor<'_, PriorEpoch, impl CipherSuiteProvider> {
        CiphertextProcessor::new(epoch, test_cipher_suite_provider(cipher_suite))
    }

    fn test_data(cipher_suite: CipherSuite) -> TestData {
        let provider = test_cipher_suite_provider(cipher_suite);

        let test_epoch = get_test_epoch(cipher_suite);
        let (test_signer, _) = provider.signature_key_generate().unwrap();

        let test_content = MLSAuthenticatedContent::new_signed(
            &provider,
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
        TestCryptoProvider::all_supported_cipher_suites()
            .into_iter()
            .for_each(|cipher_suite| {
                let mut test_data = test_data(cipher_suite);
                let mut receiver_epoch = test_data.epoch.clone();

                let mut ciphertext_processor = test_processor(&mut test_data.epoch, cipher_suite);

                let ciphertext = ciphertext_processor
                    .seal(test_data.content.clone(), PaddingMode::StepFunction)
                    .unwrap();

                receiver_epoch.self_index = LeafIndex::new(1);

                let mut receiver_processor = test_processor(&mut receiver_epoch, cipher_suite);

                let decrypted = receiver_processor.open(ciphertext).unwrap();

                assert_eq!(decrypted, test_data.content);
            })
    }

    #[test]
    fn test_padding_use() {
        let mut test_data = test_data(TEST_CIPHER_SUITE);
        let mut ciphertext_processor = test_processor(&mut test_data.epoch, TEST_CIPHER_SUITE);

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

        let mut ciphertext_processor = test_processor(&mut test_data.epoch, TEST_CIPHER_SUITE);

        let res = ciphertext_processor.seal(test_data.content, PaddingMode::None);

        assert_matches!(res, Err(CiphertextProcessorError::InvalidSender(_)))
    }

    #[test]
    fn test_cant_process_from_self() {
        let mut test_data = test_data(TEST_CIPHER_SUITE);

        let mut ciphertext_processor = test_processor(&mut test_data.epoch, TEST_CIPHER_SUITE);

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
        let mut ciphertext_processor = test_processor(&mut test_data.epoch, TEST_CIPHER_SUITE);

        let mut ciphertext = ciphertext_processor
            .seal(test_data.content.clone(), PaddingMode::StepFunction)
            .unwrap();

        ciphertext.ciphertext = random_bytes(ciphertext.ciphertext.len());
        receiver_epoch.self_index = LeafIndex::new(1);

        let res = ciphertext_processor.open(ciphertext);

        assert!(res.is_err());
    }
}
