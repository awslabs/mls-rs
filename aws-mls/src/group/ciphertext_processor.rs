use self::{
    message_key::MessageKey,
    reuse_guard::ReuseGuard,
    sender_data_key::{SenderData, SenderDataAAD, SenderDataKey},
};

use super::{
    epoch::EpochSecrets,
    framing::{ContentType, FramedContent, Sender, WireFormat},
    message_signature::AuthenticatedContent,
    padding::PaddingMode,
    secret_tree::{KeyType, MessageKeyData},
    GroupContext,
};
use crate::{client::MlsError, tree_kem::node::LeafIndex};
use alloc::vec::Vec;
use aws_mls_codec::MlsEncode;
use aws_mls_core::{crypto::CipherSuiteProvider, error::IntoAnyError};
use zeroize::Zeroizing;

mod message_key;
mod reuse_guard;
mod sender_data_key;

#[cfg(feature = "private_message")]
use super::framing::{PrivateContentAAD, PrivateContentTBE, PrivateMessage};

#[cfg(test)]
pub use sender_data_key::test_utils::*;

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

    pub fn next_encryption_key(&mut self, key_type: KeyType) -> Result<MessageKeyData, MlsError> {
        let self_index = self.group_state.self_index();

        self.group_state
            .epoch_secrets_mut()
            .secret_tree
            .next_message_key(&self.cipher_suite_provider, self_index, key_type)
            .map_err(Into::into)
    }

    pub fn decryption_key(
        &mut self,
        sender: LeafIndex,
        key_type: KeyType,
        generation: u32,
    ) -> Result<MessageKeyData, MlsError> {
        self.group_state
            .epoch_secrets_mut()
            .secret_tree
            .message_key_generation(&self.cipher_suite_provider, sender, key_type, generation)
            .map_err(Into::into)
    }

    pub fn seal(
        &mut self,
        auth_content: AuthenticatedContent,
        padding: PaddingMode,
    ) -> Result<PrivateMessage, MlsError> {
        if Sender::Member(*self.group_state.self_index()) != auth_content.content.sender {
            return Err(MlsError::InvalidSender(
                auth_content.content.sender,
                ContentType::Application,
            ));
        }

        let content_type = ContentType::from(&auth_content.content.content);
        let authenticated_data = auth_content.content.authenticated_data;

        // Build a ciphertext content using the plaintext content and signature
        let mut ciphertext_content = PrivateContentTBE {
            content: auth_content.content.content,
            auth: auth_content.auth,
            padding: Vec::new(),
        };

        padding.apply_padding(&mut ciphertext_content);

        // Build ciphertext aad using the plaintext message
        let aad = PrivateContentAAD {
            group_id: auth_content.content.group_id,
            epoch: auth_content.content.epoch,
            content_type,
            authenticated_data: authenticated_data.clone(),
        };

        // Generate a 4 byte reuse guard
        let reuse_guard = ReuseGuard::random(&self.cipher_suite_provider)
            .map_err(|e| MlsError::CryptoProviderError(e.into_any_error()))?;

        // Grab an encryption key from the current epoch's key schedule
        let key_type = match &content_type {
            ContentType::Application => KeyType::Application,
            _ => KeyType::Handshake,
        };

        let ciphertext_content = Zeroizing::new(ciphertext_content.mls_encode_to_vec()?);

        // Encrypt the ciphertext content using the encryption key and a nonce that is
        // reuse safe by xor the reuse guard with the first 4 bytes
        let self_index = self.group_state.self_index();

        let key_data = self.next_encryption_key(key_type)?;
        let generation = key_data.generation;

        let ciphertext = MessageKey::new(key_data)
            .encrypt(
                &self.cipher_suite_provider,
                &ciphertext_content,
                &aad.mls_encode_to_vec()?,
                &reuse_guard,
            )
            .map_err(|e| MlsError::CryptoProviderError(e.into_any_error()))?;

        // Construct an mls sender data struct using the plaintext sender info, the generation
        // of the key schedule encryption key, and the reuse guard used to encrypt ciphertext
        let sender_data = SenderData {
            sender: self_index,
            generation,
            reuse_guard,
        };

        let sender_data_aad = SenderDataAAD {
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

        Ok(PrivateMessage {
            group_id: self.group_state.group_context().group_id.clone(),
            epoch: self.group_state.group_context().epoch,
            content_type,
            authenticated_data,
            encrypted_sender_data,
            ciphertext,
        })
    }

    pub fn open(&mut self, ciphertext: PrivateMessage) -> Result<AuthenticatedContent, MlsError> {
        // Decrypt the sender data with the derived sender_key and sender_nonce from the message
        // epoch's key schedule
        let sender_data_aad = SenderDataAAD {
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
            return Err(MlsError::CantProcessMessageFromSelf);
        }

        // Grab a decryption key from the message epoch's key schedule
        let key_type = match &ciphertext.content_type {
            ContentType::Application => KeyType::Application,
            _ => KeyType::Handshake,
        };

        // Decrypt the content of the message using the grabbed key
        let key = self.decryption_key(sender_data.sender, key_type, sender_data.generation)?;

        let sender = Sender::Member(*sender_data.sender);

        let decrypted_content = MessageKey::new(key)
            .decrypt(
                &self.cipher_suite_provider,
                &ciphertext.ciphertext,
                &PrivateContentAAD::from(&ciphertext).mls_encode_to_vec()?,
                &sender_data.reuse_guard,
            )
            .map_err(|e| MlsError::CryptoProviderError(e.into_any_error()))?;

        let ciphertext_content =
            PrivateContentTBE::mls_decode(&mut &**decrypted_content, ciphertext.content_type)?;

        // Build the MLS plaintext object and process it
        let auth_content = AuthenticatedContent {
            wire_format: WireFormat::PrivateMessage,
            content: FramedContent {
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
        crypto::{
            test_utils::{test_cipher_suite_provider, TestCryptoProvider},
            CipherSuiteProvider,
        },
        group::{
            epoch::{test_utils::get_test_epoch, PriorEpoch},
            framing::{ApplicationData, Content, Sender, WireFormat},
            message_signature::AuthenticatedContent,
            padding::PaddingMode,
            test_utils::random_bytes,
        },
        tree_kem::node::LeafIndex,
    };

    use super::{CiphertextProcessor, MlsError};

    use alloc::vec;
    use assert_matches::assert_matches;

    #[cfg(target_arch = "wasm32")]
    use wasm_bindgen_test::wasm_bindgen_test as test;

    struct TestData {
        epoch: PriorEpoch,
        content: AuthenticatedContent,
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

        let test_content = AuthenticatedContent::new_signed(
            &provider,
            &test_epoch.context,
            Sender::Member(0),
            Content::Application(ApplicationData::from(b"test".to_vec())),
            &test_signer,
            WireFormat::PrivateMessage,
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

        assert_matches!(res, Err(MlsError::InvalidSender(..)))
    }

    #[test]
    fn test_cant_process_from_self() {
        let mut test_data = test_data(TEST_CIPHER_SUITE);

        let mut ciphertext_processor = test_processor(&mut test_data.epoch, TEST_CIPHER_SUITE);

        let ciphertext = ciphertext_processor
            .seal(test_data.content, PaddingMode::None)
            .unwrap();

        let res = ciphertext_processor.open(ciphertext);

        assert_matches!(res, Err(MlsError::CantProcessMessageFromSelf))
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
