use crate::{
    cipher_suite::CipherSuite,
    group::{
        framing::{Content, MLSMessage, MLSMessagePayload, MLSPlaintext, Sender},
        message_signature::MessageSigningContext,
        proposal::{AddProposal, Proposal, RemoveProposal},
    },
    keychain::Keychain,
    signer::{Signable, SignatureError},
    ExternalClientConfig, ProtocolVersion,
};
use thiserror::Error;
use tls_codec::Serialize;

#[derive(Debug, Error)]
pub enum ExternalClientError {
    #[error("proposing as external without external key ID")]
    ProposingAsExternalWithoutExternalKeyId,
    #[error("credential not found for cipher suite")]
    NoCredentialFound,
    #[error(transparent)]
    SignatureError(#[from] SignatureError),
    #[error(transparent)]
    SerializationError(#[from] tls_codec::Error),
}

pub struct ExternalClient<C> {
    config: C,
}

impl<C: ExternalClientConfig> ExternalClient<C> {
    pub fn new(config: C) -> Self {
        Self { config }
    }

    pub fn propose_add_from_preconfigured(
        &self,
        version: ProtocolVersion,
        group_cipher_suite: CipherSuite,
        group_id: Vec<u8>,
        proposal: AddProposal,
        epoch: u64,
        authenticated_data: Vec<u8>,
    ) -> Result<Vec<u8>, ExternalClientError> {
        self.propose_from_preconfigured(
            version,
            group_cipher_suite,
            Proposal::Add(proposal),
            group_id,
            epoch,
            authenticated_data,
        )
    }

    pub fn propose_remove_from_preconfigured(
        &self,
        version: ProtocolVersion,
        group_cipher_suite: CipherSuite,
        group_id: Vec<u8>,
        proposal: RemoveProposal,
        epoch: u64,
        authenticated_data: Vec<u8>,
    ) -> Result<Vec<u8>, ExternalClientError> {
        self.propose_from_preconfigured(
            version,
            group_cipher_suite,
            Proposal::Remove(proposal),
            group_id,
            epoch,
            authenticated_data,
        )
    }

    fn propose_from_preconfigured(
        &self,
        version: ProtocolVersion,
        group_cipher_suite: CipherSuite,
        proposal: Proposal,
        group_id: Vec<u8>,
        epoch: u64,
        authenticated_data: Vec<u8>,
    ) -> Result<Vec<u8>, ExternalClientError> {
        let sender = Sender::Preconfigured(
            self.config
                .external_key_id()
                .ok_or(ExternalClientError::ProposingAsExternalWithoutExternalKeyId)?,
        );
        let mut message = MLSPlaintext::new(
            group_id,
            epoch,
            sender,
            Content::Proposal(proposal),
            authenticated_data,
        );

        let (_, signer) = self
            .config
            .keychain()
            .default_identity(group_cipher_suite)
            .ok_or(ExternalClientError::NoCredentialFound)?;

        let signing_context = MessageSigningContext {
            group_context: None,
            encrypted: false,
        };

        message.sign(&signer, &signing_context)?;

        let message = MLSMessage {
            version,
            payload: MLSMessagePayload::Plain(message),
        };
        Ok(message.tls_serialize_detached()?)
    }
}

#[cfg(test)]
pub(crate) mod test_utils {
    use crate::{
        cipher_suite::CipherSuite, keychain::test_utils::get_test_signing_identity,
        InMemoryExternalClientConfig,
    };

    pub fn get_basic_external_config(
        cipher_suite: CipherSuite,
        identity: &str,
    ) -> InMemoryExternalClientConfig {
        let (signing_identity, secret_key) =
            get_test_signing_identity(cipher_suite, identity.as_bytes().to_vec());

        InMemoryExternalClientConfig::default().with_signing_identity(signing_identity, secret_key)
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        client::test_utils::{
            create_session, get_basic_config, test_client_with_key_pkg, TEST_CIPHER_SUITE,
            TEST_GROUP, TEST_PROTOCOL_VERSION,
        },
        client_config::InMemoryClientConfig,
        external_client::test_utils::get_basic_external_config,
        group::proposal::{AddProposal, Proposal, RemoveProposal},
        key_package::KeyPackageGeneration,
        keychain::Keychain,
        message::ProcessedMessagePayload,
        session::Session,
        ExternalClient, ExternalClientConfig, InMemoryExternalClientConfig,
    };

    #[cfg(target_arch = "wasm32")]
    use wasm_bindgen_test::wasm_bindgen_test as test;

    struct PreconfiguredEnv {
        ted: ExternalClient<InMemoryExternalClientConfig>,
        bob_key_gen: KeyPackageGeneration,
        alice_session: Session<InMemoryClientConfig>,
    }

    impl PreconfiguredEnv {
        fn new() -> Self {
            const TED_EXTERNAL_KEY_ID: &[u8] = b"ted";

            let ted_config = get_basic_external_config(TEST_CIPHER_SUITE, "ted")
                .with_external_key_id(TED_EXTERNAL_KEY_ID.to_vec());

            let ted = ted_config.clone().build_client();

            let (ted_credential, _) = ted_config
                .keychain()
                .default_identity(TEST_CIPHER_SUITE)
                .unwrap();

            let alice_config = get_basic_config(TEST_CIPHER_SUITE, "alice")
                .with_external_signing_key(
                    TED_EXTERNAL_KEY_ID.to_vec(),
                    ted_credential.public_key().unwrap(),
                );

            let alice_session = create_session(&alice_config.build_client());

            let (_, bob_key_gen) =
                test_client_with_key_pkg(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE, "bob");

            PreconfiguredEnv {
                ted,
                bob_key_gen,
                alice_session,
            }
        }
    }

    #[test]
    fn preconfigured_add_proposal_adds_to_group() {
        let mut env = PreconfiguredEnv::new();
        let proposal = AddProposal {
            key_package: env.bob_key_gen.key_package.clone(),
        };
        let msg = env
            .ted
            .propose_add_from_preconfigured(
                TEST_PROTOCOL_VERSION,
                TEST_CIPHER_SUITE,
                TEST_GROUP.to_vec(),
                proposal.clone(),
                env.alice_session.group_stats().unwrap().epoch,
                vec![],
            )
            .unwrap();
        let msg = env.alice_session.process_incoming_bytes(&msg).unwrap();
        let received_proposal = match msg.message {
            ProcessedMessagePayload::Proposal(Proposal::Add(p)) if p == proposal => {
                Proposal::Add(p)
            }
            m => panic!("Expected {:?} but got {:?}", proposal, m),
        };
        let _ = env
            .alice_session
            .commit(vec![received_proposal], vec![])
            .unwrap();
        let state_update = env.alice_session.apply_pending_commit().unwrap();

        let expected_ref = env
            .bob_key_gen
            .key_package
            .leaf_node
            .to_reference(TEST_CIPHER_SUITE)
            .unwrap();

        assert!(state_update.added.iter().any(|r| *r == expected_ref));
    }

    #[test]
    fn preconfigured_remove_proposal_removes_from_group() {
        let mut env = PreconfiguredEnv::new();

        let _ = env
            .alice_session
            .commit(
                vec![Proposal::Add(AddProposal {
                    key_package: env.bob_key_gen.key_package.clone(),
                })],
                vec![],
            )
            .unwrap();

        let _ = env.alice_session.apply_pending_commit().unwrap();

        assert!(env
            .alice_session
            .roster()
            .iter()
            .any(|&p| *p == env.bob_key_gen.key_package.leaf_node));

        let bob_leaf_ref = env
            .bob_key_gen
            .key_package
            .leaf_node
            .to_reference(TEST_CIPHER_SUITE)
            .unwrap();

        let proposal = RemoveProposal {
            to_remove: bob_leaf_ref,
        };

        let msg = env
            .ted
            .propose_remove_from_preconfigured(
                TEST_PROTOCOL_VERSION,
                TEST_CIPHER_SUITE,
                TEST_GROUP.to_vec(),
                proposal.clone(),
                env.alice_session.group_stats().unwrap().epoch,
                vec![],
            )
            .unwrap();

        let msg = env.alice_session.process_incoming_bytes(&msg).unwrap();

        let _ = match msg.message {
            ProcessedMessagePayload::Proposal(Proposal::Remove(p)) if p == proposal => {
                Proposal::Remove(p)
            }
            m => panic!("Expected {:?} but got {:?}", proposal, m),
        };

        let _ = env.alice_session.commit(Vec::new(), Vec::new()).unwrap();

        let state_update = env.alice_session.apply_pending_commit().unwrap();

        assert!(state_update
            .removed
            .iter()
            .any(|p| *p == env.bob_key_gen.key_package.leaf_node));
    }
}
