use crate::cipher_suite::CipherSuite;
use crate::client_config::{ClientConfig, KeyPackageRepository, Keychain};
use crate::credential::CredentialError;
use crate::extension::{ExtensionError, ExtensionList, LifetimeExt, MlsExtension};
use crate::group::framing::{Content, MLSMessage, MLSMessagePayload, MLSPlaintext, Sender};
use crate::group::message_signature::MessageSigningContext;
use crate::group::proposal::{AddProposal, Proposal, RemoveProposal};
use crate::key_package::{
    KeyPackage, KeyPackageGeneration, KeyPackageGenerationError, KeyPackageGenerator, KeyPackageRef,
};
use crate::session::{Session, SessionError};
use crate::signer::{Signable, SignatureError};
use crate::ProtocolVersion;
use thiserror::Error;
use tls_codec::Serialize;

#[derive(Error, Debug)]
pub enum ClientError {
    #[error(transparent)]
    ExtensionError(#[from] ExtensionError),
    #[error(transparent)]
    KeyPackageGenerationError(#[from] KeyPackageGenerationError),
    #[error(transparent)]
    SessionError(#[from] SessionError),
    #[error(transparent)]
    CredentialError(#[from] CredentialError),
    #[error("credential not found for cipher suite")]
    NoCredentialFound,
    #[error("the secret key provided does not match the public key in the credential")]
    IncorrectSecretKey,
    #[error(transparent)]
    SerializationError(#[from] tls_codec::Error),
    #[error(transparent)]
    SignatureError(#[from] SignatureError),
    #[error("proposing as external without external key ID")]
    ProposingAsExternalWithoutExternalKeyId,
    #[error(transparent)]
    KeyPackageRepoError(Box<dyn std::error::Error + Send + Sync>),
    #[error("Expected group info message")]
    ExpectedGroupInfoMessage,
}

#[non_exhaustive]
#[derive(Clone, Debug)]
pub struct Client<C: ClientConfig> {
    pub config: C,
}

impl<C: ClientConfig + Clone> Client<C> {
    pub fn new(config: C) -> Self {
        Client { config }
    }

    pub fn gen_key_package(
        &self,
        protocol_version: ProtocolVersion,
        cipher_suite: CipherSuite,
        lifetime: LifetimeExt,
    ) -> Result<KeyPackageGeneration, ClientError> {
        let keychain = self.config.keychain();

        let (credential, signer) = keychain
            .default_credential(cipher_suite)
            .ok_or(ClientError::NoCredentialFound)?;

        let key_package_generator = KeyPackageGenerator {
            protocol_version,
            cipher_suite,
            signing_key: &signer,
            credential: &credential,
            extensions: &self.get_extensions(lifetime)?,
        };

        let key_pkg_gen = key_package_generator.generate(None)?;
        self.config
            .key_package_repo()
            .insert(key_pkg_gen.clone())
            .map_err(|e| ClientError::KeyPackageRepoError(e.into()))?;

        Ok(key_pkg_gen)
    }

    fn get_extensions(&self, lifetime: LifetimeExt) -> Result<ExtensionList, ClientError> {
        // TODO: There should be a way to configure additional extensions in the client that get
        // added to each generated key package
        let extensions = ExtensionList::from(vec![
            self.config.capabilities().to_extension()?,
            lifetime.to_extension()?,
        ]);

        Ok(extensions)
    }

    pub fn create_session(
        &self,
        protocol_version: ProtocolVersion,
        cipher_suite: CipherSuite,
        lifetime: LifetimeExt,
        group_id: Vec<u8>,
        group_context_extensions: ExtensionList,
    ) -> Result<Session<C>, ClientError> {
        let keychain = self.config.keychain();

        let (credential, signer) = keychain
            .default_credential(cipher_suite)
            .ok_or(ClientError::NoCredentialFound)?;

        let key_package_generator = KeyPackageGenerator {
            protocol_version,
            cipher_suite,
            credential: &credential,
            extensions: &self.get_extensions(lifetime)?,
            signing_key: &signer,
        };

        Session::create(
            group_id,
            key_package_generator,
            group_context_extensions,
            self.config.clone(),
        )
        .map_err(Into::into)
    }

    /// If `key_package` is specified, key package references listed in the welcome message will not
    /// be used to identify the key package to use.
    pub fn join_session(
        &self,
        key_package: Option<&KeyPackageRef>,
        tree_data: Option<&[u8]>,
        welcome_message: &[u8],
    ) -> Result<Session<C>, ClientError> {
        Session::join(key_package, tree_data, welcome_message, self.config.clone())
            .map_err(Into::into)
    }

    pub fn propose_add_from_new_member(
        &self,
        version: ProtocolVersion,
        group_cipher_suite: CipherSuite,
        group_id: Vec<u8>,
        key_package: KeyPackage,
        epoch: u64,
    ) -> Result<Vec<u8>, ClientError> {
        self.propose_from_external(
            version,
            group_cipher_suite,
            group_id,
            Sender::NewMember,
            Proposal::Add(AddProposal { key_package }),
            epoch,
        )
    }

    pub fn propose_add_from_preconfigured(
        &self,
        version: ProtocolVersion,
        group_cipher_suite: CipherSuite,
        group_id: Vec<u8>,
        proposal: AddProposal,
        epoch: u64,
    ) -> Result<Vec<u8>, ClientError> {
        self.propose_from_external(
            version,
            group_cipher_suite,
            group_id,
            Sender::Preconfigured(
                self.config
                    .external_key_id()
                    .ok_or(ClientError::ProposingAsExternalWithoutExternalKeyId)?,
            ),
            Proposal::Add(proposal),
            epoch,
        )
    }

    pub fn propose_remove_from_preconfigured(
        &self,
        version: ProtocolVersion,
        group_cipher_suite: CipherSuite,
        group_id: Vec<u8>,
        proposal: RemoveProposal,
        epoch: u64,
    ) -> Result<Vec<u8>, ClientError> {
        self.propose_from_external(
            version,
            group_cipher_suite,
            group_id,
            Sender::Preconfigured(
                self.config
                    .external_key_id()
                    .ok_or(ClientError::ProposingAsExternalWithoutExternalKeyId)?,
            ),
            Proposal::Remove(proposal),
            epoch,
        )
    }

    fn propose_from_external(
        &self,
        version: ProtocolVersion,
        group_cipher_suite: CipherSuite,
        group_id: Vec<u8>,
        sender: Sender,
        proposal: Proposal,
        epoch: u64,
    ) -> Result<Vec<u8>, ClientError> {
        let mut message = MLSPlaintext::new(group_id, epoch, sender, Content::Proposal(proposal));

        let (_, signer) = self
            .config
            .keychain()
            .default_credential(group_cipher_suite)
            .ok_or(ClientError::NoCredentialFound)?;

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

    /// Returns session and commit MLSMessage
    pub fn commit_external(
        &self,
        lifetime: LifetimeExt,
        group_info_msg: MLSMessage,
        tree_data: Option<&[u8]>,
    ) -> Result<(Session<C>, Vec<u8>), ClientError> {
        let group_info = match group_info_msg.payload {
            MLSMessagePayload::GroupInfo(g) => Ok(g),
            _ => Err(ClientError::ExpectedGroupInfoMessage),
        }?;

        let keychain = self.config.keychain();

        let (credential, signer) = keychain
            .default_credential(group_info.cipher_suite)
            .ok_or(ClientError::NoCredentialFound)?;

        let key_package_generator = KeyPackageGenerator {
            protocol_version: group_info_msg.version,
            cipher_suite: group_info.cipher_suite,
            credential: &credential,
            extensions: &self.get_extensions(lifetime)?,
            signing_key: &signer,
        };

        Ok(Session::new_external(
            self.config.clone(),
            group_info_msg.version,
            group_info,
            key_package_generator,
            tree_data,
        )?)
    }
}

#[cfg(test)]
pub(crate) mod test_util {

    use super::*;
    use crate::{
        client_config::InMemoryClientConfig,
        credential::{BasicCredential, Credential},
    };
    use ferriscrypt::asym::ec_key::SecretKey;

    pub const TEST_PROTOCOL_VERSION: ProtocolVersion = ProtocolVersion::Mls10;
    pub const TEST_CIPHER_SUITE: CipherSuite = CipherSuite::Curve25519Aes128V1;
    pub const TEST_GROUP: &[u8] = b"group";

    pub fn get_test_credential(
        cipher_suite: CipherSuite,
        identity: Vec<u8>,
    ) -> (Credential, SecretKey) {
        let key = cipher_suite.generate_secret_key().unwrap();

        let credential =
            Credential::Basic(BasicCredential::new(identity, key.to_public().unwrap()).unwrap());

        (credential, key)
    }

    pub fn get_basic_config(cipher_suite: CipherSuite, identity: &str) -> InMemoryClientConfig {
        let (credential, secret_key) =
            get_test_credential(cipher_suite, identity.as_bytes().to_vec());

        InMemoryClientConfig::default().with_credential(credential, secret_key)
    }

    pub fn test_client_with_key_pkg(
        protocol_version: ProtocolVersion,
        cipher_suite: CipherSuite,
        identity: &str,
    ) -> (Client<InMemoryClientConfig>, KeyPackageGeneration) {
        let client = get_basic_config(cipher_suite, identity).build_client();

        let gen = client
            .gen_key_package(
                protocol_version,
                cipher_suite,
                LifetimeExt::years(1).unwrap(),
            )
            .unwrap();

        (client, gen)
    }
}

#[cfg(test)]
mod test {
    use super::test_util::*;

    use super::*;
    use crate::{
        client_config::InMemoryClientConfig,
        credential::Credential,
        extension::CapabilitiesExt,
        group::{GroupError, ProcessedMessage},
        psk::{ExternalPskId, PskSecretError},
    };
    use assert_matches::assert_matches;
    use ferriscrypt::kdf::hkdf::Hkdf;
    use tls_codec::Serialize;

    #[cfg(target_arch = "wasm32")]
    use wasm_bindgen_test::{wasm_bindgen_test as test, wasm_bindgen_test_configure};

    #[cfg(target_arch = "wasm32")]
    wasm_bindgen_test_configure!(run_in_browser);

    #[test]
    fn test_keygen() {
        // This is meant to test the inputs to the internal key package generator
        // See KeyPackageGenerator tests for key generation specific tests
        for (protocol_version, cipher_suite) in
            ProtocolVersion::all().flat_map(|p| CipherSuite::all().map(move |cs| (p, cs)))
        {
            println!("Running client keygen for {:?}", cipher_suite);

            let client = get_basic_config(cipher_suite, "foo").build_client();
            let key_lifetime = LifetimeExt::years(1).unwrap();

            let package_gen = client
                .gen_key_package(protocol_version, cipher_suite, key_lifetime.clone())
                .unwrap();

            assert_eq!(package_gen.key_package.version, protocol_version);
            assert_eq!(package_gen.key_package.cipher_suite, cipher_suite);
            assert_matches!(&package_gen.key_package.credential, Credential::Basic(basic) if basic.identity == "foo".as_bytes().to_vec());

            let (expected_credential, _) = client
                .config
                .keychain()
                .default_credential(cipher_suite)
                .unwrap();

            assert_eq!(
                package_gen
                    .key_package
                    .credential
                    .tls_serialize_detached()
                    .unwrap(),
                expected_credential.tls_serialize_detached().unwrap()
            );

            assert_eq!(
                package_gen
                    .key_package
                    .extensions
                    .get_extension::<LifetimeExt>()
                    .unwrap()
                    .unwrap(),
                key_lifetime
            );

            let capabilities: CapabilitiesExt = package_gen
                .key_package
                .extensions
                .get_extension()
                .unwrap()
                .unwrap();

            assert_eq!(capabilities, client.config.capabilities());
        }
    }

    #[test]
    fn new_member_add_proposal_adds_to_group() {
        let alice = get_basic_config(TEST_CIPHER_SUITE, "alice").build_client();

        let mut session = create_session(&alice);

        let (bob, bob_key_gen) =
            test_client_with_key_pkg(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE, "bob");

        let proposal = bob
            .propose_add_from_new_member(
                TEST_PROTOCOL_VERSION,
                TEST_CIPHER_SUITE,
                TEST_GROUP.to_vec(),
                bob_key_gen.key_package.clone().into(),
                session.group_stats().unwrap().epoch,
            )
            .unwrap();

        let message = session.process_incoming_bytes(&proposal).unwrap();

        assert_matches!(
            message,
            ProcessedMessage::Proposal(Proposal::Add(AddProposal { key_package })) if key_package == bob_key_gen.key_package.clone().into()
        );

        let expected_proposal = AddProposal {
            key_package: bob_key_gen.key_package.clone().into(),
        };

        let proposal = match session.process_incoming_bytes(&proposal).unwrap() {
            ProcessedMessage::Proposal(Proposal::Add(p)) if p == expected_proposal => {
                Proposal::Add(p)
            }
            m => panic!("Expected {:?} but got {:?}", expected_proposal, m),
        };

        let _ = session.commit(vec![proposal]).unwrap();
        let state_update = session.apply_pending_commit().unwrap();
        let expected_ref = bob_key_gen.key_package.to_reference().unwrap();
        assert!(state_update.added.iter().any(|r| *r == expected_ref));
    }

    struct PreconfiguredEnv {
        ted: Client<InMemoryClientConfig>,
        bob_key_gen: KeyPackageGeneration,
        alice_session: Session<InMemoryClientConfig>,
    }

    impl PreconfiguredEnv {
        fn new() -> Self {
            const TED_EXTERNAL_KEY_ID: &[u8] = b"ted";

            let ted_config = get_basic_config(TEST_CIPHER_SUITE, "ted")
                .with_external_key_id(TED_EXTERNAL_KEY_ID.to_vec());

            let ted = ted_config.clone().build_client();

            let (ted_credential, _) = ted_config
                .keychain()
                .default_credential(TEST_CIPHER_SUITE)
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

    fn create_session(client: &Client<InMemoryClientConfig>) -> Session<InMemoryClientConfig> {
        client
            .create_session(
                TEST_PROTOCOL_VERSION,
                TEST_CIPHER_SUITE,
                LifetimeExt::years(1).unwrap(),
                TEST_GROUP.to_vec(),
                ExtensionList::new(),
            )
            .unwrap()
    }

    fn join_session<'a, S>(
        committer_session: &mut Session<InMemoryClientConfig>,
        other_sessions: S,
        key_package: KeyPackage,
        client: &Client<InMemoryClientConfig>,
    ) -> Result<Session<InMemoryClientConfig>, ClientError>
    where
        S: IntoIterator<Item = &'a mut Session<InMemoryClientConfig>>,
    {
        let key_package_ref = key_package.to_reference().unwrap();

        let commit_result =
            committer_session.commit(vec![Proposal::Add(AddProposal { key_package })])?;

        committer_session.apply_pending_commit()?;

        for session in other_sessions {
            session.process_incoming_bytes(&commit_result.commit_packet)?;
        }

        client.join_session(
            Some(&key_package_ref),
            Some(&committer_session.export_tree().unwrap()),
            &commit_result.welcome_packet.unwrap(),
        )
    }

    #[test]
    fn preconfigured_add_proposal_adds_to_group() {
        let mut env = PreconfiguredEnv::new();
        let proposal = AddProposal {
            key_package: env.bob_key_gen.key_package.clone().into(),
        };
        let msg = env
            .ted
            .propose_add_from_preconfigured(
                TEST_PROTOCOL_VERSION,
                TEST_CIPHER_SUITE,
                TEST_GROUP.to_vec(),
                proposal.clone(),
                env.alice_session.group_stats().unwrap().epoch,
            )
            .unwrap();
        let msg = env.alice_session.process_incoming_bytes(&msg).unwrap();
        let received_proposal = match msg {
            ProcessedMessage::Proposal(Proposal::Add(p)) if p == proposal => Proposal::Add(p),
            m => panic!("Expected {:?} but got {:?}", proposal, m),
        };
        let _ = env.alice_session.commit(vec![received_proposal]).unwrap();
        let state_update = env.alice_session.apply_pending_commit().unwrap();
        let expected_ref = env.bob_key_gen.key_package.to_reference().unwrap();
        assert!(state_update.added.iter().any(|r| *r == expected_ref));
    }

    #[test]
    fn preconfigured_remove_proposal_removes_from_group() {
        let mut env = PreconfiguredEnv::new();
        let _ = env
            .alice_session
            .commit(vec![Proposal::Add(AddProposal {
                key_package: env.bob_key_gen.key_package.clone().into(),
            })])
            .unwrap();
        let _ = env.alice_session.apply_pending_commit().unwrap();
        assert!(env
            .alice_session
            .roster()
            .iter()
            .any(|&p| *p == env.bob_key_gen.key_package.clone().into()));
        let bob_key_pkg_ref = env.bob_key_gen.key_package.to_reference().unwrap();
        let proposal = RemoveProposal {
            to_remove: bob_key_pkg_ref,
        };
        let msg = env
            .ted
            .propose_remove_from_preconfigured(
                TEST_PROTOCOL_VERSION,
                TEST_CIPHER_SUITE,
                TEST_GROUP.to_vec(),
                proposal.clone(),
                env.alice_session.group_stats().unwrap().epoch,
            )
            .unwrap();
        let msg = env.alice_session.process_incoming_bytes(&msg).unwrap();
        let _ = match msg {
            ProcessedMessage::Proposal(Proposal::Remove(p)) if p == proposal => Proposal::Remove(p),
            m => panic!("Expected {:?} but got {:?}", proposal, m),
        };
        let _ = env.alice_session.commit(Vec::new()).unwrap();
        let state_update = env.alice_session.apply_pending_commit().unwrap();
        assert!(state_update
            .removed
            .iter()
            .any(|p| *p == env.bob_key_gen.key_package.clone().into()));
    }

    #[test]
    fn proposal_from_unknown_external_is_rejected_by_members() {
        let ted = get_basic_config(TEST_CIPHER_SUITE, "ted").build_client();
        let alice = get_basic_config(TEST_CIPHER_SUITE, "alice").build_client();

        let mut session = create_session(&alice);

        let (_, bob_key_gen) =
            test_client_with_key_pkg(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE, "bob");

        let msg = ted
            .propose_add_from_new_member(
                TEST_PROTOCOL_VERSION,
                TEST_CIPHER_SUITE,
                TEST_GROUP.to_vec(),
                bob_key_gen.key_package.into(),
                session.group_stats().unwrap().epoch,
            )
            .unwrap();

        let msg = session.process_incoming_bytes(&msg);
        assert!(msg.is_err());
    }

    #[test]
    fn proposal_can_be_rejected() {
        let alice = get_basic_config(TEST_CIPHER_SUITE, "alice")
            .with_proposal_filter(|_| Err("no"))
            .build_client();

        let mut session = create_session(&alice);

        let (bob, bob_key_gen) =
            test_client_with_key_pkg(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE, "bob");

        let proposal = bob
            .propose_add_from_new_member(
                TEST_PROTOCOL_VERSION,
                TEST_CIPHER_SUITE,
                TEST_GROUP.to_vec(),
                bob_key_gen.key_package.into(),
                session.group_stats().unwrap().epoch,
            )
            .unwrap();

        let res = session.process_incoming_bytes(&proposal);
        assert_matches!(res, Err(SessionError::ProposalRejected(e)) if e.to_string() == "no");
    }

    #[test]
    fn psk_proposal_can_be_committed() {
        let expected_id = ExternalPskId(vec![1]);

        let alice = get_basic_config(TEST_CIPHER_SUITE, "alice")
            .with_psk(
                expected_id.clone(),
                vec![1; Hkdf::from(TEST_CIPHER_SUITE.kdf_type()).extract_size()].into(),
            )
            .build_client();

        let mut session = create_session(&alice);
        let proposal = session.psk_proposal(expected_id).unwrap();
        let res = session.commit(vec![proposal]);
        assert_matches!(res, Ok(_));
    }

    #[test]
    fn psk_id_in_psk_proposal_must_be_known() {
        let alice = get_basic_config(TEST_CIPHER_SUITE, "alice").build_client();
        let mut session = create_session(&alice);
        let expected_id = ExternalPskId(vec![1]);
        let proposal = session.psk_proposal(expected_id.clone()).unwrap();
        let res = session.commit(vec![proposal]);

        assert_matches!(
            res,
            Err(SessionError::ProtocolError(GroupError::PskSecretError(PskSecretError::NoPskForId(actual_id)))) if actual_id == expected_id
        );
    }

    #[test]
    fn only_selected_members_of_the_original_group_can_join_subgroup() {
        let alice = get_basic_config(TEST_CIPHER_SUITE, "alice").build_client();
        let mut alice_session = create_session(&alice);
        let (bob, bob_key_pkg_gen) =
            test_client_with_key_pkg(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE, "bob");

        let mut bob_session = join_session(
            &mut alice_session,
            [],
            bob_key_pkg_gen.key_package.into(),
            &bob,
        )
        .unwrap();

        let (carol, carol_key_pkg_gen) =
            test_client_with_key_pkg(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE, "carol");
        let carol_key_pkg_ref = carol_key_pkg_gen.key_package.to_reference().unwrap();

        let carol_session = join_session(
            &mut alice_session,
            [&mut bob_session],
            carol_key_pkg_gen.key_package.into(),
            &carol,
        )
        .unwrap();

        let (alice_sub_session, welcome) = alice_session
            .branch(b"subgroup".to_vec(), None, |r| *r != carol_key_pkg_ref)
            .unwrap();

        let welcome = welcome.unwrap();

        assert_matches!(
            bob_session.join_subgroup(
                welcome.clone(),
                Some(&alice_sub_session.export_tree().unwrap()),
            ),
            Ok(_)
        );

        assert_matches!(
            carol_session.join_subgroup(welcome, Some(&alice_sub_session.export_tree().unwrap())),
            Err(_)
        );
    }

    fn joining_group_fails_if_unsupported<F>(f: F)
    where
        F: FnOnce(InMemoryClientConfig) -> InMemoryClientConfig,
    {
        let alice = get_basic_config(TEST_CIPHER_SUITE, "alice").build_client();
        let mut alice_session = create_session(&alice);
        let bob = f(get_basic_config(TEST_CIPHER_SUITE, "bob")).build_client();
        let bob_key_pkg = bob
            .gen_key_package(
                TEST_PROTOCOL_VERSION,
                TEST_CIPHER_SUITE,
                LifetimeExt::years(1).unwrap(),
            )
            .unwrap()
            .key_package
            .into();
        let res = join_session(&mut alice_session, [], bob_key_pkg, &bob);
        assert_matches!(
            res,
            Err(ClientError::SessionError(SessionError::ProtocolError(
                GroupError::UnsupportedProtocolVersionOrCipherSuite(
                    TEST_PROTOCOL_VERSION,
                    TEST_CIPHER_SUITE
                )
            )))
        );
    }

    #[test]
    fn joining_group_fails_if_protocol_version_is_not_supported() {
        joining_group_fails_if_unsupported(|config| config.clear_protocol_versions());
    }

    #[test]
    fn joining_group_fails_if_cipher_suite_is_not_supported() {
        joining_group_fails_if_unsupported(|config| config.clear_cipher_suites());
    }

    #[test]
    fn new_member_can_join_via_external_commit() {
        let alice = get_basic_config(TEST_CIPHER_SUITE, "alice").build_client();
        let mut alice_session = create_session(&alice);

        // An external commit cannot be the first commit in a session as it requires
        // interim_transcript_hash to be computed from the confirmed_transcript_hash and
        // confirmation_tag, which is not the case for the initial interim_transcript_hash.
        let _ = alice_session.commit(Vec::new()).unwrap();
        alice_session.apply_pending_commit().unwrap();

        let group_info_msg = alice_session.group_info_message().unwrap();
        let bob = get_basic_config(TEST_CIPHER_SUITE, "bob").build_client();

        let (mut bob_session, external_commit) = bob
            .commit_external(
                LifetimeExt::years(1).unwrap(),
                group_info_msg,
                Some(&alice_session.export_tree().unwrap()),
            )
            .unwrap();

        assert!(bob_session.participant_count() == 2);

        let _ = alice_session
            .process_incoming_bytes(&external_commit)
            .unwrap();

        assert!(alice_session.participant_count() == 2);

        let alice_msg = b"I'm Alice";
        let msg = alice_session.encrypt_application_data(alice_msg).unwrap();

        let received = bob_session.process_incoming_bytes(&msg).unwrap();
        assert_matches!(received, ProcessedMessage::Application(bytes) if bytes == alice_msg);

        let bob_msg = b"I'm Bob";
        let msg = bob_session.encrypt_application_data(bob_msg).unwrap();

        let received = alice_session.process_incoming_bytes(&msg).unwrap();
        assert_matches!(received, ProcessedMessage::Application(bytes) if bytes == bob_msg);
    }

    #[test]
    fn creating_an_external_commit_requires_a_group_info_message() {
        let alice = get_basic_config(TEST_CIPHER_SUITE, "alice").build_client();

        let msg = MLSMessage {
            version: TEST_PROTOCOL_VERSION,
            payload: MLSMessagePayload::KeyPackage(
                alice
                    .gen_key_package(
                        TEST_PROTOCOL_VERSION,
                        TEST_CIPHER_SUITE,
                        LifetimeExt::years(1).unwrap(),
                    )
                    .unwrap()
                    .key_package
                    .into(),
            ),
        };

        let res = alice.commit_external(LifetimeExt::years(1).unwrap(), msg, None);
        assert_matches!(res, Err(ClientError::ExpectedGroupInfoMessage));
    }

    #[test]
    fn external_commit_with_invalid_group_info_fails() {
        let alice = get_basic_config(TEST_CIPHER_SUITE, "alice").build_client();
        let mut alice_session = create_session(&alice);

        // An external commit cannot be the first commit in a session as it requires
        // interim_transcript_hash to be computed from the confirmed_transcript_hash and
        // confirmation_tag, which is not the case for the initial interim_transcript_hash.
        let _ = alice_session.commit(Vec::new()).unwrap();
        alice_session.apply_pending_commit().unwrap();

        let bob = get_basic_config(TEST_CIPHER_SUITE, "bob").build_client();
        let mut bob_session = create_session(&bob);

        // An external commit cannot be the first commit in a session as it requires
        // interim_transcript_hash to be computed from the confirmed_transcript_hash and
        // confirmation_tag, which is not the case for the initial interim_transcript_hash.
        let _ = bob_session.commit(Vec::new()).unwrap();
        bob_session.apply_pending_commit().unwrap();

        let group_info_msg = bob_session.group_info_message().unwrap();

        let carol = get_basic_config(TEST_CIPHER_SUITE, "carol").build_client();

        let (_, external_commit) = carol
            .commit_external(
                LifetimeExt::years(1).unwrap(),
                group_info_msg,
                Some(&bob_session.export_tree().unwrap()),
            )
            .unwrap();

        // If Carol tries to join Alice's group using the group info from Bob's session, that fails.
        let res = alice_session.process_incoming_bytes(&external_commit);
        assert_matches!(res, Err(_));
    }
}
