use crate::cipher_suite::CipherSuite;
use crate::client_config::{ClientConfig, DefaultClientConfig, KeyPackageRepository};
use crate::credential::{BasicCredential, Credential, CredentialError};
use crate::extension::{CapabilitiesExt, ExtensionError, ExtensionList, LifetimeExt, MlsExtension};
use crate::group::framing::{Content, MLSMessage, MLSPlaintext, Sender};
use crate::group::message_signature::MessageSignatureError;
use crate::group::proposal::{AddProposal, Proposal, RemoveProposal};
use crate::key_package::{
    KeyPackage, KeyPackageGeneration, KeyPackageGenerationError, KeyPackageGenerator, KeyPackageRef,
};
use crate::session::{Session, SessionError};
use ferriscrypt::asym::ec_key::{Curve, EcKeyError, SecretKey};
use thiserror::Error;
use tls_codec::Serialize;

#[derive(Error, Debug)]
pub enum ClientError {
    #[error(transparent)]
    ExtensionError(#[from] ExtensionError),
    #[error(transparent)]
    EcKeyError(#[from] EcKeyError),
    #[error(transparent)]
    KeyPackageGenerationError(#[from] KeyPackageGenerationError),
    #[error(transparent)]
    SessionError(#[from] SessionError),
    #[error(transparent)]
    CredentialError(#[from] CredentialError),
    #[error("signature key provided does not match the selected cipher suite")]
    SignatureCipherSuiteMismatch,
    #[error("the secret key provided does not match the public key in the credential")]
    IncorrectSecretKey,
    #[error(transparent)]
    SerializationError(#[from] tls_codec::Error),
    #[error(transparent)]
    MessageSignatureError(#[from] MessageSignatureError),
    #[error("proposing as external without external key ID")]
    ProposingAsExternalWithoutExternalKeyId,
    #[error(transparent)]
    KeyPackageRepoError(Box<dyn std::error::Error + Send + Sync>),
}

#[non_exhaustive]
#[derive(Clone, Debug)]
pub struct Client<C = DefaultClientConfig> {
    pub cipher_suite: CipherSuite,
    pub signature_key: SecretKey,
    pub credential: Credential,
    pub capabilities: CapabilitiesExt,
    pub config: C,
}

impl<C: ClientConfig + Clone> Client<C> {
    pub fn new(
        cipher_suite: CipherSuite,
        signature_key: SecretKey,
        credential: Credential,
        config: C,
    ) -> Result<Self, ClientError> {
        if signature_key.curve() != Curve::from(cipher_suite.signature_scheme()) {
            return Err(ClientError::SignatureCipherSuiteMismatch);
        }

        if credential.public_key()? != signature_key.to_public()? {
            return Err(ClientError::IncorrectSecretKey);
        }

        Ok(Client {
            cipher_suite,
            signature_key,
            credential,
            capabilities: CapabilitiesExt::default(),
            config,
        })
    }

    pub fn generate_basic(
        cipher_suite: CipherSuite,
        identifier: Vec<u8>,
        config: C,
    ) -> Result<Self, ClientError> {
        let signature_key = SecretKey::generate(Curve::from(cipher_suite.signature_scheme()))?;
        let credential = Credential::Basic(BasicCredential::new(
            identifier,
            signature_key.to_public()?,
        )?);
        Client::new(cipher_suite, signature_key, credential, config)
    }

    pub fn gen_key_package(
        &self,
        lifetime: LifetimeExt,
    ) -> Result<KeyPackageGeneration, ClientError> {
        let key_package_generator = KeyPackageGenerator {
            cipher_suite: self.cipher_suite,
            signing_key: &self.signature_key,
            credential: &self.credential,
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
            self.capabilities.to_extension()?,
            lifetime.to_extension()?,
        ]);

        Ok(extensions)
    }

    pub fn create_session(
        &self,
        lifetime: LifetimeExt,
        group_id: Vec<u8>,
        group_context_extensions: ExtensionList,
    ) -> Result<Session<C>, ClientError> {
        let key_package_generator = KeyPackageGenerator {
            cipher_suite: self.cipher_suite,
            credential: &self.credential,
            extensions: &self.get_extensions(lifetime)?,
            signing_key: &self.signature_key,
        };

        Session::create(
            group_id,
            self.signature_key.clone(),
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
        Session::join(
            self.signature_key.clone(),
            key_package,
            tree_data,
            welcome_message,
            self.config.clone(),
        )
        .map_err(Into::into)
    }

    pub fn propose_add_from_new_member(
        &self,
        group_id: Vec<u8>,
        key_package: KeyPackage,
        epoch: u64,
    ) -> Result<Vec<u8>, ClientError> {
        self.propose_from_external(
            group_id,
            Sender::NewMember,
            Proposal::Add(AddProposal { key_package }),
            epoch,
        )
    }

    pub fn propose_add_from_preconfigured(
        &self,
        group_id: Vec<u8>,
        proposal: AddProposal,
        epoch: u64,
    ) -> Result<Vec<u8>, ClientError> {
        self.propose_from_external(
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
        group_id: Vec<u8>,
        proposal: RemoveProposal,
        epoch: u64,
    ) -> Result<Vec<u8>, ClientError> {
        self.propose_from_external(
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
        group_id: Vec<u8>,
        sender: Sender,
        proposal: Proposal,
        epoch: u64,
    ) -> Result<Vec<u8>, ClientError> {
        let mut message = MLSPlaintext::new(group_id, epoch, sender, Content::Proposal(proposal));
        message.sign(&self.signature_key, None, false)?;
        let message = MLSMessage::Plain(message);
        Ok(message.tls_serialize_detached()?)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{
        client_config::InMemorySecretStore,
        credential::BasicCredential,
        group::{GroupError, ProcessedMessage},
        psk::{ExternalPskId, PskSecretError},
    };
    use assert_matches::assert_matches;
    use ferriscrypt::{asym::ec_key::Curve, kdf::hkdf::Hkdf, rand::SecureRng};
    use tls_codec::Serialize;

    #[cfg(target_arch = "wasm32")]
    use wasm_bindgen_test::{wasm_bindgen_test as test, wasm_bindgen_test_configure};

    #[cfg(target_arch = "wasm32")]
    wasm_bindgen_test_configure!(run_in_browser);

    const TEST_CIPHER_SUITE: CipherSuite = CipherSuite::Curve25519Aes128V1;
    const TEST_GROUP: &[u8] = b"group";

    struct TestClientBuilder<C = DefaultClientConfig> {
        identity: Vec<u8>,
        cipher_suite: Option<CipherSuite>,
        signing_key: Option<SecretKey>,
        config: C,
    }

    impl TestClientBuilder<DefaultClientConfig> {
        fn new(identity: Vec<u8>) -> Self {
            TestClientBuilder {
                identity,
                cipher_suite: None,
                signing_key: None,
                config: DefaultClientConfig::default(),
            }
        }

        fn named(s: &str) -> Self {
            Self::new(s.as_bytes().to_vec())
        }
    }

    impl<C: ClientConfig + Clone> TestClientBuilder<C> {
        fn with_cipher_suite(self, cipher_suite: CipherSuite) -> Self {
            Self {
                cipher_suite: Some(cipher_suite),
                ..self
            }
        }

        fn with_signing_key(self, signing_key: SecretKey) -> Self {
            Self {
                signing_key: Some(signing_key),
                ..self
            }
        }

        fn with_config<D>(self, config: D) -> TestClientBuilder<D>
        where
            D: ClientConfig + Clone,
        {
            TestClientBuilder {
                identity: self.identity,
                cipher_suite: self.cipher_suite,
                signing_key: self.signing_key,
                config,
            }
        }

        fn build(self) -> Client<C> {
            let cipher_suite = self.cipher_suite.unwrap_or(TEST_CIPHER_SUITE);
            let signature_key = self.signing_key.unwrap_or_else(|| {
                SecretKey::generate(Curve::from(cipher_suite.signature_scheme())).unwrap()
            });
            let credential = get_test_credential(self.identity, &signature_key);
            Client::new(cipher_suite, signature_key, credential, self.config).unwrap()
        }

        fn build_with_key_pkg(self) -> (Client<C>, KeyPackageGeneration) {
            let client = self.build();
            let gen = client
                .gen_key_package(LifetimeExt::years(1).unwrap())
                .unwrap();
            (client, gen)
        }
    }

    fn get_test_credential(identity: Vec<u8>, signature_key: &SecretKey) -> Credential {
        Credential::Basic(
            BasicCredential::new(identity, signature_key.to_public().unwrap()).unwrap(),
        )
    }

    fn get_test_client(identity: Vec<u8>, cipher_suite: CipherSuite) -> Client {
        TestClientBuilder::new(identity)
            .with_cipher_suite(cipher_suite)
            .build()
    }

    #[test]
    fn test_construction() {
        for cipher_suite in CipherSuite::all() {
            println!("Running client construction for {:?}", cipher_suite);
            let identity = SecureRng::gen(42).unwrap();
            let test_client = get_test_client(identity, cipher_suite);
            assert_eq!(test_client.cipher_suite, cipher_suite);
            assert_eq!(test_client.capabilities, CapabilitiesExt::default());
            assert_eq!(
                test_client
                    .credential
                    .public_key()
                    .unwrap()
                    .to_uncompressed_bytes()
                    .unwrap(),
                test_client
                    .signature_key
                    .to_public()
                    .unwrap()
                    .to_uncompressed_bytes()
                    .unwrap()
            );
        }
    }

    #[test]
    fn test_bad_sig_key() {
        // Signature key is P256 but cipher suite expects Ed25519
        let sig_key = SecretKey::generate(Curve::P256).unwrap();
        let credential = get_test_credential(vec![], &sig_key);
        let client_res = Client::new(
            CipherSuite::Curve25519Aes128V1,
            sig_key,
            credential,
            DefaultClientConfig::default(),
        );
        assert!(client_res.is_err());
    }

    #[test]
    fn test_bad_credential() {
        let sig_key = SecretKey::generate(Curve::P256).unwrap();
        let other_sig_key = SecretKey::generate(Curve::Ed25519).unwrap();

        let credential = Credential::Basic(
            BasicCredential::new(vec![], other_sig_key.to_public().unwrap()).unwrap(),
        );

        let client_res = Client::new(
            CipherSuite::P256Aes128V1,
            sig_key,
            credential,
            DefaultClientConfig::default(),
        );
        assert!(client_res.is_err());
    }

    #[test]
    fn test_keygen() {
        // This is meant to test the inputs to the internal key package generator
        // See KeyPackageGenerator tests for key generation specific tests
        for cipher_suite in CipherSuite::all() {
            println!("Running client keygen for {:?}", cipher_suite);

            let cred_identity = SecureRng::gen(42).unwrap();
            let client = get_test_client(cred_identity, cipher_suite);
            let key_lifetime = LifetimeExt::years(1).unwrap();
            let package_gen = client.gen_key_package(key_lifetime.clone()).unwrap();

            assert_eq!(package_gen.key_package.cipher_suite, cipher_suite);

            assert_matches!(package_gen.key_package.credential, Credential::Basic(_));

            assert_eq!(
                package_gen
                    .key_package
                    .credential
                    .tls_serialize_detached()
                    .unwrap(),
                client.credential.tls_serialize_detached().unwrap()
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

            let capabilities: Option<CapabilitiesExt> =
                package_gen.key_package.extensions.get_extension().unwrap();
            assert_eq!(capabilities, Some(client.capabilities));
        }
    }

    #[test]
    fn new_member_add_proposal_adds_to_group() {
        let alice = TestClientBuilder::named("alice").build();

        let mut session = create_session(&alice);
        let (bob, bob_key_gen) = TestClientBuilder::named("bob").build_with_key_pkg();
        let proposal = bob
            .propose_add_from_new_member(
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
        ted: Client,
        bob_key_gen: KeyPackageGeneration,
        alice_session: Session,
    }

    impl PreconfiguredEnv {
        fn new() -> Self {
            const TED_EXTERNAL_KEY_ID: &[u8] = b"ted";
            let ted_signing_key =
                SecretKey::generate(Curve::from(TEST_CIPHER_SUITE.signature_scheme())).unwrap();
            let ted = TestClientBuilder::named("ted")
                .with_signing_key(ted_signing_key.clone())
                .with_config(
                    DefaultClientConfig::default()
                        .with_external_key_id(TED_EXTERNAL_KEY_ID.to_vec()),
                )
                .build();
            let alice = TestClientBuilder::named("alice")
                .with_config(DefaultClientConfig::default().with_external_signing_key(
                    TED_EXTERNAL_KEY_ID.to_vec(),
                    ted_signing_key.to_public().unwrap(),
                ))
                .build();
            let alice_session = create_session(&alice);
            let (_, bob_key_gen) = TestClientBuilder::named("bob").build_with_key_pkg();
            PreconfiguredEnv {
                ted,
                bob_key_gen,
                alice_session,
            }
        }
    }

    fn create_session(client: &Client) -> Session {
        client
            .create_session(
                LifetimeExt::years(1).unwrap(),
                TEST_GROUP.to_vec(),
                ExtensionList::new(),
            )
            .unwrap()
    }

    fn join_session<'a, S>(
        committer_session: &mut Session,
        other_sessions: S,
        key_package: KeyPackage,
        client: &Client,
    ) -> Session
    where
        S: IntoIterator<Item = &'a mut Session>,
    {
        let key_package_ref = key_package.to_reference().unwrap();

        let commit_result = committer_session
            .commit(vec![Proposal::Add(AddProposal { key_package })])
            .unwrap();

        committer_session.apply_pending_commit().unwrap();

        for session in other_sessions {
            session
                .process_incoming_bytes(&commit_result.commit_packet)
                .unwrap();
        }

        client
            .join_session(
                Some(&key_package_ref),
                Some(&committer_session.export_tree().unwrap()),
                &commit_result.welcome_packet.unwrap(),
            )
            .unwrap()
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
        let ted = TestClientBuilder::named("ted").build();
        let alice = TestClientBuilder::named("alice").build();
        let mut session = create_session(&alice);
        let (_, bob_key_gen) = TestClientBuilder::named("bob").build_with_key_pkg();
        let msg = ted
            .propose_add_from_new_member(
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
        let alice = TestClientBuilder::named("alice")
            .with_config(DefaultClientConfig::default().with_proposal_filter(|_| Err("no")))
            .build();
        let mut session = create_session(&alice);
        let (bob, bob_key_gen) = TestClientBuilder::named("bob").build_with_key_pkg();
        let proposal = bob
            .propose_add_from_new_member(
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
        let secret_store = InMemorySecretStore::default();
        secret_store.insert(
            expected_id.clone(),
            vec![1; Hkdf::from(TEST_CIPHER_SUITE.kdf_type()).extract_size()].into(),
        );
        let alice = TestClientBuilder::named("alice")
            .with_config(DefaultClientConfig::default().with_secret_store(secret_store))
            .build();
        let mut session = create_session(&alice);
        let proposal = session.psk_proposal(expected_id).unwrap();
        let res = session.commit(vec![proposal]);
        assert_matches!(res, Ok(_));
    }

    #[test]
    fn psk_id_in_psk_proposal_must_be_known() {
        let alice = TestClientBuilder::named("alice").build();
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
        let alice = TestClientBuilder::named("alice").build();
        let mut alice_session = create_session(&alice);
        let (bob, bob_key_pkg_gen) = TestClientBuilder::named("bob").build_with_key_pkg();

        let mut bob_session = join_session(
            &mut alice_session,
            [],
            bob_key_pkg_gen.key_package.into(),
            &bob,
        );

        let (carol, carol_key_pkg_gen) = TestClientBuilder::named("carol").build_with_key_pkg();
        let carol_key_pkg_ref = carol_key_pkg_gen.key_package.to_reference().unwrap();

        let carol_session = join_session(
            &mut alice_session,
            [&mut bob_session],
            carol_key_pkg_gen.key_package.into(),
            &carol,
        );

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
            carol_session.join_subgroup(
                welcome.clone(),
                Some(&alice_sub_session.export_tree().unwrap()),
            ),
            Err(_)
        );
    }
}
