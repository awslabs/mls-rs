use crate::cipher_suite::CipherSuite;
use crate::client_config::ClientConfig;
use crate::credential::CredentialError;
use crate::extension::{ExtensionError, ExtensionList};
use crate::group::framing::{Content, MLSMessage, MLSMessagePayload, MLSPlaintext, Sender};
use crate::group::message_signature::MessageSigningContext;
use crate::group::proposal::{AddProposal, Proposal};
use crate::group::{GroupContext, GroupState};
use crate::key_package::{
    KeyPackage, KeyPackageGeneration, KeyPackageGenerationError, KeyPackageGenerator,
    KeyPackageRef, KeyPackageRepository,
};
use crate::session::{Session, SessionError};
use crate::signer::{Signable, SignatureError};
use crate::tree_kem::leaf_node::{LeafNode, LeafNodeError};
use crate::{keychain::Keychain, ProtocolVersion};
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
    #[error(transparent)]
    KeyPackageRepoError(Box<dyn std::error::Error + Send + Sync>),
    #[error(transparent)]
    LeafNodeError(#[from] LeafNodeError),
    #[error("Expected group info message")]
    ExpectedGroupInfoMessage,
}

#[non_exhaustive]
#[derive(Clone, Debug)]
pub struct Client<C: ClientConfig> {
    pub config: C,
}

impl<C> Client<C>
where
    C: ClientConfig + Clone,
{
    pub fn new(config: C) -> Self {
        Client { config }
    }

    pub fn gen_key_package(
        &self,
        protocol_version: ProtocolVersion,
        cipher_suite: CipherSuite,
    ) -> Result<KeyPackageGeneration, ClientError> {
        let (identity, signer) = self
            .config
            .keychain()
            .default_identity(cipher_suite)
            .ok_or(ClientError::NoCredentialFound)?;

        let key_package_generator = KeyPackageGenerator {
            protocol_version,
            cipher_suite,
            signing_key: &signer,
            signing_identity: &identity,
        };

        let key_pkg_gen = key_package_generator.generate(
            self.config.lifetime(),
            self.config.capabilities(),
            self.config.key_package_extensions(),
            self.config.leaf_node_extensions(),
        )?;

        self.config
            .key_package_repo()
            .insert(key_pkg_gen.clone())
            .map_err(|e| ClientError::KeyPackageRepoError(e.into()))?;

        Ok(key_pkg_gen)
    }

    pub fn create_session(
        &self,
        protocol_version: ProtocolVersion,
        cipher_suite: CipherSuite,
        group_id: Vec<u8>,
        group_context_extensions: ExtensionList,
    ) -> Result<Session<C>, ClientError> {
        let keychain = self.config.keychain();

        let (identity, signer) = keychain
            .default_identity(cipher_suite)
            .ok_or(ClientError::NoCredentialFound)?;

        let (leaf_node, leaf_node_secret) = LeafNode::generate(
            cipher_suite,
            identity,
            self.config.capabilities(),
            self.config.leaf_node_extensions(),
            &signer,
            self.config.lifetime(),
        )?;

        Session::create(
            group_id,
            cipher_suite,
            protocol_version,
            leaf_node,
            leaf_node_secret,
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

    /// Returns session and commit MLSMessage
    pub fn commit_external(
        &self,
        group_info_msg: MLSMessage,
        tree_data: Option<&[u8]>,
        authenticated_data: Vec<u8>,
    ) -> Result<(Session<C>, Vec<u8>), ClientError> {
        let group_info = match group_info_msg.payload {
            MLSMessagePayload::GroupInfo(g) => Ok(g),
            _ => Err(ClientError::ExpectedGroupInfoMessage),
        }?;

        let keychain = self.config.keychain();

        let (identity, signer) = keychain
            .default_identity(group_info.cipher_suite)
            .ok_or(ClientError::NoCredentialFound)?;

        let (leaf_node, leaf_node_secret) = LeafNode::generate(
            group_info.cipher_suite,
            identity,
            self.config.capabilities(),
            self.config.leaf_node_extensions(),
            &signer,
            self.config.lifetime(),
        )?;

        Ok(Session::new_external(
            self.config.clone(),
            group_info_msg.version,
            group_info,
            tree_data,
            leaf_node,
            leaf_node_secret,
            &signer,
            authenticated_data,
        )?)
    }

    pub fn import_session(&self, state: GroupState) -> Result<Session<C>, ClientError> {
        Ok(Session::import(self.config.clone(), state)?)
    }

    pub fn propose_add_from_new_member(
        &self,
        version: ProtocolVersion,
        group_cipher_suite: CipherSuite,
        group_context: GroupContext,
        key_package: KeyPackage,
        authenticated_data: Vec<u8>,
    ) -> Result<Vec<u8>, ClientError> {
        let mut message = MLSPlaintext::new(
            group_context.group_id.clone(),
            group_context.epoch,
            Sender::NewMember,
            Content::Proposal(Proposal::Add(AddProposal { key_package })),
            authenticated_data,
        );

        let (_, signer) = self
            .config
            .keychain()
            .default_identity(group_cipher_suite)
            .ok_or(ClientError::NoCredentialFound)?;

        let signing_context = MessageSigningContext {
            group_context: Some(&group_context),
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

    use super::*;
    use crate::{
        client_config::{InMemoryClientConfig, ONE_YEAR_IN_SECONDS},
        signing_identity::test_utils::get_test_signing_identity,
    };

    pub const TEST_PROTOCOL_VERSION: ProtocolVersion = ProtocolVersion::Mls10;
    pub const TEST_CIPHER_SUITE: CipherSuite = CipherSuite::Curve25519Aes128;
    pub const TEST_GROUP: &[u8] = b"group";

    pub fn get_basic_config(cipher_suite: CipherSuite, identity: &str) -> InMemoryClientConfig {
        let (signing_identity, secret_key) =
            get_test_signing_identity(cipher_suite, identity.as_bytes().to_vec());

        InMemoryClientConfig::default()
            .with_signing_identity(signing_identity, secret_key)
            .with_lifetime_duration(ONE_YEAR_IN_SECONDS)
    }

    pub fn test_client_with_key_pkg(
        protocol_version: ProtocolVersion,
        cipher_suite: CipherSuite,
        identity: &str,
    ) -> (Client<InMemoryClientConfig>, KeyPackageGeneration) {
        let client = get_basic_config(cipher_suite, identity).build_client();

        let gen = client
            .gen_key_package(protocol_version, cipher_suite)
            .unwrap();

        (client, gen)
    }

    pub fn create_session(client: &Client<InMemoryClientConfig>) -> Session<InMemoryClientConfig> {
        client
            .create_session(
                TEST_PROTOCOL_VERSION,
                TEST_CIPHER_SUITE,
                TEST_GROUP.to_vec(),
                ExtensionList::new(),
            )
            .unwrap()
    }
}

#[cfg(test)]
mod tests {
    use std::vec;

    use super::test_utils::*;

    use super::*;
    use crate::{
        client_config::{InMemoryClientConfig, SimpleError},
        credential::Credential,
        group::{
            epoch::EpochError,
            proposal::{AddProposal, Proposal},
            GroupError, SecretTreeError,
        },
        key_package::KeyPackage,
        message::ProcessedMessagePayload,
        psk::{ExternalPskId, PskSecretError},
        tree_kem::leaf_node::LeafNodeSource,
        ProposalBundle, ProposalFilter,
    };
    use assert_matches::assert_matches;
    use ferriscrypt::kdf::hkdf::Hkdf;
    use tls_codec::Serialize;

    #[cfg(target_arch = "wasm32")]
    use wasm_bindgen_test::wasm_bindgen_test as test;

    #[test]
    fn test_keygen() {
        // This is meant to test the inputs to the internal key package generator
        // See KeyPackageGenerator tests for key generation specific tests
        for (protocol_version, cipher_suite) in
            ProtocolVersion::all().flat_map(|p| CipherSuite::all().map(move |cs| (p, cs)))
        {
            println!("Running client keygen for {:?}", cipher_suite);

            let client = get_basic_config(cipher_suite, "foo").build_client();

            // TODO: Tests around extensions
            let package_gen = client
                .gen_key_package(protocol_version, cipher_suite)
                .unwrap();

            assert_eq!(package_gen.key_package.version, protocol_version);
            assert_eq!(package_gen.key_package.cipher_suite, cipher_suite);
            assert_matches!(&package_gen.key_package.leaf_node.signing_identity.credential, Credential::Basic(identity) if identity == "foo".as_bytes());

            let (expected_credential, _) = client
                .config
                .keychain()
                .default_identity(cipher_suite)
                .unwrap();

            assert_eq!(
                package_gen
                    .key_package
                    .leaf_node
                    .signing_identity
                    .tls_serialize_detached()
                    .unwrap(),
                expected_credential.tls_serialize_detached().unwrap()
            );

            let client_lifetime = client.config.lifetime();
            assert_matches!(package_gen.key_package.leaf_node.leaf_node_source, LeafNodeSource::KeyPackage(lifetime) if (lifetime.not_after - lifetime.not_before) == (client_lifetime.not_after - client_lifetime.not_before));

            let capabilities = package_gen.key_package.leaf_node.capabilities;
            assert_eq!(capabilities, client.config.capabilities());
        }
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
            committer_session.commit(vec![Proposal::Add(AddProposal { key_package })], vec![])?;

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
    fn new_member_add_proposal_adds_to_group() {
        let alice = get_basic_config(TEST_CIPHER_SUITE, "alice").build_client();

        let mut session = create_session(&alice);

        let (bob, bob_key_gen) =
            test_client_with_key_pkg(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE, "bob");

        let proposal = bob
            .propose_add_from_new_member(
                TEST_PROTOCOL_VERSION,
                TEST_CIPHER_SUITE,
                session.group_context(),
                bob_key_gen.key_package.clone(),
                vec![],
            )
            .unwrap();

        let message = session.process_incoming_bytes(&proposal).unwrap();

        assert_matches!(
            message.message,
            ProcessedMessagePayload::Proposal(Proposal::Add(AddProposal { key_package })) if key_package == bob_key_gen.key_package
        );

        let proposal = Proposal::Add(AddProposal {
            key_package: bob_key_gen.key_package.clone(),
        });

        let _ = session.commit(vec![proposal], vec![]).unwrap();
        let _ = session.apply_pending_commit().unwrap();

        // Check that the new member is in the group
        assert!(session
            .roster()
            .contains(&&bob_key_gen.key_package.leaf_node));
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
                session.group_context(),
                bob_key_gen.key_package,
                vec![],
            )
            .unwrap();

        let msg = session.process_incoming_bytes(&msg);
        assert!(msg.is_err());
    }

    struct RejectProposals;

    impl ProposalFilter for RejectProposals {
        type Error = SimpleError;

        fn validate(&self, _: &ProposalBundle) -> Result<(), Self::Error> {
            Err("No".into())
        }

        fn filter(&self, _: ProposalBundle) -> Result<ProposalBundle, Self::Error> {
            Ok(Default::default())
        }
    }

    #[test]
    fn proposal_can_be_rejected() {
        let alice = get_basic_config(TEST_CIPHER_SUITE, "alice")
            .with_proposal_filter(|_| RejectProposals)
            .build_client();

        let mut session = create_session(&alice);

        let (bob, bob_key_gen) =
            test_client_with_key_pkg(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE, "bob");

        let proposal = bob
            .propose_add_from_new_member(
                TEST_PROTOCOL_VERSION,
                TEST_CIPHER_SUITE,
                session.group_context(),
                bob_key_gen.key_package,
                vec![],
            )
            .unwrap();

        session.process_incoming_bytes(&proposal).unwrap();
        session.commit(Vec::new(), Vec::new()).unwrap();
        let res = session.apply_pending_commit();
        assert_matches!(
            res,
            Err(SessionError::ProtocolError(GroupError::ProposalCacheError(
                _
            )))
        );
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
        let res = session.commit(vec![proposal], vec![]);
        assert_matches!(res, Ok(_));
    }

    #[test]
    fn psk_id_in_psk_proposal_must_be_known() {
        let alice = get_basic_config(TEST_CIPHER_SUITE, "alice").build_client();
        let mut session = create_session(&alice);
        let expected_id = ExternalPskId(vec![1]);
        let proposal = session.psk_proposal(expected_id.clone()).unwrap();
        let res = session.commit(vec![proposal], vec![]);

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

        let bob_leaf_node = bob_key_pkg_gen.key_package.leaf_node.clone();

        let mut bob_session =
            join_session(&mut alice_session, [], bob_key_pkg_gen.key_package, &bob).unwrap();

        let (carol, carol_key_pkg_gen) =
            test_client_with_key_pkg(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE, "carol");

        let carol_session = join_session(
            &mut alice_session,
            [&mut bob_session],
            carol_key_pkg_gen.key_package,
            &carol,
        )
        .unwrap();

        let bob_sub_key_pkg = bob
            .gen_key_package(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE)
            .unwrap();

        let (alice_sub_session, welcome) = alice_session
            .branch(b"subgroup".to_vec(), None, |p| {
                if p == &bob_leaf_node {
                    Some(bob_sub_key_pkg.key_package.clone())
                } else {
                    None
                }
            })
            .unwrap();

        let welcome = welcome.unwrap();

        assert_matches!(
            bob_session.join_subgroup(
                None,
                welcome.clone(),
                Some(&alice_sub_session.export_tree().unwrap()),
            ),
            Ok(_)
        );

        assert_matches!(
            carol_session.join_subgroup(
                None,
                welcome,
                Some(&alice_sub_session.export_tree().unwrap())
            ),
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
            .gen_key_package(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE)
            .unwrap()
            .key_package;

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
        let _ = alice_session.commit(Vec::new(), Vec::new()).unwrap();
        alice_session.apply_pending_commit().unwrap();

        let group_info_msg = alice_session.group_info_message().unwrap();
        let bob = get_basic_config(TEST_CIPHER_SUITE, "bob").build_client();

        let (mut bob_session, external_commit) = bob
            .commit_external(
                group_info_msg,
                Some(&alice_session.export_tree().unwrap()),
                vec![],
            )
            .unwrap();

        assert!(bob_session.participant_count() == 2);

        let _ = alice_session
            .process_incoming_bytes(&external_commit)
            .unwrap();

        assert!(alice_session.participant_count() == 2);

        let alice_msg = b"I'm Alice";
        let msg = alice_session
            .encrypt_application_data(alice_msg, vec![])
            .unwrap();

        let received = bob_session.process_incoming_bytes(&msg).unwrap();
        assert_matches!(received.message, ProcessedMessagePayload::Application(bytes) if bytes == alice_msg);

        let bob_msg = b"I'm Bob";

        let msg = bob_session
            .encrypt_application_data(bob_msg, vec![])
            .unwrap();
        let received = alice_session.process_incoming_bytes(&msg).unwrap();

        assert_matches!(received.message, ProcessedMessagePayload::Application(bytes) if bytes == bob_msg);
    }

    #[test]
    fn member_can_see_sender_creds() {
        let alice = get_basic_config(TEST_CIPHER_SUITE, "alice").build_client();
        let mut alice_session = create_session(&alice);

        let (bob, bob_key_pkg) =
            test_client_with_key_pkg(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE, "bob");
        let mut bob_session =
            join_session(&mut alice_session, [], bob_key_pkg.key_package, &bob).unwrap();

        let bob_msg = b"I'm Bob";
        let bob_cred = bob_session
            .current_key_package()
            .unwrap()
            .signing_identity
            .clone();

        let msg = bob_session
            .encrypt_application_data(bob_msg, vec![])
            .unwrap();
        let received_by_alice = alice_session.process_incoming_bytes(&msg).unwrap();

        assert_eq!(
            Some(bob_cred.credential),
            received_by_alice.sender_credential
        );
    }

    #[test]
    fn creating_an_external_commit_requires_a_group_info_message() {
        let alice = get_basic_config(TEST_CIPHER_SUITE, "alice").build_client();

        let msg = MLSMessage {
            version: TEST_PROTOCOL_VERSION,
            payload: MLSMessagePayload::KeyPackage(
                alice
                    .gen_key_package(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE)
                    .unwrap()
                    .key_package,
            ),
        };

        let res = alice.commit_external(msg, None, vec![]);

        assert_matches!(res, Err(ClientError::ExpectedGroupInfoMessage));
    }

    #[test]
    fn external_commit_with_invalid_group_info_fails() {
        let alice = get_basic_config(TEST_CIPHER_SUITE, "alice").build_client();
        let mut alice_session = create_session(&alice);

        // An external commit cannot be the first commit in a session as it requires
        // interim_transcript_hash to be computed from the confirmed_transcript_hash and
        // confirmation_tag, which is not the case for the initial interim_transcript_hash.
        let _ = alice_session.commit(Vec::new(), Vec::new()).unwrap();
        alice_session.apply_pending_commit().unwrap();

        let bob = get_basic_config(TEST_CIPHER_SUITE, "bob").build_client();
        let mut bob_session = create_session(&bob);

        // An external commit cannot be the first commit in a session as it requires
        // interim_transcript_hash to be computed from the confirmed_transcript_hash and
        // confirmation_tag, which is not the case for the initial interim_transcript_hash.
        let _ = bob_session.commit(Vec::new(), Vec::new()).unwrap();
        bob_session.apply_pending_commit().unwrap();

        let group_info_msg = bob_session.group_info_message().unwrap();

        let carol = get_basic_config(TEST_CIPHER_SUITE, "carol").build_client();

        let (_, external_commit) = carol
            .commit_external(
                group_info_msg,
                Some(&bob_session.export_tree().unwrap()),
                vec![],
            )
            .unwrap();

        // If Carol tries to join Alice's group using the group info from Bob's session, that fails.
        let res = alice_session.process_incoming_bytes(&external_commit);
        assert_matches!(res, Err(_));
    }

    #[test]
    fn members_of_a_group_have_identical_authentication_secrets() {
        let alice = get_basic_config(TEST_CIPHER_SUITE, "alice").build_client();
        let mut alice_session = create_session(&alice);

        let (bob, bob_key_pkg) =
            test_client_with_key_pkg(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE, "bob");
        let bob_session =
            join_session(&mut alice_session, [], bob_key_pkg.key_package, &bob).unwrap();

        assert_eq!(
            alice_session.authentication_secret().unwrap(),
            bob_session.authentication_secret().unwrap()
        );
    }

    #[test]
    fn saved_session_can_be_resumed() {
        let alice = get_basic_config(TEST_CIPHER_SUITE, "alice").build_client();
        let mut alice_session = create_session(&alice);

        let (bob, bob_key_pkg) =
            test_client_with_key_pkg(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE, "bob");
        let mut bob_session =
            join_session(&mut alice_session, [], bob_key_pkg.key_package, &bob).unwrap();

        // Commit so that Bob's session records a new epoch.
        let commit = bob_session.commit(Vec::new(), Vec::new()).unwrap();
        bob_session.apply_pending_commit().unwrap();
        alice_session
            .process_incoming_bytes(&commit.commit_packet)
            .unwrap();

        let bob_session_bytes = serde_json::to_vec(&bob_session.export()).unwrap();

        let mut bob_session = bob
            .import_session(serde_json::from_slice(&bob_session_bytes).unwrap())
            .unwrap();

        let message = alice_session
            .encrypt_application_data(b"hello", vec![])
            .unwrap();
        let received_message = bob_session.process_incoming_bytes(&message).unwrap();

        assert_matches!(
            received_message.message,
            ProcessedMessagePayload::Application(bytes) if bytes == b"hello"
        );

        let commit = alice_session.commit(Vec::new(), Vec::new()).unwrap();
        alice_session.apply_pending_commit().unwrap();
        bob_session
            .process_incoming_bytes(&commit.commit_packet)
            .unwrap();

        assert_eq!(
            alice_session.group_stats().unwrap().epoch,
            bob_session.group_stats().unwrap().epoch
        );
    }

    #[test]
    fn member_cannot_decrypt_same_message_twice() {
        let alice = get_basic_config(TEST_CIPHER_SUITE, "alice").build_client();
        let mut alice_session = create_session(&alice);

        let (bob, bob_key_pkg) =
            test_client_with_key_pkg(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE, "bob");

        let mut bob_session =
            join_session(&mut alice_session, [], bob_key_pkg.key_package, &bob).unwrap();

        let message = alice_session
            .encrypt_application_data(b"foobar", Vec::new())
            .unwrap();

        let received_message = bob_session.process_incoming_bytes(&message).unwrap();

        assert_matches!(
            received_message.message,
            ProcessedMessagePayload::Application(data) if data == b"foobar"
        );

        let res = bob_session.process_incoming_bytes(&message);

        assert_matches!(
            res,
            Err(SessionError::ProtocolError(GroupError::EpochError(
                EpochError::SecretTreeError(SecretTreeError::KeyMissing(_))
            )))
        );
    }

    #[test]
    fn a_single_proposal_is_included_in_commit_when_multiple_add_proposals_share_same_hpke_key() {
        let alice = get_basic_config(TEST_CIPHER_SUITE, "alice").build_client();
        let mut alice_session = create_session(&alice);

        let (_, bob_key_pkg) =
            test_client_with_key_pkg(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE, "bob");

        let (alice, mut alice_key_pkg) =
            test_client_with_key_pkg(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE, "alice");

        alice_key_pkg.key_package.leaf_node.public_key =
            bob_key_pkg.key_package.leaf_node.public_key.clone();

        let (_, alice_signer) = alice
            .config
            .keychain()
            .default_identity(TEST_CIPHER_SUITE)
            .unwrap();

        alice_key_pkg
            .key_package
            .leaf_node
            .sign(&alice_signer, &None)
            .unwrap();
        alice_key_pkg.key_package.sign(&alice_signer, &()).unwrap();

        alice_session
            .commit(
                vec![
                    Proposal::Add(AddProposal {
                        key_package: bob_key_pkg.key_package,
                    }),
                    Proposal::Add(AddProposal {
                        key_package: alice_key_pkg.key_package,
                    }),
                ],
                Vec::new(),
            )
            .unwrap();

        let update = alice_session.apply_pending_commit().unwrap();

        assert_eq!(update.added.len(), 1);
    }

    #[test]
    fn a_single_proposal_is_included_in_commit_when_multiple_add_proposals_share_same_signature_key(
    ) {
        let alice = get_basic_config(TEST_CIPHER_SUITE, "alice").build_client();
        let mut alice_session = create_session(&alice);

        let bob = get_basic_config(TEST_CIPHER_SUITE, "bob").build_client();
        let bob_key_pkg = bob
            .gen_key_package(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE)
            .unwrap();
        let alice_key_pkg = bob
            .gen_key_package(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE)
            .unwrap();

        alice_session
            .commit(
                vec![
                    Proposal::Add(AddProposal {
                        key_package: bob_key_pkg.key_package,
                    }),
                    Proposal::Add(AddProposal {
                        key_package: alice_key_pkg.key_package,
                    }),
                ],
                Vec::new(),
            )
            .unwrap();

        let update = alice_session.apply_pending_commit().unwrap();

        assert_eq!(update.added.len(), 1);
    }
}
