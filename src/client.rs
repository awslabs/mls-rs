use crate::cipher_suite::CipherSuite;
use crate::client_config::ClientConfig;
use crate::credential::CredentialError;
use crate::extension::{ExtensionError, ExtensionList};
use crate::group::framing::{Content, MLSMessage, MLSMessagePayload, MLSPlaintext, Sender};
use crate::group::message_signature::MessageSigningContext;
use crate::group::proposal::{AddProposal, Proposal};
use crate::group::GroupState;
use crate::key_package::{
    KeyPackage, KeyPackageGenerationError, KeyPackageGenerator, KeyPackageRef, KeyPackageRepository,
};
use crate::session::{ExternalPskId, Session, SessionError};
use crate::signer::{Signable, SignatureError};
use crate::tree_kem::leaf_node::LeafNodeError;
use crate::{keychain::Keychain, ProtocolVersion};
use ferriscrypt::rand::{SecureRng, SecureRngError};
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
    #[error(transparent)]
    SecureRngError(#[from] SecureRngError),
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

    pub fn generate_key_package(
        &self,
        protocol_version: ProtocolVersion,
        cipher_suite: CipherSuite,
    ) -> Result<KeyPackage, ClientError> {
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
            credential_validator: &self.config.credential_validator(),
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

        Ok(key_pkg_gen.key_package)
    }

    pub fn create_session_with_group_id(
        &self,
        protocol_version: ProtocolVersion,
        cipher_suite: CipherSuite,
        group_id: Vec<u8>,
        group_context_extensions: ExtensionList,
    ) -> Result<Session<C>, ClientError> {
        Session::create(
            group_id,
            cipher_suite,
            protocol_version,
            group_context_extensions,
            self.config.clone(),
        )
        .map_err(Into::into)
    }

    pub fn create_session(
        &self,
        protocol_version: ProtocolVersion,
        cipher_suite: CipherSuite,
        group_context_extensions: ExtensionList,
    ) -> Result<Session<C>, ClientError> {
        let group_id = SecureRng::gen(cipher_suite.hash_function().digest_size())?;

        self.create_session_with_group_id(
            protocol_version,
            cipher_suite,
            group_id,
            group_context_extensions,
        )
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
        to_remove: Option<u32>,
        external_psks: Vec<ExternalPskId>,
        authenticated_data: Vec<u8>,
    ) -> Result<(Session<C>, Vec<u8>), ClientError> {
        let version = group_info_msg.version;

        let group_info = group_info_msg
            .into_group_info()
            .ok_or(ClientError::ExpectedGroupInfoMessage)?;

        Ok(Session::new_external(
            self.config.clone(),
            version,
            group_info,
            tree_data,
            to_remove,
            external_psks,
            authenticated_data,
        )?)
    }

    pub fn import_session(&self, state: GroupState) -> Result<Session<C>, ClientError> {
        Ok(Session::import(self.config.clone(), state)?)
    }

    pub fn external_add_proposal(
        &self,
        group_info: MLSMessage,
        authenticated_data: Vec<u8>,
    ) -> Result<Vec<u8>, ClientError> {
        let protocol_version = group_info.version;

        let group_info = group_info
            .into_group_info()
            .ok_or(ClientError::ExpectedGroupInfoMessage)?;

        let key_package =
            self.generate_key_package(protocol_version, group_info.group_context.cipher_suite)?;

        let mut message = MLSPlaintext::new(
            group_info.group_context.group_id.clone(),
            group_info.group_context.epoch,
            Sender::NewMemberProposal,
            Content::Proposal(Proposal::Add(AddProposal { key_package })),
            authenticated_data,
        );

        let (_, signer) = self
            .config
            .keychain()
            .default_identity(group_info.group_context.cipher_suite)
            .ok_or(ClientError::NoCredentialFound)?;

        let signing_context = MessageSigningContext {
            group_context: Some(&group_info.group_context),
            encrypted: false,
        };

        message.sign(&signer, &signing_context)?;

        let message = MLSMessage {
            version: protocol_version,
            payload: MLSMessagePayload::Plain(message),
        };

        Ok(message.tls_serialize_detached()?)
    }
}

#[cfg(any(test, feature = "benchmark"))]
pub mod test_utils {

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
    ) -> (Client<InMemoryClientConfig>, KeyPackage) {
        let client = get_basic_config(cipher_suite, identity).build_client();

        let key_package = client
            .generate_key_package(protocol_version, cipher_suite)
            .unwrap();

        (client, key_package)
    }

    pub fn create_session(client: &Client<InMemoryClientConfig>) -> Session<InMemoryClientConfig> {
        client
            .create_session_with_group_id(
                TEST_PROTOCOL_VERSION,
                TEST_CIPHER_SUITE,
                TEST_GROUP.to_vec(),
                ExtensionList::new(),
            )
            .unwrap()
    }

    pub fn join_session<'a, S>(
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
        message::ProcessedMessagePayload,
        psk::{ExternalPskId, PskSecretError},
        session::Psk,
        tree_kem::{leaf_node::LeafNodeSource, RatchetTreeError, TreeIndexError},
        ProposalBundle, ProposalFilter, ProposalFilterError,
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
            let key_package = client
                .generate_key_package(protocol_version, cipher_suite)
                .unwrap();

            assert_eq!(key_package.version, protocol_version);
            assert_eq!(key_package.cipher_suite, cipher_suite);
            assert_matches!(&key_package.leaf_node.signing_identity.credential, Credential::Basic(identity) if identity == "foo".as_bytes());

            let (expected_credential, _) = client
                .config
                .keychain()
                .default_identity(cipher_suite)
                .unwrap();

            assert_eq!(
                key_package
                    .leaf_node
                    .signing_identity
                    .tls_serialize_detached()
                    .unwrap(),
                expected_credential.tls_serialize_detached().unwrap()
            );

            let client_lifetime = client.config.lifetime();
            assert_matches!(key_package.leaf_node.leaf_node_source, LeafNodeSource::KeyPackage(lifetime) if (lifetime.not_after - lifetime.not_before) == (client_lifetime.not_after - client_lifetime.not_before));

            let capabilities = key_package.leaf_node.capabilities;
            assert_eq!(capabilities, client.config.capabilities());
        }
    }

    #[test]
    fn new_member_add_proposal_adds_to_group() {
        let alice = get_basic_config(TEST_CIPHER_SUITE, "alice").build_client();

        let mut session = create_session(&alice);

        let (bob, bob_key_package) =
            test_client_with_key_pkg(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE, "bob");

        let proposal = bob
            .external_add_proposal(session.group_info_message().unwrap(), vec![])
            .unwrap();

        let message = session.process_incoming_bytes(&proposal).unwrap();

        assert_matches!(
            message.message,
            ProcessedMessagePayload::Proposal(Proposal::Add(AddProposal { key_package })) if key_package.leaf_node.signing_identity == bob_key_package.leaf_node.signing_identity
        );

        let _ = session.commit(vec![], vec![]).unwrap();
        let _ = session.apply_pending_commit().unwrap();

        // Check that the new member is in the group
        session
            .roster()
            .iter()
            .find(|ln| ln.signing_identity == bob_key_package.leaf_node.signing_identity)
            .unwrap();
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

        let (bob, _) = test_client_with_key_pkg(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE, "bob");

        let proposal = bob
            .external_add_proposal(session.group_info_message().unwrap(), vec![])
            .unwrap();

        session.process_incoming_bytes(&proposal).unwrap();
        session.commit(Vec::new(), Vec::new()).unwrap();
        let res = session.apply_pending_commit();

        assert_matches!(
            res,
            Err(SessionError::ProposalRejected(
                ProposalFilterError::UserDefined(_)
            ))
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

        let (bob, bob_key_pkg) =
            test_client_with_key_pkg(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE, "bob");

        let bob_leaf_node = bob_key_pkg.leaf_node.clone();

        let mut bob_session = join_session(&mut alice_session, [], bob_key_pkg, &bob).unwrap();

        let (carol, carol_key_pkg) =
            test_client_with_key_pkg(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE, "carol");

        let carol_session = join_session(
            &mut alice_session,
            [&mut bob_session],
            carol_key_pkg,
            &carol,
        )
        .unwrap();

        let bob_sub_key_pkg = bob
            .generate_key_package(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE)
            .unwrap();

        let (mut alice_sub_session, welcome) = alice_session
            .branch(b"subgroup".to_vec(), |p| {
                if p == &bob_leaf_node {
                    Some(bob_sub_key_pkg.clone())
                } else {
                    None
                }
            })
            .unwrap();

        let welcome = welcome.unwrap();

        let mut bob_sub_session = bob_session
            .join_subgroup(
                None,
                welcome.clone(),
                Some(&alice_sub_session.export_tree().unwrap()),
            )
            .unwrap();

        assert_matches!(
            carol_session.join_subgroup(
                None,
                welcome,
                Some(&alice_sub_session.export_tree().unwrap())
            ),
            Err(_)
        );

        // Alice and Bob can still talk
        let commit = alice_sub_session.commit(vec![], vec![]).unwrap();
        bob_sub_session
            .process_incoming_bytes(&commit.commit_packet)
            .unwrap();
    }

    fn joining_group_fails_if_unsupported<F>(f: F)
    where
        F: FnOnce(InMemoryClientConfig) -> InMemoryClientConfig,
    {
        let alice = get_basic_config(TEST_CIPHER_SUITE, "alice").build_client();
        let mut alice_session = create_session(&alice);
        let bob = f(get_basic_config(TEST_CIPHER_SUITE, "bob")).build_client();

        let bob_key_pkg = bob
            .generate_key_package(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE)
            .unwrap();

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

    fn join_via_external_commit(do_remove: bool, with_psk: bool) -> Result<(), ClientError> {
        let psk_id = ExternalPskId(b"psk id".to_vec());
        let psk = Psk::from(b"psk".to_vec());

        let alice = get_basic_config(TEST_CIPHER_SUITE, "alice")
            .with_psk(psk_id.clone(), psk.clone())
            .build_client();

        let mut alice_session = create_session(&alice);

        let (mut bob, bob_key_pkg) =
            test_client_with_key_pkg(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE, "bob");

        bob.config = bob.config.with_psk(psk_id.clone(), psk.clone());

        // An external commit cannot be the first commit in a session as it requires
        // interim_transcript_hash to be computed from the confirmed_transcript_hash and
        // confirmation_tag, which is not the case for the initial interim_transcript_hash.
        let mut bob_session = join_session(&mut alice_session, [], bob_key_pkg, &bob).unwrap();

        let group_info_msg = alice_session.group_info_message().unwrap();

        let charlie = get_basic_config(TEST_CIPHER_SUITE, "charlie")
            .with_psk(psk_id.clone(), psk)
            .build_client();

        let (mut charlie_session, external_commit) = charlie.commit_external(
            group_info_msg,
            Some(&alice_session.export_tree().unwrap()),
            do_remove.then(|| 1),
            if with_psk { vec![psk_id] } else { vec![] },
            vec![],
        )?;

        let num_members = if do_remove { 2 } else { 3 };

        assert!(charlie_session.participant_count() == num_members);

        let _ = alice_session
            .process_incoming_bytes(&external_commit)
            .unwrap();

        let message = bob_session
            .process_incoming_bytes(&external_commit)
            .unwrap();

        assert!(alice_session.participant_count() == num_members);
        if !do_remove {
            assert!(bob_session.participant_count() == num_members);
        } else if let ProcessedMessagePayload::Commit(update) = message.message {
            assert!(!update.active);
        }

        let alice_msg = b"I'm Alice";
        let msg = alice_session
            .encrypt_application_data(alice_msg, vec![])
            .unwrap();

        let received = charlie_session.process_incoming_bytes(&msg).unwrap();
        assert_matches!(received.message, ProcessedMessagePayload::Application(bytes) if bytes == alice_msg);

        let charlie_msg = b"I'm Charlie";

        let msg = charlie_session
            .encrypt_application_data(charlie_msg, vec![])
            .unwrap();
        let received = alice_session.process_incoming_bytes(&msg).unwrap();

        assert_matches!(received.message, ProcessedMessagePayload::Application(bytes) if bytes == charlie_msg);

        Ok(())
    }

    #[test]
    fn test_external_commit() {
        // New member can join
        join_via_external_commit(false, false).unwrap();
        // New member can remove an old copy of themselves
        join_via_external_commit(true, false).unwrap();
        // New member can inject a PSK
        join_via_external_commit(false, true).unwrap();
        // All works together
        join_via_external_commit(true, true).unwrap();
    }

    #[test]
    fn member_can_see_sender_creds() {
        let alice = get_basic_config(TEST_CIPHER_SUITE, "alice").build_client();
        let mut alice_session = create_session(&alice);

        let (bob, bob_key_pkg) =
            test_client_with_key_pkg(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE, "bob");

        let mut bob_session = join_session(&mut alice_session, [], bob_key_pkg, &bob).unwrap();

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
                    .generate_key_package(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE)
                    .unwrap(),
            ),
        };

        let res = alice.commit_external(msg, None, None, vec![], vec![]);

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
                None,
                vec![],
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

        let bob_session = join_session(&mut alice_session, [], bob_key_pkg, &bob).unwrap();

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
        let mut bob_session = join_session(&mut alice_session, [], bob_key_pkg, &bob).unwrap();

        // Commit so that Bob's session records a new epoch.
        let commit = bob_session.commit(Vec::new(), Vec::new()).unwrap();
        bob_session.apply_pending_commit().unwrap();
        alice_session
            .process_incoming_bytes(&commit.commit_packet)
            .unwrap();

        let bob_session_bytes = serde_json::to_vec(&bob_session.export().unwrap()).unwrap();

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

        let mut bob_session = join_session(&mut alice_session, [], bob_key_pkg, &bob).unwrap();

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
    fn commit_is_rejected_when_multiple_add_proposals_share_same_hpke_key() {
        let alice = get_basic_config(TEST_CIPHER_SUITE, "alice").build_client();
        let mut alice_session = create_session(&alice);

        let (_, bob_key_pkg) =
            test_client_with_key_pkg(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE, "bob");

        let (alice, mut alice_key_pkg) =
            test_client_with_key_pkg(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE, "alice");

        alice_key_pkg.leaf_node.public_key = bob_key_pkg.leaf_node.public_key.clone();

        let (_, alice_signer) = alice
            .config
            .keychain()
            .default_identity(TEST_CIPHER_SUITE)
            .unwrap();

        alice_key_pkg.leaf_node.sign(&alice_signer, &None).unwrap();
        alice_key_pkg.sign(&alice_signer, &()).unwrap();

        let res = alice_session.commit(
            vec![
                Proposal::Add(AddProposal {
                    key_package: bob_key_pkg,
                }),
                Proposal::Add(AddProposal {
                    key_package: alice_key_pkg,
                }),
            ],
            Vec::new(),
        );

        assert_matches!(
            res,
            Err(SessionError::ProposalRejected(
                ProposalFilterError::RatchetTreeError(RatchetTreeError::TreeIndexError(
                    TreeIndexError::DuplicateHpkeKey(_)
                ))
            ))
        );
    }

    #[test]
    fn commit_is_rejected_when_multiple_add_proposals_share_same_signature_key() {
        let alice = get_basic_config(TEST_CIPHER_SUITE, "alice").build_client();
        let mut alice_session = create_session(&alice);

        let bob = get_basic_config(TEST_CIPHER_SUITE, "bob").build_client();

        let bob_key_pkg = bob
            .generate_key_package(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE)
            .unwrap();

        let alice_key_pkg = bob
            .generate_key_package(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE)
            .unwrap();

        let res = alice_session.commit(
            vec![
                Proposal::Add(AddProposal {
                    key_package: bob_key_pkg,
                }),
                Proposal::Add(AddProposal {
                    key_package: alice_key_pkg,
                }),
            ],
            Vec::new(),
        );

        assert_matches!(
            res,
            Err(SessionError::ProposalRejected(
                ProposalFilterError::RatchetTreeError(RatchetTreeError::TreeIndexError(
                    TreeIndexError::DuplicateSignatureKeys(_)
                ))
            ))
        );
    }
}
