use crate::cipher_suite::CipherSuite;
use crate::client_config::ClientConfig;
use crate::credential::CredentialError;
use crate::extension::{ExtensionError, ExtensionList, GroupContextExtension};
use crate::group::framing::{
    Content, MLSMessage, MLSMessagePayload, MLSPlaintext, Sender, WireFormat,
};
use crate::group::message_signature::MLSAuthenticatedContent;
use crate::group::proposal::{AddProposal, Proposal};
use crate::group::{process_group_info, Group, GroupError, Snapshot};
use crate::key_package::{
    KeyPackage, KeyPackageGenerationError, KeyPackageGenerator, KeyPackageRepository,
};
use crate::protocol_version::MaybeProtocolVersion;
use crate::psk::ExternalPskId;
use crate::signer::SignatureError;
use crate::tree_kem::leaf_node::LeafNodeError;
use crate::{keychain::Keychain, ProtocolVersion};
use ferriscrypt::rand::{SecureRng, SecureRngError};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ClientError {
    #[error(transparent)]
    ExtensionError(#[from] ExtensionError),
    #[error(transparent)]
    KeyPackageGenerationError(#[from] KeyPackageGenerationError),
    #[error(transparent)]
    GroupError(#[from] GroupError),
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
    #[error("expected group info message")]
    ExpectedGroupInfoMessage,
    #[error("unsupported message version: {0:?}")]
    UnsupportedMessageVersion(MaybeProtocolVersion),
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

    pub fn create_group_with_id(
        &self,
        protocol_version: ProtocolVersion,
        cipher_suite: CipherSuite,
        group_id: Vec<u8>,
        group_context_extensions: ExtensionList<GroupContextExtension>,
    ) -> Result<Group<C>, ClientError> {
        Group::new(
            self.config.clone(),
            group_id,
            cipher_suite,
            protocol_version,
            group_context_extensions,
        )
        .map_err(Into::into)
    }

    pub fn create_group(
        &self,
        protocol_version: ProtocolVersion,
        cipher_suite: CipherSuite,
        group_context_extensions: ExtensionList<GroupContextExtension>,
    ) -> Result<Group<C>, ClientError> {
        let group_id = SecureRng::gen(cipher_suite.hash_function().digest_size())?;

        self.create_group_with_id(
            protocol_version,
            cipher_suite,
            group_id,
            group_context_extensions,
        )
    }

    /// If `key_package` is specified, key package references listed in the welcome message will not
    /// be used to identify the key package to use.
    pub fn join_group(
        &self,
        tree_data: Option<&[u8]>,
        welcome_message: MLSMessage,
    ) -> Result<Group<C>, ClientError> {
        Group::join(welcome_message, tree_data, self.config.clone()).map_err(Into::into)
    }

    /// Returns group and commit MLSMessage
    pub fn commit_external(
        &self,
        group_info_msg: MLSMessage,
        tree_data: Option<&[u8]>,
        to_remove: Option<u32>,
        external_psks: Vec<ExternalPskId>,
        authenticated_data: Vec<u8>,
    ) -> Result<(Group<C>, MLSMessage), ClientError> {
        Group::new_external(
            self.config.clone(),
            group_info_msg,
            tree_data,
            to_remove,
            external_psks,
            authenticated_data,
        )
        .map_err(|e| {
            if matches!(e, GroupError::UnexpectedMessageType(..)) {
                ClientError::ExpectedGroupInfoMessage
            } else {
                e.into()
            }
        })
    }

    pub fn load_snapshot(&self, snapshot: Snapshot) -> Result<Group<C>, ClientError> {
        Ok(Group::from_snapshot(self.config.clone(), snapshot))
    }

    pub fn external_add_proposal(
        &self,
        group_info: MLSMessage,
        tree_data: Option<&[u8]>,
        authenticated_data: Vec<u8>,
    ) -> Result<MLSMessage, ClientError> {
        let protocol_version = group_info
            .version
            .into_enum()
            .filter(|&version| self.config.version_supported(version))
            .ok_or(ClientError::UnsupportedMessageVersion(group_info.version))?;

        let group_info = group_info
            .into_group_info()
            .ok_or(ClientError::ExpectedGroupInfoMessage)?;

        let (group_context, _, _, _) = process_group_info(
            &self.config.supported_protocol_versions(),
            &self.config.supported_cipher_suites(),
            protocol_version,
            group_info,
            tree_data,
        )?;

        let key_package =
            self.generate_key_package(protocol_version, group_context.cipher_suite)?;

        let (_, signer) = self
            .config
            .keychain()
            .default_identity(group_context.cipher_suite)
            .ok_or(ClientError::NoCredentialFound)?;

        let message = MLSAuthenticatedContent::new_signed(
            &group_context,
            Sender::NewMemberProposal,
            Content::Proposal(Proposal::Add(AddProposal { key_package })),
            &signer,
            WireFormat::Plain,
            authenticated_data,
        )?;

        let plaintext = MLSPlaintext {
            content: message.content,
            auth: message.auth,
            membership_tag: None,
        };

        Ok(MLSMessage {
            version: MaybeProtocolVersion::from(protocol_version),
            payload: MLSMessagePayload::Plain(plaintext),
        })
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

    pub fn create_group(client: &Client<InMemoryClientConfig>) -> Group<InMemoryClientConfig> {
        client
            .create_group_with_id(
                TEST_PROTOCOL_VERSION,
                TEST_CIPHER_SUITE,
                TEST_GROUP.to_vec(),
                ExtensionList::new(),
            )
            .unwrap()
    }

    pub fn join_group<'a, S>(
        committer: &mut Group<InMemoryClientConfig>,
        other_groups: S,
        key_package: KeyPackage,
        client: &Client<InMemoryClientConfig>,
    ) -> Result<Group<InMemoryClientConfig>, ClientError>
    where
        S: IntoIterator<Item = &'a mut Group<InMemoryClientConfig>>,
    {
        let (commit_msg, welcome_msg) =
            committer.commit_proposals(vec![Proposal::Add(AddProposal { key_package })], vec![])?;

        committer.process_pending_commit()?;

        for group in other_groups {
            group.process_incoming_message(commit_msg.clone())?;
        }

        client.join_group(
            Some(&committer.export_tree().unwrap()),
            welcome_msg.unwrap(),
        )
    }
}

#[cfg(test)]
mod tests {
    use std::vec;

    use super::test_utils::*;

    use super::*;
    use crate::{
        credential::Credential,
        group::{
            proposal::{AddProposal, Proposal},
            test_utils::{test_group, test_group_custom_config},
            Event,
        },
        psk::{ExternalPskId, Psk},
        tree_kem::leaf_node::LeafNodeSource,
    };
    use assert_matches::assert_matches;
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

            assert_eq!(key_package.version, protocol_version.into());
            assert_eq!(key_package.cipher_suite, cipher_suite.into());
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
        let mut alice_group = test_group(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE);

        let (bob, bob_key_package) =
            test_client_with_key_pkg(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE, "bob");

        let proposal = bob
            .external_add_proposal(
                alice_group.group.group_info_message().unwrap(),
                Some(&alice_group.group.export_tree().unwrap()),
                vec![],
            )
            .unwrap();

        let message = alice_group
            .group
            .process_incoming_message(proposal)
            .unwrap();

        assert_matches!(
            message.event,
            Event::Proposal(Proposal::Add(AddProposal { key_package })) if key_package.leaf_node.signing_identity == bob_key_package.leaf_node.signing_identity
        );

        alice_group.group.commit_proposals(vec![], vec![]).unwrap();
        alice_group.group.process_pending_commit().unwrap();

        // Check that the new member is in the group
        assert!(alice_group
            .group
            .roster()
            .into_iter()
            .any(|member| member.signing_identity() == &bob_key_package.leaf_node.signing_identity))
    }

    fn join_via_external_commit(do_remove: bool, with_psk: bool) -> Result<(), ClientError> {
        // An external commit cannot be the first commit in a group as it requires
        // interim_transcript_hash to be computed from the confirmed_transcript_hash and
        // confirmation_tag, which is not the case for the initial interim_transcript_hash.

        let psk_id = ExternalPskId(b"psk id".to_vec());
        let psk = Psk::from(b"psk".to_vec());

        let mut alice_group =
            test_group_custom_config(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE, |c| {
                c.with_psk(psk_id.clone(), psk.clone())
            });

        let (mut bob_group, _) = alice_group
            .join_with_custom_config("bob", |c| c.with_psk(psk_id.clone(), psk.clone()))
            .unwrap();

        let group_info_msg = alice_group.group.group_info_message().unwrap();

        let charlie = get_basic_config(TEST_CIPHER_SUITE, "charlie")
            .with_psk(psk_id.clone(), psk)
            .build_client();

        let (mut charlie_group, external_commit) = charlie.commit_external(
            group_info_msg,
            Some(&alice_group.group.export_tree().unwrap()),
            do_remove.then(|| 1),
            if with_psk { vec![psk_id] } else { vec![] },
            vec![],
        )?;

        let num_members = if do_remove { 2 } else { 3 };

        assert_eq!(charlie_group.roster().member_count(), num_members);

        let _ = alice_group
            .group
            .process_incoming_message(external_commit.clone())
            .unwrap();

        let message = bob_group
            .group
            .process_incoming_message(external_commit)
            .unwrap();

        assert!(alice_group.group.roster().member_count() == num_members);

        if !do_remove {
            assert!(bob_group.group.roster().member_count() == num_members);
        } else if let Event::Commit(update) = message.event {
            assert!(!update.active);
        }

        let alice_msg = b"I'm Alice";

        let msg = alice_group
            .group
            .encrypt_application_message(alice_msg, vec![])
            .unwrap();

        let received = charlie_group.process_incoming_message(msg).unwrap();
        assert_matches!(received.event, Event::ApplicationMessage(bytes) if bytes == alice_msg);

        let charlie_msg = b"I'm Charlie";

        let msg = charlie_group
            .encrypt_application_message(charlie_msg, vec![])
            .unwrap();

        let received = alice_group.group.process_incoming_message(msg).unwrap();

        assert_matches!(received.event, Event::ApplicationMessage(bytes) if bytes == charlie_msg);

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
    fn creating_an_external_commit_requires_a_group_info_message() {
        let alice = get_basic_config(TEST_CIPHER_SUITE, "alice").build_client();

        let payload = MLSMessagePayload::KeyPackage(
            alice
                .generate_key_package(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE)
                .unwrap(),
        );

        let msg = MLSMessage::new(TEST_PROTOCOL_VERSION, payload);
        let res = alice.commit_external(msg, None, None, vec![], vec![]);

        assert_matches!(res, Err(ClientError::ExpectedGroupInfoMessage));
    }

    #[test]
    fn external_commit_with_invalid_group_info_fails() {
        let mut alice_group = test_group(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE);
        let mut bob_group = test_group(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE);

        bob_group
            .group
            .commit_proposals(Vec::new(), Vec::new())
            .unwrap();

        bob_group.group.process_pending_commit().unwrap();

        let group_info_msg = bob_group.group.group_info_message().unwrap();

        let carol = get_basic_config(TEST_CIPHER_SUITE, "carol").build_client();

        let (_, external_commit) = carol
            .commit_external(
                group_info_msg,
                Some(&bob_group.group.export_tree().unwrap()),
                None,
                vec![],
                vec![],
            )
            .unwrap();

        // If Carol tries to join Alice's group using the group info from Bob's group, that fails.
        let res = alice_group.group.process_incoming_message(external_commit);
        assert_matches!(res, Err(_));
    }
}
