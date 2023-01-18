use crate::cipher_suite::{CipherSuite, MaybeCipherSuite};
use crate::client_config::ClientConfig;
use crate::extension::{ExtensionError, ExtensionList, GroupContextExtension};
use crate::group::framing::{
    Content, MLSMessage, MLSMessagePayload, MLSPlaintext, Sender, WireFormat,
};
use crate::group::message_signature::MLSAuthenticatedContent;
use crate::group::proposal::{AddProposal, Proposal};
use crate::group::{process_group_info, Group, GroupError, NewMemberInfo};
use crate::hash_reference::HashReferenceError;
use crate::identity::SigningIdentity;
use crate::key_package::{KeyPackage, KeyPackageGenerationError, KeyPackageGenerator};
use crate::protocol_version::MaybeProtocolVersion;
use crate::protocol_version::ProtocolVersion;
use crate::provider::crypto::CryptoProvider;
use crate::provider::group_state::GroupStateStorage;
use crate::provider::key_package::KeyPackageRepository;
use crate::provider::keychain::KeychainStorage;
use crate::psk::ExternalPskId;
use crate::signer::SignatureError;
use crate::tree_kem::leaf_node::LeafNodeError;
use hex::ToHex;
use thiserror::Error;

pub use crate::client_builder::{
    BaseConfig, ClientBuilder, Missing, MlsConfig, Preferences, WithCryptoProvider,
    WithGroupStateStorage, WithIdentityProvider, WithKeyPackageRepo, WithKeychain,
    WithProposalFilter, WithPskStore,
};

#[derive(Error, Debug)]
pub enum ClientError {
    #[error(transparent)]
    ExtensionError(#[from] ExtensionError),
    #[error(transparent)]
    KeyPackageGenerationError(#[from] KeyPackageGenerationError),
    #[error(transparent)]
    GroupError(#[from] GroupError),
    #[error(transparent)]
    HashReferenceError(#[from] HashReferenceError),
    #[error("signer not found for given identity")]
    SignerNotFound,
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
    #[error("unsupported cipher suite: {0:?}")]
    UnsupportedCipherSuite(MaybeCipherSuite),
    #[error("unable to load group from storage: {0:?}")]
    GroupStorageError(Box<dyn std::error::Error + Send + Sync>),
    #[error(transparent)]
    KeychainError(Box<dyn std::error::Error + Send + Sync>),
    #[error("group not found: {0}")]
    GroupNotFound(String),
}

/// MLS Client
///
/// [`Client::builder`] can be used to instantiate it.
#[derive(Clone, Debug)]
pub struct Client<C> {
    pub(crate) config: C,
}

impl Client<()> {
    pub fn builder() -> ClientBuilder<BaseConfig> {
        ClientBuilder::new()
    }
}

impl<C> Client<C>
where
    C: ClientConfig + Clone,
{
    pub(crate) fn new(config: C) -> Self {
        Client { config }
    }

    pub fn generate_key_package_message(
        &self,
        protocol_version: ProtocolVersion,
        cipher_suite: CipherSuite,
        signing_identity: SigningIdentity,
    ) -> Result<MLSMessage, ClientError> {
        let key_package =
            self.generate_key_package(protocol_version, cipher_suite, signing_identity)?;

        let key_package_message =
            MLSMessage::new(protocol_version, MLSMessagePayload::KeyPackage(key_package));

        Ok(key_package_message)
    }

    pub fn generate_key_package(
        &self,
        protocol_version: ProtocolVersion,
        cipher_suite: CipherSuite,
        signing_identity: SigningIdentity,
    ) -> Result<KeyPackage, ClientError> {
        let signer = self
            .config
            .keychain()
            .signer(&signing_identity)
            .map_err(|e| ClientError::KeychainError(e.into()))?
            .ok_or(ClientError::SignerNotFound)?;

        let cipher_suite_provider = self
            .config
            .crypto_provider()
            .cipher_suite_provider(cipher_suite)
            .ok_or_else(|| ClientError::UnsupportedCipherSuite(cipher_suite.into()))?;

        let key_package_generator = KeyPackageGenerator {
            protocol_version,
            cipher_suite_provider: &cipher_suite_provider,
            signing_key: &signer,
            signing_identity: &signing_identity,
            identity_provider: &self.config.identity_provider(),
        };

        let key_pkg_gen = key_package_generator.generate(
            self.config.lifetime(),
            self.config.capabilities(),
            self.config.key_package_extensions(),
            self.config.leaf_node_extensions(),
        )?;

        self.config
            .key_package_repo()
            .insert(
                key_pkg_gen.reference(&cipher_suite_provider)?,
                key_pkg_gen.clone(),
            )
            .map_err(|e| ClientError::KeyPackageRepoError(e.into()))?;

        Ok(key_pkg_gen.key_package)
    }

    pub fn create_group_with_id(
        &self,
        protocol_version: ProtocolVersion,
        cipher_suite: CipherSuite,
        group_id: Vec<u8>,
        signing_identity: SigningIdentity,
        group_context_extensions: ExtensionList<GroupContextExtension>,
    ) -> Result<Group<C>, ClientError> {
        Group::new(
            self.config.clone(),
            Some(group_id),
            cipher_suite,
            protocol_version,
            signing_identity,
            group_context_extensions,
        )
        .map_err(Into::into)
    }

    pub fn create_group(
        &self,
        protocol_version: ProtocolVersion,
        cipher_suite: CipherSuite,
        signing_identity: SigningIdentity,
        group_context_extensions: ExtensionList<GroupContextExtension>,
    ) -> Result<Group<C>, ClientError> {
        Group::new(
            self.config.clone(),
            None,
            cipher_suite,
            protocol_version,
            signing_identity,
            group_context_extensions,
        )
        .map_err(Into::into)
    }

    /// If `key_package` is specified, key package references listed in the welcome message will not
    /// be used to identify the key package to use.
    pub fn join_group(
        &self,
        tree_data: Option<&[u8]>,
        welcome_message: MLSMessage,
    ) -> Result<(Group<C>, NewMemberInfo), ClientError> {
        Group::join(welcome_message, tree_data, self.config.clone()).map_err(Into::into)
    }

    /// Returns group and commit MLSMessage
    pub fn commit_external(
        &self,
        group_info_msg: MLSMessage,
        tree_data: Option<&[u8]>,
        signing_identity: SigningIdentity,
        to_remove: Option<u32>,
        external_psks: Vec<ExternalPskId>,
        authenticated_data: Vec<u8>,
    ) -> Result<(Group<C>, MLSMessage), ClientError> {
        Group::new_external(
            self.config.clone(),
            group_info_msg,
            tree_data,
            signing_identity,
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

    pub fn load_group(&self, group_id: &[u8]) -> Result<Group<C>, ClientError> {
        let snapshot = self
            .config
            .group_state_storage()
            .state(group_id)
            .map_err(|e| ClientError::GroupStorageError(e.into()))?
            .ok_or_else(|| ClientError::GroupNotFound(group_id.encode_hex_upper()))?;

        Ok(Group::from_snapshot(self.config.clone(), snapshot)?)
    }

    pub fn external_add_proposal(
        &self,
        group_info: MLSMessage,
        tree_data: Option<&[u8]>,
        signing_identity: SigningIdentity,
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

        let cipher_suite_provider = group_info
            .group_context
            .cipher_suite
            .into_enum()
            .and_then(|cs| self.config.crypto_provider().cipher_suite_provider(cs))
            .ok_or_else(|| {
                ClientError::UnsupportedCipherSuite(group_info.group_context.cipher_suite)
            })?;

        let group_context = process_group_info(
            protocol_version,
            group_info,
            tree_data,
            &self.config.identity_provider(),
            &cipher_suite_provider,
        )?
        .group_context;

        let signer = self
            .config
            .keychain()
            .signer(&signing_identity)
            .map_err(|e| ClientError::KeychainError(e.into()))?
            .ok_or(ClientError::SignerNotFound)?;

        let key_package = self.generate_key_package(
            protocol_version,
            group_context.cipher_suite,
            signing_identity,
        )?;

        let message = MLSAuthenticatedContent::new_signed(
            &cipher_suite_provider,
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
    use crate::{client_config::ClientConfig, identity::test_utils::get_test_signing_identity};

    pub use crate::client_builder::test_utils::{TestClientBuilder, TestClientConfig};

    pub const TEST_PROTOCOL_VERSION: ProtocolVersion = ProtocolVersion::Mls10;
    pub const TEST_CIPHER_SUITE: CipherSuite = CipherSuite::Curve25519Aes128;

    pub fn get_basic_client_builder(
        cipher_suite: CipherSuite,
        identity: &str,
    ) -> (TestClientBuilder, SigningIdentity) {
        let (signing_identity, secret_key) =
            get_test_signing_identity(cipher_suite, identity.as_bytes().to_vec());

        let builder = TestClientBuilder::new_for_test()
            .signing_identity(signing_identity.clone(), secret_key, cipher_suite)
            .key_package_lifetime(10000);

        (builder, signing_identity)
    }

    pub fn test_client_with_key_pkg(
        protocol_version: ProtocolVersion,
        cipher_suite: CipherSuite,
        identity: &str,
    ) -> (Client<TestClientConfig>, KeyPackage) {
        let (client, identity) = get_basic_client_builder(cipher_suite, identity);
        let client = client.build();

        let key_package = client
            .generate_key_package(protocol_version, cipher_suite, identity)
            .unwrap();

        (client, key_package)
    }

    pub fn join_group<'a, C, S>(
        committer: &mut Group<C>,
        other_groups: S,
        key_package: KeyPackage,
        client: &Client<C>,
    ) -> Result<(Group<C>, NewMemberInfo), ClientError>
    where
        C: ClientConfig + 'a,
        S: IntoIterator<Item = &'a mut Group<C>>,
    {
        let commit_output = committer
            .commit_builder()
            .add_member(key_package)?
            .build()?;

        committer.apply_pending_commit()?;

        for group in other_groups {
            group.process_incoming_message(commit_output.commit_message.clone())?;
        }

        client.join_group(
            Some(&committer.export_tree().unwrap()),
            commit_output.welcome_message.unwrap(),
        )
    }
}

#[cfg(test)]
mod tests {
    use std::vec;

    use super::test_utils::*;

    use super::*;
    use crate::{
        group::{
            proposal::{AddProposal, Proposal},
            test_utils::{test_group, test_group_custom_config},
            Event,
        },
        identity::test_utils::get_test_basic_credential,
        provider::crypto::test_utils::TestCryptoProvider,
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
        for (protocol_version, cipher_suite) in ProtocolVersion::all().flat_map(|p| {
            TestCryptoProvider::all_supported_cipher_suites()
                .into_iter()
                .map(move |cs| (p, cs))
        }) {
            println!("Running client keygen for {:?}", cipher_suite);

            let (client, identity) = get_basic_client_builder(cipher_suite, "foo");
            let client = client.build();

            // TODO: Tests around extensions
            let key_package = client
                .generate_key_package(protocol_version, cipher_suite, identity.clone())
                .unwrap();

            assert_eq!(key_package.version, protocol_version.into());
            assert_eq!(key_package.cipher_suite, cipher_suite.into());

            assert_eq!(
                &key_package.leaf_node.signing_identity.credential,
                &get_test_basic_credential(b"foo".to_vec())
            );

            assert_eq!(
                key_package
                    .leaf_node
                    .signing_identity
                    .tls_serialize_detached()
                    .unwrap(),
                identity.tls_serialize_detached().unwrap()
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

        let (bob, bob_identity) = get_basic_client_builder(TEST_CIPHER_SUITE, "bob");

        let proposal = bob
            .build()
            .external_add_proposal(
                alice_group.group.group_info_message(true).unwrap(),
                Some(&alice_group.group.export_tree().unwrap()),
                bob_identity.clone(),
                vec![],
            )
            .unwrap();

        let message = alice_group
            .group
            .process_incoming_message(proposal)
            .unwrap();

        assert_matches!(
            message.event,
            Event::Proposal((Proposal::Add(AddProposal { key_package }), _)) if key_package.leaf_node.signing_identity == bob_identity
        );

        alice_group.group.commit(vec![]).unwrap();
        alice_group.group.apply_pending_commit().unwrap();

        // Check that the new member is in the group
        assert!(alice_group
            .group
            .roster()
            .into_iter()
            .any(|member| member.signing_identity() == &bob_identity))
    }

    fn join_via_external_commit(do_remove: bool, with_psk: bool) -> Result<(), ClientError> {
        // An external commit cannot be the first commit in a group as it requires
        // interim_transcript_hash to be computed from the confirmed_transcript_hash and
        // confirmation_tag, which is not the case for the initial interim_transcript_hash.

        let psk_id = ExternalPskId(b"psk id".to_vec());
        let psk = Psk::from(b"psk".to_vec());

        let mut alice_group =
            test_group_custom_config(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE, |c| {
                c.psk(psk_id.clone(), psk.clone())
            });

        let (mut bob_group, _) = alice_group
            .join_with_custom_config("bob", |c| {
                c.0.psk_store.insert(psk_id.clone(), psk.clone());
            })
            .unwrap();

        let group_info_msg = alice_group.group.group_info_message(true).unwrap();

        let new_client_id = if do_remove { "bob" } else { "charlie" };
        let (new_client, new_client_identity) =
            get_basic_client_builder(TEST_CIPHER_SUITE, new_client_id);

        let new_client = new_client.psk(psk_id.clone(), psk).build();

        let (mut new_group, external_commit) = new_client.commit_external(
            group_info_msg,
            Some(&alice_group.group.export_tree().unwrap()),
            new_client_identity,
            do_remove.then_some(1),
            if with_psk { vec![psk_id] } else { vec![] },
            vec![],
        )?;

        let num_members = if do_remove { 2 } else { 3 };

        assert_eq!(new_group.roster().len(), num_members);

        let _ = alice_group
            .group
            .process_incoming_message(external_commit.clone())
            .unwrap();

        let message = bob_group
            .group
            .process_incoming_message(external_commit)
            .unwrap();

        assert!(alice_group.group.roster().len() == num_members);

        if !do_remove {
            assert!(bob_group.group.roster().len() == num_members);
        } else if let Event::Commit(update) = message.event {
            assert!(!update.active);
        }

        let alice_msg = b"I'm Alice";

        let msg = alice_group
            .group
            .encrypt_application_message(alice_msg, vec![])
            .unwrap();

        let received = new_group.process_incoming_message(msg).unwrap();
        assert_matches!(received.event, Event::ApplicationMessage(bytes) if bytes == alice_msg);

        let new_msg = b"I'm the new guy";

        let msg = new_group
            .encrypt_application_message(new_msg, vec![])
            .unwrap();

        let received = alice_group.group.process_incoming_message(msg).unwrap();

        assert_matches!(received.event, Event::ApplicationMessage(bytes) if bytes == new_msg);

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
        let (alice, alice_identity) = get_basic_client_builder(TEST_CIPHER_SUITE, "alice");
        let alice = alice.build();

        let payload = MLSMessagePayload::KeyPackage(
            alice
                .generate_key_package(
                    TEST_PROTOCOL_VERSION,
                    TEST_CIPHER_SUITE,
                    alice_identity.clone(),
                )
                .unwrap(),
        );

        let msg = MLSMessage::new(TEST_PROTOCOL_VERSION, payload);

        let res = alice
            .commit_external(msg, None, alice_identity, None, vec![], vec![])
            .map(|_| ());

        assert_matches!(res, Err(ClientError::ExpectedGroupInfoMessage));
    }

    #[test]
    fn external_commit_with_invalid_group_info_fails() {
        let mut alice_group = test_group(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE);
        let mut bob_group = test_group(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE);

        bob_group.group.commit(vec![]).unwrap();
        bob_group.group.apply_pending_commit().unwrap();

        let group_info_msg = bob_group.group.group_info_message(true).unwrap();

        let (carol, carol_identity) = get_basic_client_builder(TEST_CIPHER_SUITE, "carol");

        let (_, external_commit) = carol
            .build()
            .commit_external(
                group_info_msg,
                Some(&bob_group.group.export_tree().unwrap()),
                carol_identity,
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
