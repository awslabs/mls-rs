use crate::cipher_suite::CipherSuite;
use crate::client_builder::{BaseConfig, ClientBuilder};
use crate::client_config::ClientConfig;
use crate::group::confirmation_tag::ConfirmationTagError;
use crate::group::framing::{
    Content, ContentType, MLSMessage, MLSMessagePayload, PublicMessage, Sender, WireFormat,
};
use crate::group::key_schedule::KeyScheduleError;
use crate::group::message_signature::AuthenticatedContent;
use crate::group::proposal::{AddProposal, Proposal};
use crate::group::state_repo::GroupStateRepositoryError;
use crate::group::transcript_hash::TranscriptHashError;
use crate::group::{process_group_info, Group, NewMemberInfo, ProposalCacheError};
use crate::hash_reference::HashReferenceError;
use crate::identity::SigningIdentity;
use crate::key_package::{
    KeyPackageError, KeyPackageGeneration, KeyPackageGenerationError, KeyPackageGenerator,
    KeyPackageValidationError,
};
use crate::protocol_version::ProtocolVersion;
use crate::psk::{ExternalPskId, PskError};
use crate::signer::SignatureError;
use crate::tree_kem::{
    hpke_encryption::HpkeEncryptionError, leaf_node::LeafNodeError,
    leaf_node_validator::LeafNodeValidationError, path_secret::PathSecretError,
    tree_validator::TreeValidationError, RatchetTreeError, UpdatePathValidationError,
};
use aws_mls_core::crypto::CryptoProvider;
use aws_mls_core::extension::{ExtensionError, ExtensionList};
use aws_mls_core::group::GroupStateStorage;
use aws_mls_core::key_package::KeyPackageStorage;
use aws_mls_core::keychain::KeychainStorage;
use hex::ToHex;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum MlsError {
    #[error(transparent)]
    RatchetTreeError(#[from] RatchetTreeError),
    #[error(transparent)]
    CiphertextProcessorError(Box<dyn std::error::Error + Send + Sync>),
    #[error(transparent)]
    SignerError(Box<dyn std::error::Error + Send + Sync>),
    #[error(transparent)]
    TranscriptHashError(#[from] TranscriptHashError),
    #[error(transparent)]
    KeyPackageError(#[from] KeyPackageError),
    #[error(transparent)]
    IdentityProviderError(Box<dyn std::error::Error + Send + Sync + 'static>),
    #[error(transparent)]
    CryptoProviderError(Box<dyn std::error::Error + Send + Sync + 'static>),
    #[error(transparent)]
    ExtensionError(#[from] ExtensionError),
    #[error(transparent)]
    KeyPackageGenerationError(#[from] KeyPackageGenerationError),
    #[error(transparent)]
    LeafNodeValidationError(#[from] LeafNodeValidationError),
    #[error(transparent)]
    MembershipTagError(Box<dyn std::error::Error + Send + Sync>),
    #[error(transparent)]
    ConfirmationTagError(#[from] ConfirmationTagError),
    #[error(transparent)]
    LeafSecretError(#[from] PathSecretError),
    #[error(transparent)]
    GroupStateRepositoryError(#[from] GroupStateRepositoryError),
    #[error(transparent)]
    KeyScheduleError(#[from] KeyScheduleError),
    #[error(transparent)]
    UpdatePathValidationError(#[from] UpdatePathValidationError),
    #[error(transparent)]
    ProposalCacheError(#[from] ProposalCacheError),
    #[error(transparent)]
    TreeValidationError(#[from] TreeValidationError),
    #[error(transparent)]
    HashReferenceError(#[from] HashReferenceError),
    #[error("key package not found")]
    KeyPackageNotFound,
    #[error("Cipher suite does not match")]
    CipherSuiteMismatch,
    #[error("Invalid key package signature")]
    InvalidKeyPackage,
    #[error("Invalid commit, missing required path")]
    CommitMissingPath,
    #[error("plaintext message for incorrect epoch")]
    InvalidEpoch(u64),
    #[error("epoch metadata not found for group: {0:?}")]
    EpochMetadataNotFound(Vec<u8>),
    #[error("invalid signature found")]
    InvalidSignature,
    #[error("invalid confirmation tag")]
    InvalidConfirmationTag,
    #[error("invalid membership tag")]
    InvalidMembershipTag,
    #[error("corrupt private key, missing required values")]
    InvalidTreeKemPrivateKey,
    #[error("key package not found, unable to process")]
    WelcomeKeyPackageNotFound,
    #[error("invalid participant {0}")]
    InvalidGroupParticipant(u32),
    #[error("self not found in ratchet tree")]
    TreeMissingSelfUser,
    #[error("leaf not found in tree for index {0}")]
    LeafNotFound(u32),
    #[error("message from self can't be processed")]
    CantProcessMessageFromSelf,
    #[error("pending proposals found, commit required before application messages can be sent")]
    CommitRequired,
    #[error("ratchet tree not provided or discovered in GroupInfo")]
    RatchetTreeNotFound,
    #[error("Only members can encrypt messages")]
    OnlyMembersCanEncryptMessages,
    #[error("External sender cannot commit")]
    ExternalSenderCannotCommit,
    #[error("Only members can update")]
    OnlyMembersCanUpdate,
    #[error(transparent)]
    PskSecretError(#[from] PskError),
    #[error("Subgroup uses a different protocol version: {0:?}")]
    SubgroupWithDifferentProtocolVersion(ProtocolVersion),
    #[error("Subgroup uses a different cipher suite: {0:?}")]
    SubgroupWithDifferentCipherSuite(CipherSuite),
    #[error("Unsupported protocol version {0:?}")]
    UnsupportedProtocolVersion(ProtocolVersion),
    #[error(
        "message protocol version {msg_version:?} does not match version {version:?} in {wire_format:?}"
    )]
    ProtocolVersionMismatch {
        msg_version: ProtocolVersion,
        wire_format: WireFormat,
        version: ProtocolVersion,
    },
    #[error("Unsupported cipher suite {0:?}")]
    UnsupportedCipherSuite(CipherSuite),
    #[error("Signing key of external sender is unknown")]
    UnknownSigningIdentityForExternalSender,
    #[error("External proposals are disabled for this group")]
    ExternalProposalsDisabled,
    #[error("Signing identity is not allowed to externally propose")]
    InvalidExternalSigningIdentity,
    #[error("Missing ExternalPub extension")]
    MissingExternalPubExtension,
    #[error("Missing update path in external commit")]
    MissingUpdatePathInExternalCommit,
    #[error("Epoch {0} not found")]
    EpochNotFound(u64),
    #[error("expected protocol version {0:?}, found version {1:?}")]
    InvalidProtocolVersion(ProtocolVersion, ProtocolVersion),
    #[error("unexpected group ID {0:?}")]
    InvalidGroupId(Vec<u8>),
    #[error("Unencrypted application message")]
    UnencryptedApplicationMessage,
    #[error("NewMemberCommit sender type can only be used to send Commit content")]
    ExpectedCommitForNewMemberCommit,
    #[error("NewMemberProposal sender type can only be used to send add proposals")]
    ExpectedAddProposalForNewMemberProposal,
    #[error("External commit missing ExternalInit proposal")]
    ExternalCommitMissingExternalInit,
    #[error(
        "A ReIinit has been applied. The next action must be creating or receiving a welcome."
    )]
    GroupUsedAfterReInit,
    #[error("Pending ReIinit not found.")]
    PendingReInitNotFound,
    #[error("A commit after ReIinit did not output a welcome message.")]
    ReInitCommitDidNotOutputWelcome,
    #[error("The ciphersuites in the welcome message {0:?} and in the reinit {1:?} do not match.")]
    ReInitCiphersuiteMismatch(CipherSuite, CipherSuite),
    #[error("The versions in the welcome message {0:?} and in the reinit {1:?} do not match.")]
    ReInitVersionMismatch(ProtocolVersion, ProtocolVersion),
    #[error("The extensions in the welcome message {0:?} and in the reinit {1:?} do not match.")]
    ReInitExtensionsMismatch(ExtensionList, ExtensionList),
    #[error("The group ids in the welcome message {0:?} and in the reinit {1:?} do not match.")]
    ReInitIdMismatch(Vec<u8>, Vec<u8>),
    #[error("No credential found for given ciphersuite.")]
    NoCredentialFound,
    #[error("Expected commit message, found: {0:?}")]
    NotCommitContent(ContentType),
    #[error("Expected proposal message, found: {0:?}")]
    NotProposalContent(ContentType),
    #[error("signer not found for given identity")]
    SignerNotFound,
    #[error("commit already pending")]
    ExistingPendingCommit,
    #[error("pending commit not found")]
    PendingCommitNotFound,
    #[error("unexpected message type, expected {0:?}, found {1:?}")]
    UnexpectedMessageType(Vec<WireFormat>, WireFormat),
    #[error("membership tag on MLSPlaintext for non-member sender")]
    MembershipTagForNonMember,
    #[error("mls message is not a key package")]
    NotKeyPackage,
    #[error("No member found for given identity id.")]
    MemberNotFound,
    #[error(transparent)]
    HpkeEncryptionError(#[from] HpkeEncryptionError),
    #[error("the secret key provided does not match the public key in the credential")]
    IncorrectSecretKey,
    #[error(transparent)]
    SerializationError(#[from] aws_mls_codec::Error),
    #[error(transparent)]
    SignatureError(#[from] SignatureError),
    #[error(transparent)]
    KeyPackageRepoError(Box<dyn std::error::Error + Send + Sync>),
    #[error(transparent)]
    LeafNodeError(#[from] LeafNodeError),
    #[error(transparent)]
    KeyPackageValidationError(#[from] KeyPackageValidationError),
    #[error("expected group info message")]
    ExpectedGroupInfoMessage,
    #[error("expected key package message")]
    ExpectedKeyPackageMessage,
    #[error("unsupported message protocol version: {0:?}")]
    UnsupportedMessageVersion(ProtocolVersion),
    #[error("unable to load group from storage: {0:?}")]
    GroupStorageError(Box<dyn std::error::Error + Send + Sync>),
    #[error(transparent)]
    KeychainError(Box<dyn std::error::Error + Send + Sync>),
    #[error("group not found: {0}")]
    GroupNotFound(String),
    #[error("unexpected PSK ID")]
    UnexpectedPskId,
    #[error("invalid sender {0:?} for content type {1:?}")]
    InvalidSender(Sender, ContentType),
}

/// MLS client used to create key packages and manage groups.
///
/// [`Client::builder`] can be used to instantiate it.
///
/// Clients are able to support multiple protocol versions, ciphersuites
/// and underlying identities used to join groups and generate key packages.
/// Applications may decide to create one or many clients depending on their
/// specific needs.
#[derive(Clone, Debug)]
pub struct Client<C> {
    pub(crate) config: C,
}

impl Client<()> {
    /// Returns a [ClientBuilder](crate::client_builder::ClientBuilder)
    /// used to configure client preferences and providers.
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

    /// Creates a new key package message that can be used to to add this
    /// client to a [Group](crate::group::Group). Each call to this function
    /// will produce a unique value that is signed by `signing_identity`.
    ///
    /// The [KeychainStorage](crate::KeychainStorage) used to configure
    /// the client will be searched for a secret key matching `signing_identity`
    /// in order to generate a signature.
    ///
    /// The secret keys for the resulting key package message will be stored in
    /// the [KeyPackageStorage](crate::KeyPackageStorage)
    /// that was used to configure the client and will
    /// automatically be erased when this key package is used to
    /// [join a group](Client::join_group).
    ///
    /// # Warning
    ///
    /// A key package message may only be used once.
    pub async fn generate_key_package_message(
        &self,
        protocol_version: ProtocolVersion,
        cipher_suite: CipherSuite,
        signing_identity: SigningIdentity,
    ) -> Result<MLSMessage, MlsError> {
        let key_package = self
            .generate_key_package(protocol_version, cipher_suite, signing_identity)
            .await?;

        Ok(key_package.key_package_message())
    }

    async fn generate_key_package(
        &self,
        protocol_version: ProtocolVersion,
        cipher_suite: CipherSuite,
        signing_identity: SigningIdentity,
    ) -> Result<KeyPackageGeneration, MlsError> {
        let signer = self
            .config
            .keychain()
            .signer(&signing_identity)
            .await
            .map_err(|e| MlsError::KeychainError(e.into()))?
            .ok_or(MlsError::SignerNotFound)?;

        let cipher_suite_provider = self
            .config
            .crypto_provider()
            .cipher_suite_provider(cipher_suite)
            .ok_or_else(|| MlsError::UnsupportedCipherSuite(cipher_suite))?;

        let key_package_generator = KeyPackageGenerator {
            protocol_version,
            cipher_suite_provider: &cipher_suite_provider,
            signing_key: &signer,
            signing_identity: &signing_identity,
            identity_provider: &self.config.identity_provider(),
        };

        let key_pkg_gen = key_package_generator
            .generate(
                self.config.lifetime(),
                self.config.capabilities(),
                self.config.key_package_extensions(),
                self.config.leaf_node_extensions(),
            )
            .await?;

        let (id, key_package_data) = key_pkg_gen.to_storage()?;

        self.config
            .key_package_repo()
            .insert(id, key_package_data)
            .await
            .map_err(|e| MlsError::KeyPackageRepoError(e.into()))?;

        Ok(key_pkg_gen)
    }

    /// Create a group with a specific group_id.
    ///
    /// This function behaves the same way as
    /// [create_group](Client::create_group) except that it
    /// specifies a specific unique group identifier to be used.
    ///
    /// # Warning
    ///
    /// It is recommended to use [create_group](Client::create_group)
    /// instead of this function because it guarantees that group_id values
    /// are globally unique.
    pub async fn create_group_with_id(
        &self,
        protocol_version: ProtocolVersion,
        cipher_suite: CipherSuite,
        group_id: Vec<u8>,
        signing_identity: SigningIdentity,
        group_context_extensions: ExtensionList,
    ) -> Result<Group<C>, MlsError> {
        Group::new(
            self.config.clone(),
            Some(group_id),
            cipher_suite,
            protocol_version,
            signing_identity,
            group_context_extensions,
        )
        .await
        .map_err(Into::into)
    }

    /// Create a MLS group.
    ///
    /// The `cipher_suite` provided must be supported by the
    /// [CipherSuiteProvider](crate::CipherSuiteProvider)
    /// that was used to build the client.
    ///
    /// The [KeychainStorage](crate::KeychainStorage) used to configure
    /// the client will be searched for a secret key matching `signing_identity`
    /// that will be used to sign messages sent to this group.
    pub async fn create_group(
        &self,
        protocol_version: ProtocolVersion,
        cipher_suite: CipherSuite,
        signing_identity: SigningIdentity,
        group_context_extensions: ExtensionList,
    ) -> Result<Group<C>, MlsError> {
        Group::new(
            self.config.clone(),
            None,
            cipher_suite,
            protocol_version,
            signing_identity,
            group_context_extensions,
        )
        .await
        .map_err(Into::into)
    }

    /// Join a MLS group via a welcome message created by a
    /// [Commit](crate::group::CommitOutput).
    ///
    /// `tree_data` is required to be provided out of band if the client that
    /// created `welcome_message` did not have the
    /// [ratchet tree extension preference](crate::client_builder::Preferences::ratchet_tree_extension)
    /// enabled at the time the welcome message was created. `tree_data` can
    /// be exported from a group using the
    /// [export tree function](crate::group::Group::export_tree).
    pub async fn join_group(
        &self,
        tree_data: Option<&[u8]>,
        welcome_message: MLSMessage,
    ) -> Result<(Group<C>, NewMemberInfo), MlsError> {
        Group::join(welcome_message, tree_data, self.config.clone())
            .await
            .map_err(Into::into)
    }

    /// 0-RTT add to an existing [group](crate::group::Group)
    ///
    /// External commits allow for immediate entry into a
    /// [group](crate::group::Group), even if all of the group members
    /// are currently offline and unable to process messages. Sending an
    /// external commit is only allowed for groups that have provided
    /// a public `group_info_message` containing an
    /// [ExternalPubExt](crate::extension::ExternalPubExt), which can be
    /// generated by an existing group member using the
    /// [group_info_message](crate::group::Group::group_info_message)
    /// function.
    ///
    /// `tree_data` may be provided following the same rules as [Client::join_group]
    ///
    /// The [KeychainStorage](crate::KeychainStorage) used to configure
    /// the client will be searched for a secret key matching `signing_identity`
    /// that will be used to sign messages sent to this group.
    ///
    /// If PSKs are provided in `external_psks`, the
    /// [PreSharedKeyStorage](crate::PreSharedKeyStorage)
    /// used to configure the client will be searched to resolve their values.
    ///
    /// `to_remove` may be used to remove an existing member provided that the
    /// identity of the existing group member at that [index](crate::group::Member::index)
    /// is a [valid successor](crate::IdentityProvider::valid_successor)
    /// of `signing_identity` as defined by the
    /// [IdentityProvider](crate::IdentityProvider) that this client
    /// was configured with.
    ///
    /// # Warning
    ///
    /// Only one external commit can be performed against a given group info.
    /// There may also be security trade-offs to this approach.
    ///
    // TODO: Add a comment about forward secrecy and a pointer to the future
    // book chapter on this topic
    pub async fn commit_external(
        &self,
        group_info_msg: MLSMessage,
        tree_data: Option<&[u8]>,
        signing_identity: SigningIdentity,
        to_remove: Option<u32>,
        external_psks: Vec<ExternalPskId>,
        authenticated_data: Vec<u8>,
    ) -> Result<(Group<C>, MLSMessage), MlsError> {
        Group::new_external(
            self.config.clone(),
            group_info_msg,
            tree_data,
            signing_identity,
            to_remove,
            external_psks,
            authenticated_data,
        )
        .await
        .map_err(|e| {
            if matches!(e, MlsError::UnexpectedMessageType(..)) {
                MlsError::ExpectedGroupInfoMessage
            } else {
                e
            }
        })
    }

    /// Load an existing group state into this client using the
    /// [GroupStateStorage](crate::GroupStateStorage) that
    /// this client was configured to use.
    pub async fn load_group(&self, group_id: &[u8]) -> Result<Group<C>, MlsError> {
        let snapshot = self
            .config
            .group_state_storage()
            .state(group_id)
            .await
            .map_err(|e| MlsError::GroupStorageError(e.into()))?
            .ok_or_else(|| MlsError::GroupNotFound(group_id.encode_hex_upper()))?;

        Group::from_snapshot(self.config.clone(), snapshot).await
    }

    /// Request to join an existing [group](crate::group::Group).
    ///
    /// The [KeychainStorage](crate::KeychainStorage) used to configure
    /// the client will be searched for a secret key matching `signing_identity`
    /// that will be used to sign this external add request.
    ///
    /// An existing group member will need to perform a
    /// [commit](crate::Group::commit) to complete the add and the resulting
    /// welcome message can be used by [join_group](Client::join_group).
    pub async fn external_add_proposal(
        &self,
        group_info: MLSMessage,
        tree_data: Option<&[u8]>,
        signing_identity: SigningIdentity,
        authenticated_data: Vec<u8>,
    ) -> Result<MLSMessage, MlsError> {
        let protocol_version = group_info.version;

        if !self.config.version_supported(protocol_version) {
            return Err(MlsError::UnsupportedMessageVersion(group_info.version));
        }

        let group_info = group_info
            .into_group_info()
            .ok_or(MlsError::ExpectedGroupInfoMessage)?;

        let cipher_suite_provider = self
            .config
            .crypto_provider()
            .cipher_suite_provider(group_info.group_context.cipher_suite)
            .ok_or_else(|| {
                MlsError::UnsupportedCipherSuite(group_info.group_context.cipher_suite)
            })?;

        let group_context = process_group_info(
            protocol_version,
            group_info,
            tree_data,
            &self.config.identity_provider(),
            &cipher_suite_provider,
        )
        .await?
        .group_context;

        let signer = self
            .config
            .keychain()
            .signer(&signing_identity)
            .await
            .map_err(|e| MlsError::KeychainError(e.into()))?
            .ok_or(MlsError::SignerNotFound)?;

        let key_package = self
            .generate_key_package(
                protocol_version,
                group_context.cipher_suite,
                signing_identity,
            )
            .await?
            .key_package;

        let message = AuthenticatedContent::new_signed(
            &cipher_suite_provider,
            &group_context,
            Sender::NewMemberProposal,
            Content::Proposal(Proposal::Add(AddProposal { key_package })),
            &signer,
            WireFormat::PublicMessage,
            authenticated_data,
        )?;

        let plaintext = PublicMessage {
            content: message.content,
            auth: message.auth,
            membership_tag: None,
        };

        Ok(MLSMessage {
            version: protocol_version,
            payload: MLSMessagePayload::Plain(plaintext),
        })
    }
}

#[cfg(any(test, feature = "benchmark"))]
pub(crate) mod test_utils {
    use super::*;
    use crate::{client_config::ClientConfig, identity::test_utils::get_test_signing_identity};

    pub use crate::client_builder::test_utils::{TestClientBuilder, TestClientConfig};

    pub const TEST_PROTOCOL_VERSION: ProtocolVersion = ProtocolVersion::MLS_10;
    pub const TEST_CIPHER_SUITE: CipherSuite = CipherSuite::CURVE25519_AES128;

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

    pub async fn test_client_with_key_pkg(
        protocol_version: ProtocolVersion,
        cipher_suite: CipherSuite,
        identity: &str,
    ) -> (Client<TestClientConfig>, MLSMessage) {
        test_client_with_key_pkg_custom(protocol_version, cipher_suite, identity, |_| {}).await
    }

    pub async fn test_client_with_key_pkg_custom<F>(
        protocol_version: ProtocolVersion,
        cipher_suite: CipherSuite,
        identity: &str,
        mut config: F,
    ) -> (Client<TestClientConfig>, MLSMessage)
    where
        F: FnMut(&mut TestClientConfig),
    {
        let (client, identity) = get_basic_client_builder(cipher_suite, identity);
        let mut client = client.build();

        config(&mut client.config);

        let key_package = client
            .generate_key_package_message(protocol_version, cipher_suite, identity)
            .await
            .unwrap();

        (client, key_package)
    }

    pub async fn join_group<'a, C, S>(
        committer: &mut Group<C>,
        other_groups: S,
        key_package: MLSMessage,
        client: &Client<C>,
    ) -> Result<(Group<C>, NewMemberInfo), MlsError>
    where
        C: ClientConfig + 'a,
        S: IntoIterator<Item = &'a mut Group<C>>,
    {
        let commit_output = committer
            .commit_builder()
            .add_member(key_package)?
            .build()
            .await?;

        committer.apply_pending_commit().await?;

        for group in other_groups {
            group
                .process_incoming_message(commit_output.commit_message.clone())
                .await?;
        }

        client
            .join_group(
                Some(&committer.export_tree().unwrap()),
                commit_output.welcome_message.unwrap(),
            )
            .await
    }
}

#[cfg(test)]
mod tests {
    use std::vec;

    use super::test_utils::*;

    use super::*;
    use crate::{
        crypto::test_utils::TestCryptoProvider,
        group::{
            message_processor::ProposalMessageDescription,
            proposal::{AddProposal, Proposal},
            test_utils::{test_group, test_group_custom_config},
            CommitMessageDescription, ReceivedMessage,
        },
        identity::test_utils::get_test_basic_credential,
        psk::{ExternalPskId, PreSharedKey},
        tree_kem::leaf_node::LeafNodeSource,
    };
    use assert_matches::assert_matches;

    use aws_mls_codec::MlsEncode;
    #[cfg(target_arch = "wasm32")]
    use wasm_bindgen_test::wasm_bindgen_test as test;

    #[futures_test::test]
    async fn test_keygen() {
        // This is meant to test the inputs to the internal key package generator
        // See KeyPackageGenerator tests for key generation specific tests
        for (protocol_version, cipher_suite) in ProtocolVersion::all().flat_map(|p| {
            TestCryptoProvider::all_supported_cipher_suites()
                .into_iter()
                .map(move |cs| (p, cs))
        }) {
            println!("Running client keygen for {cipher_suite:?}");

            let (client, identity) = get_basic_client_builder(cipher_suite, "foo");
            let client = client.build();

            // TODO: Tests around extensions
            let key_package = client
                .generate_key_package_message(protocol_version, cipher_suite, identity.clone())
                .await
                .unwrap();

            assert_eq!(key_package.version, protocol_version);

            let key_package = key_package.into_key_package().unwrap();

            assert_eq!(key_package.cipher_suite, cipher_suite);

            assert_eq!(
                &key_package.leaf_node.signing_identity.credential,
                &get_test_basic_credential(b"foo".to_vec())
            );

            assert_eq!(
                key_package
                    .leaf_node
                    .signing_identity
                    .mls_encode_to_vec()
                    .unwrap(),
                identity.mls_encode_to_vec().unwrap()
            );

            let client_lifetime = client.config.lifetime();
            assert_matches!(key_package.leaf_node.leaf_node_source, LeafNodeSource::KeyPackage(lifetime) if (lifetime.not_after - lifetime.not_before) == (client_lifetime.not_after - client_lifetime.not_before));

            let capabilities = key_package.leaf_node.capabilities;
            assert_eq!(capabilities, client.config.capabilities());
        }
    }

    #[futures_test::test]
    async fn new_member_add_proposal_adds_to_group() {
        let mut alice_group = test_group(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE).await;

        let (bob, bob_identity) = get_basic_client_builder(TEST_CIPHER_SUITE, "bob");

        let proposal = bob
            .build()
            .external_add_proposal(
                alice_group.group.group_info_message(true).await.unwrap(),
                Some(&alice_group.group.export_tree().unwrap()),
                bob_identity.clone(),
                vec![],
            )
            .await
            .unwrap();

        let message = alice_group
            .group
            .process_incoming_message(proposal)
            .await
            .unwrap();

        assert_matches!(
            message,
            ReceivedMessage::Proposal(ProposalMessageDescription {
                proposal: Proposal::Add(AddProposal { key_package }), ..}
            ) if key_package.leaf_node.signing_identity == bob_identity
        );

        alice_group.group.commit(vec![]).await.unwrap();
        alice_group.group.apply_pending_commit().await.unwrap();

        // Check that the new member is in the group
        assert!(alice_group
            .group
            .roster()
            .into_iter()
            .any(|member| member.signing_identity() == &bob_identity))
    }

    async fn join_via_external_commit(do_remove: bool, with_psk: bool) -> Result<(), MlsError> {
        // An external commit cannot be the first commit in a group as it requires
        // interim_transcript_hash to be computed from the confirmed_transcript_hash and
        // confirmation_tag, which is not the case for the initial interim_transcript_hash.

        let psk = PreSharedKey::from(b"psk".to_vec());
        let psk_id = ExternalPskId::new(b"psk id".to_vec());

        let mut alice_group =
            test_group_custom_config(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE, |c| {
                c.psk(psk_id.clone(), psk.clone())
            })
            .await;

        let (mut bob_group, _) = alice_group
            .join_with_custom_config("bob", false, |c| {
                c.0.psk_store.insert(psk_id.clone(), psk.clone());
            })
            .await
            .unwrap();

        let group_info_msg = alice_group.group.group_info_message(true).await.unwrap();

        let new_client_id = if do_remove { "bob" } else { "charlie" };
        let (new_client, new_client_identity) =
            get_basic_client_builder(TEST_CIPHER_SUITE, new_client_id);

        let new_client = new_client.psk(psk_id.clone(), psk).build();

        let (mut new_group, external_commit) = new_client
            .commit_external(
                group_info_msg,
                Some(&alice_group.group.export_tree().unwrap()),
                new_client_identity,
                do_remove.then_some(1),
                if with_psk { vec![psk_id] } else { vec![] },
                vec![],
            )
            .await?;

        let num_members = if do_remove { 2 } else { 3 };

        assert_eq!(new_group.roster().len(), num_members);

        let _ = alice_group
            .group
            .process_incoming_message(external_commit.clone())
            .await
            .unwrap();

        let message = bob_group
            .group
            .process_incoming_message(external_commit)
            .await
            .unwrap();

        assert!(alice_group.group.roster().len() == num_members);

        if !do_remove {
            assert!(bob_group.group.roster().len() == num_members);
        } else if let ReceivedMessage::Commit(CommitMessageDescription { state_update, .. }) =
            message
        {
            assert!(!state_update.active);
        }

        let alice_msg = b"I'm Alice";

        let msg = alice_group
            .group
            .encrypt_application_message(alice_msg, vec![])
            .await
            .unwrap();

        let received = new_group.process_incoming_message(msg).await.unwrap();
        assert_matches!(received, ReceivedMessage::ApplicationMessage(bytes) if bytes.data() == alice_msg);

        let new_msg = b"I'm the new guy";

        let msg = new_group
            .encrypt_application_message(new_msg, vec![])
            .await
            .unwrap();

        let received = alice_group
            .group
            .process_incoming_message(msg)
            .await
            .unwrap();

        assert_matches!(received, ReceivedMessage::ApplicationMessage(application_msg) if application_msg.data() == new_msg);

        Ok(())
    }

    #[futures_test::test]
    async fn test_external_commit() {
        // New member can join
        join_via_external_commit(false, false).await.unwrap();
        // New member can remove an old copy of themselves
        join_via_external_commit(true, false).await.unwrap();
        // New member can inject a PSK
        join_via_external_commit(false, true).await.unwrap();
        // All works together
        join_via_external_commit(true, true).await.unwrap();
    }

    #[futures_test::test]
    async fn creating_an_external_commit_requires_a_group_info_message() {
        let (alice, alice_identity) = get_basic_client_builder(TEST_CIPHER_SUITE, "alice");
        let alice = alice.build();

        let msg = alice
            .generate_key_package_message(
                TEST_PROTOCOL_VERSION,
                TEST_CIPHER_SUITE,
                alice_identity.clone(),
            )
            .await
            .unwrap();

        let res = alice
            .commit_external(msg, None, alice_identity, None, vec![], vec![])
            .await
            .map(|_| ());

        assert_matches!(res, Err(MlsError::ExpectedGroupInfoMessage));
    }

    #[futures_test::test]
    async fn external_commit_with_invalid_group_info_fails() {
        let mut alice_group = test_group(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE).await;
        let mut bob_group = test_group(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE).await;

        bob_group.group.commit(vec![]).await.unwrap();
        bob_group.group.apply_pending_commit().await.unwrap();

        let group_info_msg = bob_group.group.group_info_message(true).await.unwrap();

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
            .await
            .unwrap();

        // If Carol tries to join Alice's group using the group info from Bob's group, that fails.
        let res = alice_group
            .group
            .process_incoming_message(external_commit)
            .await;
        assert_matches!(res, Err(_));
    }
}
