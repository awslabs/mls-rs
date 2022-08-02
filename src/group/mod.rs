use ferriscrypt::asym::ec_key::EcKeyError;
use ferriscrypt::cipher::aead::AeadError;
use ferriscrypt::hmac::Tag;
use ferriscrypt::hpke::kem::{HpkePublicKey, HpkeSecretKey};
use ferriscrypt::hpke::HpkeError;
use ferriscrypt::kdf::hkdf::Hkdf;
use ferriscrypt::kdf::KdfError;
use ferriscrypt::rand::{SecureRng, SecureRngError};
use std::collections::HashMap;
use std::ops::Deref;
use std::option::Option::Some;
use thiserror::Error;
use tls_codec::{Deserialize, Serialize};
use tls_codec_derive::{TlsDeserialize, TlsSerialize, TlsSize};
use zeroize::Zeroizing;

use crate::cipher_suite::{CipherSuite, HpkeCiphertext};
use crate::client_config::{ClientConfig, CredentialValidator, ProposalFilterInit};
use crate::credential::CredentialError;
use crate::extension::{
    ExtensionError, ExtensionList, ExternalPubExt, ExternalSendersExt, RatchetTreeExt,
    RequiredCapabilitiesExt,
};
use crate::group::{KeySchedule, KeyScheduleError};
use crate::key_package::{
    KeyPackage, KeyPackageError, KeyPackageGeneration, KeyPackageGenerationError, KeyPackageRef,
    KeyPackageRepository, KeyPackageValidationError, KeyPackageValidator,
};
use crate::keychain::Keychain;
use crate::message::{Event, ProcessedMessage};
use crate::psk::{
    ExternalPskId, JoinerSecret, JustPreSharedKeyID, PreSharedKeyID, Psk, PskGroupId, PskNonce,
    PskSecretError, ResumptionPSKUsage, ResumptionPsk,
};
use crate::signer::{Signable, SignatureError, Signer};
use crate::signing_identity::SigningIdentityError;
use crate::tree_kem::kem::TreeKem;
use crate::tree_kem::leaf_node::{LeafNode, LeafNodeError};
use crate::tree_kem::leaf_node_validator::{LeafNodeValidationError, LeafNodeValidator};
use crate::tree_kem::math as tree_math;
use crate::tree_kem::node::LeafIndex;
use crate::tree_kem::path_secret::{PathSecret, PathSecretError};
use crate::tree_kem::tree_validator::{TreeValidationError, TreeValidator};
use crate::tree_kem::{
    Capabilities, RatchetTreeError, TreeKemPrivate, TreeKemPublic, UpdatePath,
    UpdatePathValidationError, UpdatePathValidator,
};
use crate::{EpochRepository, ProtocolVersion};

#[cfg(feature = "benchmark")]
use crate::client_config::Preferences;

use confirmation_tag::*;
use epoch::*;
use framing::*;
use key_schedule::*;
use membership_tag::*;
use message_signature::*;
use message_verifier::*;
use proposal::*;
use proposal_cache::*;
use secret_tree::*;
use transcript_hash::*;

use group_core::GroupCore;
use padding::PaddingMode;

pub use external_group::ExternalGroup;
pub use external_group_config::{ExternalGroupConfig, InMemoryExternalGroupConfig};
pub use group_info::GroupInfo;
pub use group_state::GroupState;
pub(crate) use proposal_cache::ProposalCacheError;
pub use proposal_filter::{
    BoxedProposalFilter, PassThroughProposalFilter, ProposalBundle, ProposalFilter,
    ProposalFilterError,
};
pub(crate) use proposal_ref::ProposalRef;
pub use roster::*;
pub use secret_tree::SecretTreeError;
pub use stats::*;
pub use transcript_hash::ConfirmedTranscriptHash;

mod confirmation_tag;
pub(crate) mod epoch;
mod external_group;
mod external_group_config;
pub mod framing;
mod group_core;
mod group_info;
mod group_state;
pub mod key_schedule;
mod membership_tag;
pub mod message_signature;
mod message_verifier;
pub mod padding;
pub mod proposal;
mod proposal_cache;
mod proposal_filter;
mod proposal_ref;
mod roster;
mod stats;
mod transcript_hash;

#[cfg(feature = "benchmark")]
pub mod secret_tree;

#[cfg(not(feature = "benchmark"))]
pub(crate) mod secret_tree;

struct ProvisionalState {
    public_state: ProvisionalPublicState,
    private_tree: TreeKemPrivate,
}

struct ProvisionalPublicState {
    public_tree: TreeKemPublic,
    added_leaves: Vec<(KeyPackage, LeafIndex)>,
    removed_leaves: Vec<(LeafIndex, LeafNode)>,
    updated_leaves: Vec<LeafIndex>,
    group_context: GroupContext,
    epoch: u64,
    path_update_required: bool,
    psks: Vec<PreSharedKeyID>,
    reinit: Option<ReInit>,
    external_init: Option<(LeafIndex, ExternalInit)>,
    rejected_proposals: Vec<(ProposalRef, Proposal)>,
}

#[derive(Clone, Debug)]
pub struct StateUpdate {
    pub added: Vec<LeafIndex>,
    pub removed: Vec<(LeafIndex, LeafNode)>,
    pub updated: Vec<LeafIndex>,
    pub psks: Vec<JustPreSharedKeyID>,
    pub reinit: Option<ReInit>,
    pub external_init: Option<LeafIndex>,
    pub active: bool,
    pub epoch: u64,
    pub rejected_proposals: Vec<(ProposalRef, Proposal)>,
}

impl From<&ProvisionalPublicState> for StateUpdate {
    fn from(provisional: &ProvisionalPublicState) -> Self {
        let added = provisional
            .added_leaves
            .iter()
            .map(|(_, leaf_index)| *leaf_index)
            .collect::<Vec<_>>();

        let removed = provisional
            .removed_leaves
            .iter()
            .map(|(index, kp)| (*index, kp.clone()))
            .collect::<Vec<(_, _)>>();

        let external_init_leaf = provisional
            .external_init
            .clone()
            .map(|(leaf_index, _)| leaf_index);

        let psks = provisional
            .psks
            .iter()
            .map(|psk_id| psk_id.key_id.clone())
            .collect::<Vec<_>>();

        StateUpdate {
            added,
            removed,
            updated: provisional.updated_leaves.clone(),
            psks,
            reinit: provisional.reinit.clone(),
            external_init: external_init_leaf,
            active: true,
            epoch: provisional.epoch,
            rejected_proposals: provisional.rejected_proposals.clone(),
        }
    }
}

impl From<&ProvisionalState> for StateUpdate {
    fn from(provisional: &ProvisionalState) -> Self {
        Self {
            ..Self::from(&provisional.public_state)
        }
    }
}

impl ProvisionalState {
    fn self_index_removed(&self) -> bool {
        self.public_state
            .removed_leaves
            .iter()
            .any(|(index, _)| index == &self.private_tree.self_index)
    }
}

#[derive(Clone, Debug, PartialEq, TlsDeserialize, TlsSerialize, TlsSize)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct Commit {
    #[tls_codec(with = "crate::tls::DefVec")]
    pub proposals: Vec<ProposalOrRef>,
    pub path: Option<UpdatePath>,
}

#[derive(Error, Debug)]
pub enum GroupError {
    #[error(transparent)]
    RatchetTreeError(#[from] RatchetTreeError),
    #[error(transparent)]
    EpochError(#[from] EpochError),
    #[error(transparent)]
    SignerError(Box<dyn std::error::Error>),
    #[error(transparent)]
    EcKeyError(#[from] EcKeyError),
    #[error(transparent)]
    SignatureError(#[from] SignatureError),
    #[error(transparent)]
    TlsCodecError(#[from] tls_codec::Error),
    #[error(transparent)]
    TranscriptHashError(#[from] TranscriptHashError),
    #[error(transparent)]
    KeyPackageError(#[from] KeyPackageError),
    #[error(transparent)]
    LeafNodeError(#[from] LeafNodeError),
    #[error(transparent)]
    LeafNodeValidationError(#[from] LeafNodeValidationError),
    #[error(transparent)]
    MembershipTagError(#[from] MembershipTagError),
    #[error(transparent)]
    RngError(#[from] SecureRngError),
    #[error(transparent)]
    HpkeError(#[from] HpkeError),
    #[error(transparent)]
    CredentialError(#[from] CredentialError),
    #[error(transparent)]
    ConfirmationTagError(#[from] ConfirmationTagError),
    #[error(transparent)]
    KeyScheduleKdfError(#[from] KeyScheduleKdfError),
    #[error(transparent)]
    AeadError(#[from] AeadError),
    #[error(transparent)]
    LeafSecretError(#[from] PathSecretError),
    #[error(transparent)]
    EpochRepositoryError(Box<dyn std::error::Error + Send + Sync>),
    #[error(transparent)]
    KeyPackageRepositoryError(Box<dyn std::error::Error + Send + Sync>),
    #[error(transparent)]
    ExtensionError(#[from] ExtensionError),
    #[error(transparent)]
    KdfError(#[from] KdfError),
    #[error(transparent)]
    KeyScheduleError(#[from] KeyScheduleError),
    #[error(transparent)]
    KeyPackageGenerationError(#[from] KeyPackageGenerationError),
    #[error(transparent)]
    KeyPackageValidationError(#[from] KeyPackageValidationError),
    #[error(transparent)]
    UpdatePathValidationError(#[from] UpdatePathValidationError),
    #[error(transparent)]
    ProposalCacheError(#[from] ProposalCacheError),
    #[error(transparent)]
    TreeValidationError(#[from] TreeValidationError),
    #[error(transparent)]
    SigningIdentityError(#[from] SigningIdentityError),
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
    PskSecretError(#[from] PskSecretError),
    #[error("Subgroup uses a different protocol version: {0:?}")]
    SubgroupWithDifferentProtocolVersion(ProtocolVersion),
    #[error("Subgroup uses a different cipher suite: {0:?}")]
    SubgroupWithDifferentCipherSuite(CipherSuite),
    #[error("Unsupported protocol version {0:?} or cipher suite {1:?}")]
    UnsupportedProtocolVersionOrCipherSuite(ProtocolVersion, CipherSuite),
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
    #[error("signer not found")]
    SignerNotFound,
    #[error("commit already pending")]
    ExistingPendingCommit,
    #[error("pending commit not found")]
    PendingCommitNotFound,
    #[error("received unexpected welcome message")]
    UnexpectedWelcomeMessage,
    #[error("received unexpected group info message")]
    UnexpectedGroupInfo,
    #[error("received unexpected key package message")]
    UnexpectedKeyPackage,
    #[error("membership tag on MLSPlaintext for non-member sender")]
    MembershipTagForNonMember,
}

#[derive(
    Clone,
    Debug,
    PartialEq,
    TlsDeserialize,
    TlsSerialize,
    TlsSize,
    serde::Deserialize,
    serde::Serialize,
)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct GroupContext {
    pub protocol_version: ProtocolVersion,
    pub cipher_suite: CipherSuite,
    #[tls_codec(with = "crate::tls::ByteVec")]
    pub group_id: Vec<u8>,
    pub epoch: u64,
    #[tls_codec(with = "crate::tls::ByteVec")]
    pub tree_hash: Vec<u8>,
    pub confirmed_transcript_hash: ConfirmedTranscriptHash,
    pub extensions: ExtensionList,
}

impl GroupContext {
    pub fn new_group(
        protocol_version: ProtocolVersion,
        cipher_suite: CipherSuite,
        group_id: Vec<u8>,
        tree_hash: Vec<u8>,
        extensions: ExtensionList,
    ) -> Self {
        GroupContext {
            protocol_version,
            cipher_suite,
            group_id,
            epoch: 0,
            tree_hash,
            confirmed_transcript_hash: ConfirmedTranscriptHash::from(vec![]),
            extensions,
        }
    }
}

#[derive(
    Clone, Debug, serde::Serialize, serde::Deserialize, TlsSerialize, TlsDeserialize, TlsSize,
)]
pub struct CommitGeneration {
    pub content: MLSAuthenticatedContent,
    pub pending_secrets: Option<(TreeKemPrivate, PathSecret)>,
}

#[derive(Clone, Debug)]
pub struct CommitOptions {
    pub prefer_path_update: bool,
    pub extension_update: Option<ExtensionList>,
    pub capabilities_update: Option<Capabilities>,
    pub encryption_mode: ControlEncryptionMode,
    pub ratchet_tree_extension: bool,
}

#[derive(Clone, Debug, PartialEq, TlsDeserialize, TlsSerialize, TlsSize)]
struct GroupSecrets {
    joiner_secret: JoinerSecret,
    path_secret: Option<PathSecret>,
    #[tls_codec(with = "crate::tls::DefVec")]
    psks: Vec<PreSharedKeyID>,
}

#[derive(Clone, Debug, PartialEq, TlsDeserialize, TlsSerialize, TlsSize)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct EncryptedGroupSecrets {
    pub new_member: KeyPackageRef,
    pub encrypted_group_secrets: HpkeCiphertext,
}

#[derive(Clone, Debug, PartialEq, TlsDeserialize, TlsSerialize, TlsSize)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct Welcome {
    pub cipher_suite: CipherSuite,
    #[tls_codec(with = "crate::tls::DefVec")]
    pub secrets: Vec<EncryptedGroupSecrets>,
    #[tls_codec(with = "crate::tls::ByteVec")]
    pub encrypted_group_info: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ControlEncryptionMode {
    Plaintext,
    Encrypted(PaddingMode),
}

#[derive(Clone, Debug)]
pub struct Group<C>
where
    C: ClientConfig + Clone,
{
    config: C,
    #[cfg(feature = "benchmark")]
    pub core: GroupCore,
    #[cfg(not(feature = "benchmark"))]
    core: GroupCore,
    private_tree: TreeKemPrivate,
    // TODO: HpkePublicKey does not have Eq and Hash
    pub pending_updates: HashMap<Vec<u8>, HpkeSecretKey>, // Hash of leaf node hpke public key to secret key
    pending_commit: Option<CommitGeneration>,
    key_schedule: KeySchedule,
    confirmation_tag: ConfirmationTag,
}

impl<C: ClientConfig + Clone> PartialEq for Group<C> {
    fn eq(&self, other: &Self) -> bool {
        self.context() == other.context()
            && self.core.interim_transcript_hash == other.core.interim_transcript_hash
            && self.core.proposals == other.core.proposals
            && self.key_schedule == other.key_schedule
    }
}

impl<C> Group<C>
where
    C: ClientConfig + Clone,
{
    pub fn new(
        config: C,
        group_id: Vec<u8>,
        cipher_suite: CipherSuite,
        protocol_version: ProtocolVersion,
        group_context_extensions: ExtensionList,
    ) -> Result<Self, GroupError> {
        let (signing_identity, signer) = config
            .keychain()
            .default_identity(cipher_suite)
            .ok_or(GroupError::NoCredentialFound)?;

        let (leaf_node, leaf_node_secret) = LeafNode::generate(
            cipher_suite,
            signing_identity,
            config.capabilities(),
            config.leaf_node_extensions(),
            &signer,
            config.lifetime(),
            &config.credential_validator(),
        )?;

        let (mut public_tree, private_tree) =
            TreeKemPublic::derive(cipher_suite, leaf_node, leaf_node_secret)?;

        let tree_hash = public_tree.tree_hash()?;

        let context = GroupContext::new_group(
            protocol_version,
            cipher_suite,
            group_id,
            tree_hash,
            group_context_extensions,
        );

        let kdf = Hkdf::from(cipher_suite.kdf_type());

        let key_schedule_result = KeySchedule::derive(
            &KeySchedule::new(InitSecret::random(&kdf)?),
            &CommitSecret::empty(cipher_suite),
            &context,
            LeafIndex(0),
            &public_tree,
            &Psk::from(vec![0; kdf.extract_size()]),
        )?;

        //TODO: Is this actually needed here?
        config
            .epoch_repo()
            .insert(key_schedule_result.epoch.into())
            .map_err(|e| GroupError::EpochRepositoryError(e.into()))?;

        Ok(Self {
            config,
            core: GroupCore::new(context, public_tree, InterimTranscriptHash::from(vec![])),
            private_tree,
            confirmation_tag: ConfirmationTag::empty(&cipher_suite)?,
            pending_updates: Default::default(),
            pending_commit: None,
            key_schedule: key_schedule_result.key_schedule,
        })
    }

    #[cfg(feature = "benchmark")]
    pub fn preferences(&self) -> Preferences {
        self.config.preferences()
    }

    pub fn join(
        protocol_version: ProtocolVersion,
        welcome: Welcome,
        public_tree: Option<TreeKemPublic>,
        config: C,
    ) -> Result<Self, GroupError> {
        Self::from_welcome_message(None, protocol_version, welcome, public_tree, config)
    }

    fn from_welcome_message(
        parent_group_id: Option<&[u8]>,
        protocol_version: ProtocolVersion,
        welcome: Welcome,
        public_tree: Option<TreeKemPublic>,
        config: C,
    ) -> Result<Self, GroupError> {
        let key_package_generation = find_key_package_generation(&config, &welcome)?;
        // Identify an entry in the secrets array where the KeyPackageRef value corresponds to
        // one of this client's KeyPackages, using the hash indicated by the cipher_suite field.
        // If no such field exists, or if the ciphersuite indicated in the KeyPackage does not
        // match the one in the Welcome message, return an error.
        let key_package_reference = key_package_generation.key_package.to_reference()?;

        let encrypted_group_secrets = welcome
            .secrets
            .iter()
            .find(|s| s.new_member == key_package_reference)
            .ok_or(GroupError::WelcomeKeyPackageNotFound)?;

        // Decrypt the encrypted_group_secrets using HPKE with the algorithms indicated by the
        // cipher suite and the HPKE private key corresponding to the GroupSecrets. If a
        // PreSharedKeyID is part of the GroupSecrets and the client is not in possession of
        // the corresponding PSK, return an error
        let decrypted_group_secrets = welcome.cipher_suite.hpke().open(
            &encrypted_group_secrets
                .encrypted_group_secrets
                .clone()
                .into(),
            &key_package_generation.init_secret_key,
            &[],
            None,
            None,
        )?;

        let group_secrets = GroupSecrets::tls_deserialize(&mut &*decrypted_group_secrets)?;
        let psk_store = config.secret_store();
        let epoch_repo = config.epoch_repo();

        let psk_secret = crate::psk::psk_secret(
            welcome.cipher_suite,
            Some(&psk_store),
            parent_group_id.map(|gid| (gid, &epoch_repo)),
            &group_secrets.psks,
        )?;

        // From the joiner_secret in the decrypted GroupSecrets object and the PSKs specified in
        // the GroupSecrets, derive the welcome_secret and using that the welcome_key and
        // welcome_nonce.
        let welcome_secret = WelcomeSecret::from_joiner_secret(
            welcome.cipher_suite,
            &group_secrets.joiner_secret,
            &psk_secret,
        )?;

        // Use the key and nonce to decrypt the encrypted_group_info field.
        let decrypted_group_info = welcome_secret.decrypt(&welcome.encrypted_group_info)?;
        let group_info = GroupInfo::tls_deserialize(&mut &*decrypted_group_info)?;

        let cipher_suite = group_info.group_context.cipher_suite;

        if !version_and_cipher_filter(&config, protocol_version, cipher_suite) {
            return Err(GroupError::UnsupportedProtocolVersionOrCipherSuite(
                protocol_version,
                cipher_suite,
            ));
        }

        let mut public_tree = find_tree(public_tree, &group_info)?;

        validate_existing_group(
            &mut public_tree,
            &group_info,
            &config.credential_validator(),
        )?;

        // Identify a leaf in the tree array (any even-numbered node) whose leaf_node is identical
        // to the leaf_node field of the KeyPackage. If no such field exists, return an error. Let
        // index represent the index of this node among the leaves in the tree, namely the index of
        // the node in the tree array divided by two.
        let self_index = public_tree
            .find_leaf_node(&key_package_generation.key_package.leaf_node)
            .ok_or(GroupError::WelcomeKeyPackageNotFound)?;

        // Construct a new group state using the information in the GroupInfo object. The new
        // member's position in the tree is index, as defined above. In particular, the confirmed
        // transcript hash for the new state is the prior_confirmed_transcript_hash in the GroupInfo
        // object.
        let context = &group_info.group_context;

        let mut private_tree =
            TreeKemPrivate::new_self_leaf(self_index, key_package_generation.leaf_node_secret_key);

        // If the path_secret value is set in the GroupSecrets object
        if let Some(path_secret) = group_secrets.path_secret {
            private_tree.update_secrets(
                group_info.group_context.cipher_suite,
                group_info.signer,
                path_secret,
                &public_tree,
            )?;
        }

        // Use the joiner_secret from the GroupSecrets object to generate the epoch secret and
        // other derived secrets for the current epoch.
        let key_schedule_result = KeySchedule::new_joiner(
            group_info.group_context.cipher_suite,
            &group_secrets.joiner_secret,
            context,
            self_index,
            &public_tree,
            &psk_secret,
        )?;

        // Verify the confirmation tag in the GroupInfo using the derived confirmation key and the
        // confirmed_transcript_hash from the GroupInfo.
        if !group_info.confirmation_tag.matches(
            &key_schedule_result.confirmation_key,
            &group_info.group_context.confirmed_transcript_hash,
            &group_info.group_context.cipher_suite,
        )? {
            return Err(GroupError::InvalidConfirmationTag);
        }

        config
            .epoch_repo()
            .insert(key_schedule_result.epoch.into())
            .map_err(|e| GroupError::EpochRepositoryError(e.into()))?;

        Self::join_with(
            config,
            &group_info.confirmation_tag,
            group_info.group_context,
            public_tree,
            key_schedule_result.key_schedule,
            private_tree,
        )
    }

    fn join_with(
        config: C,
        confirmation_tag: &ConfirmationTag,
        context: GroupContext,
        current_tree: TreeKemPublic,
        key_schedule: KeySchedule,
        private_tree: TreeKemPrivate,
    ) -> Result<Self, GroupError> {
        // Use the confirmed transcript hash and confirmation tag to compute the interim transcript
        // hash in the new state.
        let interim_transcript_hash = InterimTranscriptHash::create(
            current_tree.cipher_suite,
            &context.confirmed_transcript_hash,
            confirmation_tag,
        )?;

        Ok(Group {
            config,
            core: GroupCore::new(context, current_tree, interim_transcript_hash),
            private_tree,
            confirmation_tag: confirmation_tag.clone(),
            pending_updates: Default::default(),
            pending_commit: None,
            key_schedule,
        })
    }

    /// Returns group and external commit message
    pub fn new_external(
        config: C,
        protocol_version: ProtocolVersion,
        group_info: GroupInfo,
        public_tree: Option<TreeKemPublic>,
        to_remove: Option<u32>,
        external_psks: Vec<ExternalPskId>,
        authenticated_data: Vec<u8>,
    ) -> Result<(Self, MLSMessage), GroupError> {
        // Validate received group info and tree.
        if !version_and_cipher_filter(
            &config,
            protocol_version,
            group_info.group_context.cipher_suite,
        ) {
            return Err(GroupError::UnsupportedProtocolVersionOrCipherSuite(
                protocol_version,
                group_info.group_context.cipher_suite,
            ));
        }

        let external_pub_ext = group_info
            .extensions
            .get_extension::<ExternalPubExt>()?
            .ok_or(GroupError::MissingExternalPubExtension)?;

        let (identity, signer) = config
            .keychain()
            .default_identity(group_info.group_context.cipher_suite)
            .ok_or(GroupError::NoCredentialFound)?;

        let (leaf_node, leaf_node_secret) = LeafNode::generate(
            group_info.group_context.cipher_suite,
            identity,
            config.capabilities(),
            config.leaf_node_extensions(),
            &signer,
            config.lifetime(),
            &config.credential_validator(),
        )?;

        let mut public_tree = find_tree(public_tree, &group_info)?;
        validate_existing_group(
            &mut public_tree,
            &group_info,
            &config.credential_validator(),
        )?;

        let (init_secret, kem_output) = InitSecret::encode_for_external(
            group_info.group_context.cipher_suite,
            &external_pub_ext.external_pub,
        )?;

        let mut group = Self::join_with(
            config,
            &group_info.confirmation_tag,
            group_info.group_context,
            public_tree,
            KeySchedule::new(init_secret),
            TreeKemPrivate::new_self_leaf(LeafIndex(0), leaf_node_secret),
        )?;

        let psk_ids = external_psks
            .into_iter()
            .map(|psk_id| {
                Ok(PreSharedKeyID {
                    key_id: crate::session::JustPreSharedKeyID::External(psk_id),
                    psk_nonce: PskNonce::random(group.core.cipher_suite())?,
                })
            })
            .collect::<Result<Vec<_>, GroupError>>()?;

        let proposals = psk_ids
            .into_iter()
            .map(|psk| Proposal::Psk(PreSharedKey { psk }))
            .chain([Proposal::ExternalInit(ExternalInit { kem_output })])
            .chain(to_remove.map(|r| {
                Proposal::Remove(RemoveProposal {
                    to_remove: LeafIndex(r),
                })
            }))
            .collect::<Vec<_>>();

        let (commit, _) =
            group.commit_proposals(proposals, Some(&leaf_node), authenticated_data)?;

        group.process_pending_commit()?;

        Ok((group, commit))
    }

    #[inline(always)]
    pub fn current_epoch_tree(&self) -> &TreeKemPublic {
        &self.core.current_tree
    }

    #[inline(always)]
    pub fn current_epoch(&self) -> u64 {
        self.context().epoch
    }

    #[inline(always)]
    pub fn current_user_index(&self) -> u32 {
        self.private_tree.self_index.0 as u32
    }

    pub fn current_user_leaf_node(&self) -> Result<&LeafNode, GroupError> {
        self.current_epoch_tree()
            .get_leaf_node(self.private_tree.self_index)
            .map_err(Into::into)
    }

    fn apply_proposals(
        &self,
        proposals: ProposalSetEffects,
    ) -> Result<ProvisionalState, GroupError> {
        let mut provisional_private_tree = self.private_tree.clone();
        let total_leaf_count = self.current_epoch_tree().total_leaf_count();

        // Apply updates to private tree
        for (_, leaf_node) in &proposals.updates {
            // Update the leaf in the private tree if this is our update
            if let Some(new_leaf_sk) = self
                .pending_updates
                .get(leaf_node.public_key.as_ref())
                .cloned()
            {
                provisional_private_tree.update_leaf(total_leaf_count, new_leaf_sk)?;
            }
        }

        // Remove elements from the private tree
        proposals.removes.iter().try_for_each(|&leaf_index| {
            provisional_private_tree.remove_leaf(total_leaf_count, leaf_index)?;
            Ok::<_, GroupError>(())
        })?;

        Ok(ProvisionalState {
            public_state: self.core.apply_proposals(proposals)?,
            private_tree: provisional_private_tree,
        })
    }

    pub fn create_proposal(
        &mut self,
        proposal: Proposal,
        authenticated_data: Vec<u8>,
    ) -> Result<MLSMessage, GroupError> {
        let signer = self.signer()?;

        let auth_content = MLSAuthenticatedContent::new_signed(
            self.context(),
            Sender::Member(self.private_tree.self_index),
            Content::Proposal(proposal.clone()),
            &signer,
            self.config.preferences().encryption_mode().into(),
            authenticated_data,
        )?;

        let proposal_ref = ProposalRef::from_content(self.core.cipher_suite(), &auth_content)?;

        self.core
            .proposals
            .insert(proposal_ref, proposal, auth_content.content.sender.clone());

        self.format_for_wire(auth_content)
    }

    pub(crate) fn signer(&self) -> Result<<C::Keychain as Keychain>::Signer, GroupError> {
        self.config
            .keychain()
            .signer(&self.current_user_leaf_node()?.signing_identity)
            .ok_or(GroupError::SignerNotFound)
    }

    #[inline(always)]
    pub fn group_id(&self) -> &[u8] {
        &self.context().group_id
    }

    /// Returns commit and optional `MLSMessage` containing a `Welcome`
    pub fn commit_proposals(
        &mut self,
        proposals: Vec<Proposal>,
        external_leaf: Option<&LeafNode>,
        authenticated_data: Vec<u8>,
    ) -> Result<(MLSMessage, Option<MLSMessage>), GroupError> {
        if self.pending_commit.is_some() {
            return Err(GroupError::ExistingPendingCommit);
        }

        let options = self.config.commit_options();

        // Construct an initial Commit object with the proposals field populated from Proposals
        // received during the current epoch, and an empty path field. Add passed in proposals
        // by value
        let is_external = external_leaf.is_some();

        let sender = if is_external {
            Sender::NewMemberCommit
        } else {
            Sender::Member(self.private_tree.self_index)
        };

        let signer = match external_leaf {
            Some(leaf_node) => self
                .config
                .keychain()
                .signer(&leaf_node.signing_identity)
                .ok_or(GroupError::NoCredentialFound),
            None => self.signer(),
        }?;

        let (commit_proposals, proposal_effects) = self.core.proposals.prepare_commit(
            sender.clone(),
            proposals,
            self.context().extensions.get_extension()?,
            self.config.credential_validator(),
            &self.core.current_tree,
            external_leaf,
            self.config.proposal_filter(ProposalFilterInit::new(
                &self.core.current_tree,
                self.context(),
                sender.clone(),
            )),
        )?;

        let mut provisional_state = self.apply_proposals(proposal_effects)?;

        if is_external {
            provisional_state.private_tree.self_index = provisional_state
                .public_state
                .external_init
                .ok_or(GroupError::ExternalCommitMissingExternalInit)?
                .0;

            self.private_tree.self_index = provisional_state.private_tree.self_index;
        }

        let mut provisional_group_context = provisional_state.public_state.group_context;
        provisional_group_context.epoch += 1;

        // Decide whether to populate the path field: If the path field is required based on the
        // proposals that are in the commit (see above), then it MUST be populated. Otherwise, the
        // sender MAY omit the path field at its discretion.
        let perform_path_update =
            options.prefer_path_update || provisional_state.public_state.path_update_required;

        let added_leaves = provisional_state.public_state.added_leaves;

        let (update_path, path_secrets, root_secret) = if perform_path_update {
            // If populating the path field: Create an UpdatePath using the new tree. Any new
            // member (from an add proposal) MUST be excluded from the resolution during the
            // computation of the UpdatePath. The GroupContext for this operation uses the
            // group_id, epoch, tree_hash, and confirmed_transcript_hash values in the initial
            // GroupContext object. The leaf_key_package for this UpdatePath must have a
            // parent_hash extension.
            let encap_gen = TreeKem::new(
                &mut provisional_state.public_state.public_tree,
                &mut provisional_state.private_tree,
            )
            .encap(
                &self.context().group_id,
                &mut provisional_group_context,
                &added_leaves
                    .iter()
                    .map(|(_, leaf_index)| *leaf_index)
                    .collect::<Vec<LeafIndex>>(),
                &signer,
                options.capabilities_update,
                options.extension_update,
            )?;

            (
                Some(encap_gen.update_path),
                Some(encap_gen.path_secrets),
                Some(encap_gen.root_secret),
            )
        } else {
            // Update the tree hash, since it was not updated by encap.
            provisional_state
                .public_state
                .public_tree
                .update_hashes(&mut vec![provisional_state.private_tree.self_index], &[])?;

            provisional_group_context.tree_hash =
                provisional_state.public_state.public_tree.tree_hash()?;
            (None, None, None)
        };

        let commit_secret =
            CommitSecret::from_root_secret(self.core.cipher_suite(), root_secret.as_ref())?;

        let epoch_repo = self.config.epoch_repo();
        let psk_store = self.config.secret_store();

        let psk_secret = crate::psk::psk_secret(
            self.core.cipher_suite(),
            Some(&psk_store),
            Some((&self.context().group_id, &epoch_repo)),
            &provisional_state.public_state.psks,
        )?;

        let commit = Commit {
            proposals: commit_proposals,
            path: update_path,
        };

        let mut auth_content = MLSAuthenticatedContent::new_signed(
            self.context(),
            sender,
            Content::Commit(commit),
            &signer,
            options.encryption_mode.into(),
            authenticated_data,
        )?;

        // Use the signature, the commit_secret and the psk_secret to advance the key schedule and
        // compute the confirmation_tag value in the MLSPlaintext.
        let confirmed_transcript_hash = ConfirmedTranscriptHash::create(
            self.core.cipher_suite(),
            &self.core.interim_transcript_hash,
            &auth_content,
        )?;

        provisional_group_context.confirmed_transcript_hash = confirmed_transcript_hash;

        let mut extensions = ExtensionList::new();

        if options.ratchet_tree_extension {
            let ratchet_tree_ext = RatchetTreeExt {
                tree_data: provisional_state
                    .public_state
                    .public_tree
                    .export_node_data(),
            };

            extensions.set_extension(ratchet_tree_ext)?;
        }

        let key_schedule_result = KeySchedule::derive(
            &self.key_schedule,
            &commit_secret,
            &provisional_group_context,
            provisional_state.private_tree.self_index,
            &self.core.current_tree,
            &psk_secret,
        )?;

        let confirmation_tag = ConfirmationTag::create(
            &key_schedule_result.confirmation_key,
            &provisional_group_context.confirmed_transcript_hash,
            &self.core.cipher_suite(),
        )?;

        auth_content.auth.confirmation_tag = Some(confirmation_tag.clone());

        // Construct a GroupInfo reflecting the new state
        // Group ID, epoch, tree, and confirmed transcript hash from the new state
        let mut group_info = GroupInfo {
            group_context: provisional_group_context.clone(),
            extensions,
            confirmation_tag, // The confirmation_tag from the MLSPlaintext object
            signer: provisional_state.private_tree.self_index,
            signature: vec![],
        };

        // Sign the GroupInfo using the member's private signing key
        group_info.sign(&signer, &())?;

        let welcome = self
            .make_welcome_message(
                added_leaves,
                &key_schedule_result.joiner_secret,
                &psk_secret,
                path_secrets.as_ref(),
                provisional_state.public_state.psks,
                &group_info,
            )?
            .map(|welcome| MLSMessage {
                version: provisional_group_context.protocol_version,
                payload: MLSMessagePayload::Welcome(welcome),
            });

        let commit_message = self.format_for_wire(auth_content.clone())?;

        let pending_commit = CommitGeneration {
            content: auth_content,
            pending_secrets: root_secret.map(|rs| (provisional_state.private_tree, rs)),
        };

        self.pending_commit = Some(pending_commit);

        Ok((commit_message, welcome))
    }

    fn make_welcome_message(
        &self,
        new_members: Vec<(KeyPackage, LeafIndex)>,
        joiner_secret: &JoinerSecret,
        psk_secret: &Psk,
        path_secrets: Option<&Vec<Option<PathSecret>>>,
        psks: Vec<PreSharedKeyID>,
        group_info: &GroupInfo,
    ) -> Result<Option<Welcome>, GroupError> {
        // Encrypt the GroupInfo using the key and nonce derived from the joiner_secret for
        // the new epoch
        let welcome_secret =
            WelcomeSecret::from_joiner_secret(self.core.cipher_suite(), joiner_secret, psk_secret)?;

        let group_info_data = group_info.tls_serialize_detached()?;
        let encrypted_group_info = welcome_secret.encrypt(&group_info_data)?;

        let secrets = new_members
            .into_iter()
            .map(|(key_package, leaf_index)| {
                self.encrypt_group_secrets(
                    &key_package,
                    leaf_index,
                    joiner_secret,
                    path_secrets,
                    psks.clone(),
                )
            })
            .collect::<Result<Vec<EncryptedGroupSecrets>, GroupError>>()?;

        Ok(match secrets.len() {
            0 => None,
            _ => Some(Welcome {
                cipher_suite: group_info.group_context.cipher_suite,
                secrets,
                encrypted_group_info,
            }),
        })
    }

    fn new_for_resumption<S, F>(
        &self,
        new_context: &mut GroupContext,
        new_validated_leaf: LeafNode,
        new_leaf_secret: HpkeSecretKey,
        new_signer: &S,
        mut get_new_key_package: F,
        resumption_psk_id: JustPreSharedKeyID,
    ) -> Result<(Self, Option<Welcome>), GroupError>
    where
        S: Signer,
        F: FnMut(&LeafNode) -> Option<KeyPackage>,
    {
        let required_capabilities = new_context.extensions.get_extension()?;

        let key_package_validator = KeyPackageValidator::new(
            new_context.protocol_version,
            new_context.cipher_suite,
            required_capabilities.as_ref(),
            self.config.credential_validator(),
        );

        // Generate new leaves for all existing members
        let (new_members, new_key_pkgs) = {
            let current_tree = self.current_epoch_tree();
            let self_index = self.private_tree.self_index;

            current_tree
                .non_empty_leaves()
                .filter_map(|(index, leaf_node)| {
                    if index == self_index {
                        None
                    } else {
                        get_new_key_package(leaf_node)
                    }
                })
                .try_fold(
                    (Vec::new(), Vec::new()),
                    |(mut leaves, mut new_key_pkgs), new_key_pkg| {
                        key_package_validator.check_if_valid(&new_key_pkg, Default::default())?;
                        let new_leaf = new_key_pkg.leaf_node.clone();
                        leaves.push(new_leaf);
                        new_key_pkgs.push(new_key_pkg);
                        Ok::<_, GroupError>((leaves, new_key_pkgs))
                    },
                )?
        };

        let (mut new_pub_tree, new_priv_tree) = TreeKemPublic::derive(
            new_context.cipher_suite,
            new_validated_leaf,
            new_leaf_secret,
        )?;

        // Add the generated leaves to new tree
        let added_member_indexes = new_pub_tree.add_leaves(new_members)?;
        new_context.tree_hash = new_pub_tree.tree_hash()?;

        let epoch_repo = self.config.epoch_repo();

        let psks = vec![PreSharedKeyID {
            key_id: resumption_psk_id,
            psk_nonce: PskNonce::random(new_context.cipher_suite)?,
        }];

        let psk_secret = crate::psk::psk_secret(
            new_context.cipher_suite,
            None::<&C::PskStore>,
            Some((&self.context().group_id, &epoch_repo)),
            &psks,
        )?;

        let kdf = Hkdf::from(new_context.cipher_suite.kdf_type());

        let key_schedule_result = KeySchedule::derive(
            &KeySchedule::new(InitSecret::random(&kdf)?),
            &CommitSecret::empty(new_context.cipher_suite),
            new_context,
            LeafIndex(0),
            &new_pub_tree,
            &psk_secret,
        )?;

        let mut group_info = GroupInfo {
            group_context: new_context.clone(),
            extensions: ExtensionList::new(),
            confirmation_tag: ConfirmationTag::create(
                &key_schedule_result.confirmation_key,
                &new_context.confirmed_transcript_hash,
                &new_context.cipher_suite,
            )?,
            signer: new_priv_tree.self_index,
            signature: Vec::new(),
        };

        group_info.sign(new_signer, &())?;

        self.config
            .epoch_repo()
            .insert(key_schedule_result.epoch.into())
            .map_err(|e| GroupError::EpochRepositoryError(e.into()))?;

        let interim_transcript_hash = InterimTranscriptHash::create(
            new_context.cipher_suite,
            &new_context.confirmed_transcript_hash,
            &group_info.confirmation_tag,
        )?;

        let new_group = Group {
            config: self.config.clone(),
            core: GroupCore::new(new_context.clone(), new_pub_tree, interim_transcript_hash),
            private_tree: new_priv_tree,
            key_schedule: key_schedule_result.key_schedule,
            confirmation_tag: ConfirmationTag::empty(&self.core.cipher_suite())?,
            pending_updates: Default::default(),
            pending_commit: None,
        };

        let welcome = new_group.make_welcome_message(
            new_key_pkgs.into_iter().zip(added_member_indexes).collect(),
            &key_schedule_result.joiner_secret,
            &psk_secret,
            None,
            psks,
            &group_info,
        )?;

        Ok((new_group, welcome))
    }

    pub fn branch<F>(
        &self,
        sub_group_id: Vec<u8>,
        get_new_key_package: F,
    ) -> Result<(Self, Option<Welcome>), GroupError>
    where
        F: FnMut(&LeafNode) -> Option<KeyPackage>,
    {
        let signer = self.signer()?;

        let current_leaf_node = self.current_user_leaf_node()?;

        let (new_leaf_node, new_leaf_secret) = LeafNode::generate(
            self.core.cipher_suite(),
            current_leaf_node.signing_identity.clone(),
            current_leaf_node.capabilities.clone(),
            current_leaf_node.extensions.clone(),
            &signer,
            self.config.lifetime(),
            &self.config.credential_validator(),
        )?;

        let mut new_context = GroupContext {
            epoch: 1,
            ..GroupContext::new_group(
                self.core.protocol_version(),
                self.core.cipher_suite(),
                sub_group_id.clone(),
                vec![],
                self.context().extensions.clone(),
            )
        };

        let resumption_psk_id = JustPreSharedKeyID::Resumption(ResumptionPsk {
            usage: ResumptionPSKUsage::Branch,
            psk_group_id: PskGroupId(sub_group_id),
            psk_epoch: self.current_epoch(),
        });

        self.new_for_resumption(
            &mut new_context,
            new_leaf_node,
            new_leaf_secret,
            &signer,
            get_new_key_package,
            resumption_psk_id,
        )
    }

    pub fn join_subgroup(
        &self,
        welcome: Welcome,
        public_tree: Option<TreeKemPublic>,
    ) -> Result<Self, GroupError> {
        let subgroup = Self::from_welcome_message(
            Some(&self.context().group_id),
            self.core.protocol_version(),
            welcome,
            public_tree,
            self.config.clone(),
        )?;

        if subgroup.core.protocol_version() != self.core.protocol_version() {
            Err(GroupError::SubgroupWithDifferentProtocolVersion(
                subgroup.core.protocol_version(),
            ))
        } else if subgroup.core.cipher_suite() != self.core.cipher_suite() {
            Err(GroupError::SubgroupWithDifferentCipherSuite(
                subgroup.core.cipher_suite(),
            ))
        } else {
            Ok(subgroup)
        }
    }

    pub fn finish_reinit_commit<F>(
        &self,
        get_new_key_package: F,
    ) -> Result<(Self, Option<Welcome>), GroupError>
    where
        F: FnMut(&LeafNode) -> Option<KeyPackage>,
    {
        let config = self.config.clone();

        let reinit = self
            .core
            .pending_reinit
            .as_ref()
            .ok_or(GroupError::PendingReInitNotFound)?;

        let (new_signing_id, new_signer) = config
            .keychain()
            .default_identity(reinit.cipher_suite)
            .ok_or(GroupError::NoCredentialFound)?;

        let (new_leaf_node, new_leaf_secret) = LeafNode::generate(
            reinit.cipher_suite,
            new_signing_id,
            config.capabilities(),
            config.leaf_node_extensions(),
            &new_signer,
            config.lifetime(),
            &config.credential_validator(),
        )?;

        let mut new_context = GroupContext {
            epoch: 1,
            ..GroupContext::new_group(
                reinit.version,
                reinit.cipher_suite,
                reinit.group_id.clone(),
                vec![],
                reinit.extensions.clone(),
            )
        };

        let resumption_psk_id = JustPreSharedKeyID::Resumption(ResumptionPsk {
            usage: ResumptionPSKUsage::Reinit,
            psk_group_id: PskGroupId(self.context().group_id.clone()),
            psk_epoch: self.current_epoch(),
        });

        let (group, welcome) = self.new_for_resumption(
            &mut new_context,
            new_leaf_node,
            new_leaf_secret,
            &new_signer,
            get_new_key_package,
            resumption_psk_id,
        )?;

        if group.core.current_tree.occupied_leaf_count()
            != self.core.current_tree.occupied_leaf_count()
        {
            Err(GroupError::CommitRequired)
        } else {
            Ok((group, welcome))
        }
    }

    pub fn finish_reinit_join(
        &self,
        welcome: Welcome,
        public_tree: Option<TreeKemPublic>,
    ) -> Result<Self, GroupError> {
        let reinit = self
            .core
            .pending_reinit
            .as_ref()
            .ok_or(GroupError::PendingReInitNotFound)?;

        if reinit.cipher_suite != welcome.cipher_suite {
            return Err(GroupError::CipherSuiteMismatch);
        }

        let group = Self::from_welcome_message(
            Some(&self.context().group_id),
            reinit.version,
            welcome,
            public_tree,
            self.config.clone(),
        )?;

        if group.core.protocol_version() != reinit.version {
            Err(GroupError::ReInitVersionMismatch(
                group.core.protocol_version(),
                reinit.version,
            ))
        } else if group.core.cipher_suite() != reinit.cipher_suite {
            Err(GroupError::ReInitCiphersuiteMismatch(
                group.core.cipher_suite(),
                reinit.cipher_suite,
            ))
        } else if group.core.context.group_id != reinit.group_id {
            Err(GroupError::ReInitIdMismatch(
                group.core.context.group_id,
                reinit.group_id.clone(),
            ))
        } else if group.core.context.extensions != reinit.extensions {
            Err(GroupError::ReInitExtensionsMismatch(
                group.core.context.extensions,
                reinit.extensions.clone(),
            ))
        } else {
            Ok(group)
        }
    }

    fn encrypt_group_secrets(
        &self,
        key_package: &KeyPackage,
        leaf_index: LeafIndex,
        joiner_secret: &JoinerSecret,
        path_secrets: Option<&Vec<Option<PathSecret>>>,
        psks: Vec<PreSharedKeyID>,
    ) -> Result<EncryptedGroupSecrets, GroupError> {
        let path_secret = path_secrets
            .map(|secrets| {
                secrets
                    .get(
                        tree_math::leaf_lca_level(*self.private_tree.self_index, *leaf_index)
                            as usize
                            - 1,
                    )
                    .cloned()
                    .flatten()
                    .ok_or(GroupError::InvalidTreeKemPrivateKey)
            })
            .transpose()?;

        let group_secrets = GroupSecrets {
            joiner_secret: joiner_secret.clone(),
            path_secret,
            psks,
        };

        let group_secrets_bytes = Zeroizing::new(group_secrets.tls_serialize_detached()?);

        let encrypted_group_secrets = key_package.cipher_suite.hpke().seal(
            &key_package.hpke_init_key,
            &[],
            None,
            None,
            &group_secrets_bytes,
        )?;

        Ok(EncryptedGroupSecrets {
            new_member: key_package.to_reference()?,
            encrypted_group_secrets: encrypted_group_secrets.into(),
        })
    }

    pub fn add_proposal(&self, key_package: KeyPackage) -> Result<Proposal, GroupError> {
        let required_capabilities = self.context().extensions.get_extension()?;

        // Check that this proposal has a valid lifetime, signature, and meets the requirements
        // of the current group required capabilities extension.
        let key_package_validator = KeyPackageValidator::new(
            self.core.protocol_version(),
            self.core.cipher_suite(),
            required_capabilities.as_ref(),
            self.config.credential_validator(),
        );

        key_package_validator.check_if_valid(&key_package, Default::default())?;

        Ok(Proposal::Add(AddProposal { key_package }))
    }

    pub fn update_proposal(&mut self) -> Result<Proposal, GroupError> {
        let signer = self.signer()?;
        // Grab a copy of the current node and update it to have new key material
        let mut new_leaf_node = self.current_user_leaf_node()?.clone();

        let secret_key = new_leaf_node.update(
            self.core.cipher_suite(),
            self.group_id(),
            Some(self.config.capabilities()),
            Some(self.config.leaf_node_extensions()),
            &signer,
        )?;

        // Store the secret key in the pending updates storage for later
        self.pending_updates
            .insert(new_leaf_node.public_key.as_ref().to_vec(), secret_key);

        Ok(Proposal::Update(UpdateProposal {
            leaf_node: new_leaf_node,
        }))
    }

    pub fn remove_proposal(&mut self, leaf_index: LeafIndex) -> Result<Proposal, GroupError> {
        // Verify that this leaf is actually in the tree
        self.current_epoch_tree().get_leaf_node(leaf_index)?;

        Ok(Proposal::Remove(RemoveProposal {
            to_remove: leaf_index,
        }))
    }

    pub fn psk_proposal(&mut self, psk: ExternalPskId) -> Result<Proposal, GroupError> {
        Ok(Proposal::Psk(PreSharedKey {
            psk: PreSharedKeyID {
                key_id: JustPreSharedKeyID::External(psk),
                psk_nonce: PskNonce::random(self.core.cipher_suite())?,
            },
        }))
    }

    pub fn reinit_proposal(
        &mut self,
        group_id: Vec<u8>,
        version: ProtocolVersion,
        cipher_suite: CipherSuite,
        extensions: ExtensionList,
    ) -> Result<Proposal, GroupError> {
        Ok(Proposal::ReInit(ReInit {
            group_id,
            version,
            cipher_suite,
            extensions,
        }))
    }

    pub fn group_context_extensions_proposal(&self, extensions: ExtensionList) -> Proposal {
        Proposal::GroupContextExtensions(extensions)
    }

    pub fn format_for_wire(
        &mut self,
        content: MLSAuthenticatedContent,
    ) -> Result<MLSMessage, GroupError> {
        let message = if content.wire_format == WireFormat::Cipher {
            let ciphertext = self.create_ciphertext(content)?;

            MLSMessage {
                version: self.protocol_version(),
                payload: MLSMessagePayload::Cipher(ciphertext),
            }
        } else {
            let plaintext = self.create_plaintext(content)?;

            MLSMessage {
                version: self.protocol_version(),
                payload: MLSMessagePayload::Plain(plaintext),
            }
        };

        Ok(message)
    }

    fn create_plaintext(
        &self,
        auth_content: MLSAuthenticatedContent,
    ) -> Result<MLSPlaintext, GroupError> {
        let membership_tag = matches!(auth_content.content.sender, Sender::Member(_))
            .then(|| {
                self.key_schedule
                    .get_membership_tag(&auth_content, self.context())
            })
            .transpose()?;

        Ok(MLSPlaintext {
            content: auth_content.content,
            auth: auth_content.auth,
            membership_tag,
        })
    }

    fn create_ciphertext(
        &mut self,
        auth_content: MLSAuthenticatedContent,
    ) -> Result<MLSCiphertext, GroupError> {
        let padding = self.config.preferences().padding_mode;

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
        let mut reuse_guard = [0u8; 4];
        SecureRng::fill(&mut reuse_guard)?;

        // Grab an encryption key from the current epoch's key schedule
        let key_type = match &content_type {
            ContentType::Application => KeyType::Application,
            _ => KeyType::Handshake,
        };

        let mut epoch = self
            .config
            .epoch_repo()
            .get(self.group_id(), self.current_epoch())
            .map_err(|e| GroupError::EpochRepositoryError(e.into()))?
            .ok_or_else(|| GroupError::EpochNotFound(self.current_epoch()))?;

        // Encrypt the ciphertext content using the encryption key and a nonce that is
        // reuse safe by xor the reuse guard with the first 4 bytes
        let (ciphertext, generation) = epoch.inner_mut().encrypt(
            key_type,
            &ciphertext_content.tls_serialize_detached()?,
            &aad.tls_serialize_detached()?,
            &reuse_guard,
        )?;

        // Construct an mls sender data struct using the plaintext sender info, the generation
        // of the key schedule encryption key, and the reuse guard used to encrypt ciphertext
        let sender_data = MLSSenderData {
            sender: match auth_content.content.sender {
                Sender::Member(sender) => Ok(sender),
                _ => Err(GroupError::OnlyMembersCanEncryptMessages),
            }?,
            generation,
            reuse_guard,
        };

        let sender_data_aad = MLSSenderDataAAD {
            group_id: self.group_id().to_vec(),
            epoch: self.context().epoch,
            content_type,
        };

        // Encrypt the sender data with the derived sender_key and sender_nonce from the current
        // epoch's key schedule
        let (sender_key, sender_nonce) = epoch.inner_mut().get_sender_data_params(&ciphertext)?;

        let encrypted_sender_data = sender_key.encrypt_to_vec(
            &sender_data.tls_serialize_detached()?,
            Some(&sender_data_aad.tls_serialize_detached()?),
            sender_nonce,
        )?;

        self.config
            .epoch_repo()
            .insert(epoch)
            .map_err(|e| GroupError::EpochRepositoryError(e.into()))?;

        Ok(MLSCiphertext {
            group_id: self.group_id().to_vec(),
            epoch: self.current_epoch(),
            content_type,
            authenticated_data,
            encrypted_sender_data,
            ciphertext,
        })
    }

    pub fn encrypt_application_message(
        &mut self,
        message: &[u8],
        authenticated_data: Vec<u8>,
    ) -> Result<MLSMessage, GroupError> {
        let signer = self.signer()?;

        // A group member that has observed one or more proposals within an epoch MUST send a Commit message
        // before sending application data
        if !self.core.proposals.is_empty() {
            return Err(GroupError::CommitRequired);
        }

        let auth_content = MLSAuthenticatedContent::new_signed(
            self.context(),
            Sender::Member(self.private_tree.self_index),
            Content::Application(message.to_vec()),
            &signer,
            WireFormat::Cipher,
            authenticated_data,
        )?;

        self.format_for_wire(auth_content)
    }

    pub fn decrypt_incoming_ciphertext(
        &mut self,
        message: MLSCiphertext,
    ) -> Result<MLSAuthenticatedContent, GroupError> {
        let epoch_id = message.epoch;

        let mut epoch = self
            .config
            .epoch_repo()
            .get(self.group_id(), epoch_id)
            .map_err(|e| GroupError::EpochRepositoryError(e.into()))?
            .ok_or(GroupError::EpochNotFound(epoch_id))?;

        let auth_content = decrypt_ciphertext(message, epoch.inner_mut())?;

        // Update the epoch repo with new data post decryption
        self.config
            .epoch_repo()
            .insert(epoch)
            .map_err(|e| GroupError::EpochRepositoryError(e.into()))?;

        Ok(auth_content)
    }

    pub fn process_incoming_message(
        &mut self,
        message: MLSMessage,
    ) -> Result<ProcessedMessage<Event>, GroupError> {
        self.core.check_metadata(&message)?;

        let auth_content = match message.payload {
            MLSMessagePayload::Welcome(_) => Err(GroupError::UnexpectedWelcomeMessage),
            MLSMessagePayload::GroupInfo(_) => Err(GroupError::UnexpectedGroupInfo),
            MLSMessagePayload::KeyPackage(_) => Err(GroupError::UnexpectedKeyPackage),
            MLSMessagePayload::Plain(plaintext) => self.core.verify_plaintext_authentication(
                Some(&self.key_schedule),
                Some(self.private_tree.self_index),
                plaintext,
            ),
            MLSMessagePayload::Cipher(ciphertext) => self.decrypt_incoming_ciphertext(ciphertext),
        }?;

        let authenticated_data = auth_content.content.authenticated_data.clone();

        let sender_index = match auth_content.content.sender {
            Sender::Member(index) => Some(index.0),
            _ => None,
        };

        let message_payload = match auth_content.content.content {
            Content::Application(data) => Ok(Event::ApplicationMessage(data)),
            Content::Commit(_) => self.process_commit(auth_content, None).map(Event::Commit),
            Content::Proposal(ref p) => {
                let proposal_ref =
                    ProposalRef::from_content(self.core.cipher_suite(), &auth_content)?;

                self.core
                    .proposals
                    .insert(proposal_ref, p.clone(), auth_content.content.sender);

                Ok(Event::Proposal(p.clone()))
            }
        }?;

        Ok(ProcessedMessage {
            event: message_payload,
            sender_index,
            authenticated_data,
        })
    }

    pub fn process_pending_commit(&mut self) -> Result<StateUpdate, GroupError> {
        let pending_commit = self
            .pending_commit
            .take()
            .ok_or(GroupError::PendingCommitNotFound)?;

        self.process_commit(pending_commit.content, pending_commit.pending_secrets)
    }

    pub fn clear_pending_commit(&mut self) {
        self.pending_commit = None
    }

    // This function takes a provisional copy of the tree and returns an updated tree and epoch key schedule
    fn process_commit(
        &mut self,
        auth_content: MLSAuthenticatedContent,
        local_pending: Option<(TreeKemPrivate, PathSecret)>,
    ) -> Result<StateUpdate, GroupError> {
        let (commit, sender) = match auth_content.content.content {
            Content::Commit(ref commit) => Ok((commit, &auth_content.content.sender)),
            _ => Err(GroupError::NotCommitContent(
                auth_content.content.content_type(),
            )),
        }?;

        //Generate a provisional GroupContext object by applying the proposals referenced in the
        // initial Commit object, as described in Section 11.1. Update proposals are applied first,
        // followed by Remove proposals, and then finally Add proposals. Add proposals are applied
        // in the order listed in the proposals vector, and always to the leftmost unoccupied leaf
        // in the tree, or the right edge of the tree if all leaves are occupied.
        let proposal_effects = proposal_effects(
            Some(self.private_tree.self_index),
            &self.core.proposals,
            commit,
            sender,
            self.context().extensions.get_extension()?,
            self.config.credential_validator(),
            &self.core.current_tree,
            self.config.proposal_filter(ProposalFilterInit::new(
                &self.core.current_tree,
                self.context(),
                auth_content.content.sender.clone(),
            )),
        )?;

        let mut provisional_state = self.apply_proposals(proposal_effects)?;
        let sender = commit_sender(sender, &provisional_state.public_state)?;
        let mut state_update = StateUpdate::from(&provisional_state);
        let from_self = local_pending.is_some();

        //Verify that the path value is populated if the proposals vector contains any Update
        // or Remove proposals, or if it's empty. Otherwise, the path value MAY be omitted.
        if provisional_state.public_state.path_update_required && commit.path.is_none() {
            return Err(GroupError::CommitMissingPath);
        }

        if provisional_state.self_index_removed() && !from_self {
            state_update.active = false;
            return Ok(state_update);
        }

        if provisional_state.public_state.reinit.is_some() {
            self.core.pending_reinit = provisional_state.public_state.reinit;
            state_update.active = false;
            return Ok(state_update);
        }

        // Generate provisional context for decap. This is the new context but with old tree hash and confirmed transcript
        // hash. Tree hash will be updated by decap.
        let mut provisional_group_context = provisional_state.public_state.group_context.clone();
        provisional_group_context.epoch = provisional_state.public_state.epoch;

        // Apply the update path if needed
        let updated_secrets = match &commit.path {
            None => None,
            Some(update_path) => {
                let required_capabilities = provisional_state
                    .public_state
                    .group_context
                    .extensions
                    .get_extension()?;

                let leaf_validator = LeafNodeValidator::new(
                    self.core.cipher_suite(),
                    required_capabilities.as_ref(),
                    self.config.credential_validator(),
                );

                let update_path_validator = UpdatePathValidator::new(leaf_validator);

                let validated_update_path = update_path_validator
                    .validate(update_path.clone(), &self.context().group_id)?;

                let secrets = if let Some(pending) = local_pending {
                    // Receiving from yourself is a special case, we already have the new private keys
                    provisional_state
                        .public_state
                        .public_tree
                        .update_hashes(&mut vec![self.private_tree.self_index], &[])?;

                    provisional_state
                        .public_state
                        .public_tree
                        .apply_self_update(&validated_update_path, self.private_tree.self_index)?;

                    Ok(pending)
                } else {
                    TreeKem::new(
                        &mut provisional_state.public_state.public_tree,
                        &mut provisional_state.private_tree,
                    )
                    .decap(
                        sender,
                        &validated_update_path,
                        &provisional_state
                            .public_state
                            .added_leaves
                            .into_iter()
                            .map(|(_, index)| index)
                            .collect::<Vec<LeafIndex>>(),
                        &mut provisional_group_context,
                    )
                    .map(|root_secret| (provisional_state.private_tree, root_secret))
                }?;

                Some(secrets)
            }
        };

        let commit_secret = CommitSecret::from_root_secret(
            self.core.cipher_suite(),
            updated_secrets.as_ref().map(|(_, root_secret)| root_secret),
        )?;

        // Update the new GroupContext's confirmed and interim transcript hashes using the new Commit.
        let (interim_transcript_hash, confirmed_transcript_hash) = transcript_hashes(
            self.core.cipher_suite(),
            &self.core.interim_transcript_hash,
            &auth_content,
        )?;

        // Update the transcript hash to get the new context.
        provisional_group_context.confirmed_transcript_hash = confirmed_transcript_hash;

        provisional_state
            .public_state
            .public_tree
            .update_hashes(&mut vec![sender], &[])?;

        provisional_group_context.tree_hash =
            provisional_state.public_state.public_tree.tree_hash()?;

        let epoch_repo = self.config.epoch_repo();
        let secret_store = self.config.secret_store();

        let psk_secret = crate::psk::psk_secret(
            self.core.cipher_suite(),
            Some(&secret_store),
            Some((&self.core.context.group_id, &epoch_repo)),
            &provisional_state.public_state.psks,
        )?;

        // Use the commit_secret, the psk_secret, the provisional GroupContext, and the init secret
        // from the previous epoch (or from the external init) to compute the epoch secret and
        // derived secrets for the new epoch

        let key_schedule = match provisional_state.public_state.external_init {
            Some((_, ExternalInit { kem_output })) if !from_self => self
                .key_schedule
                .derive_for_external(&kem_output, self.core.cipher_suite())?,
            _ => self.key_schedule.clone(),
        };

        let key_schedule_result = KeySchedule::derive(
            &key_schedule,
            &commit_secret,
            &provisional_group_context,
            self.private_tree.self_index, // The index never changes
            &provisional_state.public_state.public_tree,
            &psk_secret,
        )?;

        // Use the confirmation_key for the new epoch to compute the confirmation tag for
        // this message, as described below, and verify that it is the same as the
        // confirmation_tag field in the MLSPlaintext object.
        let confirmation_tag = ConfirmationTag::create(
            &key_schedule_result.confirmation_key,
            &provisional_group_context.confirmed_transcript_hash,
            &self.core.cipher_suite(),
        )?;

        if Some(confirmation_tag.clone()) != auth_content.auth.confirmation_tag {
            return Err(GroupError::InvalidConfirmationTag);
        }

        // If the above checks are successful, consider the updated GroupContext object
        // as the current state of the group
        if let Some(private_tree) = updated_secrets.map(|(private_key, _)| private_key) {
            self.private_tree = private_tree
        }

        self.core.context = provisional_group_context;

        self.config
            .epoch_repo()
            .insert(key_schedule_result.epoch.into())
            .map_err(|e| GroupError::EpochRepositoryError(e.into()))?;

        self.core.interim_transcript_hash = interim_transcript_hash;

        self.key_schedule = key_schedule_result.key_schedule;

        self.core.current_tree = provisional_state.public_state.public_tree;
        self.confirmation_tag = confirmation_tag;

        // Clear the proposals list
        self.core.proposals.clear();

        // Clear the pending updates list
        self.pending_updates = Default::default();
        self.pending_commit = None;

        Ok(state_update)
    }

    pub fn current_direct_path(&self) -> Result<Vec<Option<HpkePublicKey>>, GroupError> {
        self.core
            .current_tree
            .direct_path_keys(self.private_tree.self_index)
            .map_err(Into::into)
    }

    /// The returned `GroupInfo` is suitable for one external commit for the current epoch.
    pub fn group_info_message(&self) -> Result<MLSMessage, GroupError> {
        let signer = self.signer()?;

        let mut extensions = ExtensionList::new();

        extensions.set_extension(ExternalPubExt {
            external_pub: self
                .key_schedule
                .get_external_public_key(self.core.cipher_suite())?,
        })?;

        let mut info = GroupInfo {
            group_context: self.context().clone(),
            extensions,
            confirmation_tag: self.confirmation_tag.clone(),
            signer: self.private_tree.self_index,
            signature: Vec::new(),
        };

        info.sign(&signer, &())?;

        Ok(MLSMessage {
            version: self.protocol_version(),
            payload: MLSMessagePayload::GroupInfo(info),
        })
    }

    #[inline(always)]
    pub fn context(&self) -> &GroupContext {
        &self.core.context
    }

    pub fn authentication_secret(&self) -> Result<Vec<u8>, GroupError> {
        Ok(self.key_schedule.authentication_secret.clone())
    }

    pub fn export_secret(
        &self,
        label: &str,
        context: &[u8],
        len: usize,
    ) -> Result<Vec<u8>, GroupError> {
        Ok(self
            .key_schedule
            .export_secret(label, context, len, self.context().cipher_suite)?)
    }

    pub fn protocol_version(&self) -> ProtocolVersion {
        self.core.protocol_version()
    }
}

pub(crate) fn find_tree(
    public_tree: Option<TreeKemPublic>,
    group_info: &GroupInfo,
) -> Result<TreeKemPublic, GroupError> {
    match public_tree {
        Some(tree) => Ok(tree),
        None => {
            let tree_extension = group_info
                .extensions
                .get_extension::<RatchetTreeExt>()?
                .ok_or(GroupError::RatchetTreeNotFound)?;
            Ok(TreeKemPublic::import_node_data(
                group_info.group_context.cipher_suite,
                tree_extension.tree_data,
            )?)
        }
    }
}

fn validate_existing_group<C: CredentialValidator>(
    public_tree: &mut TreeKemPublic,
    group_info: &GroupInfo,
    credential_validator: &C,
) -> Result<(), GroupError> {
    let sender_key_package = public_tree.get_leaf_node(group_info.signer)?;
    group_info.verify(
        &sender_key_package
            .signing_identity
            .public_key(public_tree.cipher_suite)?,
        &(),
    )?;

    let required_capabilities = group_info.group_context.extensions.get_extension()?;

    // Verify the integrity of the ratchet tree
    let tree_validator = TreeValidator::new(
        group_info.group_context.cipher_suite,
        &group_info.group_context.group_id,
        &group_info.group_context.tree_hash,
        required_capabilities.as_ref(),
        credential_validator,
    );

    tree_validator.validate(public_tree)?;

    if let Some(ext_senders) = group_info
        .group_context
        .extensions
        .get_extension::<ExternalSendersExt>()?
    {
        ext_senders.verify_all(&credential_validator, group_info.group_context.cipher_suite)?;
    }

    Ok(())
}

fn commit_sender(
    sender: &Sender,
    provisional_state: &ProvisionalPublicState,
) -> Result<LeafIndex, GroupError> {
    match sender {
        Sender::Member(index) => Ok(*index),
        Sender::External(_) => Err(GroupError::ExternalSenderCannotCommit),
        Sender::NewMemberProposal => Err(GroupError::ExpectedAddProposalForNewMemberProposal),
        Sender::NewMemberCommit => provisional_state
            .external_init
            .as_ref()
            .map(|(index, _)| *index)
            .ok_or(GroupError::ExternalCommitMissingExternalInit),
    }
}

#[allow(clippy::too_many_arguments)]
fn proposal_effects<C, F>(
    commit_receiver: Option<LeafIndex>,
    proposals: &ProposalCache,
    commit: &Commit,
    sender: &Sender,
    required_capabilities: Option<RequiredCapabilitiesExt>,
    credential_validator: C,
    public_tree: &TreeKemPublic,
    user_filter: F,
) -> Result<ProposalSetEffects, ProposalCacheError>
where
    C: CredentialValidator,
    F: ProposalFilter,
{
    proposals.resolve_for_commit(
        sender.clone(),
        commit_receiver,
        commit.proposals.clone(),
        commit.path.as_ref().map(|path| &path.leaf_node),
        required_capabilities,
        credential_validator,
        public_tree,
        user_filter,
    )
}

fn transcript_hashes(
    cipher_suite: CipherSuite,
    prev_interim_transcript_hash: &InterimTranscriptHash,
    content: &MLSAuthenticatedContent,
) -> Result<(InterimTranscriptHash, ConfirmedTranscriptHash), GroupError> {
    let confirmed_transcript_hash =
        ConfirmedTranscriptHash::create(cipher_suite, prev_interim_transcript_hash, content)?;

    let confirmation_tag = content
        .auth
        .confirmation_tag
        .as_ref()
        .ok_or(GroupError::InvalidConfirmationTag)?;

    let interim_transcript_hash =
        InterimTranscriptHash::create(cipher_suite, &confirmed_transcript_hash, confirmation_tag)?;

    Ok((interim_transcript_hash, confirmed_transcript_hash))
}

fn version_and_cipher_filter<C: ClientConfig>(
    config: &C,
    version: ProtocolVersion,
    cipher_suite: CipherSuite,
) -> bool {
    config.supported_protocol_versions().contains(&version)
        && config.supported_cipher_suites().contains(&cipher_suite)
}

fn find_key_package_generation<C>(
    config: &C,
    welcome_message: &Welcome,
) -> Result<KeyPackageGeneration, GroupError>
where
    C: ClientConfig,
{
    welcome_message
        .secrets
        .iter()
        .find_map(|secrets| {
            config
                .key_package_repo()
                .get(&secrets.new_member)
                .transpose()
        })
        .transpose()
        .map_err(|e| GroupError::KeyPackageRepositoryError(e.into()))?
        .ok_or(GroupError::KeyPackageNotFound)
}

#[cfg(test)]
pub(crate) mod test_utils {
    use ferriscrypt::asym::ec_key::SecretKey;

    use super::*;
    use crate::{
        cipher_suite::MaybeCipherSuite,
        client_config::{
            test_utils::test_config, InMemoryClientConfig, PassthroughCredentialValidator,
            Preferences,
        },
        extension::RequiredCapabilitiesExt,
        key_package::KeyPackageGenerator,
        signing_identity::test_utils::get_test_signing_identity,
        tree_kem::Lifetime,
    };

    pub const TEST_GROUP: &[u8] = b"group";

    pub(crate) struct TestGroup {
        pub group: Group<InMemoryClientConfig>,
    }

    impl TestGroup {
        pub(crate) fn propose(&mut self, proposal: Proposal) -> MLSMessage {
            self.group.create_proposal(proposal, vec![]).unwrap()
        }

        pub(crate) fn join_with_preferences(
            &mut self,
            name: &str,
            preferences: Preferences,
        ) -> (TestGroup, MLSMessage) {
            let (new_key_package, secret_key) = test_member(
                self.group.core.protocol_version(),
                self.group.core.cipher_suite(),
                name.as_bytes(),
            );

            // Add new member to the group
            let add_proposal = self
                .group
                .add_proposal(new_key_package.key_package.clone())
                .unwrap();

            let (commit, welcome) = self
                .group
                .commit_proposals(vec![add_proposal], None, Vec::new())
                .unwrap();

            // Apply the commit to the original group
            self.group.process_pending_commit().unwrap();

            let tree = (!preferences.ratchet_tree_extension)
                .then(|| self.group.current_epoch_tree().clone());

            let welcome = match welcome.unwrap().payload {
                MLSMessagePayload::Welcome(w) => w,
                _ => panic!("Expected Welcome message"),
            };

            // Group from new member's perspective
            let new_group = Group::join(
                self.group.protocol_version(),
                welcome,
                tree,
                test_config(secret_key, new_key_package, preferences),
            )
            .unwrap();

            let new_test_group = TestGroup { group: new_group };

            (new_test_group, commit)
        }

        pub(crate) fn join(&mut self, name: &str) -> (TestGroup, MLSMessage) {
            self.join_with_preferences(name, self.group.config.preferences())
        }

        pub(crate) fn commit(
            &mut self,
            proposals: Vec<Proposal>,
        ) -> Result<(MLSMessage, Option<MLSMessage>), GroupError> {
            self.group.commit_proposals(proposals, None, Vec::new())
        }

        pub(crate) fn process_pending_commit(&mut self) -> Result<StateUpdate, GroupError> {
            self.group.process_pending_commit()
        }

        pub(crate) fn process_message(&mut self, message: MLSMessage) -> Result<Event, GroupError> {
            self.group
                .process_incoming_message(message)
                .map(|r| r.event)
        }

        pub(crate) fn make_plaintext(&mut self, content: Content) -> MLSMessage {
            let auth_content = MLSAuthenticatedContent::new_signed(
                &self.group.core.context,
                Sender::Member(self.group.private_tree.self_index),
                content,
                &self.group.signer().unwrap(),
                WireFormat::Plain,
                Vec::new(),
            )
            .unwrap();

            self.group.format_for_wire(auth_content).unwrap()
        }

        pub(crate) fn required_capabilities(&self) -> Option<RequiredCapabilitiesExt> {
            self.group.context().extensions.get_extension().unwrap()
        }
    }

    pub(crate) fn get_test_group_context(epoch: u64, cipher_suite: CipherSuite) -> GroupContext {
        GroupContext {
            protocol_version: ProtocolVersion::Mls10,
            cipher_suite,
            group_id: vec![],
            epoch,
            tree_hash: vec![],
            confirmed_transcript_hash: ConfirmedTranscriptHash::from(vec![]),
            extensions: ExtensionList::from(vec![]),
        }
    }

    pub(crate) fn group_extensions() -> ExtensionList {
        let required_capabilities = RequiredCapabilitiesExt::default();

        let mut extensions = ExtensionList::new();
        extensions.set_extension(required_capabilities).unwrap();
        extensions
    }

    pub(crate) fn lifetime() -> Lifetime {
        Lifetime::years(1).unwrap()
    }

    pub(crate) fn test_member(
        protocol_version: ProtocolVersion,
        cipher_suite: CipherSuite,
        identifier: &[u8],
    ) -> (KeyPackageGeneration, SecretKey) {
        let (signing_identity, signing_key) =
            get_test_signing_identity(cipher_suite, identifier.to_vec());

        let key_package_generator = KeyPackageGenerator {
            protocol_version,
            cipher_suite,
            signing_identity: &signing_identity,
            signing_key: &signing_key,
            credential_validator: &PassthroughCredentialValidator::new(),
        };

        let key_package = key_package_generator
            .generate(
                lifetime(),
                Capabilities::default(),
                ExtensionList::default(),
                ExtensionList::default(),
            )
            .unwrap();

        (key_package, signing_key)
    }

    pub(crate) fn test_group_custom(
        protocol_version: ProtocolVersion,
        cipher_suite: CipherSuite,
        capabilities: Option<Capabilities>,
        leaf_extensions: Option<ExtensionList>,
        preferences: Option<Preferences>,
    ) -> TestGroup {
        let capabilities = capabilities.unwrap_or_default();
        let leaf_extensions = leaf_extensions.unwrap_or_default();
        let preferences = preferences.unwrap_or_default();

        let (signing_identity, secret_key) =
            get_test_signing_identity(cipher_suite, b"member".to_vec());

        let mut config = InMemoryClientConfig::default()
            .with_signing_identity(signing_identity, secret_key)
            .with_leaf_node_extensions(leaf_extensions)
            .with_credential_types(capabilities.credentials)
            .with_preferences(preferences);

        config.cipher_suites = capabilities
            .cipher_suites
            .into_iter()
            .map(|cs| match cs {
                MaybeCipherSuite::CipherSuite(cipher_suite) => cipher_suite,
                _ => panic!("Unsupported cipher suite found"),
            })
            .collect();

        config.supported_extensions = capabilities.extensions;
        config.protocol_versions = capabilities.protocol_versions;

        let group = Group::new(
            config,
            TEST_GROUP.to_vec(),
            cipher_suite,
            protocol_version,
            group_extensions(),
        )
        .unwrap();

        TestGroup { group }
    }

    pub(crate) fn test_group(
        protocol_version: ProtocolVersion,
        cipher_suite: CipherSuite,
    ) -> TestGroup {
        test_group_custom(
            protocol_version,
            cipher_suite,
            None,
            None,
            Some(Preferences::default().with_ratchet_tree_extension(true)),
        )
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        client_config::{test_utils::test_config, Preferences},
        extension::{test_utils::TestExtension, RequiredCapabilitiesExt},
        key_package::test_utils::test_key_package,
        psk::Psk,
    };

    use super::{
        test_utils::{group_extensions, test_group, test_group_custom, test_member, TestGroup},
        *,
    };
    use assert_matches::assert_matches;

    use crate::group::test_utils::TEST_GROUP;
    use tls_codec::Size;

    #[cfg(target_arch = "wasm32")]
    use wasm_bindgen_test::wasm_bindgen_test as test;

    #[test]
    fn test_create_group() {
        for (protocol_version, cipher_suite) in
            ProtocolVersion::all().flat_map(|p| CipherSuite::all().map(move |cs| (p, cs)))
        {
            let test_group = test_group(protocol_version, cipher_suite);
            let group = test_group.group;

            assert_eq!(group.core.cipher_suite(), cipher_suite);
            assert_eq!(group.core.context.epoch, 0);
            assert_eq!(group.core.context.group_id, TEST_GROUP.to_vec());
            assert_eq!(group.core.context.extensions, group_extensions());
            assert_eq!(
                group.core.context.confirmed_transcript_hash,
                ConfirmedTranscriptHash::from(vec![])
            );
            assert!(group.core.proposals.is_empty());
            assert!(group.pending_updates.is_empty());
            assert_eq!(group.private_tree.self_index.0, group.current_user_index());

            assert_eq!(
                group.core.current_tree.get_leaf_nodes()[0]
                    .signing_identity
                    .public_key(cipher_suite)
                    .unwrap(),
                group
                    .config
                    .keychain()
                    .default_identity(cipher_suite)
                    .unwrap()
                    .1
                    .to_public()
                    .unwrap()
            );
        }
    }

    #[test]
    fn test_pending_proposals_application_data() {
        let protocol_version = ProtocolVersion::Mls10;
        let cipher_suite = CipherSuite::Curve25519Aes128;

        let mut test_group = test_group(protocol_version, cipher_suite);

        // Create a proposal
        let (bob_key_package, _) = test_member(protocol_version, cipher_suite, b"bob");

        let proposal = test_group
            .group
            .add_proposal(bob_key_package.key_package)
            .unwrap();

        test_group.group.create_proposal(proposal, vec![]).unwrap();

        // We should not be able to send application messages until a commit happens
        let res = test_group
            .group
            .encrypt_application_message(b"test", vec![]);

        assert_matches!(res, Err(GroupError::CommitRequired));

        // We should be able to send application messages after a commit
        test_group
            .group
            .commit_proposals(vec![], None, vec![])
            .unwrap();

        test_group.group.process_pending_commit().unwrap();

        assert!(test_group
            .group
            .encrypt_application_message(b"test", vec![])
            .is_ok());
    }

    #[test]
    fn test_update_proposals() {
        let protocol_version = ProtocolVersion::Mls10;
        let cipher_suite = CipherSuite::Curve25519Aes128;

        let mut new_capabilities = Capabilities::default();
        new_capabilities.extensions.push(42);

        let new_extension = TestExtension { foo: 10 };
        let mut extension_list = ExtensionList::default();
        extension_list.set_extension(new_extension).unwrap();

        let mut test_group = test_group_custom(
            protocol_version,
            cipher_suite,
            Some(new_capabilities.clone()),
            Some(extension_list.clone()),
            None,
        );

        let existing_leaf = test_group.group.current_user_leaf_node().unwrap().clone();

        // Create an update proposal
        let proposal = test_group.group.update_proposal().unwrap();

        let update = match proposal {
            Proposal::Update(update) => update,
            _ => panic!("non update proposal found"),
        };

        assert_ne!(update.leaf_node.public_key, existing_leaf.public_key);
        assert_eq!(
            update.leaf_node.signing_identity,
            existing_leaf.signing_identity
        );
        assert_eq!(update.leaf_node.extensions, extension_list);
        assert_eq!(update.leaf_node.capabilities, new_capabilities);
    }

    #[test]
    fn test_invalid_commit_self_update() {
        let protocol_version = ProtocolVersion::Mls10;
        let cipher_suite = CipherSuite::Curve25519Aes128;

        let mut test_group = test_group(protocol_version, cipher_suite);

        // Create an update proposal
        let proposal = test_group.group.update_proposal().unwrap();

        // There should be an error because path_update is set to `true` while there is a pending
        // update proposal for the committer
        let res = test_group
            .group
            .commit_proposals(vec![proposal], None, vec![]);

        assert_matches!(
            res,
            Err(GroupError::ProposalCacheError(
                ProposalCacheError::ProposalFilterError(
                    ProposalFilterError::InvalidCommitSelfUpdate
                )
            ))
        );
    }

    #[test]
    fn test_invalid_add_proposal_bad_key_package() {
        let protocol_version = ProtocolVersion::Mls10;
        let cipher_suite = CipherSuite::Curve25519Aes128;

        let test_group = test_group(protocol_version, cipher_suite);
        let (mut bob_keys, _) = test_member(protocol_version, cipher_suite, b"bob");
        bob_keys.key_package.signature = SecureRng::gen(32).unwrap();

        let proposal = test_group.group.add_proposal(bob_keys.key_package);
        assert_matches!(proposal, Err(GroupError::KeyPackageValidationError(_)));
    }

    #[test]
    fn committing_add_proposal_with_bad_key_package_fails() {
        let protocol_version = ProtocolVersion::Mls10;
        let cipher_suite = CipherSuite::Curve25519Aes128;

        let mut test_group = test_group(protocol_version, cipher_suite);
        let (bob_keys, _) = test_member(protocol_version, cipher_suite, b"bob");

        let mut proposal = test_group.group.add_proposal(bob_keys.key_package).unwrap();

        if let Proposal::Add(ref mut kp) = proposal {
            kp.key_package.signature = SecureRng::gen(32).unwrap()
        }

        let res = test_group
            .group
            .commit_proposals(vec![proposal], None, vec![]);

        assert_matches!(
            res,
            Err(GroupError::ProposalCacheError(
                ProposalCacheError::ProposalFilterError(
                    ProposalFilterError::KeyPackageValidationError(_)
                )
            ))
        );
    }

    #[test]
    fn update_proposal_with_bad_key_package_is_ignored_when_committing() {
        let protocol_version = ProtocolVersion::Mls10;
        let cipher_suite = CipherSuite::Curve25519Aes128;

        let (mut alice_group, mut bob_group) =
            test_two_member_group(protocol_version, cipher_suite, true);

        let mut proposal = alice_group.group.update_proposal().unwrap();

        if let Proposal::Update(ref mut update) = proposal {
            update.leaf_node.signature = SecureRng::gen(32).unwrap();
        } else {
            panic!("Invalid update proposal")
        }

        let proposal_message = alice_group
            .group
            .create_proposal(proposal.clone(), vec![])
            .unwrap();

        let proposal_plaintext = match proposal_message.payload {
            MLSMessagePayload::Plain(p) => p,
            _ => panic!("Unexpected non-plaintext message"),
        };

        let proposal_ref =
            ProposalRef::from_content(cipher_suite, &proposal_plaintext.clone().into()).unwrap();

        // Hack bob's receipt of the proposal
        bob_group.group.core.proposals.insert(
            proposal_ref,
            proposal,
            proposal_plaintext.content.sender,
        );

        let (commit, _) = bob_group
            .group
            .commit_proposals(vec![], None, vec![])
            .unwrap();

        assert_matches!(
            commit,
            MLSMessage {
                payload: MLSMessagePayload::Plain(
                    MLSPlaintext {
                        content: MLSContent {
                            content: Content::Commit(Commit {
                                proposals,
                                ..
                            }),
                            ..
                        },
                        ..
                    }),
                ..
            } if proposals.is_empty()
        );
    }

    fn test_two_member_group(
        protocol_version: ProtocolVersion,
        cipher_suite: CipherSuite,
        tree_ext: bool,
    ) -> (TestGroup, TestGroup) {
        let mut test_group = test_group_custom(
            protocol_version,
            cipher_suite,
            None,
            None,
            Some(Preferences::default().with_ratchet_tree_extension(tree_ext)),
        );

        let (bob_test_group, _) = test_group.join("bob");

        assert_eq!(test_group.group, bob_test_group.group);
        (test_group, bob_test_group)
    }

    #[test]
    fn test_welcome_processing_exported_tree() {
        test_two_member_group(ProtocolVersion::Mls10, CipherSuite::P256Aes128, false);
    }

    #[test]
    fn test_welcome_processing_tree_extension() {
        test_two_member_group(ProtocolVersion::Mls10, CipherSuite::P256Aes128, true);
    }

    #[test]
    fn test_welcome_processing_missing_tree() {
        let protocol_version = ProtocolVersion::Mls10;
        let cipher_suite = CipherSuite::P256Aes128;

        let mut test_group = test_group_custom(
            protocol_version,
            cipher_suite,
            None,
            None,
            Some(Preferences::default().with_ratchet_tree_extension(false)),
        );

        let (bob_key_package, secret_key) = test_member(protocol_version, cipher_suite, b"bob");

        // Add bob to the group
        let add_bob_proposal = test_group
            .group
            .add_proposal(bob_key_package.key_package.clone())
            .unwrap();

        let (_, welcome) = test_group
            .group
            .commit_proposals(vec![add_bob_proposal], None, vec![])
            .unwrap();

        let welcome = match welcome.unwrap().payload {
            MLSMessagePayload::Welcome(w) => w,
            _ => panic!("Expected Welcome message"),
        };

        // Group from Bob's perspective
        let bob_group = Group::join(
            protocol_version,
            welcome,
            None,
            test_config(
                secret_key,
                bob_key_package,
                test_group.group.config.preferences(),
            ),
        );

        assert_matches!(bob_group, Err(GroupError::RatchetTreeNotFound));
    }

    #[test]
    fn test_group_context_ext_proposal_create() {
        let test_group = test_group(ProtocolVersion::Mls10, CipherSuite::P256Aes128);

        let mut extension_list = ExtensionList::new();
        extension_list
            .set_extension(RequiredCapabilitiesExt {
                extensions: vec![42],
                proposals: vec![],
                credentials: vec![],
            })
            .unwrap();

        let proposal = test_group
            .group
            .group_context_extensions_proposal(extension_list.clone());

        assert_matches!(proposal, Proposal::GroupContextExtensions(ext) if ext == extension_list);
    }

    fn group_context_extension_proposal_test(
        ext_list: ExtensionList,
    ) -> (TestGroup, Result<MLSMessage, GroupError>) {
        let protocol_version = ProtocolVersion::Mls10;
        let cipher_suite = CipherSuite::P256Aes128;

        let mut capabilities = Capabilities::default();
        capabilities.extensions.push(42);

        let mut test_group = test_group_custom(
            protocol_version,
            cipher_suite,
            Some(capabilities),
            None,
            None,
        );

        let proposals = vec![test_group.group.group_context_extensions_proposal(ext_list)];

        let commit = test_group
            .group
            .commit_proposals(proposals, None, vec![])
            .map(|(commit, _)| commit);

        (test_group, commit)
    }

    #[test]
    fn test_group_context_ext_proposal_commit() {
        let mut extension_list = ExtensionList::new();
        extension_list
            .set_extension(RequiredCapabilitiesExt {
                extensions: vec![42],
                proposals: vec![],
                credentials: vec![],
            })
            .unwrap();

        let (mut test_group, _) = group_context_extension_proposal_test(extension_list.clone());
        let state_update = test_group.group.process_pending_commit().unwrap();

        assert!(state_update.active);
        assert_eq!(test_group.group.core.context.extensions, extension_list)
    }

    #[test]
    fn test_group_context_ext_proposal_invalid() {
        let mut extension_list = ExtensionList::new();
        extension_list
            .set_extension(RequiredCapabilitiesExt {
                extensions: vec![999],
                proposals: vec![],
                credentials: vec![],
            })
            .unwrap();

        let (_, commit) = group_context_extension_proposal_test(extension_list.clone());

        assert_matches!(
            commit,
            Err(GroupError::ProposalCacheError(
                ProposalCacheError::ProposalFilterError(
                    ProposalFilterError::LeafNodeValidationError(
                        LeafNodeValidationError::RequiredExtensionNotFound(999)
                    )
                )
            ))
        );
    }

    #[test]
    fn test_group_encrypt_plaintext_padding() {
        let protocol_version = ProtocolVersion::Mls10;
        let cipher_suite = CipherSuite::P256Aes128;

        let mut test_group = test_group_custom(
            protocol_version,
            cipher_suite,
            None,
            None,
            Some(Preferences::default().with_padding_mode(PaddingMode::None)),
        );

        let without_padding = test_group
            .group
            .encrypt_application_message(&SecureRng::gen(150).unwrap(), vec![])
            .unwrap();

        let mut test_group = test_group_custom(
            protocol_version,
            cipher_suite,
            None,
            None,
            Some(Preferences::default().with_padding_mode(PaddingMode::StepFunction)),
        );

        let with_padding = test_group
            .group
            .encrypt_application_message(&SecureRng::gen(150).unwrap(), vec![])
            .unwrap();

        assert!(with_padding.tls_serialized_len() > without_padding.tls_serialized_len());
    }

    #[test]
    fn external_commit_requires_external_pub_extension() {
        let protocol_version = ProtocolVersion::Mls10;
        let cipher_suite = CipherSuite::P256Aes128;
        let group = test_group(protocol_version, cipher_suite);

        let mut info = group
            .group
            .group_info_message()
            .unwrap()
            .into_group_info()
            .unwrap();

        info.extensions = ExtensionList::new();
        info.sign(&group.group.signer().unwrap(), &()).unwrap();

        let res = Group::new_external(
            group.group.config,
            protocol_version,
            info,
            None,
            None,
            vec![],
            vec![],
        );

        assert_matches!(res, Err(GroupError::MissingExternalPubExtension));
    }

    #[test]
    fn test_path_update_preference() {
        let protocol_version = ProtocolVersion::Mls10;
        let cipher_suite = CipherSuite::P256Aes128;

        let mut test_group = test_group_custom(
            protocol_version,
            cipher_suite,
            None,
            None,
            Some(Preferences::default().force_commit_path_update(false)),
        );

        let add = Proposal::Add(AddProposal {
            key_package: test_key_package(protocol_version, cipher_suite),
        });

        test_group
            .group
            .commit_proposals(vec![add.clone()], None, vec![])
            .unwrap();

        assert!(test_group
            .group
            .pending_commit
            .unwrap()
            .pending_secrets
            .is_none());

        let mut test_group = test_group_custom(
            protocol_version,
            cipher_suite,
            None,
            None,
            Some(Preferences::default().force_commit_path_update(true)),
        );

        test_group
            .group
            .commit_proposals(vec![add], None, vec![])
            .unwrap();

        assert!(test_group
            .group
            .pending_commit
            .unwrap()
            .pending_secrets
            .is_some());
    }

    #[test]
    fn test_path_update_preference_override() {
        let protocol_version = ProtocolVersion::Mls10;
        let cipher_suite = CipherSuite::P256Aes128;

        let mut test_group = test_group_custom(
            protocol_version,
            cipher_suite,
            None,
            None,
            Some(Preferences::default().force_commit_path_update(false)),
        );

        test_group
            .group
            .commit_proposals(vec![], None, vec![])
            .unwrap();

        assert!(test_group
            .group
            .pending_commit
            .unwrap()
            .pending_secrets
            .is_some());
    }

    #[test]
    fn group_rejects_unencrypted_application_message() {
        let protocol_version = ProtocolVersion::Mls10;
        let cipher_suite = CipherSuite::P256Aes128;
        let mut alice = test_group(protocol_version, cipher_suite);
        let (mut bob, _) = alice.join("bob");
        let message = alice.make_plaintext(Content::Application(b"hello".to_vec()));

        assert_matches!(
            bob.group.process_incoming_message(message),
            Err(GroupError::UnencryptedApplicationMessage)
        );
    }

    fn canonicalize_state_update(update: &mut StateUpdate) {
        update.added.sort();
        update.updated.sort();

        update.removed.sort_by_key(|a| a.0);
    }

    #[test]
    fn test_state_update() {
        let protocol_version = ProtocolVersion::Mls10;
        let cipher_suite = CipherSuite::Curve25519Aes128;

        // Create a group with 10 members
        let mut alice = test_group(protocol_version, cipher_suite);
        let (mut bob, _) = alice.join("bob");
        let mut leaves = vec![];

        for _ in 0..8 {
            let (group, commit) = alice.join("charlie");
            leaves.push(group.group.current_user_leaf_node().unwrap().clone());
            bob.process_message(commit).unwrap();
        }

        // Create many proposals, make Alice commit them
        let mut proposals = vec![];

        for index in [2, 5, 6] {
            proposals.push(alice.group.remove_proposal(LeafIndex(index)).unwrap());
        }

        for _ in 0..5 {
            let (key_package, _) = test_member(protocol_version, cipher_suite, b"dave");
            proposals.push(alice.group.add_proposal(key_package.key_package).unwrap());
        }

        for i in 0..5 {
            alice
                .group
                .config
                .secret_store()
                .insert(ExternalPskId(vec![i]), Psk::from(vec![i]));

            bob.group
                .config
                .secret_store()
                .insert(ExternalPskId(vec![i]), Psk::from(vec![i]));

            proposals.push(alice.group.psk_proposal(ExternalPskId(vec![i])).unwrap());
        }

        let update_proposal = bob.group.update_proposal().unwrap();
        let update_message = bob.group.create_proposal(update_proposal, vec![]).unwrap();

        alice.process_message(update_message).unwrap();

        let (commit, _) = alice.commit(proposals).unwrap();

        // Check that applying pending commit and processing commit yields correct update.
        let mut state_update_alice = alice.process_pending_commit().unwrap();
        canonicalize_state_update(&mut state_update_alice);

        assert_eq!(
            state_update_alice.added,
            vec![2, 5, 6, 10, 11]
                .into_iter()
                .map(LeafIndex)
                .collect::<Vec<_>>()
        );

        assert_eq!(
            state_update_alice.removed,
            vec![2, 5, 6]
                .into_iter()
                .map(|i| (LeafIndex(i), leaves[i as usize - 2].clone()))
                .collect::<Vec<_>>()
        );

        assert_eq!(state_update_alice.updated, vec![LeafIndex(1)]);

        assert_eq!(
            state_update_alice.psks,
            (0..5)
                .map(|i| JustPreSharedKeyID::External(ExternalPskId(vec![i])))
                .collect::<Vec<_>>()
        );

        let payload = bob.process_message(commit).unwrap();
        assert_matches!(payload, Event::Commit(_));

        if let Event::Commit(mut state_update_bob) = payload {
            canonicalize_state_update(&mut state_update_bob);
            assert_eq!(state_update_alice.added, state_update_bob.added);
            assert_eq!(state_update_alice.removed, state_update_bob.removed);
            assert_eq!(state_update_alice.updated, state_update_bob.updated);
            assert_eq!(state_update_alice.psks, state_update_bob.psks);
        }
    }

    #[test]
    fn test_membership_tag_from_non_member() {
        let (mut alice_group, mut bob_group) =
            test_two_member_group(ProtocolVersion::Mls10, CipherSuite::Curve25519Aes128, true);

        let (mut commit, _) = alice_group.commit(vec![]).unwrap();

        let mut plaintext = match commit.payload {
            MLSMessagePayload::Plain(ref mut plain) => plain,
            _ => panic!("Non plaintext message"),
        };

        plaintext.content.sender = Sender::External(0);

        assert_matches!(
            bob_group.process_message(commit),
            Err(GroupError::MembershipTagForNonMember)
        );
    }

    #[test]
    fn test_partial_commits() {
        let protocol_version = ProtocolVersion::Mls10;
        let cipher_suite = CipherSuite::Curve25519Aes128;

        // Create a group with 3 members
        let mut alice = test_group(protocol_version, cipher_suite);
        let (mut bob, _) = alice.join("bob");

        let (mut charlie, commit) = alice.join_with_preferences(
            "charlie",
            Preferences::default()
                .with_ratchet_tree_extension(true)
                .force_commit_path_update(false),
        );

        bob.process_message(commit).unwrap();

        let (_, commit) = charlie.join_with_preferences("dave", charlie.group.config.preferences());

        alice.process_message(commit.clone()).unwrap();
        bob.process_message(commit).unwrap();
    }

    #[test]
    fn old_hpke_secrets_are_removed() {
        let mut alice = test_group(ProtocolVersion::Mls10, CipherSuite::Curve25519Aes128);
        alice.join("bob");
        alice.join("charlie");
        let remove = alice.group.remove_proposal(LeafIndex(1)).unwrap();
        alice.commit(vec![remove]).unwrap();

        assert!(alice.group.private_tree.secret_keys.contains_key(&1));
        alice.process_pending_commit().unwrap();
        assert!(!alice.group.private_tree.secret_keys.contains_key(&1));
    }
}
