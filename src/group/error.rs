use ferriscrypt::{
    asym::ec_key::EcKeyError, cipher::aead::AeadError, hpke::HpkeError, kdf::KdfError,
    rand::SecureRngError,
};
use thiserror::Error;

use crate::{
    cipher_suite::{CipherSuite, MaybeCipherSuite},
    extension::{ExtensionError, ExtensionList, GroupContextExtension},
    identity::CredentialError,
    identity::SigningIdentityError,
    key_package::{KeyPackageError, KeyPackageGenerationError, KeyPackageValidationError},
    protocol_version::{MaybeProtocolVersion, ProtocolVersion},
    psk::PskSecretError,
    signer::SignatureError,
    tree_kem::{
        leaf_node::LeafNodeError, leaf_node_validator::LeafNodeValidationError,
        path_secret::PathSecretError, tree_validator::TreeValidationError, RatchetTreeError,
        UpdatePathValidationError,
    },
};

use super::{
    ciphertext_processor::CiphertextProcessorError,
    confirmation_tag::ConfirmationTagError,
    framing::{ContentType, WireFormat},
    key_schedule::{KeyScheduleError, KeyScheduleKdfError},
    membership_tag::MembershipTagError,
    state_repo::GroupStateRepositoryError,
    transcript_hash::TranscriptHashError,
    ProposalCacheError,
};

#[derive(Error, Debug)]
pub enum GroupError {
    #[error(transparent)]
    RatchetTreeError(#[from] RatchetTreeError),
    #[error(transparent)]
    CiphertextProcessorError(CiphertextProcessorError),
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
    KeychainError(Box<dyn std::error::Error + Send + Sync + 'static>),
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
    GroupStateRepositoryError(#[from] GroupStateRepositoryError),
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
    PskSecretError(#[from] PskSecretError),
    #[error("Subgroup uses a different protocol version: {0:?}")]
    SubgroupWithDifferentProtocolVersion(ProtocolVersion),
    #[error("Subgroup uses a different cipher suite: {0:?}")]
    SubgroupWithDifferentCipherSuite(CipherSuite),
    #[error("Unsupported protocol version {0:?}")]
    UnsupportedProtocolVersion(MaybeProtocolVersion),
    #[error(
        "message protocol version {msg_version:?} does not match version {version:?} in {wire_format:?}"
    )]
    ProtocolVersionMismatch {
        msg_version: ProtocolVersion,
        wire_format: WireFormat,
        version: ProtocolVersion,
    },
    #[error("Unsupported cipher suite {0:?}")]
    UnsupportedCipherSuite(MaybeCipherSuite),
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
    InvalidProtocolVersion(ProtocolVersion, MaybeProtocolVersion),
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
    ReInitExtensionsMismatch(
        ExtensionList<GroupContextExtension>,
        ExtensionList<GroupContextExtension>,
    ),
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
    #[error("unexpected message type, expected {0:?}, found {1:?}")]
    UnexpectedMessageType(Vec<WireFormat>, WireFormat),
    #[error("membership tag on MLSPlaintext for non-member sender")]
    MembershipTagForNonMember,
}

impl From<CiphertextProcessorError> for GroupError {
    fn from(e: CiphertextProcessorError) -> Self {
        if matches!(e, CiphertextProcessorError::CantProcessMessageFromSelf) {
            GroupError::CantProcessMessageFromSelf
        } else {
            GroupError::CiphertextProcessorError(e)
        }
    }
}
