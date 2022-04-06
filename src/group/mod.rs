use std::collections::HashMap;
use std::ops::Deref;
use std::option::Option::Some;

use ferriscrypt::asym::ec_key::{EcKeyError, PublicKey};
use ferriscrypt::cipher::aead::AeadError;
use ferriscrypt::hmac::Tag;
use ferriscrypt::hpke::kem::{HpkePublicKey, HpkeSecretKey, KemType};
use ferriscrypt::hpke::HpkeError;
use ferriscrypt::kdf::hkdf::Hkdf;
use ferriscrypt::kdf::KdfError;
use ferriscrypt::rand::{SecureRng, SecureRngError};
use thiserror::Error;
use tls_codec::{Deserialize, Serialize};
use tls_codec_derive::{TlsDeserialize, TlsSerialize, TlsSize};

use crate::cipher_suite::{CipherSuite, HpkeCiphertext};
use crate::client_config::PskStore;
use crate::credential::CredentialError;
use crate::extension::{
    ExtensionError, ExtensionList, ExternalPubExt, LifetimeExt, RatchetTreeExt,
    RequiredCapabilitiesExt,
};
use crate::key_package::{
    KeyPackage, KeyPackageError, KeyPackageGeneration, KeyPackageGenerationError, KeyPackageRef,
    KeyPackageValidationError, KeyPackageValidationOptions, KeyPackageValidator,
};
use crate::psk::{
    ExternalPskId, JustPreSharedKeyID, PreSharedKeyID, PskGroupId, PskNonce, PskSecretError,
    ResumptionPSKUsage, ResumptionPsk,
};
use crate::signer::{Signable, SignatureError, Signer};
use crate::tree_kem::leaf_node::{LeafNode, LeafNodeError};
use crate::tree_kem::leaf_node_ref::LeafNodeRef;
use crate::tree_kem::leaf_node_validator::{
    LeafNodeValidationError, LeafNodeValidator, ValidationContext,
};
use crate::tree_kem::node::LeafIndex;
use crate::tree_kem::path_secret::{PathSecret, PathSecretError};
use crate::tree_kem::tree_validator::{TreeValidationError, TreeValidator};
use crate::tree_kem::{
    RatchetTreeError, TreeKemPrivate, TreeKemPublic, UpdatePath, UpdatePathGeneration,
    UpdatePathValidationError, UpdatePathValidator,
};
use crate::ProtocolVersion;

use confirmation_tag::*;
use epoch::*;
use framing::*;
use init_secret::*;
use key_schedule::*;
use membership_tag::*;
use message_signature::*;
use message_verifier::*;
use proposal::*;
use proposal_cache::*;
use proposal_ref::*;
use secret_tree::*;
use transcript_hash::*;

use self::epoch_repo::{EpochRepository, EpochRepositoryError};
use self::padding::PaddingMode;

pub use group_info::GroupInfo;

mod confirmation_tag;
pub(crate) mod epoch;
pub(crate) mod epoch_repo;
pub mod framing;
mod group_info;
mod init_secret;
pub mod key_schedule;
mod membership_tag;
pub mod message_signature;
mod message_verifier;
pub mod padding;
pub mod proposal;
mod proposal_cache;
mod proposal_ref;
mod secret_tree;
mod transcript_hash;

// TODO: Make the repository bounds configurable somehow
const EPOCH_REPO_RETENTION_LIMIT: u32 = 3;

struct ProvisionalState {
    public_tree: TreeKemPublic,
    private_tree: TreeKemPrivate,
    added_leaves: Vec<(KeyPackage, LeafNodeRef)>,
    removed_leaves: HashMap<LeafNodeRef, LeafNode>,
    group_context: GroupContext,
    epoch: u64,
    path_update_required: bool,
    psks: Vec<PreSharedKeyID>,
    reinit: Option<ReInit>,
    external_init: Option<(LeafNodeRef, ExternalInit)>,
}

#[derive(Clone, Debug)]
pub struct StateUpdate {
    pub added: Vec<LeafNodeRef>,
    pub removed: Vec<LeafNode>,
    pub active: bool,
    pub epoch: u64,
}

impl From<&ProvisionalState> for StateUpdate {
    fn from(provisional: &ProvisionalState) -> Self {
        let self_removed = provisional.self_removed();

        let removed: Vec<LeafNode> = provisional
            .removed_leaves
            .iter()
            .map(|(_, kp)| kp.clone())
            .collect();

        StateUpdate {
            added: provisional
                .added_leaves
                .iter()
                .map(|(_, leaf_ref)| leaf_ref.clone())
                .collect(),
            removed,
            active: !self_removed,
            epoch: provisional.epoch,
        }
    }
}

impl ProvisionalState {
    fn self_removed(&self) -> bool {
        self.removed_leaves
            .contains_key(&self.private_tree.leaf_node_ref)
    }
}

#[derive(Clone, Debug, PartialEq, TlsDeserialize, TlsSerialize, TlsSize)]
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
    EpochRepositoryError(#[from] EpochRepositoryError),
    #[error(transparent)]
    ExtensionError(#[from] ExtensionError),
    #[error(transparent)]
    KdfError(#[from] KdfError),
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
    #[error("Cipher suite does not match")]
    CipherSuiteMismatch,
    #[error("Invalid key package signature")]
    InvalidKeyPackage,
    #[error("Invalid commit, missing required path")]
    CommitMissingPath,
    #[error("plaintext message for incorrect epoch")]
    InvalidPlaintextEpoch,
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
    #[error("leaf not found in tree for ref {0}")]
    LeafNotFound(String),
    #[error("remove not allowed on single leaf tree")]
    RemoveNotAllowed,
    #[error("message from self can't be processed")]
    CantProcessMessageFromSelf,
    #[error("pending proposals found, commit required before application messages can be sent")]
    CommitRequired,
    #[error("commiter must not include any update proposals generated by the commiter")]
    InvalidCommitSelfUpdate,
    #[error("ratchet tree not provided or discovered in GroupInfo")]
    RatchetTreeNotFound,
    #[error("Only members can encrypt messages")]
    OnlyMembersCanEncryptMessages,
    #[error("Preconfigured sender cannot commit")]
    PreconfiguredSenderCannotCommit,
    #[error("Only members can update")]
    OnlyMembersCanUpdate,
    #[error("commiter must not propose unsupported required capabilities")]
    UnsupportedRequiredCapabilities,
    #[error("PSK proposal must contain an external PSK")]
    PskProposalMustContainExternalPsk,
    #[error(transparent)]
    PskSecretError(#[from] PskSecretError),
    #[error("Subgroup uses a different protocol version: {0:?}")]
    SubgroupWithDifferentProtocolVersion(ProtocolVersion),
    #[error("Subgroup uses a different cipher suite: {0:?}")]
    SubgroupWithDifferentCipherSuite(CipherSuite),
    #[error("Unsupported protocol version {0:?} or cipher suite {1:?}")]
    UnsupportedProtocolVersionOrCipherSuite(ProtocolVersion, CipherSuite),
    #[error("Signing key of preconfigured external sender is unknown")]
    UnknownSigningKeyForExternalSender,
    #[error("New members can only propose adding themselves")]
    NewMembersCanOnlyProposeAddingThemselves,
    #[error("Missing ExternalPub extension")]
    MissingExternalPubExtension,
    #[error("Missing update path in external commit")]
    MissingUpdatePathInExternalCommit,
}

#[derive(Clone, Debug, PartialEq, TlsDeserialize, TlsSerialize, TlsSize)]
pub struct GroupContext {
    #[tls_codec(with = "crate::tls::ByteVec")]
    pub group_id: Vec<u8>,
    pub epoch: u64,
    #[tls_codec(with = "crate::tls::ByteVec")]
    pub tree_hash: Vec<u8>,
    pub confirmed_transcript_hash: ConfirmedTranscriptHash,
    pub extensions: ExtensionList,
}

impl GroupContext {
    pub fn new_group(group_id: Vec<u8>, tree_hash: Vec<u8>, extensions: ExtensionList) -> Self {
        GroupContext {
            group_id,
            epoch: 0,
            tree_hash,
            confirmed_transcript_hash: ConfirmedTranscriptHash::from(vec![]),
            extensions,
        }
    }
}

#[derive(Clone, Debug, TlsDeserialize, TlsSerialize, TlsSize)]
pub struct CommitGeneration {
    pub plaintext: OutboundMessage,
    pub secrets: Option<UpdatePathGeneration>,
}

#[derive(Clone, Debug, PartialEq, TlsDeserialize, TlsSerialize, TlsSize)]
pub struct GroupSecrets {
    #[tls_codec(with = "crate::tls::ByteVec")]
    pub joiner_secret: Vec<u8>,
    pub path_secret: Option<PathSecret>,
    #[tls_codec(with = "crate::tls::DefVec")]
    pub psks: Vec<PreSharedKeyID>,
}

#[derive(Clone, Debug, PartialEq, TlsDeserialize, TlsSerialize, TlsSize)]
pub struct EncryptedGroupSecrets {
    pub new_member: KeyPackageRef,
    pub encrypted_group_secrets: HpkeCiphertext,
}

#[derive(Clone, Debug, PartialEq, TlsDeserialize, TlsSerialize, TlsSize)]
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
pub struct Group {
    pub protocol_version: ProtocolVersion,
    pub cipher_suite: CipherSuite,
    context: GroupContext,
    private_tree: TreeKemPrivate,
    epoch_repo: EpochRepository,
    interim_transcript_hash: InterimTranscriptHash,
    proposals: ProposalCache,
    pub pending_updates: HashMap<LeafNodeRef, HpkeSecretKey>, // Hash of key package to key generation
}

impl PartialEq for Group {
    fn eq(&self, other: &Self) -> bool {
        self.cipher_suite == other.cipher_suite
            && self.context == other.context
            && self.epoch_repo.current().ok() == other.epoch_repo.current().ok()
            && self.interim_transcript_hash == other.interim_transcript_hash
            && self.proposals == other.proposals
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct VerifiedPlaintext {
    encrypted: bool,
    plaintext: MLSPlaintext,
}

impl From<VerifiedPlaintext> for MLSPlaintext {
    fn from(verified: VerifiedPlaintext) -> Self {
        verified.plaintext
    }
}

impl Deref for VerifiedPlaintext {
    type Target = MLSPlaintext;

    fn deref(&self) -> &Self::Target {
        &self.plaintext
    }
}

#[derive(Debug, Clone, PartialEq, TlsSerialize, TlsDeserialize, TlsSize)]
#[repr(u8)]
pub enum OutboundMessage {
    Plaintext(MLSPlaintext),
    Ciphertext {
        original: MLSPlaintext,
        encrypted: MLSCiphertext,
    },
}

impl OutboundMessage {
    pub fn into_message(self, version: ProtocolVersion) -> MLSMessage {
        let payload = match self {
            OutboundMessage::Plaintext(m) => MLSMessagePayload::Plain(m),
            OutboundMessage::Ciphertext { encrypted, .. } => MLSMessagePayload::Cipher(encrypted),
        };
        MLSMessage { version, payload }
    }
}

impl Deref for OutboundMessage {
    type Target = MLSPlaintext;

    fn deref(&self) -> &Self::Target {
        match self {
            OutboundMessage::Plaintext(m) => m,
            OutboundMessage::Ciphertext { original, .. } => original,
        }
    }
}

impl From<OutboundMessage> for MLSPlaintext {
    fn from(outbound: OutboundMessage) -> Self {
        match outbound {
            OutboundMessage::Plaintext(m) => m,
            OutboundMessage::Ciphertext { original, .. } => original,
        }
    }
}

impl From<OutboundMessage> for VerifiedPlaintext {
    fn from(outbound: OutboundMessage) -> Self {
        VerifiedPlaintext {
            encrypted: match outbound {
                OutboundMessage::Plaintext(_) => false,
                OutboundMessage::Ciphertext { .. } => true,
            },
            plaintext: outbound.into(),
        }
    }
}

#[derive(Clone, Debug)]
pub enum ProcessedMessage {
    Application(Vec<u8>),
    Commit(StateUpdate),
    Proposal(Proposal),
    Welcome(Welcome),
    GroupInfo(GroupInfo),
    KeyPackage(KeyPackage),
}

impl Group {
    pub fn new(
        group_id: Vec<u8>,
        cipher_suite: CipherSuite,
        protocol_version: ProtocolVersion,
        leaf_node: LeafNode,
        leaf_node_secret: HpkeSecretKey,
        group_context_extensions: ExtensionList,
    ) -> Result<Self, GroupError> {
        let required_capabilities = group_context_extensions.get_extension()?;

        let validated_leaf = LeafNodeValidator::new(cipher_suite, required_capabilities.as_ref())
            .validate(leaf_node, ValidationContext::Add(None))?;

        let kdf = Hkdf::from(cipher_suite.kdf_type());

        let (public_tree, private_tree) =
            TreeKemPublic::derive(cipher_suite, validated_leaf, leaf_node_secret)?;

        let init_secret = InitSecret::random(&kdf)?;
        let tree_hash = public_tree.tree_hash()?;

        let context = GroupContext::new_group(group_id, tree_hash, group_context_extensions);

        let (epoch, _) = Epoch::derive(
            cipher_suite,
            &init_secret,
            &CommitSecret::empty(cipher_suite),
            public_tree,
            &context,
            LeafIndex(0),
            &vec![0; kdf.extract_size()],
        )?;

        let epoch_repo = EpochRepository::new(epoch, EPOCH_REPO_RETENTION_LIMIT);

        Ok(Self {
            protocol_version,
            cipher_suite,
            private_tree,
            context,
            epoch_repo,
            interim_transcript_hash: InterimTranscriptHash::from(vec![]),
            proposals: ProposalCache::new(),
            pending_updates: Default::default(),
        })
    }

    pub fn from_welcome_message<S, F>(
        protocol_version: ProtocolVersion,
        welcome: Welcome,
        public_tree: Option<TreeKemPublic>,
        key_package: KeyPackageGeneration,
        secret_store: &S,
        support_version_and_cipher: F,
    ) -> Result<Self, GroupError>
    where
        S: PskStore,
        F: FnOnce(ProtocolVersion, CipherSuite) -> bool,
    {
        Self::join_with_welcome(
            protocol_version,
            welcome,
            public_tree,
            key_package,
            secret_store,
            None,
            support_version_and_cipher,
        )
    }

    fn join_with_welcome<P: PskStore, F>(
        protocol_version: ProtocolVersion,
        welcome: Welcome,
        public_tree: Option<TreeKemPublic>,
        key_package_generation: KeyPackageGeneration,
        psk_store: &P,
        epoch_repo: Option<&EpochRepository>,
        support_version_and_cipher: F,
    ) -> Result<Self, GroupError>
    where
        P: PskStore,
        F: FnOnce(ProtocolVersion, CipherSuite) -> bool,
    {
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
        let decrypted_group_secrets = welcome.cipher_suite.hpke().open_base(
            &encrypted_group_secrets
                .encrypted_group_secrets
                .clone()
                .into(),
            &key_package_generation.init_secret_key,
            &[],
            None,
        )?;

        let group_secrets = GroupSecrets::tls_deserialize(&mut &*decrypted_group_secrets)?;

        let psk_secret = crate::psk::psk_secret(
            welcome.cipher_suite,
            psk_store,
            epoch_repo,
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

        let cipher_suite = group_info.cipher_suite;
        if !support_version_and_cipher(protocol_version, cipher_suite) {
            return Err(GroupError::UnsupportedProtocolVersionOrCipherSuite(
                protocol_version,
                cipher_suite,
            ));
        }

        let public_tree = find_tree(public_tree, &group_info)?;
        validate_tree(&public_tree, &group_info)?;

        // Identify a leaf in the tree array (any even-numbered node) whose leaf_node is identical
        // to the leaf_node field of the KeyPackage. If no such field exists, return an error. Let
        // index represent the index of this node among the leaves in the tree, namely the index of
        // the node in the tree array divided by two.
        let leaf_node_ref = key_package_generation
            .key_package
            .leaf_node
            .to_reference(welcome.cipher_suite)?;

        let self_index = public_tree.leaf_node_index(&leaf_node_ref)?;

        // Construct a new group state using the information in the GroupInfo object. The new
        // member's position in the tree is index, as defined above. In particular, the confirmed
        // transcript hash for the new state is the prior_confirmed_transcript_hash in the GroupInfo
        // object.
        let context = GroupContext::from(&group_info);

        let mut private_tree = TreeKemPrivate::new_self_leaf(
            self_index,
            leaf_node_ref,
            key_package_generation.leaf_node_secret_key,
        );

        // If the path_secret value is set in the GroupSecrets object
        if let Some(path_secret) = group_secrets.path_secret {
            private_tree.update_secrets(
                group_info.cipher_suite,
                public_tree.leaf_node_index(&group_info.signer)?,
                path_secret,
                &public_tree,
            )?;
        }

        // Use the joiner_secret from the GroupSecrets object to generate the epoch secret and
        // other derived secrets for the current epoch.
        let epoch = Epoch::new_joiner(
            group_info.cipher_suite,
            &group_secrets.joiner_secret,
            public_tree,
            &context,
            self_index,
            &psk_secret,
        )?;

        // Verify the confirmation tag in the GroupInfo using the derived confirmation key and the
        // confirmed_transcript_hash from the GroupInfo.
        if !group_info
            .confirmation_tag
            .matches(&epoch, &group_info.confirmed_transcript_hash)?
        {
            return Err(GroupError::InvalidConfirmationTag);
        }

        Self::join_with(
            protocol_version,
            group_info.cipher_suite,
            &group_info.confirmation_tag,
            (&group_info).into(),
            epoch,
            private_tree,
        )
    }

    fn join_with(
        protocol_version: ProtocolVersion,
        cipher_suite: CipherSuite,
        confirmation_tag: &ConfirmationTag,
        context: GroupContext,
        epoch: Epoch,
        private_tree: TreeKemPrivate,
    ) -> Result<Self, GroupError> {
        // Use the confirmed transcript hash and confirmation tag to compute the interim transcript
        // hash in the new state.
        let interim_transcript_hash = InterimTranscriptHash::create(
            cipher_suite,
            &context.confirmed_transcript_hash,
            MLSPlaintextCommitAuthData::from(confirmation_tag),
        )?;

        let epoch_repo = EpochRepository::new(epoch, EPOCH_REPO_RETENTION_LIMIT);

        Ok(Group {
            protocol_version,
            cipher_suite,
            context,
            private_tree,
            epoch_repo,
            interim_transcript_hash,
            proposals: ProposalCache::new(),
            pending_updates: Default::default(),
        })
    }

    /// Returns group and external commit message
    pub fn new_external<S, F>(
        protocol_version: ProtocolVersion,
        group_info: GroupInfo,
        public_tree: Option<TreeKemPublic>,
        leaf_node: LeafNode,
        leaf_node_secret: HpkeSecretKey,
        support_version_and_cipher: F,
        signer: &S,
    ) -> Result<(Self, OutboundMessage), GroupError>
    where
        S: Signer,
        F: FnOnce(ProtocolVersion, CipherSuite) -> bool,
    {
        if !support_version_and_cipher(protocol_version, group_info.cipher_suite) {
            return Err(GroupError::UnsupportedProtocolVersionOrCipherSuite(
                protocol_version,
                group_info.cipher_suite,
            ));
        }

        let external_pub_ext = group_info
            .other_extensions
            .get_extension::<ExternalPubExt>()?
            .ok_or(GroupError::MissingExternalPubExtension)?;

        let (init_secret, kem_output) = InitSecret::encode_for_external(
            group_info.cipher_suite,
            &external_pub_ext.external_pub,
        )?;

        let required_capabilities = group_info.group_context_extensions.get_extension()?;

        let leaf_node =
            LeafNodeValidator::new(group_info.cipher_suite, required_capabilities.as_ref())
                .validate(leaf_node, ValidationContext::Add(None))?;

        let leaf_node_ref = leaf_node.to_reference(group_info.cipher_suite)?;

        let psk_secret = vec![0; Hkdf::from(group_info.cipher_suite.kdf_type()).extract_size()];

        let mut public_tree = find_tree(public_tree, &group_info)?;
        validate_tree(&public_tree, &group_info)?;

        public_tree.add_leaves(vec![leaf_node])?;

        let self_index = public_tree.leaf_node_index(&leaf_node_ref)?;

        let private_tree =
            TreeKemPrivate::new_self_leaf(self_index, leaf_node_ref, leaf_node_secret);

        let old_context = GroupContext::from(&group_info);

        let update_path = public_tree.encap(
            &private_tree,
            &group_info.group_id,
            &old_context.tls_serialize_detached()?,
            &[],
            signer,
        )?;

        let commit_secret =
            CommitSecret::from_update_path(group_info.cipher_suite, Some(&update_path))?;

        let private_tree = update_path.secrets.private_key;

        let proposals = vec![Proposal::ExternalInit(ExternalInit { kem_output }).into()];

        let commit = Commit {
            proposals,
            path: Some(update_path.update_path),
        };

        let mut commit_message = MLSPlaintext::new_signed(
            &old_context,
            Sender::NewMember,
            Content::Commit(commit),
            signer,
            ControlEncryptionMode::Plaintext,
        )?;

        let interim_transcript_hash = InterimTranscriptHash::create(
            group_info.cipher_suite,
            &group_info.confirmed_transcript_hash,
            (&group_info.confirmation_tag).into(),
        )?;

        let confirmed_transcript_hash = ConfirmedTranscriptHash::create(
            group_info.cipher_suite,
            &interim_transcript_hash,
            MLSMessageCommitContent::new(&commit_message, false)?,
        )?;

        let new_context = GroupContext {
            group_id: old_context.group_id,
            epoch: old_context.epoch + 1,
            tree_hash: public_tree.tree_hash()?,
            confirmed_transcript_hash,
            extensions: old_context.extensions,
        };

        let (epoch, _) = Epoch::derive(
            group_info.cipher_suite,
            &init_secret,
            &commit_secret,
            public_tree,
            &new_context,
            self_index,
            &psk_secret,
        )?;

        let confirmation_tag =
            ConfirmationTag::create(&epoch, &new_context.confirmed_transcript_hash)?;

        let mut group = Self::join_with(
            protocol_version,
            group_info.cipher_suite,
            &confirmation_tag,
            new_context,
            epoch,
            private_tree,
        )?;

        commit_message.auth.confirmation_tag = Some(confirmation_tag);

        let commit_message =
            group.format_for_wire(commit_message, ControlEncryptionMode::Plaintext)?;

        Ok((group, commit_message))
    }

    #[inline(always)]
    pub fn current_epoch_tree(&self) -> Result<&TreeKemPublic, GroupError> {
        Ok(&self.epoch_repo.current()?.public_tree)
    }

    #[inline(always)]
    pub fn current_epoch(&self) -> u64 {
        self.context.epoch
    }

    #[inline(always)]
    pub fn current_user_index(&self) -> u32 {
        self.private_tree.self_index.0 as u32
    }

    #[inline(always)]
    pub fn current_user_ref(&self) -> &LeafNodeRef {
        &self.private_tree.leaf_node_ref
    }

    pub fn current_user_leaf_node(&self) -> Result<&LeafNode, GroupError> {
        self.current_epoch_tree()?
            .get_leaf_node(self.current_user_ref())
            .map_err(Into::into)
    }

    fn check_required_capabilities(
        &self,
        tree: &TreeKemPublic,
        group_context_extensions: &ExtensionList,
    ) -> Result<(), GroupError> {
        let existing_required_capabilities = self
            .context
            .extensions
            .get_extension::<RequiredCapabilitiesExt>()?;

        let new_required_capabilities =
            group_context_extensions.get_extension::<RequiredCapabilitiesExt>()?;

        if existing_required_capabilities != new_required_capabilities {
            let leaf_node_validator =
                LeafNodeValidator::new(self.cipher_suite, new_required_capabilities.as_ref());

            tree.get_leaf_nodes()
                .iter()
                .try_for_each(|ln| leaf_node_validator.validate_required_capabilities(ln))
                .map_err(|_| GroupError::UnsupportedRequiredCapabilities)
        } else {
            Ok(())
        }
    }

    fn apply_proposals(
        &self,
        proposals: ProposalSetEffects,
    ) -> Result<ProvisionalState, GroupError> {
        let mut provisional_tree = self.current_epoch_tree()?.clone();
        let mut provisional_private_tree = self.private_tree.clone();
        let mut provisional_group_context = self.context.clone();

        // Determine if a path update is required
        let has_update_or_remove = !proposals.updates.is_empty() || !proposals.removes.is_empty();
        let path_update_required = proposals.is_empty() || has_update_or_remove;

        // Locate a group context extension
        if let Some(group_context_extensions) = proposals.group_context_ext {
            // Group context extensions are a full replacement and not a merge
            provisional_group_context.extensions = group_context_extensions;
        }

        let required_capabilities = provisional_group_context.extensions.get_extension()?;

        let leaf_node_validator =
            LeafNodeValidator::new(self.cipher_suite, required_capabilities.as_ref());

        // Apply updates
        for (update_sender, leaf_node) in proposals.updates {
            let validated = leaf_node_validator.validate(
                leaf_node.clone(),
                ValidationContext::Update(&self.context.group_id),
            )?;

            // Update the leaf in the provisional tree
            provisional_tree.update_leaf(&update_sender, validated)?;
            let leaf_node_ref = leaf_node.to_reference(self.cipher_suite)?;

            // Update the leaf in the private tree if this is our update
            if let Some(new_leaf_sk) = self.pending_updates.get(&leaf_node_ref).cloned() {
                provisional_private_tree.update_leaf(
                    provisional_tree.total_leaf_count(),
                    leaf_node_ref,
                    new_leaf_sk,
                )?;
            }
        }

        // Apply removes
        // If there is only one user in the tree, they can't be removed
        if !proposals.removes.is_empty() && provisional_tree.occupied_leaf_count() == 1 {
            return Err(GroupError::RemoveNotAllowed);
        }

        let old_tree = self.current_epoch_tree()?;

        // Remove elements from the private tree
        proposals.removes.iter().try_for_each(|key_package_ref| {
            let leaf = old_tree.leaf_node_index(key_package_ref)?;
            provisional_private_tree.remove_leaf(provisional_tree.total_leaf_count(), leaf)?;

            Ok::<_, GroupError>(())
        })?;

        // Remove elements from the public tree
        let removed_leaves = provisional_tree
            .remove_leaves(old_tree, proposals.removes)?
            .into_iter()
            .collect::<HashMap<_, _>>();

        let key_package_validator = KeyPackageValidator::new(
            self.protocol_version,
            self.cipher_suite,
            required_capabilities.as_ref(),
        );

        // Apply adds
        let adds = proposals
            .adds
            .iter()
            .cloned()
            .map(|p| {
                // This check does not validate lifetime since lifetime is only validated by the sender at
                // the time the proposal is created. See https://github.com/mlswg/mls-protocol/issues/538
                //
                // TODO: If we are supplied a timestamp for the commit message, we can validate the
                // lifetime was valid at the moment the commit was generated
                key_package_validator
                    .validate(p, [KeyPackageValidationOptions::SkipLifetimeCheck].into())
            })
            .collect::<Result<_, _>>()?;

        let added_leaves = provisional_tree.add_leaves(adds)?;

        // Apply add by external init
        if let Some((external_add_leaf, _)) = &proposals.external_init {
            let validated = leaf_node_validator.validate(
                external_add_leaf.clone(),
                ValidationContext::Commit(&self.context.group_id),
            )?;

            provisional_tree.add_leaves(vec![validated])?;
        }

        let external_init = proposals
            .external_init
            .map(|(leaf, extern_init)| {
                leaf.to_reference(self.cipher_suite)
                    .map(|leaf_ref| (leaf_ref, extern_init))
            })
            .transpose()?;

        // Now that the tree is updated we can check required capabilities if needed
        self.check_required_capabilities(&provisional_tree, &provisional_group_context.extensions)?;

        let psks = match &proposals.reinit {
            Some(reinit) => vec![PreSharedKeyID {
                key_id: JustPreSharedKeyID::Resumption(ResumptionPsk {
                    usage: ResumptionPSKUsage::Reinit,
                    psk_group_id: PskGroupId(reinit.group_id.clone()),
                    psk_epoch: self.current_epoch() + 1,
                }),
                psk_nonce: PskNonce::random(self.cipher_suite)?,
            }],
            None => proposals.psks,
        };

        Ok(ProvisionalState {
            public_tree: provisional_tree,
            private_tree: provisional_private_tree,
            added_leaves: proposals.adds.into_iter().zip(added_leaves).collect(),
            removed_leaves,
            epoch: self.context.epoch + 1,
            path_update_required,
            group_context: provisional_group_context,
            psks,
            reinit: proposals.reinit,
            external_init,
        })
    }

    pub fn create_proposal<S: Signer>(
        &mut self,
        proposal: Proposal,
        signer: &S,
        encryption_mode: ControlEncryptionMode,
    ) -> Result<OutboundMessage, GroupError> {
        let plaintext = self.construct_mls_plaintext(
            Sender::Member(self.private_tree.leaf_node_ref.clone()),
            Content::Proposal(proposal),
            signer,
            encryption_mode,
        )?;

        // If we are going to encrypt then the tag will be dropped so it shouldn't be included
        // in the hash
        let membership_tag = if matches!(encryption_mode, ControlEncryptionMode::Encrypted(_)) {
            None
        } else {
            Some(MembershipTag::create(
                &plaintext,
                &self.context,
                self.epoch_repo.current()?,
            )?)
        };
        let plaintext = MLSPlaintext {
            membership_tag,
            ..plaintext
        };

        self.proposals.insert(
            self.cipher_suite,
            &plaintext,
            matches!(encryption_mode, ControlEncryptionMode::Encrypted(_)),
        )?;

        self.format_for_wire(plaintext, encryption_mode)
    }

    fn construct_mls_plaintext<S: Signer>(
        &self,
        sender: Sender,
        content: Content,
        signer: &S,
        encryption_mode: ControlEncryptionMode,
    ) -> Result<MLSPlaintext, GroupError> {
        Ok(MLSPlaintext::new_signed(
            &self.context,
            sender,
            content,
            signer,
            encryption_mode,
        )?)
    }

    /// Returns commit and optional `MLSMessage` containing a `Welcome`
    pub fn commit_proposals<P: PskStore, S: Signer>(
        &mut self,
        proposals: Vec<Proposal>,
        update_path: bool,
        encryption_mode: ControlEncryptionMode,
        ratchet_tree_extension: bool,
        psk_store: &P,
        signer: &S,
    ) -> Result<(CommitGeneration, Option<MLSMessage>), GroupError> {
        // Construct an initial Commit object with the proposals field populated from Proposals
        // received during the current epoch, and an empty path field. Add passed in proposals
        // by value
        let (commit_proposals, proposal_effects) = self
            .proposals
            .prepare_commit(&self.private_tree.leaf_node_ref, proposals)?;

        // Generate a provisional GroupContext object by applying the proposals referenced in the
        // initial Commit object, as described in Section 11.1. Update proposals are applied first,
        // followed by Remove proposals, and then finally Add proposals.
        // Add proposals are applied in the order listed in the proposals vector,
        // and always to the leftmost unoccupied leaf in the tree, or the right edge of
        // the tree if all leaves are occupied

        let mut provisional_state = self.apply_proposals(proposal_effects)?;

        let mut provisional_group_context = provisional_state.group_context;
        provisional_group_context.epoch += 1;

        //Decide whether to populate the path field: If the path field is required based on the
        // proposals that are in the commit (see above), then it MUST be populated. Otherwise, the
        // sender MAY omit the path field at its discretion.
        if provisional_state.path_update_required && !update_path {
            return Err(GroupError::CommitMissingPath);
        }

        let update_path = if update_path {
            // The committer MUST NOT include any Update proposals generated by the committer, since they would be duplicative with the path field in the Commit
            if !self.pending_updates.is_empty() {
                return Err(GroupError::InvalidCommitSelfUpdate);
            }

            //If populating the path field: Create an UpdatePath using the new tree. Any new
            // member (from an add proposal) MUST be excluded from the resolution during the
            // computation of the UpdatePath. The GroupContext for this operation uses the
            // group_id, epoch, tree_hash, and confirmed_transcript_hash values in the initial
            // GroupContext object. The leaf_key_package for this UpdatePath must have a
            // parent_hash extension.
            let context_bytes = self.context.tls_serialize_detached()?;

            let update_path = provisional_state.public_tree.encap(
                &self.private_tree,
                &self.context.group_id,
                &context_bytes,
                &provisional_state
                    .added_leaves
                    .iter()
                    // TODO: Modify encap so that clone isn't needed here
                    .map(|(_, leaf_node_ref)| leaf_node_ref.clone())
                    .collect::<Vec<LeafNodeRef>>(),
                signer,
            )?;

            Some(update_path)
        } else {
            None
        };

        // Update the tree hash in the provisional group context
        provisional_group_context.tree_hash = provisional_state.public_tree.tree_hash()?;

        let commit_secret =
            CommitSecret::from_update_path(self.cipher_suite, update_path.as_ref())?;

        let psk_secret = crate::psk::psk_secret(
            self.cipher_suite,
            psk_store,
            Some(&self.epoch_repo),
            &provisional_state.psks,
        )?;

        let commit = Commit {
            proposals: commit_proposals,
            path: update_path.clone().map(|up| up.update_path),
        };

        //Construct an MLSPlaintext object containing the Commit object
        let mut plaintext = self.construct_mls_plaintext(
            Sender::Member(self.private_tree.leaf_node_ref.clone()),
            Content::Commit(commit),
            signer,
            encryption_mode,
        )?;

        // Use the signature, the commit_secret and the psk_secret to advance the key schedule and
        // compute the confirmation_tag value in the MLSPlaintext.
        let confirmed_transcript_hash = ConfirmedTranscriptHash::create(
            self.cipher_suite,
            &self.interim_transcript_hash,
            MLSMessageCommitContent::new(
                &plaintext,
                matches!(encryption_mode, ControlEncryptionMode::Encrypted(_)),
            )?,
        )?;

        provisional_group_context.confirmed_transcript_hash = confirmed_transcript_hash;

        let mut extensions = ExtensionList::new();

        if ratchet_tree_extension {
            let ratchet_tree_ext = RatchetTreeExt {
                tree_data: provisional_state.public_tree.export_node_data(),
            };

            extensions.set_extension(ratchet_tree_ext)?;
        }

        let current_epoch = self.epoch_repo.current()?;

        let (next_epoch, joiner_secret) = Epoch::evolved_from(
            current_epoch,
            &commit_secret,
            provisional_state.public_tree,
            &provisional_group_context,
            &psk_secret,
        )?;

        let confirmation_tag = ConfirmationTag::create(
            &next_epoch,
            &provisional_group_context.confirmed_transcript_hash,
        )?;

        plaintext.auth.confirmation_tag = Some(confirmation_tag.clone());

        if matches!(encryption_mode, ControlEncryptionMode::Plaintext) {
            // Create the membership tag using the current group context and key schedule
            let membership_tag = MembershipTag::create(&plaintext, &self.context, current_epoch)?;
            plaintext.membership_tag = Some(membership_tag);
        }

        let (protocol_version, cipher_suite, added_members) = match provisional_state.reinit {
            Some(reinit) => {
                // TODO: This logic needs to be verified when we complete work on reinit
                (
                    reinit.version,
                    reinit.cipher_suite,
                    provisional_state.added_leaves,
                )
            }
            None => {
                // Welcome messages will be built for each added member
                (
                    self.protocol_version,
                    self.cipher_suite,
                    provisional_state.added_leaves,
                )
            }
        };

        // Construct a GroupInfo reflecting the new state
        // Group ID, epoch, tree, and confirmed transcript hash from the new state
        let mut group_info = GroupInfo {
            cipher_suite,
            group_id: self.context.group_id.clone(),
            epoch: provisional_group_context.epoch,
            tree_hash: provisional_group_context.tree_hash,
            confirmed_transcript_hash: provisional_group_context.confirmed_transcript_hash,
            other_extensions: extensions,
            group_context_extensions: provisional_group_context.extensions,
            confirmation_tag, // The confirmation_tag from the MLSPlaintext object
            signer: update_path
                .as_ref()
                .map(|up| up.secrets.private_key.leaf_node_ref.clone())
                .unwrap_or_else(|| self.private_tree.leaf_node_ref.clone()),
            signature: vec![],
        };

        // Sign the GroupInfo using the member's private signing key
        group_info.sign(signer, &())?;

        let welcome = self
            .make_welcome_message(
                added_members,
                &next_epoch.public_tree,
                &joiner_secret,
                &psk_secret,
                update_path.as_ref(),
                provisional_state.psks,
                &group_info,
            )?
            .map(|welcome| MLSMessage {
                version: protocol_version,
                payload: MLSMessagePayload::Welcome(welcome),
            });

        let pending_commit = CommitGeneration {
            plaintext: self.format_for_wire(plaintext, encryption_mode)?,
            secrets: update_path,
        };

        Ok((pending_commit, welcome))
    }

    #[allow(clippy::too_many_arguments)]
    fn make_welcome_message(
        &self,
        new_members: Vec<(KeyPackage, LeafNodeRef)>,
        tree: &TreeKemPublic,
        joiner_secret: &[u8],
        psk_secret: &[u8],
        update_path: Option<&UpdatePathGeneration>,
        psks: Vec<PreSharedKeyID>,
        group_info: &GroupInfo,
    ) -> Result<Option<Welcome>, GroupError> {
        // Encrypt the GroupInfo using the key and nonce derived from the joiner_secret for
        // the new epoch
        let welcome_secret =
            WelcomeSecret::from_joiner_secret(self.cipher_suite, joiner_secret, psk_secret)?;

        let group_info_data = group_info.tls_serialize_detached()?;
        let encrypted_group_info = welcome_secret.encrypt(&group_info_data)?;

        let secrets = new_members
            .into_iter()
            .map(|(key_package, leaf_node_ref)| {
                self.encrypt_group_secrets(
                    tree,
                    &key_package,
                    &leaf_node_ref,
                    joiner_secret,
                    update_path,
                    psks.clone(),
                )
            })
            .collect::<Result<Vec<EncryptedGroupSecrets>, GroupError>>()?;

        Ok(match secrets.len() {
            0 => None,
            _ => Some(Welcome {
                cipher_suite: group_info.cipher_suite,
                secrets,
                encrypted_group_info,
            }),
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub fn branch<S, P, F>(
        &self,
        sub_group_id: Vec<u8>,
        resumption_psk_epoch: Option<u64>,
        lifetime: LifetimeExt,
        psk_store: &P,
        signer: &S,
        mut get_new_key_package: F,
    ) -> Result<(Self, Option<Welcome>), GroupError>
    where
        S: Signer,
        P: PskStore,
        F: FnMut(&LeafNode) -> Option<KeyPackage>,
    {
        let current_leaf_node = self.current_user_leaf_node()?;

        let (leaf_node, leaf_node_secret) = LeafNode::generate(
            self.cipher_suite,
            current_leaf_node.credential.clone(),
            current_leaf_node.capabilities.clone(),
            current_leaf_node.extensions.clone(),
            signer,
            lifetime,
        )?;

        let required_capabilities = self.context.extensions.get_extension()?;

        let leaf_node_validator =
            LeafNodeValidator::new(self.cipher_suite, required_capabilities.as_ref());

        let key_package_validator = KeyPackageValidator::new(
            self.protocol_version,
            self.cipher_suite,
            required_capabilities.as_ref(),
        );

        let new_self_leaf_node =
            leaf_node_validator.validate(leaf_node, ValidationContext::Add(None))?;

        let (new_member_refs, new_members, new_key_pkgs) = {
            let current_tree = self.current_epoch_tree()?;
            let self_leaf_node_ref = &self.private_tree.leaf_node_ref;

            current_tree
                .get_leaf_node_refs()
                .filter_map(|leaf_node_ref| {
                    if self_leaf_node_ref == leaf_node_ref {
                        None
                    } else {
                        current_tree
                            .get_leaf_node(leaf_node_ref)
                            .map(&mut get_new_key_package)
                            .transpose()
                    }
                })
                .try_fold(
                    (Vec::new(), Vec::new(), Vec::new()),
                    |(mut refs, mut leaves, mut new_key_pkgs), new_key_pkg| {
                        let new_key_pkg = new_key_pkg?;
                        let new_leaf_ref = new_key_pkg.leaf_node.to_reference(self.cipher_suite)?;
                        let new_leaf = key_package_validator
                            .validate(new_key_pkg.clone(), Default::default())?;
                        refs.push(new_leaf_ref);
                        leaves.push(new_leaf);
                        new_key_pkgs.push(new_key_pkg);
                        Ok::<_, GroupError>((refs, leaves, new_key_pkgs))
                    },
                )?
        };

        let (mut new_pub_tree, new_priv_tree) =
            TreeKemPublic::derive(self.cipher_suite, new_self_leaf_node, leaf_node_secret)?;

        // Add existing members to new tree
        new_pub_tree.add_leaves(new_members)?;
        let new_pub_tree_hash = new_pub_tree.tree_hash()?;

        let new_context = GroupContext {
            epoch: 1,
            ..GroupContext::new_group(
                sub_group_id.clone(),
                new_pub_tree_hash.clone(),
                self.context.extensions.clone(),
            )
        };

        let kdf = Hkdf::from(self.cipher_suite.kdf_type());
        let init_secret = InitSecret::random(&kdf)?;

        let psk = PreSharedKeyID {
            key_id: JustPreSharedKeyID::Resumption(ResumptionPsk {
                usage: ResumptionPSKUsage::Branch,
                psk_group_id: PskGroupId(sub_group_id.clone()),
                psk_epoch: resumption_psk_epoch.unwrap_or_else(|| self.current_epoch()),
            }),
            psk_nonce: PskNonce::random(self.cipher_suite)?,
        };

        let psks = vec![psk];

        let psk_secret =
            crate::psk::psk_secret(self.cipher_suite, psk_store, Some(&self.epoch_repo), &psks)?;

        let (epoch, joiner_secret) = Epoch::derive(
            self.cipher_suite,
            &init_secret,
            &CommitSecret::empty(self.cipher_suite),
            new_pub_tree.clone(),
            &new_context,
            LeafIndex(0),
            &psk_secret,
        )?;

        let epoch_repo = EpochRepository::new(epoch.clone(), EPOCH_REPO_RETENTION_LIMIT);

        let mut group_info = GroupInfo {
            cipher_suite: self.cipher_suite,
            group_id: sub_group_id,
            epoch: 1,
            tree_hash: new_pub_tree_hash,
            confirmed_transcript_hash: new_context.confirmed_transcript_hash.clone(),
            group_context_extensions: new_context.extensions.clone(),
            other_extensions: ExtensionList::new(),
            confirmation_tag: ConfirmationTag::create(
                &epoch,
                &new_context.confirmed_transcript_hash,
            )?,
            signer: new_priv_tree.leaf_node_ref.clone(),
            signature: Vec::new(),
        };

        group_info.sign(signer, &())?;

        let new_group = Group {
            protocol_version: self.protocol_version,
            cipher_suite: self.cipher_suite,
            context: new_context,
            private_tree: new_priv_tree,
            epoch_repo,
            interim_transcript_hash: Vec::new().into(),
            proposals: ProposalCache::new(),
            pending_updates: Default::default(),
        };

        let welcome = self.make_welcome_message(
            new_key_pkgs.into_iter().zip(new_member_refs).collect(),
            &new_pub_tree,
            &joiner_secret,
            &psk_secret,
            None,
            psks,
            &group_info,
        )?;

        Ok((new_group, welcome))
    }

    pub fn join_subgroup<P, F>(
        &self,
        welcome: Welcome,
        public_tree: Option<TreeKemPublic>,
        key_package_generation: KeyPackageGeneration,
        psk_store: &P,
        support_version_and_cipher: F,
    ) -> Result<Self, GroupError>
    where
        P: PskStore,
        F: FnOnce(ProtocolVersion, CipherSuite) -> bool,
    {
        let subgroup = Self::join_with_welcome(
            self.protocol_version,
            welcome,
            public_tree,
            key_package_generation,
            psk_store,
            Some(&self.epoch_repo),
            support_version_and_cipher,
        )?;

        if subgroup.protocol_version != self.protocol_version {
            Err(GroupError::SubgroupWithDifferentProtocolVersion(
                subgroup.protocol_version,
            ))
        } else if subgroup.cipher_suite != self.cipher_suite {
            Err(GroupError::SubgroupWithDifferentCipherSuite(
                subgroup.cipher_suite,
            ))
        } else {
            Ok(subgroup)
        }
    }

    fn encrypt_group_secrets(
        &self,
        provisional_tree: &TreeKemPublic,
        key_package: &KeyPackage,
        leaf_node_ref: &LeafNodeRef,
        joiner_secret: &[u8],
        update_path: Option<&UpdatePathGeneration>,
        psks: Vec<PreSharedKeyID>,
    ) -> Result<EncryptedGroupSecrets, GroupError> {
        let leaf_index = provisional_tree.leaf_node_index(leaf_node_ref)?;

        let path_secret = update_path.and_then(|up| up.get_common_path_secret(leaf_index));

        // Ensure that we have a path secret if one is required
        if path_secret.is_none() && update_path.is_some() {
            return Err(GroupError::InvalidTreeKemPrivateKey);
        }

        let group_secrets = GroupSecrets {
            joiner_secret: joiner_secret.to_vec(),
            path_secret,
            psks,
        };

        let group_secrets_bytes = group_secrets.tls_serialize_detached()?;

        let encrypted_group_secrets = self.cipher_suite.hpke().seal_base(
            &key_package.hpke_init_key,
            &[],
            None,
            &group_secrets_bytes,
        )?;

        Ok(EncryptedGroupSecrets {
            new_member: key_package.to_reference()?,
            encrypted_group_secrets: encrypted_group_secrets.into(),
        })
    }

    pub fn add_proposal(&self, key_package: KeyPackage) -> Result<Proposal, GroupError> {
        let required_capabilities = self.context.extensions.get_extension()?;

        // Check that this proposal has a valid lifetime, signature, and meets the requirements
        // of the current group required capabilities extension.
        let key_package_validator = KeyPackageValidator::new(
            self.protocol_version,
            self.cipher_suite,
            required_capabilities.as_ref(),
        );

        //TODO: This clone can be removed if the api for the validator allows by-reference
        //validation
        key_package_validator.validate(key_package.clone(), Default::default())?;

        Ok(Proposal::Add(AddProposal { key_package }))
    }

    pub fn update_proposal<S: Signer>(&mut self, signer: &S) -> Result<Proposal, GroupError> {
        // Grab a copy of the current node and update it to have new key material
        // TODO: Support modifying extensions / capabilities
        let mut existing_leaf_node = self.current_user_leaf_node()?.clone();

        let secret_key = existing_leaf_node.update(
            self.cipher_suite,
            &self.context.group_id,
            None,
            None,
            signer,
        )?;

        // Store the secret key in the pending updates storage for later
        self.pending_updates.insert(
            existing_leaf_node.to_reference(self.cipher_suite)?,
            secret_key,
        );

        Ok(Proposal::Update(UpdateProposal {
            leaf_node: existing_leaf_node,
        }))
    }

    pub fn remove_proposal(&mut self, leaf_node_ref: &LeafNodeRef) -> Result<Proposal, GroupError> {
        self.current_epoch_tree()?.leaf_node_index(leaf_node_ref)?;

        Ok(Proposal::Remove(RemoveProposal {
            to_remove: leaf_node_ref.clone(),
        }))
    }

    pub fn psk_proposal(&mut self, psk: ExternalPskId) -> Result<Proposal, GroupError> {
        Ok(Proposal::Psk(PreSharedKey {
            psk: PreSharedKeyID {
                key_id: JustPreSharedKeyID::External(psk),
                psk_nonce: PskNonce::random(self.cipher_suite)?,
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
        plaintext: MLSPlaintext,
        encryption_mode: ControlEncryptionMode,
    ) -> Result<OutboundMessage, GroupError> {
        Ok(
            if let ControlEncryptionMode::Encrypted(padding_mode) = encryption_mode {
                let ciphertext = self.encrypt_plaintext(plaintext.clone(), padding_mode)?;

                OutboundMessage::Ciphertext {
                    original: plaintext,
                    encrypted: ciphertext,
                }
            } else {
                OutboundMessage::Plaintext(plaintext)
            },
        )
    }

    fn encrypt_plaintext(
        &mut self,
        plaintext: MLSPlaintext,
        padding: PaddingMode,
    ) -> Result<MLSCiphertext, GroupError> {
        let content_type = ContentType::from(&plaintext.content.content);

        // Build a ciphertext content using the plaintext content and signature
        let mut ciphertext_content = MLSCiphertextContent {
            content: plaintext.content.content,
            auth: plaintext.auth,
            padding: Vec::new(),
        };

        padding.apply_padding(&mut ciphertext_content);

        // Build ciphertext aad using the plaintext message
        let aad = MLSCiphertextContentAAD {
            group_id: plaintext.content.group_id,
            epoch: plaintext.content.epoch,
            content_type,
            authenticated_data: vec![],
        };

        // Generate a 4 byte reuse guard
        let mut reuse_guard = [0u8; 4];
        SecureRng::fill(&mut reuse_guard)?;

        // Grab an encryption key from the current epoch's key schedule
        let key_type = match &content_type {
            ContentType::Application => KeyType::Application,
            _ => KeyType::Handshake,
        };

        let current_epoch = self.epoch_repo.current_mut()?;

        let encryption_key = current_epoch.get_encryption_key(key_type)?;

        // Encrypt the ciphertext content using the encryption key and a nonce that is
        // reuse safe by xor the reuse guard with the first 4 bytes
        let ciphertext = encryption_key.encrypt(
            &ciphertext_content.tls_serialize_detached()?,
            &aad.tls_serialize_detached()?,
            &reuse_guard,
        )?;

        // Construct an mls sender data struct using the plaintext sender info, the generation
        // of the key schedule encryption key, and the reuse guard used to encrypt ciphertext
        let sender_data = MLSSenderData {
            sender: match plaintext.content.sender {
                Sender::Member(sender) => Ok(sender),
                Sender::Preconfigured(_) | Sender::NewMember => {
                    Err(GroupError::OnlyMembersCanEncryptMessages)
                }
            }?,
            generation: encryption_key.generation,
            reuse_guard,
        };

        let sender_data_aad = MLSSenderDataAAD {
            group_id: self.context.group_id.clone(),
            epoch: self.context.epoch,
            content_type,
        };

        // Encrypt the sender data with the derived sender_key and sender_nonce from the current
        // epoch's key schedule
        let (sender_key, sender_nonce) = current_epoch.get_sender_data_params(&ciphertext)?;

        let encrypted_sender_data = sender_key.encrypt_to_vec(
            &sender_data.tls_serialize_detached()?,
            Some(&sender_data_aad.tls_serialize_detached()?),
            sender_nonce,
        )?;

        Ok(MLSCiphertext {
            group_id: self.context.group_id.clone(),
            epoch: self.context.epoch,
            content_type,
            authenticated_data: vec![],
            encrypted_sender_data,
            ciphertext,
        })
    }

    pub fn encrypt_application_message<S: Signer>(
        &mut self,
        message: &[u8],
        signer: &S,
        padding: PaddingMode,
    ) -> Result<MLSCiphertext, GroupError> {
        // A group member that has observed one or more proposals within an epoch MUST send a Commit message
        // before sending application data
        if !self.proposals.is_empty() {
            return Err(GroupError::CommitRequired);
        }

        let mut plaintext = MLSPlaintext {
            content: MLSMessageContent {
                group_id: self.context.group_id.clone(),
                epoch: self.context.epoch,
                sender: Sender::Member(self.private_tree.leaf_node_ref.clone()),
                authenticated_data: Vec::new(),
                content: Content::Application(message.to_vec()),
            },
            auth: MLSMessageAuth {
                signature: MessageSignature::empty(),
                confirmation_tag: None,
            },
            membership_tag: None,
        };

        let signing_context = MessageSigningContext {
            group_context: Some(&self.context),
            encrypted: true,
        };

        plaintext.sign(signer, &signing_context)?;

        self.encrypt_plaintext(plaintext, padding)
    }

    pub fn verify_incoming_plaintext<F>(
        &mut self,
        message: MLSPlaintext,
        external_key_id_to_signing_key: F,
    ) -> Result<VerifiedPlaintext, GroupError>
    where
        F: Fn(&[u8]) -> Option<PublicKey>,
    {
        let mut verifier = MessageVerifier {
            msg_epoch: self.epoch_repo.get_mut(message.content.epoch)?,
            context: &self.context,
            private_tree: &self.private_tree,
            external_key_id_to_signing_key,
        };

        let plaintext = verifier.verify_plaintext(message)?;
        self.verify_incoming_message(plaintext)
    }

    pub fn verify_incoming_ciphertext<F>(
        &mut self,
        message: MLSCiphertext,
        external_key_id_to_signing_key: F,
    ) -> Result<VerifiedPlaintext, GroupError>
    where
        F: Fn(&[u8]) -> Option<PublicKey>,
    {
        let mut verifier = MessageVerifier {
            msg_epoch: self.epoch_repo.get_mut(message.epoch)?,
            context: &self.context,
            private_tree: &self.private_tree,
            external_key_id_to_signing_key,
        };
        let plaintext = verifier.decrypt_ciphertext(message)?;
        self.verify_incoming_message(plaintext)
    }

    fn verify_incoming_message(
        &mut self,
        plaintext: VerifiedPlaintext,
    ) -> Result<VerifiedPlaintext, GroupError> {
        match &plaintext.content.sender {
            Sender::Member(sender) if *sender == self.private_tree.leaf_node_ref => {
                Err(GroupError::CantProcessMessageFromSelf)
            }
            _ => Ok(()),
        }?;
        match &plaintext.plaintext.content.content {
            Content::Application(_) => Ok(()),
            Content::Commit(_) => (plaintext.plaintext.content.epoch == self.context.epoch)
                .then(|| ())
                .ok_or(GroupError::InvalidPlaintextEpoch),
            Content::Proposal(p) => {
                (plaintext.plaintext.content.epoch == self.context.epoch)
                    .then(|| ())
                    .ok_or(GroupError::InvalidPlaintextEpoch)?;
                match p {
                    Proposal::Psk(PreSharedKey {
                        psk: PreSharedKeyID { key_id, .. },
                    }) => matches!(key_id, JustPreSharedKeyID::External(_))
                        .then(|| ())
                        .ok_or(GroupError::PskProposalMustContainExternalPsk),
                    _ => Ok(()),
                }
            }
        }?;
        Ok(plaintext)
    }

    pub fn process_incoming_message<S: PskStore>(
        &mut self,
        plaintext: VerifiedPlaintext,
        secret_store: &S,
    ) -> Result<ProcessedMessage, GroupError> {
        match plaintext.plaintext.content.content {
            Content::Application(data) => Ok(ProcessedMessage::Application(data)),
            Content::Commit(_) => {
                self.process_commit(plaintext, None, secret_store)
                    .map(ProcessedMessage::Commit)
                //TODO: If the Commit included a ReInit proposal, the client MUST NOT use the group to send
                // messages anymore. Instead, it MUST wait for a Welcome message from the committer
                // and check that
            }
            Content::Proposal(ref p) => {
                self.proposals
                    .insert(self.cipher_suite, &plaintext, plaintext.encrypted)?;
                Ok(ProcessedMessage::Proposal(p.clone()))
            }
        }
    }

    pub fn process_pending_commit<S: PskStore>(
        &mut self,
        commit: CommitGeneration,
        secret_store: &S,
    ) -> Result<StateUpdate, GroupError> {
        self.process_commit(commit.plaintext.into(), commit.secrets, secret_store)
    }

    // This function takes a provisional copy of the tree and returns an updated tree and epoch key schedule
    fn process_commit<S: PskStore>(
        &mut self,
        plaintext: VerifiedPlaintext,
        local_pending: Option<UpdatePathGeneration>,
        secret_store: &S,
    ) -> Result<StateUpdate, GroupError> {
        //TODO: PSK Verify that all PSKs specified in any PreSharedKey proposals in the proposals
        // vector are available.

        let commit_content = MLSMessageCommitContent::new(plaintext.deref(), plaintext.encrypted)?;
        let sender = match &plaintext.content.sender {
            Sender::Member(sender) => Ok(sender.clone()),
            Sender::NewMember => commit_content
                .commit
                .path
                .as_ref()
                .map(|p| p.leaf_node.to_reference(self.cipher_suite))
                .transpose()?
                .ok_or(GroupError::MissingUpdatePathInExternalCommit),
            Sender::Preconfigured(_) => Err(GroupError::PreconfiguredSenderCannotCommit),
        }?;

        //Generate a provisional GroupContext object by applying the proposals referenced in the
        // initial Commit object, as described in Section 11.1. Update proposals are applied first,
        // followed by Remove proposals, and then finally Add proposals. Add proposals are applied
        // in the order listed in the proposals vector, and always to the leftmost unoccupied leaf
        // in the tree, or the right edge of the tree if all leaves are occupied.
        let proposal_effects = self.proposals.resolve_for_commit(
            plaintext.content.sender.clone(),
            commit_content.commit.proposals.clone(),
            commit_content.commit.path.as_ref(),
        )?;

        let mut provisional_state = self.apply_proposals(proposal_effects)?;

        let state_update = StateUpdate::from(&provisional_state);

        //Verify that the path value is populated if the proposals vector contains any Update
        // or Remove proposals, or if it's empty. Otherwise, the path value MAY be omitted.
        if provisional_state.path_update_required && commit_content.commit.path.is_none() {
            return Err(GroupError::CommitMissingPath);
        }

        if provisional_state.self_removed() {
            return Ok(state_update);
        }

        // Apply the update path if needed
        let updated_secrets = match &commit_content.commit.path {
            None => None,
            Some(update_path) => {
                let required_capabilities =
                    provisional_state.group_context.extensions.get_extension()?;

                let leaf_validator =
                    LeafNodeValidator::new(self.cipher_suite, required_capabilities.as_ref());

                let update_path_validator = UpdatePathValidator::new(leaf_validator);

                let validated_update_path =
                    update_path_validator.validate(update_path.clone(), &self.context.group_id)?;

                let secrets = if let Some(pending) = local_pending {
                    // Receiving from yourself is a special case, we already have the new private keys
                    provisional_state.public_tree.apply_self_update(
                        &validated_update_path,
                        &self.private_tree.leaf_node_ref,
                    )?;

                    Ok(pending.secrets)
                } else {
                    provisional_state.public_tree.decap(
                        provisional_state.private_tree,
                        &sender,
                        &validated_update_path,
                        &provisional_state
                            .added_leaves
                            .into_iter()
                            .map(|(_, leaf_node_ref)| leaf_node_ref)
                            .collect::<Vec<LeafNodeRef>>(),
                        &self.context.tls_serialize_detached()?,
                    )
                }?;

                Some(secrets)
            }
        };

        let commit_secret =
            CommitSecret::from_tree_secrets(self.cipher_suite, updated_secrets.as_ref())?;

        let mut provisional_group_context = provisional_state.group_context;

        // Bump up the epoch in the provisional group context
        provisional_group_context.epoch = provisional_state.epoch;

        // Update the new GroupContext's confirmed and interim transcript hashes using the new Commit.
        let confirmed_transcript_hash = ConfirmedTranscriptHash::create(
            self.cipher_suite,
            &self.interim_transcript_hash,
            commit_content,
        )?;

        let interim_transcript_hash = InterimTranscriptHash::create(
            self.cipher_suite,
            &confirmed_transcript_hash,
            MLSPlaintextCommitAuthData::from(plaintext.deref()),
        )?;

        provisional_group_context.confirmed_transcript_hash = confirmed_transcript_hash;
        provisional_group_context.tree_hash = provisional_state.public_tree.tree_hash()?;

        let psk_secret = crate::psk::psk_secret(
            self.cipher_suite,
            secret_store,
            Some(&self.epoch_repo),
            &provisional_state.psks,
        )?;

        // Use the commit_secret, the psk_secret, the provisional GroupContext, and the init secret
        // from the previous epoch (or from the external init) to compute the epoch secret and
        // derived secrets for the new epoch

        let (next_epoch, _) = {
            let current_epoch = self.epoch_repo.current()?;

            match provisional_state.external_init {
                Some((_, ExternalInit { kem_output })) => {
                    let init_secret = InitSecret::decode_for_external(
                        self.cipher_suite,
                        &kem_output,
                        &current_epoch.key_schedule.external_secret,
                    )?;

                    Epoch::derive(
                        self.cipher_suite,
                        &init_secret,
                        &commit_secret,
                        provisional_state.public_tree,
                        &provisional_group_context,
                        current_epoch.self_index,
                        &psk_secret,
                    )?
                }
                None => Epoch::evolved_from(
                    current_epoch,
                    &commit_secret,
                    provisional_state.public_tree,
                    &provisional_group_context,
                    &psk_secret,
                )?,
            }
        };

        // Use the confirmation_key for the new epoch to compute the confirmation tag for
        // this message, as described below, and verify that it is the same as the
        // confirmation_tag field in the MLSPlaintext object.
        let confirmation_tag = ConfirmationTag::create(
            &next_epoch,
            &provisional_group_context.confirmed_transcript_hash,
        )?;

        if Some(confirmation_tag) != plaintext.auth.confirmation_tag {
            return Err(GroupError::InvalidConfirmationTag);
        }

        // If the above checks are successful, consider the updated GroupContext object
        // as the current state of the group
        if let Some(private_tree) = updated_secrets.map(|us| us.private_key) {
            self.private_tree = private_tree
        }

        self.context = provisional_group_context;
        self.epoch_repo.add(next_epoch);

        self.interim_transcript_hash = interim_transcript_hash;

        // Clear the proposals list
        self.proposals = ProposalCache::new();
        // Clear the pending updates list
        self.pending_updates = Default::default();

        Ok(state_update)
    }

    pub fn current_direct_path(&self) -> Result<Vec<Option<HpkePublicKey>>, GroupError> {
        self.epoch_repo
            .current()?
            .public_tree
            .direct_path_keys(self.private_tree.self_index)
            .map_err(Into::into)
    }

    /// The returned `GroupInfo` is suitable for one external commit for the current epoch.
    pub fn external_commit_info<S: Signer>(&self, signer: &S) -> Result<GroupInfo, GroupError> {
        let current_epoch = self.epoch_repo.current()?;

        let mut other_extensions = ExtensionList::new();

        other_extensions.set_extension(ExternalPubExt {
            external_pub: self
                .cipher_suite
                .kem()
                .derive(&current_epoch.key_schedule.external_secret)?
                .1,
        })?;

        let mut info = GroupInfo {
            cipher_suite: self.cipher_suite,
            group_id: self.context.group_id.clone(),
            epoch: self.current_epoch(),
            tree_hash: self.context.tree_hash.clone(),
            confirmed_transcript_hash: self.context.confirmed_transcript_hash.clone(),
            group_context_extensions: self.context.extensions.clone(),
            other_extensions,
            confirmation_tag: ConfirmationTag::create(
                current_epoch,
                &self.context.confirmed_transcript_hash,
            )?,
            signer: self.private_tree.leaf_node_ref.clone(),
            signature: Vec::new(),
        };

        info.sign(signer, &())?;

        Ok(info)
    }

    pub fn context(&self) -> &GroupContext {
        &self.context
    }

    pub fn authentication_secret(&self) -> Result<Vec<u8>, GroupError> {
        Ok(self
            .epoch_repo
            .current()?
            .key_schedule
            .authentication_secret
            .clone())
    }

    pub fn export_secret(
        &self,
        label: &str,
        context: &[u8],
        len: usize,
    ) -> Result<Vec<u8>, GroupError> {
        Ok(self.epoch_repo.current()?.key_schedule.export_secret(
            label,
            context,
            len,
            self.cipher_suite,
        )?)
    }
}

fn find_tree(
    public_tree: Option<TreeKemPublic>,
    group_info: &GroupInfo,
) -> Result<TreeKemPublic, GroupError> {
    match public_tree {
        Some(tree) => Ok(tree),
        None => {
            let tree_extension = group_info
                .other_extensions
                .get_extension::<RatchetTreeExt>()?
                .ok_or(GroupError::RatchetTreeNotFound)?;
            Ok(TreeKemPublic::import_node_data(
                group_info.cipher_suite,
                tree_extension.tree_data,
            )?)
        }
    }
}

fn validate_tree(public_tree: &TreeKemPublic, group_info: &GroupInfo) -> Result<(), GroupError> {
    let sender_key_package = public_tree.get_leaf_node(&group_info.signer)?;
    group_info.verify(&sender_key_package.credential.public_key()?, &())?;

    let required_capabilities = group_info.group_context_extensions.get_extension()?;

    // Verify the integrity of the ratchet tree
    let tree_validator = TreeValidator::new(
        group_info.cipher_suite,
        &group_info.group_id,
        &group_info.tree_hash,
        required_capabilities.as_ref(),
    );

    tree_validator.validate(public_tree)?;

    Ok(())
}

#[cfg(test)]
pub(crate) mod test_utils {
    use ferriscrypt::asym::ec_key::SecretKey;

    use super::*;
    use crate::{
        credential::{BasicCredential, Credential, CredentialConvertible},
        extension::{CapabilitiesExt, LifetimeExt, RequiredCapabilitiesExt},
        key_package::KeyPackageGenerator,
    };

    pub const TEST_GROUP: &[u8] = b"group";

    pub(crate) struct TestGroup {
        pub group: Group,
        pub credential: Credential,
        pub signing_key: SecretKey,
    }

    pub(crate) fn get_test_group_context(epoch: u64) -> GroupContext {
        GroupContext {
            group_id: vec![],
            epoch,
            tree_hash: vec![],
            confirmed_transcript_hash: ConfirmedTranscriptHash::from(vec![]),
            extensions: ExtensionList::from(vec![]),
        }
    }

    pub(crate) fn credential(signing_key: &SecretKey, identifier: &[u8]) -> Credential {
        BasicCredential::new(identifier.to_vec(), signing_key.to_public().unwrap())
            .unwrap()
            .into_credential()
    }

    pub(crate) fn group_extensions() -> ExtensionList {
        let required_capabilities = RequiredCapabilitiesExt::default();

        let mut extensions = ExtensionList::new();
        extensions.set_extension(required_capabilities).unwrap();
        extensions
    }

    pub(crate) fn lifetime() -> LifetimeExt {
        LifetimeExt::years(1).unwrap()
    }

    pub(crate) fn test_member(
        protocol_version: ProtocolVersion,
        cipher_suite: CipherSuite,
        identifier: &[u8],
    ) -> (KeyPackageGeneration, SecretKey) {
        let signing_key = cipher_suite.generate_secret_key().unwrap();

        let key_package_generator = KeyPackageGenerator {
            protocol_version,
            cipher_suite,
            credential: &credential(&signing_key, identifier),
            signing_key: &signing_key,
        };

        let key_package = key_package_generator
            .generate(
                lifetime(),
                CapabilitiesExt::default(),
                ExtensionList::default(),
                ExtensionList::default(),
            )
            .unwrap();

        (key_package, signing_key)
    }

    pub(crate) fn test_group_custom(
        protocol_version: ProtocolVersion,
        cipher_suite: CipherSuite,
        capabilities: CapabilitiesExt,
        leaf_extensions: ExtensionList,
    ) -> TestGroup {
        let signing_key = cipher_suite.generate_secret_key().unwrap();
        let credential = credential(&signing_key, b"alice");

        let (leaf_node, leaf_secret_key) = LeafNode::generate(
            cipher_suite,
            credential.clone(),
            capabilities,
            leaf_extensions,
            &signing_key,
            lifetime(),
        )
        .unwrap();

        let group = Group::new(
            TEST_GROUP.to_vec(),
            cipher_suite,
            protocol_version,
            leaf_node,
            leaf_secret_key,
            group_extensions(),
        )
        .unwrap();

        TestGroup {
            group,
            credential,
            signing_key,
        }
    }

    pub(crate) fn test_group(
        protocol_version: ProtocolVersion,
        cipher_suite: CipherSuite,
    ) -> TestGroup {
        test_group_custom(
            protocol_version,
            cipher_suite,
            CapabilitiesExt::default(),
            ExtensionList::default(),
        )
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        client_config::InMemoryPskStore,
        extension::{CapabilitiesExt, LifetimeExt, MlsExtension, RequiredCapabilitiesExt},
        group::test_utils::lifetime,
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

            assert_eq!(group.cipher_suite, cipher_suite);
            assert_eq!(group.context.epoch, 0);
            assert_eq!(group.context.group_id, TEST_GROUP.to_vec());
            assert_eq!(group.context.extensions, group_extensions());
            assert_eq!(
                group.context.confirmed_transcript_hash,
                ConfirmedTranscriptHash::from(vec![])
            );
            assert!(group.proposals.is_empty());
            assert!(group.pending_updates.is_empty());
            assert!(group.epoch_repo.current().is_ok());
            assert_eq!(group.private_tree.self_index.0, group.current_user_index());

            assert_eq!(
                group
                    .epoch_repo
                    .current()
                    .unwrap()
                    .public_tree
                    .get_leaf_nodes()[0]
                    .credential
                    .public_key()
                    .unwrap(),
                test_group.signing_key.to_public().unwrap()
            );
        }
    }

    #[test]
    fn test_pending_proposals_application_data() {
        let protocol_version = ProtocolVersion::Mls10;
        let cipher_suite = CipherSuite::Curve25519Aes128V1;

        let mut test_group = test_group(protocol_version, cipher_suite);

        // Create a proposal
        let (bob_key_package, _) = test_member(protocol_version, cipher_suite, b"bob");

        let proposal = test_group
            .group
            .add_proposal(bob_key_package.key_package)
            .unwrap();

        test_group
            .group
            .create_proposal(
                proposal,
                &test_group.signing_key,
                ControlEncryptionMode::Plaintext,
            )
            .unwrap();

        // We should not be able to send application messages until a commit happens
        let res = test_group.group.encrypt_application_message(
            b"test",
            &test_group.signing_key,
            PaddingMode::None,
        );

        assert_matches!(res, Err(GroupError::CommitRequired));

        let secret_store = InMemoryPskStore::default();

        // We should be able to send application messages after a commit
        let (commit, _) = test_group
            .group
            .commit_proposals(
                vec![],
                true,
                ControlEncryptionMode::Plaintext,
                false,
                &secret_store,
                &test_group.signing_key,
            )
            .unwrap();

        test_group
            .group
            .process_pending_commit(commit, &secret_store)
            .unwrap();

        assert!(test_group
            .group
            .encrypt_application_message(b"test", &test_group.signing_key, PaddingMode::None)
            .is_ok());
    }

    #[test]
    fn test_invalid_commit_self_update() {
        let protocol_version = ProtocolVersion::Mls10;
        let cipher_suite = CipherSuite::Curve25519Aes128V1;

        let mut test_group = test_group(protocol_version, cipher_suite);

        // Create an update proposal
        let proposal = test_group
            .group
            .update_proposal(&test_group.signing_key)
            .unwrap();

        // There should be an error because path_update is set to `true` while there is a pending
        // update proposal for the commiter
        let res = test_group.group.commit_proposals(
            vec![proposal],
            true,
            ControlEncryptionMode::Plaintext,
            false,
            &InMemoryPskStore::default(),
            &test_group.signing_key,
        );

        assert_matches!(res, Err(GroupError::InvalidCommitSelfUpdate));
    }

    #[test]
    fn test_invalid_commit_self_update_cached() {
        let protocol_version = ProtocolVersion::Mls10;
        let cipher_suite = CipherSuite::Curve25519Aes128V1;

        let mut test_group = test_group(protocol_version, cipher_suite);

        // Create an update proposal
        let proposal = test_group
            .group
            .update_proposal(&test_group.signing_key)
            .unwrap();

        test_group
            .group
            .create_proposal(
                proposal,
                &test_group.signing_key,
                ControlEncryptionMode::Plaintext,
            )
            .unwrap();

        // There should be an error because path_update is set to `true` while there is a pending
        // update proposal for the commiter
        let res = test_group.group.commit_proposals(
            vec![],
            true,
            ControlEncryptionMode::Plaintext,
            false,
            &InMemoryPskStore::default(),
            &test_group.signing_key,
        );

        assert_matches!(res, Err(GroupError::InvalidCommitSelfUpdate));
    }

    #[test]
    fn test_invalid_add_proposal_bad_key_package() {
        let protocol_version = ProtocolVersion::Mls10;
        let cipher_suite = CipherSuite::Curve25519Aes128V1;

        let test_group = test_group(protocol_version, cipher_suite);
        let (mut bob_keys, _) = test_member(protocol_version, cipher_suite, b"bob");
        bob_keys.key_package.signature = SecureRng::gen(32).unwrap();

        let proposal = test_group.group.add_proposal(bob_keys.key_package);
        assert_matches!(proposal, Err(GroupError::KeyPackageValidationError(_)));
    }

    #[test]
    fn test_invalid_add_bad_key_package() {
        let protocol_version = ProtocolVersion::Mls10;
        let cipher_suite = CipherSuite::Curve25519Aes128V1;

        let mut test_group = test_group(protocol_version, cipher_suite);
        let (bob_keys, _) = test_member(protocol_version, cipher_suite, b"bob");

        let mut proposal = test_group.group.add_proposal(bob_keys.key_package).unwrap();

        if let Proposal::Add(ref mut kp) = proposal {
            kp.key_package.signature = SecureRng::gen(32).unwrap()
        }

        let res = test_group.group.commit_proposals(
            vec![proposal],
            false,
            ControlEncryptionMode::Plaintext,
            false,
            &InMemoryPskStore::default(),
            &test_group.signing_key,
        );

        assert_matches!(res, Err(GroupError::KeyPackageValidationError(_)));
    }

    #[test]
    fn test_invalid_update_bad_key_package() {
        let protocol_version = ProtocolVersion::Mls10;
        let cipher_suite = CipherSuite::Curve25519Aes128V1;

        let (mut alice_group, mut bob_group) =
            test_two_member_group(protocol_version, cipher_suite, true);

        let mut proposal = alice_group
            .group
            .update_proposal(&alice_group.signing_key)
            .unwrap();

        if let Proposal::Update(ref mut update) = proposal {
            update.leaf_node.signature = SecureRng::gen(32).unwrap();
        } else {
            panic!("Invalid update proposal")
        }

        let proposal = alice_group
            .group
            .create_proposal(
                proposal,
                &alice_group.signing_key,
                ControlEncryptionMode::Plaintext,
            )
            .unwrap();

        // Hack bob's receipt of the proposal
        bob_group
            .group
            .proposals
            .insert(cipher_suite, &proposal, false)
            .unwrap();

        let res = bob_group.group.commit_proposals(
            vec![],
            true,
            ControlEncryptionMode::Plaintext,
            false,
            &InMemoryPskStore::default(),
            &bob_group.signing_key,
        );

        assert_matches!(
            res,
            Err(GroupError::LeafNodeValidationError(
                LeafNodeValidationError::SignatureError(SignatureError::SignatureValidationFailed(
                    _
                ))
            ))
        );
    }

    fn test_two_member_group(
        protocol_version: ProtocolVersion,
        cipher_suite: CipherSuite,
        tree_ext: bool,
    ) -> (TestGroup, TestGroup) {
        let mut test_group = test_group(protocol_version, cipher_suite);

        let (bob_key_package, bob_key) = test_member(
            test_group.group.protocol_version,
            test_group.group.cipher_suite,
            b"bob",
        );

        // Add bob to the group
        let add_bob_proposal = test_group
            .group
            .add_proposal(bob_key_package.key_package.clone())
            .unwrap();

        let secret_store = InMemoryPskStore::default();

        let (commit_generation, welcome) = test_group
            .group
            .commit_proposals(
                vec![add_bob_proposal],
                false,
                ControlEncryptionMode::Plaintext,
                tree_ext,
                &secret_store,
                &test_group.signing_key,
            )
            .unwrap();

        // Apply the commit to the original group
        test_group
            .group
            .process_pending_commit(commit_generation, &secret_store)
            .unwrap();

        let tree = if tree_ext {
            None
        } else {
            Some(test_group.group.current_epoch_tree().unwrap().clone())
        };

        let welcome = match welcome.unwrap().payload {
            MLSMessagePayload::Welcome(w) => w,
            _ => panic!("Expected Welcome message"),
        };

        // Group from Bob's perspective
        let bob_group = Group::from_welcome_message(
            protocol_version,
            welcome,
            tree,
            bob_key_package.clone(),
            &secret_store,
            |_, _| true,
        )
        .unwrap();

        assert_eq!(test_group.group, bob_group);

        let bob_test_group = TestGroup {
            group: bob_group,
            credential: bob_key_package.key_package.leaf_node.credential,
            signing_key: bob_key,
        };

        (test_group, bob_test_group)
    }

    #[test]
    fn test_welcome_processing_exported_tree() {
        test_two_member_group(ProtocolVersion::Mls10, CipherSuite::P256Aes128V1, false);
    }

    #[test]
    fn test_welcome_processing_tree_extension() {
        test_two_member_group(ProtocolVersion::Mls10, CipherSuite::P256Aes128V1, true);
    }

    #[test]
    fn test_welcome_processing_missing_tree() {
        let protocol_version = ProtocolVersion::Mls10;
        let cipher_suite = CipherSuite::P256Aes128V1;
        let mut test_group = test_group(protocol_version, cipher_suite);
        let (bob_key_package, _) = test_member(protocol_version, cipher_suite, b"bob");

        // Add bob to the group
        let add_bob_proposal = test_group
            .group
            .add_proposal(bob_key_package.key_package.clone())
            .unwrap();

        let secret_store = InMemoryPskStore::default();

        let (_, welcome) = test_group
            .group
            .commit_proposals(
                vec![add_bob_proposal],
                false,
                ControlEncryptionMode::Plaintext,
                false,
                &secret_store,
                &test_group.signing_key,
            )
            .unwrap();

        let welcome = match welcome.unwrap().payload {
            MLSMessagePayload::Welcome(w) => w,
            _ => panic!("Expected Welcome message"),
        };

        // Group from Bob's perspective
        let bob_group = Group::from_welcome_message(
            protocol_version,
            welcome,
            None,
            bob_key_package,
            &secret_store,
            |_, _| true,
        );

        assert_matches!(bob_group, Err(GroupError::RatchetTreeNotFound));
    }

    #[test]
    fn test_group_context_ext_proposal_create() {
        let test_group = test_group(ProtocolVersion::Mls10, CipherSuite::P256Aes128V1);

        let mut extension_list = ExtensionList::new();
        extension_list
            .set_extension(RequiredCapabilitiesExt {
                extensions: vec![LifetimeExt::IDENTIFIER],
                proposals: vec![],
            })
            .unwrap();

        let proposal = test_group
            .group
            .group_context_extensions_proposal(extension_list.clone());

        assert_matches!(proposal, Proposal::GroupContextExtensions(ext) if ext == extension_list);
    }

    fn group_context_extension_proposal_test(
        ext_list: ExtensionList,
    ) -> (TestGroup, Result<CommitGeneration, GroupError>) {
        let protocol_version = ProtocolVersion::Mls10;
        let cipher_suite = CipherSuite::P256Aes128V1;

        let mut capabilities = CapabilitiesExt::default();
        capabilities.extensions.push(42);

        let mut test_group = test_group_custom(
            protocol_version,
            cipher_suite,
            capabilities,
            ExtensionList::default(),
        );

        let proposals = vec![test_group.group.group_context_extensions_proposal(ext_list)];

        let commit = test_group
            .group
            .commit_proposals(
                proposals,
                true,
                ControlEncryptionMode::Plaintext,
                false,
                &InMemoryPskStore::default(),
                &test_group.signing_key,
            )
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
            })
            .unwrap();

        let (mut test_group, commit) =
            group_context_extension_proposal_test(extension_list.clone());

        let state_update = test_group
            .group
            .process_pending_commit(commit.unwrap(), &InMemoryPskStore::default())
            .unwrap();

        assert!(state_update.active);
        assert_eq!(test_group.group.context.extensions, extension_list)
    }

    #[test]
    fn test_group_context_ext_proposal_invalid() {
        let mut extension_list = ExtensionList::new();
        extension_list
            .set_extension(RequiredCapabilitiesExt {
                extensions: vec![999],
                proposals: vec![],
            })
            .unwrap();

        let (_, commit) = group_context_extension_proposal_test(extension_list.clone());

        assert_matches!(commit, Err(GroupError::UnsupportedRequiredCapabilities));
    }

    #[test]
    fn test_group_encrypt_plaintext_padding() {
        let protocol_version = ProtocolVersion::Mls10;
        let cipher_suite = CipherSuite::P256Aes128V1;
        let mut test_group = test_group(protocol_version, cipher_suite);

        let proposal = test_group
            .group
            .group_context_extensions_proposal(ExtensionList::new());

        let without_padding = test_group
            .group
            .create_proposal(
                proposal.clone(),
                &test_group.signing_key,
                ControlEncryptionMode::Encrypted(PaddingMode::None),
            )
            .unwrap();

        let with_padding = test_group
            .group
            .create_proposal(
                proposal,
                &test_group.signing_key,
                ControlEncryptionMode::Encrypted(PaddingMode::StepFunction(1024)),
            )
            .unwrap();

        let without_padding_length = match without_padding {
            OutboundMessage::Plaintext(_) => panic!("unexpected plaintext"),
            OutboundMessage::Ciphertext {
                original: _,
                encrypted,
            } => encrypted.tls_serialized_len(),
        };

        let with_padding_length = match with_padding {
            OutboundMessage::Plaintext(_) => panic!("unexpected plaintext"),
            OutboundMessage::Ciphertext {
                original: _,
                encrypted,
            } => encrypted.tls_serialized_len(),
        };

        assert!(with_padding_length > without_padding_length);
    }

    #[test]
    fn external_commit_requires_external_pub_extension() {
        let protocol_version = ProtocolVersion::Mls10;
        let cipher_suite = CipherSuite::P256Aes128V1;
        let group = test_group(protocol_version, cipher_suite);

        let mut info = group
            .group
            .external_commit_info(&group.signing_key)
            .unwrap();
        info.other_extensions = ExtensionList::new();
        info.sign(&group.signing_key, &()).unwrap();

        let (leaf_node, leaf_secret) = LeafNode::generate(
            cipher_suite,
            group.credential,
            CapabilitiesExt::default(),
            ExtensionList::default(),
            &group.signing_key,
            lifetime(),
        )
        .unwrap();

        let res = Group::new_external(
            protocol_version,
            info,
            None,
            leaf_node,
            leaf_secret,
            |_, _| true,
            &group.signing_key,
        );

        assert_matches!(res, Err(GroupError::MissingExternalPubExtension));
    }
}
//TODO: More Group unit tests
