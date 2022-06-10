use std::collections::HashMap;
use std::ops::{Deref, DerefMut};
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
use crate::client_config::{CredentialValidator, PskStore};
use crate::credential::CredentialError;
use crate::extension::{
    ExtensionError, ExtensionList, ExternalPubExt, RatchetTreeExt, RequiredCapabilitiesExt,
};
use crate::group::{KeySchedule, KeyScheduleError};
use crate::key_package::{
    KeyPackage, KeyPackageError, KeyPackageGeneration, KeyPackageGenerationError, KeyPackageRef,
    KeyPackageValidationError, KeyPackageValidator,
};
use crate::message::ProcessedMessagePayload;
use crate::psk::{
    ExternalPskId, JustPreSharedKeyID, PreSharedKeyID, PskGroupId, PskNonce, PskSecretError,
    ResumptionPSKUsage, ResumptionPsk,
};
use crate::signer::{Signable, SignatureError, Signer};
use crate::signing_identity::SigningIdentityError;
use crate::tree_kem::kem::TreeKem;
use crate::tree_kem::leaf_node::{LeafNode, LeafNodeError};
use crate::tree_kem::leaf_node_validator::{
    LeafNodeValidationError, LeafNodeValidator, ValidationContext,
};
use crate::tree_kem::node::LeafIndex;
use crate::tree_kem::path_secret::{PathSecret, PathSecretError};
use crate::tree_kem::tree_validator::{TreeValidationError, TreeValidator};
use crate::tree_kem::{
    Capabilities, Lifetime, RatchetTreeError, TreeKemPrivate, TreeKemPublic, UpdatePath,
    UpdatePathGeneration, UpdatePathValidationError, UpdatePathValidator,
};
use crate::{EpochRepository, ProtocolVersion};

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

use group_core::GroupCore;
use padding::PaddingMode;

pub use epoch::PublicEpoch;
pub use external_group::ExternalGroup;
pub use external_group_config::{ExternalGroupConfig, InMemoryExternalGroupConfig};
pub use group_config::{GroupConfig, InMemoryGroupConfig};
pub use group_info::GroupInfo;
pub use group_state::GroupState;
pub use secret_tree::SecretTreeError;

mod confirmation_tag;
pub(crate) mod epoch;
mod external_group;
mod external_group_config;
pub mod framing;
mod group_config;
mod group_core;
mod group_info;
mod group_state;
mod init_secret;
pub mod key_schedule;
mod membership_tag;
pub mod message_signature;
mod message_verifier;
pub mod padding;
pub mod proposal;
mod proposal_cache;
mod proposal_filter;
mod proposal_ref;
mod secret_tree;
mod transcript_hash;

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
            active: false,
            epoch: provisional.epoch,
        }
    }
}

impl From<&ProvisionalState> for StateUpdate {
    fn from(provisional: &ProvisionalState) -> Self {
        Self {
            active: !provisional.self_removed(),
            ..Self::from(&provisional.public_state)
        }
    }
}

impl ProvisionalState {
    fn self_removed(&self) -> bool {
        self.public_state
            .removed_leaves
            .iter()
            .any(|(index, _)| index == &self.private_tree.self_index)
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
    EpochRepositoryError(Box<dyn std::error::Error + Send + Sync>),
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
    #[error("leaf not found in tree for index {0}")]
    LeafNotFound(u32),
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
    #[error("Epoch {0} not found")]
    EpochNotFound(u64),
    #[error("expected protocol version {0:?}, found version {1:?}")]
    InvalidProtocol(ProtocolVersion, ProtocolVersion),
    #[error("unexpected group ID {0:?}")]
    InvalidGroupId(Vec<u8>),
    #[error("Unencrypted application message")]
    UnencryptedApplicationMessage,
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

#[derive(Clone, Debug)]
pub struct CommitOptions {
    pub prefer_path_update: bool,
    pub extension_update: Option<ExtensionList>,
    pub capabilities_update: Option<Capabilities>,
    pub encryption_mode: ControlEncryptionMode,
    pub ratchet_tree_extension: bool,
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
pub struct Group<C: GroupConfig> {
    config: C,
    core: GroupCore,
    private_tree: TreeKemPrivate,
    current_public_epoch: PublicEpoch,
    interim_transcript_hash: InterimTranscriptHash,
    // TODO: HpkePublicKey does not have Eq and Hash
    pub pending_updates: HashMap<Vec<u8>, HpkeSecretKey>, // Hash of leaf node hpke public key to secret key
    key_schedule: KeySchedule,
    confirmation_tag: ConfirmationTag,
}

impl<C: GroupConfig> PartialEq for Group<C> {
    fn eq(&self, other: &Self) -> bool {
        self.core.cipher_suite == other.core.cipher_suite
            && self.core.context == other.core.context
            && self.interim_transcript_hash == other.interim_transcript_hash
            && self.core.proposals == other.core.proposals
            && self.key_schedule == other.key_schedule
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct VerifiedPlaintext {
    pub encrypted: bool,
    pub plaintext: MLSPlaintext,
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
        MLSMessage {
            version,
            payload: self.into(),
        }
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

impl DerefMut for OutboundMessage {
    fn deref_mut(&mut self) -> &mut Self::Target {
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

impl From<OutboundMessage> for MLSMessagePayload {
    fn from(outbound: OutboundMessage) -> Self {
        match outbound {
            OutboundMessage::Plaintext(p) => Self::Plain(p),
            OutboundMessage::Ciphertext { encrypted, .. } => Self::Cipher(encrypted),
        }
    }
}

impl<C: GroupConfig> Group<C> {
    pub fn new(
        config: C,
        group_id: Vec<u8>,
        cipher_suite: CipherSuite,
        protocol_version: ProtocolVersion,
        leaf_node: LeafNode,
        leaf_node_secret: HpkeSecretKey,
        group_context_extensions: ExtensionList,
    ) -> Result<Self, GroupError> {
        let required_capabilities = group_context_extensions.get_extension()?;

        LeafNodeValidator::new(
            cipher_suite,
            required_capabilities.as_ref(),
            config.credential_validator(),
        )
        .check_if_valid(&leaf_node, ValidationContext::Add(None))?;

        let kdf = Hkdf::from(cipher_suite.kdf_type());

        let (public_tree, private_tree) =
            TreeKemPublic::derive(cipher_suite, leaf_node, leaf_node_secret)?;

        let init_secret = InitSecret::random(&kdf)?;
        let tree_hash = public_tree.tree_hash()?;

        let context = GroupContext::new_group(group_id, tree_hash, group_context_extensions);

        let public_epoch = PublicEpoch {
            identifier: context.epoch,
            cipher_suite,
            public_tree: public_tree.clone(),
        };

        let key_schedule_result = KeySchedule::derive(
            cipher_suite,
            &init_secret,
            &CommitSecret::empty(cipher_suite),
            &context,
            LeafIndex(0),
            public_tree,
            &vec![0; kdf.extract_size()],
        )?;

        config
            .epoch_repo()
            .insert(public_epoch.identifier, key_schedule_result.epoch.into())
            .map_err(|e| GroupError::EpochRepositoryError(e.into()))?;

        Ok(Self {
            config,
            core: GroupCore::new(protocol_version, cipher_suite, context),
            private_tree,
            current_public_epoch: public_epoch,
            interim_transcript_hash: InterimTranscriptHash::from(vec![]),
            confirmation_tag: ConfirmationTag::empty(&cipher_suite)?,
            pending_updates: Default::default(),
            key_schedule: key_schedule_result.key_schedule,
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub fn from_welcome_message<S, F, G, V>(
        protocol_version: ProtocolVersion,
        welcome: Welcome,
        public_tree: Option<TreeKemPublic>,
        key_package: KeyPackageGeneration,
        secret_store: &S,
        make_config: G,
        support_version_and_cipher: F,
        credential_validator: V,
    ) -> Result<Self, GroupError>
    where
        S: PskStore,
        F: FnOnce(ProtocolVersion, CipherSuite) -> bool,
        G: FnOnce(&[u8]) -> C,
        V: CredentialValidator,
    {
        Self::join_with_welcome(
            protocol_version,
            welcome,
            public_tree,
            key_package,
            secret_store,
            |_| Ok(None),
            make_config,
            support_version_and_cipher,
            credential_validator,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn join_with_welcome<P, F, G, E, V>(
        protocol_version: ProtocolVersion,
        welcome: Welcome,
        public_tree: Option<TreeKemPublic>,
        key_package_generation: KeyPackageGeneration,
        psk_store: &P,
        get_epoch: E,
        make_config: G,
        support_version_and_cipher: F,
        credential_validator: V,
    ) -> Result<Self, GroupError>
    where
        P: PskStore,
        F: FnOnce(ProtocolVersion, CipherSuite) -> bool,
        G: FnOnce(&[u8]) -> C,
        V: CredentialValidator,
        E: FnMut(u64) -> Result<Option<Epoch>, <C::EpochRepository as EpochRepository>::Error>,
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

        let psk_secret = crate::psk::psk_secret(
            welcome.cipher_suite,
            psk_store,
            get_epoch,
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
        validate_tree(&public_tree, &group_info, credential_validator)?;

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
        let context = GroupContext::from(&group_info);

        let mut private_tree =
            TreeKemPrivate::new_self_leaf(self_index, key_package_generation.leaf_node_secret_key);

        // If the path_secret value is set in the GroupSecrets object
        if let Some(path_secret) = group_secrets.path_secret {
            private_tree.update_secrets(
                group_info.cipher_suite,
                group_info.signer,
                path_secret,
                &public_tree,
            )?;
        }

        // Use the joiner_secret from the GroupSecrets object to generate the epoch secret and
        // other derived secrets for the current epoch.
        let key_schedule_result = KeySchedule::new_joiner(
            group_info.cipher_suite,
            &group_secrets.joiner_secret,
            &context,
            self_index,
            public_tree.clone(),
            &psk_secret,
        )?;

        // Verify the confirmation tag in the GroupInfo using the derived confirmation key and the
        // confirmed_transcript_hash from the GroupInfo.
        if !group_info.confirmation_tag.matches(
            &key_schedule_result.confirmation_key,
            &group_info.confirmed_transcript_hash,
            &group_info.cipher_suite,
        )? {
            return Err(GroupError::InvalidConfirmationTag);
        }

        let public_epoch = PublicEpoch {
            identifier: context.epoch,
            cipher_suite,
            public_tree: public_tree.clone(),
        };

        let config = make_config(&group_info.group_id);

        config
            .epoch_repo()
            .insert(public_epoch.identifier, key_schedule_result.epoch.into())
            .map_err(|e| GroupError::EpochRepositoryError(e.into()))?;

        Self::join_with(
            config,
            protocol_version,
            &group_info.confirmation_tag,
            (&group_info).into(),
            public_epoch,
            key_schedule_result.key_schedule,
            private_tree,
        )
    }

    fn join_with(
        config: C,
        protocol_version: ProtocolVersion,
        confirmation_tag: &ConfirmationTag,
        context: GroupContext,
        public_epoch: PublicEpoch,
        key_schedule: KeySchedule,
        private_tree: TreeKemPrivate,
    ) -> Result<Self, GroupError> {
        // Use the confirmed transcript hash and confirmation tag to compute the interim transcript
        // hash in the new state.
        let interim_transcript_hash = InterimTranscriptHash::create(
            public_epoch.cipher_suite,
            &context.confirmed_transcript_hash,
            MLSPlaintextCommitAuthData::from(confirmation_tag),
        )?;

        Ok(Group {
            config,
            core: GroupCore::new(protocol_version, public_epoch.cipher_suite, context),
            private_tree,
            current_public_epoch: public_epoch,
            interim_transcript_hash,
            confirmation_tag: confirmation_tag.clone(),
            pending_updates: Default::default(),
            key_schedule,
        })
    }

    /// Returns group and external commit message
    #[allow(clippy::too_many_arguments)]
    pub fn new_external<S, F>(
        config: C,
        protocol_version: ProtocolVersion,
        group_info: GroupInfo,
        public_tree: Option<TreeKemPublic>,
        leaf_node: LeafNode,
        leaf_node_secret: HpkeSecretKey,
        support_version_and_cipher: F,
        signer: &S,
        authenticated_data: Vec<u8>,
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

        LeafNodeValidator::new(
            group_info.cipher_suite,
            required_capabilities.as_ref(),
            config.credential_validator(),
        )
        .check_if_valid(&leaf_node, ValidationContext::Add(None))?;

        let psk_secret = vec![0; Hkdf::from(group_info.cipher_suite.kdf_type()).extract_size()];

        let mut public_tree = find_tree(public_tree, &group_info)?;
        validate_tree(&public_tree, &group_info, config.credential_validator())?;

        let self_index = public_tree.add_leaves(vec![leaf_node])?[0];

        let private_tree = TreeKemPrivate::new_self_leaf(self_index, leaf_node_secret);

        let old_context = GroupContext::from(&group_info);

        let update_path = TreeKem::new(&mut public_tree, private_tree).encap(
            &group_info.group_id,
            &old_context.tls_serialize_detached()?,
            &[],
            signer,
            None,
            None,
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
            authenticated_data,
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

        let key_schedule_result = KeySchedule::derive(
            group_info.cipher_suite,
            &init_secret,
            &commit_secret,
            &new_context,
            self_index,
            public_tree.clone(),
            &psk_secret,
        )?;

        let confirmation_tag = ConfirmationTag::create(
            &key_schedule_result.confirmation_key,
            &new_context.confirmed_transcript_hash,
            &group_info.cipher_suite,
        )?;

        let public_epoch = PublicEpoch {
            identifier: new_context.epoch,
            cipher_suite: group_info.cipher_suite,
            public_tree,
        };

        config
            .epoch_repo()
            .insert(new_context.epoch, key_schedule_result.epoch.into())
            .map_err(|e| GroupError::EpochRepositoryError(e.into()))?;

        let mut group = Self::join_with(
            config,
            protocol_version,
            &confirmation_tag,
            new_context,
            public_epoch,
            key_schedule_result.key_schedule,
            private_tree,
        )?;

        commit_message.auth.confirmation_tag = Some(confirmation_tag);

        let commit_message =
            group.format_for_wire(commit_message, ControlEncryptionMode::Plaintext)?;

        Ok((group, commit_message))
    }

    #[inline(always)]
    pub fn current_epoch_tree(&self) -> Result<&TreeKemPublic, GroupError> {
        Ok(&self.current_public_epoch.public_tree)
    }

    #[inline(always)]
    pub fn current_epoch(&self) -> u64 {
        self.core.context.epoch
    }

    #[inline(always)]
    pub fn current_user_index(&self) -> u32 {
        self.private_tree.self_index.0 as u32
    }

    pub fn current_user_leaf_node(&self) -> Result<&LeafNode, GroupError> {
        self.current_epoch_tree()?
            .get_leaf_node(self.private_tree.self_index)
            .map_err(Into::into)
    }

    fn apply_proposals(
        &self,
        proposals: ProposalSetEffects,
    ) -> Result<ProvisionalState, GroupError> {
        let old_tree = self.current_epoch_tree()?;
        let mut provisional_private_tree = self.private_tree.clone();
        let total_leaf_count = old_tree.total_leaf_count();

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
            public_state: self.core.apply_proposals(
                old_tree,
                proposals,
                self.config.credential_validator(),
            )?,
            private_tree: provisional_private_tree,
        })
    }

    pub fn create_proposal<S: Signer>(
        &mut self,
        proposal: Proposal,
        signer: &S,
        encryption_mode: ControlEncryptionMode,
        authenticated_data: Vec<u8>,
    ) -> Result<OutboundMessage, GroupError> {
        let plaintext = self.construct_mls_plaintext(
            Sender::Member(self.private_tree.self_index),
            Content::Proposal(proposal.clone()),
            signer,
            encryption_mode,
            authenticated_data,
        )?;

        // If we are going to encrypt then the tag will be dropped so it shouldn't be included
        // in the hash
        let membership_tag = if matches!(encryption_mode, ControlEncryptionMode::Encrypted(_)) {
            None
        } else {
            Some(MembershipTag::create(
                &plaintext,
                &self.core.context,
                &self.key_schedule.membership_key,
                &self.current_public_epoch.cipher_suite,
            )?)
        };

        let plaintext = MLSPlaintext {
            membership_tag,
            ..plaintext
        };

        let proposal_ref = ProposalRef::from_plaintext(
            self.core.cipher_suite,
            &plaintext,
            matches!(encryption_mode, ControlEncryptionMode::Encrypted(_)),
        )?;

        self.core
            .proposals
            .insert(proposal_ref, proposal, plaintext.content.sender.clone());

        self.format_for_wire(plaintext, encryption_mode)
    }

    fn construct_mls_plaintext<S: Signer>(
        &self,
        sender: Sender,
        content: Content,
        signer: &S,
        encryption_mode: ControlEncryptionMode,
        authenticated_data: Vec<u8>,
    ) -> Result<MLSPlaintext, GroupError> {
        Ok(MLSPlaintext::new_signed(
            &self.core.context,
            sender,
            content,
            signer,
            encryption_mode,
            authenticated_data,
        )?)
    }

    /// Returns commit and optional `MLSMessage` containing a `Welcome`
    pub fn commit_proposals<P: PskStore, S: Signer>(
        &mut self,
        proposals: Vec<Proposal>,
        options: CommitOptions,
        psk_store: &P,
        signer: &S,
        authenticated_data: Vec<u8>,
    ) -> Result<(CommitGeneration, Option<MLSMessage>), GroupError> {
        // Construct an initial Commit object with the proposals field populated from Proposals
        // received during the current epoch, and an empty path field. Add passed in proposals
        // by value
        let (commit_proposals, proposal_effects) = self.core.proposals.prepare_commit(
            self.private_tree.self_index,
            proposals,
            self.core.context.extensions.get_extension()?,
            self.config.credential_validator(),
            &self.current_public_epoch.public_tree,
        )?;

        // Generate a provisional GroupContext object by applying the proposals referenced in the
        // initial Commit object, as described in Section 11.1. Update proposals are applied first,
        // followed by Remove proposals, and then finally Add proposals.
        // Add proposals are applied in the order listed in the proposals vector,
        // and always to the leftmost unoccupied leaf in the tree, or the right edge of
        // the tree if all leaves are occupied

        let mut provisional_state = self.apply_proposals(proposal_effects)?;

        let mut provisional_group_context = provisional_state.public_state.group_context;
        provisional_group_context.epoch += 1;

        // Decide whether to populate the path field: If the path field is required based on the
        // proposals that are in the commit (see above), then it MUST be populated. Otherwise, the
        // sender MAY omit the path field at its discretion.
        let perform_path_update =
            options.prefer_path_update || provisional_state.public_state.path_update_required;

        let added_leaves = provisional_state.public_state.added_leaves;

        let update_path = if perform_path_update {
            // The committer MUST NOT include any Update proposals generated by the committer, since they would be duplicative with the path field in the Commit
            if !self.pending_updates.is_empty() {
                return Err(GroupError::InvalidCommitSelfUpdate);
            }

            // If populating the path field: Create an UpdatePath using the new tree. Any new
            // member (from an add proposal) MUST be excluded from the resolution during the
            // computation of the UpdatePath. The GroupContext for this operation uses the
            // group_id, epoch, tree_hash, and confirmed_transcript_hash values in the initial
            // GroupContext object. The leaf_key_package for this UpdatePath must have a
            // parent_hash extension.
            let context_bytes = self.core.context.tls_serialize_detached()?;
            let update_path = TreeKem::new(
                &mut provisional_state.public_state.public_tree,
                self.private_tree.clone(),
            )
            .encap(
                &self.core.context.group_id,
                &context_bytes,
                &added_leaves
                    .iter()
                    .map(|(_, leaf_index)| *leaf_index)
                    .collect::<Vec<LeafIndex>>(),
                signer,
                options.capabilities_update,
                options.extension_update,
            )?;

            Some(update_path)
        } else {
            None
        };

        // Update the tree hash in the provisional group context
        provisional_group_context.tree_hash =
            provisional_state.public_state.public_tree.tree_hash()?;

        let commit_secret =
            CommitSecret::from_update_path(self.core.cipher_suite, update_path.as_ref())?;

        let psk_secret = crate::psk::psk_secret(
            self.core.cipher_suite,
            psk_store,
            |epoch_id| {
                self.config
                    .epoch_repo()
                    .get(epoch_id)
                    .map(|ep_opt| ep_opt.map(|ep| ep.into_inner()))
            },
            &provisional_state.public_state.psks,
        )?;

        let commit = Commit {
            proposals: commit_proposals,
            path: update_path.clone().map(|up| up.update_path),
        };

        //Construct an MLSPlaintext object containing the Commit object
        let mut plaintext = self.construct_mls_plaintext(
            Sender::Member(self.private_tree.self_index),
            Content::Commit(commit),
            signer,
            options.encryption_mode,
            authenticated_data,
        )?;

        // Use the signature, the commit_secret and the psk_secret to advance the key schedule and
        // compute the confirmation_tag value in the MLSPlaintext.
        let confirmed_transcript_hash = ConfirmedTranscriptHash::create(
            self.core.cipher_suite,
            &self.interim_transcript_hash,
            MLSMessageCommitContent::new(
                &plaintext,
                matches!(options.encryption_mode, ControlEncryptionMode::Encrypted(_)),
            )?,
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
            self.current_public_epoch.cipher_suite,
            &self.key_schedule.init_secret,
            &commit_secret,
            &provisional_group_context,
            self.private_tree.self_index,
            self.current_public_epoch.public_tree.clone(),
            &psk_secret,
        )?;

        let confirmation_tag = ConfirmationTag::create(
            &key_schedule_result.confirmation_key,
            &provisional_group_context.confirmed_transcript_hash,
            &self.core.cipher_suite,
        )?;

        plaintext.auth.confirmation_tag = Some(confirmation_tag.clone());

        if matches!(options.encryption_mode, ControlEncryptionMode::Plaintext) {
            // Create the membership tag using the current group context and key schedule
            let membership_tag = MembershipTag::create(
                &plaintext,
                &self.core.context,
                &self.key_schedule.membership_key,
                &self.core.cipher_suite,
            )?;

            plaintext.membership_tag = Some(membership_tag);
        }

        let (protocol_version, cipher_suite) = match provisional_state.public_state.reinit {
            Some(reinit) => {
                // TODO: This logic needs to be verified when we complete work on reinit
                (reinit.version, reinit.cipher_suite)
            }
            None => {
                // Welcome messages will be built for each added member
                (self.core.protocol_version, self.core.cipher_suite)
            }
        };

        // Construct a GroupInfo reflecting the new state
        // Group ID, epoch, tree, and confirmed transcript hash from the new state
        let mut group_info = GroupInfo {
            cipher_suite,
            group_id: self.core.context.group_id.clone(),
            epoch: provisional_group_context.epoch,
            tree_hash: provisional_group_context.tree_hash,
            confirmed_transcript_hash: provisional_group_context.confirmed_transcript_hash,
            other_extensions: extensions,
            group_context_extensions: provisional_group_context.extensions,
            confirmation_tag, // The confirmation_tag from the MLSPlaintext object
            signer: update_path
                .as_ref()
                .map(|up| up.secrets.private_key.self_index)
                .unwrap_or_else(|| self.private_tree.self_index),
            signature: vec![],
        };

        // Sign the GroupInfo using the member's private signing key
        group_info.sign(signer, &())?;

        let welcome = self
            .make_welcome_message(
                added_leaves,
                &key_schedule_result.joiner_secret,
                &psk_secret,
                update_path.as_ref(),
                provisional_state.public_state.psks,
                &group_info,
            )?
            .map(|welcome| MLSMessage {
                version: protocol_version,
                payload: MLSMessagePayload::Welcome(welcome),
            });

        let pending_commit = CommitGeneration {
            plaintext: self.format_for_wire(plaintext, options.encryption_mode)?,
            secrets: update_path,
        };

        Ok((pending_commit, welcome))
    }

    fn make_welcome_message(
        &self,
        new_members: Vec<(KeyPackage, LeafIndex)>,
        joiner_secret: &[u8],
        psk_secret: &[u8],
        update_path: Option<&UpdatePathGeneration>,
        psks: Vec<PreSharedKeyID>,
        group_info: &GroupInfo,
    ) -> Result<Option<Welcome>, GroupError> {
        // Encrypt the GroupInfo using the key and nonce derived from the joiner_secret for
        // the new epoch
        let welcome_secret =
            WelcomeSecret::from_joiner_secret(self.core.cipher_suite, joiner_secret, psk_secret)?;

        let group_info_data = group_info.tls_serialize_detached()?;
        let encrypted_group_info = welcome_secret.encrypt(&group_info_data)?;

        let secrets = new_members
            .into_iter()
            .map(|(key_package, leaf_index)| {
                self.encrypt_group_secrets(
                    &key_package,
                    leaf_index,
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
    pub fn branch<S, P, F, G>(
        &self,
        sub_group_id: Vec<u8>,
        resumption_psk_epoch: Option<u64>,
        lifetime: Lifetime,
        psk_store: &P,
        signer: &S,
        make_config: G,
        mut get_new_key_package: F,
    ) -> Result<(Self, Option<Welcome>), GroupError>
    where
        S: Signer,
        P: PskStore,
        F: FnMut(&LeafNode) -> Option<KeyPackage>,
        G: FnOnce(&[u8]) -> C,
    {
        let current_leaf_node = self.current_user_leaf_node()?;

        let (new_self_leaf_node, leaf_node_secret) = LeafNode::generate(
            self.core.cipher_suite,
            current_leaf_node.signing_identity.clone(),
            current_leaf_node.capabilities.clone(),
            current_leaf_node.extensions.clone(),
            signer,
            lifetime,
        )?;

        let required_capabilities = self.core.context.extensions.get_extension()?;

        let leaf_node_validator = LeafNodeValidator::new(
            self.core.cipher_suite,
            required_capabilities.as_ref(),
            self.config.credential_validator(),
        );

        let key_package_validator = KeyPackageValidator::new(
            self.core.protocol_version,
            self.core.cipher_suite,
            required_capabilities.as_ref(),
            self.config.credential_validator(),
        );

        leaf_node_validator.check_if_valid(&new_self_leaf_node, ValidationContext::Add(None))?;

        let (new_members, new_key_pkgs) = {
            let current_tree = self.current_epoch_tree()?;
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

        let (mut new_pub_tree, new_priv_tree) =
            TreeKemPublic::derive(self.core.cipher_suite, new_self_leaf_node, leaf_node_secret)?;

        // Add existing members to new tree
        let added_member_indexes = new_pub_tree.add_leaves(new_members)?;
        let new_pub_tree_hash = new_pub_tree.tree_hash()?;

        let new_context = GroupContext {
            epoch: 1,
            ..GroupContext::new_group(
                sub_group_id.clone(),
                new_pub_tree_hash.clone(),
                self.core.context.extensions.clone(),
            )
        };

        let kdf = Hkdf::from(self.core.cipher_suite.kdf_type());
        let init_secret = InitSecret::random(&kdf)?;

        let psk = PreSharedKeyID {
            key_id: JustPreSharedKeyID::Resumption(ResumptionPsk {
                usage: ResumptionPSKUsage::Branch,
                psk_group_id: PskGroupId(sub_group_id.clone()),
                psk_epoch: resumption_psk_epoch.unwrap_or_else(|| self.current_epoch()),
            }),
            psk_nonce: PskNonce::random(self.core.cipher_suite)?,
        };

        let psks = vec![psk];

        let psk_secret = crate::psk::psk_secret(
            self.core.cipher_suite,
            psk_store,
            |epoch_id| {
                self.config
                    .epoch_repo()
                    .get(epoch_id)
                    .map(|ep_opt| ep_opt.map(|ep| ep.into_inner()))
            },
            &psks,
        )?;

        let key_schedule_result = KeySchedule::derive(
            self.core.cipher_suite,
            &init_secret,
            &CommitSecret::empty(self.core.cipher_suite),
            &new_context,
            LeafIndex(0),
            new_pub_tree.clone(),
            &psk_secret,
        )?;

        let public_epoch = PublicEpoch {
            identifier: new_context.epoch,
            cipher_suite: self.core.cipher_suite,
            public_tree: new_pub_tree.clone(),
        };

        let sub_config = make_config(&sub_group_id);

        let mut group_info = GroupInfo {
            cipher_suite: self.core.cipher_suite,
            group_id: sub_group_id,
            epoch: 1,
            tree_hash: new_pub_tree_hash,
            confirmed_transcript_hash: new_context.confirmed_transcript_hash.clone(),
            group_context_extensions: new_context.extensions.clone(),
            other_extensions: ExtensionList::new(),
            confirmation_tag: ConfirmationTag::create(
                &key_schedule_result.confirmation_key,
                &new_context.confirmed_transcript_hash,
                &self.core.cipher_suite,
            )?,
            signer: new_priv_tree.self_index,
            signature: Vec::new(),
        };

        group_info.sign(signer, &())?;

        sub_config
            .epoch_repo()
            .insert(public_epoch.identifier, key_schedule_result.epoch.into())
            .map_err(|e| GroupError::EpochRepositoryError(e.into()))?;

        let new_group = Group {
            config: sub_config,
            core: GroupCore::new(
                self.core.protocol_version,
                self.core.cipher_suite,
                new_context,
            ),
            private_tree: new_priv_tree,
            current_public_epoch: public_epoch,
            key_schedule: key_schedule_result.key_schedule,
            interim_transcript_hash: Vec::new().into(),
            confirmation_tag: ConfirmationTag::empty(&self.core.cipher_suite)?,
            pending_updates: Default::default(),
        };

        let welcome = self.make_welcome_message(
            new_key_pkgs.into_iter().zip(added_member_indexes).collect(),
            &key_schedule_result.joiner_secret,
            &psk_secret,
            None,
            psks,
            &group_info,
        )?;

        Ok((new_group, welcome))
    }

    pub fn join_subgroup<P, F, G>(
        &self,
        welcome: Welcome,
        public_tree: Option<TreeKemPublic>,
        key_package_generation: KeyPackageGeneration,
        psk_store: &P,
        make_config: G,
        support_version_and_cipher: F,
    ) -> Result<Self, GroupError>
    where
        P: PskStore,
        F: FnOnce(ProtocolVersion, CipherSuite) -> bool,
        G: FnOnce(&[u8]) -> C,
    {
        let subgroup = Self::join_with_welcome(
            self.core.protocol_version,
            welcome,
            public_tree,
            key_package_generation,
            psk_store,
            |epoch_id| {
                self.config
                    .epoch_repo()
                    .get(epoch_id)
                    .map(|ep_opt| ep_opt.map(|ep| ep.into_inner()))
            },
            make_config,
            support_version_and_cipher,
            self.config.credential_validator(),
        )?;

        if subgroup.core.protocol_version != self.core.protocol_version {
            Err(GroupError::SubgroupWithDifferentProtocolVersion(
                subgroup.core.protocol_version,
            ))
        } else if subgroup.core.cipher_suite != self.core.cipher_suite {
            Err(GroupError::SubgroupWithDifferentCipherSuite(
                subgroup.core.cipher_suite,
            ))
        } else {
            Ok(subgroup)
        }
    }

    fn encrypt_group_secrets(
        &self,
        key_package: &KeyPackage,
        leaf_index: LeafIndex,
        joiner_secret: &[u8],
        update_path: Option<&UpdatePathGeneration>,
        psks: Vec<PreSharedKeyID>,
    ) -> Result<EncryptedGroupSecrets, GroupError> {
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

        let encrypted_group_secrets = self.core.cipher_suite.hpke().seal(
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
        let required_capabilities = self.core.context.extensions.get_extension()?;

        // Check that this proposal has a valid lifetime, signature, and meets the requirements
        // of the current group required capabilities extension.
        let key_package_validator = KeyPackageValidator::new(
            self.core.protocol_version,
            self.core.cipher_suite,
            required_capabilities.as_ref(),
            self.config.credential_validator(),
        );

        key_package_validator.check_if_valid(&key_package, Default::default())?;

        Ok(Proposal::Add(AddProposal { key_package }))
    }

    pub fn update_proposal<S: Signer>(
        &mut self,
        signer: &S,
        extension_list: Option<ExtensionList>,
        capabilities_update: Option<Capabilities>,
    ) -> Result<Proposal, GroupError> {
        // Grab a copy of the current node and update it to have new key material
        let mut new_leaf_node = self.current_user_leaf_node()?.clone();

        let secret_key = new_leaf_node.update(
            self.core.cipher_suite,
            &self.core.context.group_id,
            capabilities_update,
            extension_list,
            signer,
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
        self.current_epoch_tree()?.get_leaf_node(leaf_index)?;

        Ok(Proposal::Remove(RemoveProposal {
            to_remove: leaf_index,
        }))
    }

    pub fn psk_proposal(&mut self, psk: ExternalPskId) -> Result<Proposal, GroupError> {
        Ok(Proposal::Psk(PreSharedKey {
            psk: PreSharedKeyID {
                key_id: JustPreSharedKeyID::External(psk),
                psk_nonce: PskNonce::random(self.core.cipher_suite)?,
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
        let authenticated_data = plaintext.content.authenticated_data;

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
            .get(self.current_epoch())
            .map_err(|e| GroupError::EpochRepositoryError(e.into()))?
            .ok_or_else(|| GroupError::EpochNotFound(self.current_epoch()))?;

        let encryption_key = epoch.inner_mut().get_encryption_key(key_type)?;

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
            group_id: self.core.context.group_id.clone(),
            epoch: self.core.context.epoch,
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
            .insert(self.current_epoch(), epoch)
            .map_err(|e| GroupError::EpochRepositoryError(e.into()))?;

        Ok(MLSCiphertext {
            group_id: self.core.context.group_id.clone(),
            epoch: self.core.context.epoch,
            content_type,
            authenticated_data,
            encrypted_sender_data,
            ciphertext,
        })
    }

    pub fn encrypt_application_message<S: Signer>(
        &mut self,
        message: &[u8],
        signer: &S,
        padding: PaddingMode,
        authenticated_data: Vec<u8>,
    ) -> Result<MLSCiphertext, GroupError> {
        // A group member that has observed one or more proposals within an epoch MUST send a Commit message
        // before sending application data
        if !self.core.proposals.is_empty() {
            return Err(GroupError::CommitRequired);
        }

        let mut plaintext = MLSPlaintext {
            content: MLSMessageContent {
                group_id: self.core.context.group_id.clone(),
                epoch: self.core.context.epoch,
                sender: Sender::Member(self.private_tree.self_index),
                authenticated_data,
                content: Content::Application(message.to_vec()),
            },
            auth: MLSMessageAuth {
                signature: MessageSignature::empty(),
                confirmation_tag: None,
            },
            membership_tag: None,
        };

        let signing_context = MessageSigningContext {
            group_context: Some(&self.core.context),
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
        let membership_key = self.key_schedule.membership_key.clone();

        let plaintext = verify_plaintext(
            message,
            &membership_key,
            &self.current_public_epoch,
            &self.core.context,
            external_key_id_to_signing_key,
        )?;

        self.validate_incoming_message(plaintext)
    }

    pub fn verify_incoming_ciphertext(
        &mut self,
        message: MLSCiphertext,
    ) -> Result<VerifiedPlaintext, GroupError> {
        let epoch_id = message.epoch;

        let mut epoch = self
            .config
            .epoch_repo()
            .get(epoch_id)
            .map_err(|e| GroupError::EpochRepositoryError(e.into()))?
            .ok_or(GroupError::EpochNotFound(epoch_id))?;

        let plaintext = decrypt_ciphertext(message, epoch.inner_mut())?;

        self.config
            .epoch_repo()
            .insert(epoch_id, epoch)
            .map_err(|e| GroupError::EpochRepositoryError(e.into()))?;

        self.validate_incoming_message(plaintext)
    }

    fn validate_incoming_message(
        &mut self,
        plaintext: VerifiedPlaintext,
    ) -> Result<VerifiedPlaintext, GroupError> {
        match &plaintext.content.sender {
            Sender::Member(sender) if *sender == self.private_tree.self_index => {
                Err(GroupError::CantProcessMessageFromSelf)
            }
            _ => Ok(()),
        }?;
        self.core.validate_incoming_message(plaintext)
    }

    pub fn process_incoming_message<S: PskStore>(
        &mut self,
        plaintext: VerifiedPlaintext,
        secret_store: &S,
    ) -> Result<ProcessedMessagePayload, GroupError> {
        match plaintext.plaintext.content.content {
            Content::Application(data) => Ok(ProcessedMessagePayload::Application(data)),
            Content::Commit(_) => {
                self.process_commit(plaintext, None, secret_store)
                    .map(ProcessedMessagePayload::Commit)
                //TODO: If the Commit included a ReInit proposal, the client MUST NOT use the group to send
                // messages anymore. Instead, it MUST wait for a Welcome message from the committer
                // and check that
            }
            Content::Proposal(ref p) => {
                let proposal_ref = ProposalRef::from_plaintext(
                    self.core.cipher_suite,
                    &plaintext,
                    plaintext.encrypted,
                )?;

                self.core.proposals.insert(
                    proposal_ref,
                    p.clone(),
                    plaintext.plaintext.content.sender,
                );

                Ok(ProcessedMessagePayload::Proposal(p.clone()))
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

        //Generate a provisional GroupContext object by applying the proposals referenced in the
        // initial Commit object, as described in Section 11.1. Update proposals are applied first,
        // followed by Remove proposals, and then finally Add proposals. Add proposals are applied
        // in the order listed in the proposals vector, and always to the leftmost unoccupied leaf
        // in the tree, or the right edge of the tree if all leaves are occupied.
        let proposal_effects = proposal_effects(
            &self.core.proposals,
            &commit_content,
            self.core.context.extensions.get_extension()?,
            self.config.credential_validator(),
            &self.current_public_epoch.public_tree,
        )?;

        let mut provisional_state = self.apply_proposals(proposal_effects)?;

        let state_update = StateUpdate::from(&provisional_state);

        //Verify that the path value is populated if the proposals vector contains any Update
        // or Remove proposals, or if it's empty. Otherwise, the path value MAY be omitted.
        if provisional_state.public_state.path_update_required
            && commit_content.commit.path.is_none()
        {
            return Err(GroupError::CommitMissingPath);
        }

        if provisional_state.self_removed() {
            return Ok(state_update);
        }

        // Apply the update path if needed
        let updated_secrets = match &commit_content.commit.path {
            None => None,
            Some(update_path) => {
                let required_capabilities = provisional_state
                    .public_state
                    .group_context
                    .extensions
                    .get_extension()?;

                let leaf_validator = LeafNodeValidator::new(
                    self.core.cipher_suite,
                    required_capabilities.as_ref(),
                    self.config.credential_validator(),
                );

                let update_path_validator = UpdatePathValidator::new(leaf_validator);

                let validated_update_path = update_path_validator
                    .validate(update_path.clone(), &self.core.context.group_id)?;

                let secrets = if let Some(pending) = local_pending {
                    // Receiving from yourself is a special case, we already have the new private keys
                    provisional_state
                        .public_state
                        .public_tree
                        .apply_self_update(&validated_update_path, self.private_tree.self_index)?;

                    Ok(pending.secrets)
                } else {
                    let sender = commit_sender(&commit_content, &provisional_state.public_state)?;

                    TreeKem::new(
                        &mut provisional_state.public_state.public_tree,
                        provisional_state.private_tree,
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
                        &self.core.context.tls_serialize_detached()?,
                    )
                }?;

                Some(secrets)
            }
        };

        let commit_secret =
            CommitSecret::from_tree_secrets(self.core.cipher_suite, updated_secrets.as_ref())?;

        let mut provisional_group_context = provisional_state.public_state.group_context;

        // Bump up the epoch in the provisional group context
        provisional_group_context.epoch = provisional_state.public_state.epoch;

        // Update the new GroupContext's confirmed and interim transcript hashes using the new Commit.
        let (interim_transcript_hash, confirmed_transcript_hash) = transcript_hashes(
            self.core.cipher_suite,
            &self.interim_transcript_hash,
            commit_content.clone(),
            (&*plaintext).into(),
        )?;

        provisional_group_context.confirmed_transcript_hash = confirmed_transcript_hash;
        provisional_group_context.tree_hash =
            provisional_state.public_state.public_tree.tree_hash()?;

        let psk_secret = crate::psk::psk_secret(
            self.core.cipher_suite,
            secret_store,
            |epoch_id| {
                self.config
                    .epoch_repo()
                    .get(epoch_id)
                    .map(|ep_opt| ep_opt.map(|ep| ep.into_inner()))
            },
            &provisional_state.public_state.psks,
        )?;

        // Use the commit_secret, the psk_secret, the provisional GroupContext, and the init secret
        // from the previous epoch (or from the external init) to compute the epoch secret and
        // derived secrets for the new epoch

        let init_secret = match provisional_state.public_state.external_init {
            Some((_, ExternalInit { kem_output })) => InitSecret::decode_for_external(
                self.core.cipher_suite,
                &kem_output,
                &self.key_schedule.external_secret,
            )?,
            None => self.key_schedule.init_secret.clone(),
        };

        let key_schedule_result = KeySchedule::derive(
            self.core.cipher_suite,
            &init_secret,
            &commit_secret,
            &provisional_group_context,
            self.private_tree.self_index, // The index never changes
            provisional_state.public_state.public_tree.clone(),
            &psk_secret,
        )?;

        // Use the confirmation_key for the new epoch to compute the confirmation tag for
        // this message, as described below, and verify that it is the same as the
        // confirmation_tag field in the MLSPlaintext object.
        let confirmation_tag = ConfirmationTag::create(
            &key_schedule_result.confirmation_key,
            &provisional_group_context.confirmed_transcript_hash,
            &self.core.cipher_suite,
        )?;

        if Some(confirmation_tag.clone()) != plaintext.auth.confirmation_tag {
            return Err(GroupError::InvalidConfirmationTag);
        }

        // If the above checks are successful, consider the updated GroupContext object
        // as the current state of the group
        if let Some(private_tree) = updated_secrets.map(|us| us.private_key) {
            self.private_tree = private_tree
        }

        self.core.context = provisional_group_context;

        self.config
            .epoch_repo()
            .insert(
                provisional_state.public_state.epoch,
                key_schedule_result.epoch.into(),
            )
            .map_err(|e| GroupError::EpochRepositoryError(e.into()))?;

        self.interim_transcript_hash = interim_transcript_hash;

        self.key_schedule = key_schedule_result.key_schedule;

        self.current_public_epoch = PublicEpoch {
            identifier: self.current_public_epoch.identifier + 1,
            cipher_suite: self.core.cipher_suite,
            public_tree: provisional_state.public_state.public_tree,
        };

        self.confirmation_tag = confirmation_tag;

        // Clear the proposals list
        self.core.proposals.clear();

        // Clear the pending updates list
        self.pending_updates = Default::default();

        Ok(state_update)
    }

    pub fn current_direct_path(&self) -> Result<Vec<Option<HpkePublicKey>>, GroupError> {
        self.current_public_epoch
            .public_tree
            .direct_path_keys(self.private_tree.self_index)
            .map_err(Into::into)
    }

    /// The returned `GroupInfo` is suitable for one external commit for the current epoch.
    pub fn external_commit_info<S: Signer>(&self, signer: &S) -> Result<GroupInfo, GroupError> {
        let mut other_extensions = ExtensionList::new();

        other_extensions.set_extension(ExternalPubExt {
            external_pub: self
                .core
                .cipher_suite
                .kem()
                .derive(&self.key_schedule.external_secret)?
                .1,
        })?;

        let mut info = GroupInfo {
            cipher_suite: self.core.cipher_suite,
            group_id: self.core.context.group_id.clone(),
            epoch: self.current_epoch(),
            tree_hash: self.core.context.tree_hash.clone(),
            confirmed_transcript_hash: self.core.context.confirmed_transcript_hash.clone(),
            group_context_extensions: self.core.context.extensions.clone(),
            other_extensions,
            confirmation_tag: self.confirmation_tag.clone(),
            signer: self.private_tree.self_index,
            signature: Vec::new(),
        };

        info.sign(signer, &())?;

        Ok(info)
    }

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
            .export_secret(label, context, len, self.core.cipher_suite)?)
    }

    pub fn export(&self) -> GroupState {
        GroupState {
            protocol_version: self.core.protocol_version,
            cipher_suite: self.core.cipher_suite,
            context: self.core.context.clone(),
            private_tree: self.private_tree.clone(),
            current_public_epoch: self.current_public_epoch.clone(),
            key_schedule: self.key_schedule.clone(),
            interim_transcript_hash: self.interim_transcript_hash.clone(),
            confirmation_tag: self.confirmation_tag.clone(),
            proposals: self.core.proposals.clone(),
            pending_updates: self.pending_updates.clone(),
        }
    }

    pub fn import(config: C, state: GroupState) -> Result<Self, GroupError> {
        Ok(Self {
            config,
            core: GroupCore {
                protocol_version: state.protocol_version,
                cipher_suite: state.cipher_suite,
                proposals: state.proposals,
                context: state.context,
            },
            private_tree: state.private_tree,
            current_public_epoch: state.current_public_epoch,
            key_schedule: state.key_schedule,
            interim_transcript_hash: state.interim_transcript_hash,
            confirmation_tag: state.confirmation_tag,
            pending_updates: state.pending_updates,
        })
    }

    pub fn protocol_version(&self) -> ProtocolVersion {
        self.core.protocol_version
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

fn validate_tree<C: CredentialValidator>(
    public_tree: &TreeKemPublic,
    group_info: &GroupInfo,
    credential_validator: C,
) -> Result<(), GroupError> {
    let sender_key_package = public_tree.get_leaf_node(group_info.signer)?;
    group_info.verify(
        &sender_key_package
            .signing_identity
            .public_key(public_tree.cipher_suite)?,
        &(),
    )?;

    let required_capabilities = group_info.group_context_extensions.get_extension()?;

    // Verify the integrity of the ratchet tree
    let tree_validator = TreeValidator::new(
        group_info.cipher_suite,
        &group_info.group_id,
        &group_info.tree_hash,
        required_capabilities.as_ref(),
        credential_validator,
    );

    tree_validator.validate(public_tree)?;

    Ok(())
}

fn commit_sender(
    commit_content: &MLSMessageCommitContent<'_>,
    provisional_state: &ProvisionalPublicState,
) -> Result<LeafIndex, GroupError> {
    match commit_content.sender {
        Sender::Member(index) => Ok(*index),
        Sender::Preconfigured(_) => Err(GroupError::PreconfiguredSenderCannotCommit),
        Sender::NewMember => provisional_state
            .external_init
            .as_ref()
            .map(|(index, _)| *index)
            .ok_or(GroupError::MissingUpdatePathInExternalCommit),
    }
}

fn proposal_effects<C>(
    proposals: &ProposalCache,
    commit_content: &MLSMessageCommitContent<'_>,
    required_capabilities: Option<RequiredCapabilitiesExt>,
    credential_validator: C,
    public_tree: &TreeKemPublic,
) -> Result<ProposalSetEffects, ProposalCacheError>
where
    C: CredentialValidator,
{
    proposals.resolve_for_commit(
        commit_content.sender.clone(),
        commit_content.commit.proposals.clone(),
        commit_content.commit.path.as_ref(),
        required_capabilities,
        credential_validator,
        public_tree,
    )
}

fn transcript_hashes(
    cipher_suite: CipherSuite,
    prev_interim_transcript_hash: &InterimTranscriptHash,
    commit_content: MLSMessageCommitContent<'_>,
    commit_auth: MLSPlaintextCommitAuthData<'_>,
) -> Result<(InterimTranscriptHash, ConfirmedTranscriptHash), GroupError> {
    let confirmed_transcript_hash = ConfirmedTranscriptHash::create(
        cipher_suite,
        prev_interim_transcript_hash,
        commit_content,
    )?;

    let interim_transcript_hash =
        InterimTranscriptHash::create(cipher_suite, &confirmed_transcript_hash, commit_auth)?;

    Ok((interim_transcript_hash, confirmed_transcript_hash))
}

#[cfg(test)]
pub(crate) mod test_utils {
    use ferriscrypt::asym::ec_key::SecretKey;

    use super::*;
    use crate::{
        client_config::{InMemoryPskStore, PassthroughCredentialValidator},
        extension::RequiredCapabilitiesExt,
        key_package::KeyPackageGenerator,
        signing_identity::test_utils::get_test_signing_identity,
        signing_identity::SigningIdentity,
    };

    pub const TEST_GROUP: &[u8] = b"group";

    pub(crate) struct TestGroup {
        pub group: Group<InMemoryGroupConfig>,
        pub signing_identity: SigningIdentity,
        pub signing_key: SecretKey,
        pub secret_store: InMemoryPskStore,
    }

    impl TestGroup {
        pub(crate) fn commit_options(&self) -> CommitOptions {
            CommitOptions {
                prefer_path_update: true,
                extension_update: None,
                capabilities_update: None,
                encryption_mode: ControlEncryptionMode::Plaintext,
                ratchet_tree_extension: true,
            }
        }

        pub(crate) fn join(&mut self, name: &str) -> (TestGroup, OutboundMessage) {
            self.join_with_options(name, self.commit_options())
        }

        pub(crate) fn join_with_options(
            &mut self,
            name: &str,
            commit_options: CommitOptions,
        ) -> (TestGroup, OutboundMessage) {
            let (new_key_package, new_key) = test_member(
                self.group.core.protocol_version,
                self.group.core.cipher_suite,
                name.as_bytes(),
            );

            // Add new member to the group
            let add_proposal = self
                .group
                .add_proposal(new_key_package.key_package.clone())
                .unwrap();

            let secret_store = InMemoryPskStore::default();
            let tree_ext = commit_options.ratchet_tree_extension;

            let (commit_generation, welcome) = self
                .group
                .commit_proposals(
                    vec![add_proposal],
                    commit_options,
                    &secret_store,
                    &self.signing_key,
                    Vec::new(),
                )
                .unwrap();

            let commit = commit_generation.plaintext.clone();

            // Apply the commit to the original group
            self.group
                .process_pending_commit(commit_generation, &secret_store)
                .unwrap();

            let tree = (!tree_ext).then(|| self.group.current_epoch_tree().unwrap().clone());

            let welcome = match welcome.unwrap().payload {
                MLSMessagePayload::Welcome(w) => w,
                _ => panic!("Expected Welcome message"),
            };

            // Group from new member's perspective
            let new_group = Group::from_welcome_message(
                self.group.protocol_version(),
                welcome,
                tree,
                new_key_package.clone(),
                &secret_store,
                |_| InMemoryGroupConfig::default(),
                |_, _| true,
                PassthroughCredentialValidator::new(),
            )
            .unwrap();

            let new_test_group = TestGroup {
                group: new_group,
                signing_identity: new_key_package.key_package.leaf_node.signing_identity,
                signing_key: new_key,
                secret_store,
            };

            (new_test_group, commit)
        }

        pub(crate) fn commit(
            &mut self,
            proposals: Vec<Proposal>,
        ) -> Result<(CommitGeneration, Option<MLSMessage>), GroupError> {
            self.group.commit_proposals(
                proposals,
                self.commit_options(),
                &self.secret_store,
                &self.signing_key,
                Vec::new(),
            )
        }

        pub(crate) fn process_pending_commit(
            &mut self,
            commit: CommitGeneration,
        ) -> Result<StateUpdate, GroupError> {
            self.group
                .process_pending_commit(commit, &self.secret_store)
        }

        pub(crate) fn process_message(
            &mut self,
            plaintext: MLSPlaintext,
        ) -> Result<ProcessedMessagePayload, GroupError> {
            self.group.process_incoming_message(
                VerifiedPlaintext {
                    encrypted: false,
                    plaintext,
                },
                &self.secret_store,
            )
        }

        pub(crate) fn make_plaintext(&mut self, content: Content) -> MLSPlaintext {
            let plaintext = self
                .group
                .construct_mls_plaintext(
                    Sender::Member(self.group.private_tree.self_index),
                    content,
                    &self.signing_key,
                    ControlEncryptionMode::Plaintext,
                    Vec::new(),
                )
                .unwrap();

            let membership_tag = Some(
                MembershipTag::create(
                    &plaintext,
                    &self.group.core.context,
                    &self.group.key_schedule.membership_key,
                    &self.group.core.cipher_suite,
                )
                .unwrap(),
            );

            MLSPlaintext {
                membership_tag,
                ..plaintext
            }
        }

        pub(crate) fn required_capabilities(&self) -> Option<RequiredCapabilitiesExt> {
            self.group.context().extensions.get_extension().unwrap()
        }
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
        capabilities: Capabilities,
        leaf_extensions: ExtensionList,
    ) -> TestGroup {
        let (signing_identity, signing_key) =
            get_test_signing_identity(cipher_suite, b"alice".to_vec());

        let (leaf_node, leaf_secret_key) = LeafNode::generate(
            cipher_suite,
            signing_identity.clone(),
            capabilities,
            leaf_extensions,
            &signing_key,
            lifetime(),
        )
        .unwrap();

        let group = Group::new(
            InMemoryGroupConfig::default(),
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
            signing_identity,
            signing_key,
            secret_store: InMemoryPskStore::default(),
        }
    }

    pub(crate) fn test_group(
        protocol_version: ProtocolVersion,
        cipher_suite: CipherSuite,
    ) -> TestGroup {
        test_group_custom(
            protocol_version,
            cipher_suite,
            Capabilities::default(),
            ExtensionList::default(),
        )
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        client_config::InMemoryPskStore,
        extension::{test_utils::TestExtension, RequiredCapabilitiesExt},
        group::test_utils::lifetime,
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

    use crate::client_config::PassthroughCredentialValidator;
    #[cfg(target_arch = "wasm32")]
    use wasm_bindgen_test::wasm_bindgen_test as test;

    #[test]
    fn test_create_group() {
        for (protocol_version, cipher_suite) in
            ProtocolVersion::all().flat_map(|p| CipherSuite::all().map(move |cs| (p, cs)))
        {
            let test_group = test_group(protocol_version, cipher_suite);
            let group = test_group.group;

            assert_eq!(group.core.cipher_suite, cipher_suite);
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
                group.current_public_epoch.public_tree.get_leaf_nodes()[0]
                    .signing_identity
                    .public_key(cipher_suite)
                    .unwrap(),
                test_group.signing_key.to_public().unwrap()
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

        test_group
            .group
            .create_proposal(
                proposal,
                &test_group.signing_key,
                ControlEncryptionMode::Plaintext,
                vec![],
            )
            .unwrap();

        // We should not be able to send application messages until a commit happens
        let res = test_group.group.encrypt_application_message(
            b"test",
            &test_group.signing_key,
            PaddingMode::None,
            vec![],
        );

        assert_matches!(res, Err(GroupError::CommitRequired));

        // We should be able to send application messages after a commit
        let (commit, _) = test_group
            .group
            .commit_proposals(
                vec![],
                test_group.commit_options(),
                &test_group.secret_store,
                &test_group.signing_key,
                vec![],
            )
            .unwrap();

        test_group
            .group
            .process_pending_commit(commit, &test_group.secret_store)
            .unwrap();

        assert!(test_group
            .group
            .encrypt_application_message(
                b"test",
                &test_group.signing_key,
                PaddingMode::None,
                vec![]
            )
            .is_ok());
    }

    #[test]
    fn test_update_proposals() {
        let protocol_version = ProtocolVersion::Mls10;
        let cipher_suite = CipherSuite::Curve25519Aes128;

        let mut test_group = test_group(protocol_version, cipher_suite);

        let existing_leaf = test_group.group.current_user_leaf_node().unwrap().clone();

        let mut new_capabilities = Capabilities::default();
        new_capabilities.proposals.push(42.into());

        let new_extension = TestExtension { foo: 10 };
        let mut extension_list = ExtensionList::default();
        extension_list.set_extension(new_extension).unwrap();

        // Create an update proposal
        let proposal = test_group
            .group
            .update_proposal(
                &test_group.signing_key,
                Some(extension_list.clone()),
                Some(new_capabilities.clone()),
            )
            .unwrap();

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
        let proposal = test_group
            .group
            .update_proposal(&test_group.signing_key, None, None)
            .unwrap();

        // There should be an error because path_update is set to `true` while there is a pending
        // update proposal for the commiter
        let res = test_group.group.commit_proposals(
            vec![proposal],
            test_group.commit_options(),
            &test_group.secret_store,
            &test_group.signing_key,
            vec![],
        );

        assert_matches!(res, Err(GroupError::InvalidCommitSelfUpdate));
    }

    #[test]
    fn test_invalid_commit_self_update_cached() {
        let protocol_version = ProtocolVersion::Mls10;
        let cipher_suite = CipherSuite::Curve25519Aes128;

        let mut test_group = test_group(protocol_version, cipher_suite);

        // Create an update proposal
        let proposal = test_group
            .group
            .update_proposal(&test_group.signing_key, None, None)
            .unwrap();

        test_group
            .group
            .create_proposal(
                proposal,
                &test_group.signing_key,
                ControlEncryptionMode::Plaintext,
                vec![],
            )
            .unwrap();

        // There should be an error because path_update is set to `true` while there is a pending
        // update proposal for the commiter
        let res = test_group.group.commit_proposals(
            vec![],
            test_group.commit_options(),
            &test_group.secret_store,
            &test_group.signing_key,
            vec![],
        );

        assert_matches!(res, Err(GroupError::InvalidCommitSelfUpdate));
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
    fn add_proposal_with_bad_key_package_is_ignored_when_committing() {
        let protocol_version = ProtocolVersion::Mls10;
        let cipher_suite = CipherSuite::Curve25519Aes128;

        let mut test_group = test_group(protocol_version, cipher_suite);
        let (bob_keys, _) = test_member(protocol_version, cipher_suite, b"bob");

        let mut proposal = test_group.group.add_proposal(bob_keys.key_package).unwrap();

        if let Proposal::Add(ref mut kp) = proposal {
            kp.key_package.signature = SecureRng::gen(32).unwrap()
        }

        let (commit, _) = test_group
            .group
            .commit_proposals(
                vec![proposal],
                test_group.commit_options(),
                &test_group.secret_store,
                &test_group.signing_key,
                vec![],
            )
            .unwrap();

        assert_matches!(
            commit,
            CommitGeneration {
                plaintext: OutboundMessage::Plaintext(MLSPlaintext {
                    content: MLSMessageContent {
                        content: Content::Commit(Commit { proposals, .. }),
                        ..
                    },
                    ..
                }),
                ..
            } if proposals.is_empty()
        );
    }

    #[test]
    fn update_proposal_with_bad_key_package_is_ignored_when_committing() {
        let protocol_version = ProtocolVersion::Mls10;
        let cipher_suite = CipherSuite::Curve25519Aes128;

        let (mut alice_group, mut bob_group) =
            test_two_member_group(protocol_version, cipher_suite, true);

        let mut proposal = alice_group
            .group
            .update_proposal(&alice_group.signing_key, None, None)
            .unwrap();

        if let Proposal::Update(ref mut update) = proposal {
            update.leaf_node.signature = SecureRng::gen(32).unwrap();
        } else {
            panic!("Invalid update proposal")
        }

        let proposal_plaintext = alice_group
            .group
            .create_proposal(
                proposal.clone(),
                &alice_group.signing_key,
                ControlEncryptionMode::Plaintext,
                vec![],
            )
            .unwrap();

        let proposal_ref =
            ProposalRef::from_plaintext(cipher_suite, &proposal_plaintext, false).unwrap();

        // Hack bob's receipt of the proposal
        bob_group.group.core.proposals.insert(
            proposal_ref,
            proposal,
            proposal_plaintext.content.sender.clone(),
        );

        let (commit, _) = bob_group
            .group
            .commit_proposals(
                vec![],
                bob_group.commit_options(),
                &bob_group.secret_store,
                &bob_group.signing_key,
                vec![],
            )
            .unwrap();

        assert_matches!(
            commit,
            CommitGeneration {
                plaintext: OutboundMessage::Plaintext(MLSPlaintext {
                    content: MLSMessageContent {
                        content: Content::Commit(Commit { proposals, .. }),
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
        let mut test_group = test_group(protocol_version, cipher_suite);

        let (bob_test_group, _) = test_group.join_with_options(
            "bob",
            CommitOptions {
                ratchet_tree_extension: tree_ext,
                ..test_group.commit_options()
            },
        );

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
        let mut test_group = test_group(protocol_version, cipher_suite);
        let (bob_key_package, _) = test_member(protocol_version, cipher_suite, b"bob");

        // Add bob to the group
        let add_bob_proposal = test_group
            .group
            .add_proposal(bob_key_package.key_package.clone())
            .unwrap();

        let mut commit_options = test_group.commit_options();
        commit_options.ratchet_tree_extension = false;

        let (_, welcome) = test_group
            .group
            .commit_proposals(
                vec![add_bob_proposal],
                commit_options,
                &test_group.secret_store,
                &test_group.signing_key,
                vec![],
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
            &InMemoryPskStore::default(),
            |_| InMemoryGroupConfig::default(),
            |_, _| true,
            PassthroughCredentialValidator::new(),
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
    ) -> (TestGroup, Result<CommitGeneration, GroupError>) {
        let protocol_version = ProtocolVersion::Mls10;
        let cipher_suite = CipherSuite::P256Aes128;

        let mut capabilities = Capabilities::default();
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
                test_group.commit_options(),
                &test_group.secret_store,
                &test_group.signing_key,
                vec![],
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
                credentials: vec![],
            })
            .unwrap();

        let (mut test_group, commit) =
            group_context_extension_proposal_test(extension_list.clone());

        let state_update = test_group
            .group
            .process_pending_commit(commit.unwrap(), &test_group.secret_store)
            .unwrap();

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

        assert_matches!(commit, Err(GroupError::UnsupportedRequiredCapabilities));
    }

    #[test]
    fn test_group_encrypt_plaintext_padding() {
        let protocol_version = ProtocolVersion::Mls10;
        let cipher_suite = CipherSuite::P256Aes128;
        let mut test_group = test_group(protocol_version, cipher_suite);

        let without_padding = test_group
            .group
            .encrypt_application_message(
                &SecureRng::gen(150).unwrap(),
                &test_group.signing_key,
                PaddingMode::None,
                vec![],
            )
            .unwrap();

        let with_padding = test_group
            .group
            .encrypt_application_message(
                &SecureRng::gen(150).unwrap(),
                &test_group.signing_key,
                PaddingMode::StepFunction,
                vec![],
            )
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
            .external_commit_info(&group.signing_key)
            .unwrap();
        info.other_extensions = ExtensionList::new();
        info.sign(&group.signing_key, &()).unwrap();

        let (leaf_node, leaf_secret) = LeafNode::generate(
            cipher_suite,
            group.signing_identity,
            Capabilities::default(),
            ExtensionList::default(),
            &group.signing_key,
            lifetime(),
        )
        .unwrap();

        let res = Group::new_external(
            InMemoryGroupConfig::default(),
            protocol_version,
            info,
            None,
            leaf_node,
            leaf_secret,
            |_, _| true,
            &group.signing_key,
            vec![],
        );

        assert_matches!(res, Err(GroupError::MissingExternalPubExtension));
    }

    #[test]
    fn test_path_update_preference() {
        let protocol_version = ProtocolVersion::Mls10;
        let cipher_suite = CipherSuite::P256Aes128;
        let mut test_group = test_group(protocol_version, cipher_suite);

        let mut commit_options = test_group.commit_options();
        commit_options.prefer_path_update = false;

        let add = Proposal::Add(AddProposal {
            key_package: test_key_package(protocol_version, cipher_suite),
        });

        let (pending_commit, _) = test_group
            .group
            .commit_proposals(
                vec![add.clone()],
                commit_options.clone(),
                &test_group.secret_store,
                &test_group.signing_key,
                vec![],
            )
            .unwrap();

        assert!(pending_commit.secrets.is_none());

        commit_options.prefer_path_update = true;

        let (pending_commit, _) = test_group
            .group
            .commit_proposals(
                vec![add],
                commit_options,
                &test_group.secret_store,
                &test_group.signing_key,
                vec![],
            )
            .unwrap();

        assert!(pending_commit.secrets.is_some());
    }

    #[test]
    fn test_path_update_preference_override() {
        let protocol_version = ProtocolVersion::Mls10;
        let cipher_suite = CipherSuite::P256Aes128;
        let mut test_group = test_group(protocol_version, cipher_suite);

        let mut commit_options = test_group.commit_options();
        commit_options.prefer_path_update = false;

        let (pending_commit, _) = test_group
            .group
            .commit_proposals(
                vec![],
                commit_options,
                &test_group.secret_store,
                &test_group.signing_key,
                vec![],
            )
            .unwrap();

        assert!(pending_commit.secrets.is_some());
    }

    #[test]
    fn group_rejects_unencrypted_application_message() {
        let protocol_version = ProtocolVersion::Mls10;
        let cipher_suite = CipherSuite::P256Aes128;
        let mut alice = test_group(protocol_version, cipher_suite);
        let (mut bob, _) = alice.join("bob");
        let plaintext = alice.make_plaintext(Content::Application(b"hello".to_vec()));
        assert_matches!(
            bob.group.verify_incoming_plaintext(plaintext, |_| None),
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
            if let OutboundMessage::Plaintext(ptxt) = commit {
                bob.process_message(ptxt).unwrap();
            }
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
                .secret_store
                .insert(ExternalPskId(vec![i]), Psk(vec![i]));

            bob.secret_store
                .insert(ExternalPskId(vec![i]), Psk(vec![i]));

            proposals.push(alice.group.psk_proposal(ExternalPskId(vec![i])).unwrap());
        }

        let update_proposal = bob
            .group
            .update_proposal(&bob.signing_key, None, None)
            .unwrap();

        let update_message = bob
            .group
            .create_proposal(
                update_proposal,
                &bob.signing_key,
                ControlEncryptionMode::Plaintext,
                vec![],
            )
            .unwrap();

        if let OutboundMessage::Plaintext(ptxt) = update_message {
            alice.process_message(ptxt).unwrap();
        }

        let (commit, _) = alice.commit(proposals).unwrap();

        // Check that applying pending commit and processing commit yields correct update.
        let mut state_update_alice = alice.process_pending_commit(commit.clone()).unwrap();
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

        assert_matches!(commit.plaintext, OutboundMessage::Plaintext(_));

        if let OutboundMessage::Plaintext(ptxt) = commit.plaintext {
            let payload = bob.process_message(ptxt).unwrap();
            assert_matches!(payload, ProcessedMessagePayload::Commit(_));

            if let ProcessedMessagePayload::Commit(mut state_update_bob) = payload {
                canonicalize_state_update(&mut state_update_bob);
                assert_eq!(state_update_alice.added, state_update_bob.added);
                assert_eq!(state_update_alice.removed, state_update_bob.removed);
                assert_eq!(state_update_alice.updated, state_update_bob.updated);
                assert_eq!(state_update_alice.psks, state_update_bob.psks);
            }
        }
    }

    #[test]
    fn test_commit_from_preconfigured_is_rejected() {
        let (mut alice_group, mut bob_group) =
            test_two_member_group(ProtocolVersion::Mls10, CipherSuite::Curve25519Aes128, true);

        let (commit, _) = alice_group.commit(vec![]).unwrap();

        if let OutboundMessage::Plaintext(mut ptxt) = commit.plaintext {
            ptxt.content.sender = Sender::Preconfigured(vec![0u8]);

            assert_matches!(
                bob_group.process_message(ptxt),
                Err(GroupError::PreconfiguredSenderCannotCommit)
            );
        }
    }
}
