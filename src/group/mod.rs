use std::collections::HashMap;
use std::ops::Deref;
use std::option::Option::Some;

use ferriscrypt::asym::ec_key::{EcKeyError, PublicKey, SecretKey};
use ferriscrypt::cipher::aead::AeadError;
use ferriscrypt::hmac::Tag;
use ferriscrypt::hpke::kem::{HpkePublicKey, HpkeSecretKey};
use ferriscrypt::hpke::HpkeError;
use ferriscrypt::kdf::hkdf::Hkdf;
use ferriscrypt::kdf::KdfError;
use ferriscrypt::rand::{SecureRng, SecureRngError};
use ferriscrypt::{Signer, Verifier};
use thiserror::Error;
use tls_codec::{Deserialize, Serialize};
use tls_codec_derive::{TlsDeserialize, TlsSerialize, TlsSize};

use crate::cipher_suite::{CipherSuite, HpkeCiphertext, ProtocolVersion};
use crate::credential::CredentialError;
use crate::extension::{Extension, ExtensionError, ExtensionList, RatchetTreeExt};
use crate::key_package::{
    KeyPackage, KeyPackageError, KeyPackageGeneration, KeyPackageGenerationError,
    KeyPackageGenerator, KeyPackageRef, KeyPackageValidationError, KeyPackageValidationOptions,
    KeyPackageValidator,
};
use crate::tree_kem::leaf_secret::LeafSecretError;
use crate::tree_kem::node::LeafIndex;
use crate::tree_kem::{
    RatchetTreeError, TreeKemPrivate, TreeKemPublic, UpdatePath, UpdatePathGeneration,
    UpdatePathValidationError, UpdatePathValidator,
};

use confirmation_tag::*;
use epoch::*;
use framing::*;
use key_schedule::*;
use membership_tag::*;
use message_signature::*;
use message_verifier::*;
use proposal::*;
use secret_tree::*;
use transcript_hash::*;

use self::epoch_repo::{EpochRepository, EpochRepositoryError};

mod confirmation_tag;
mod epoch;
mod epoch_repo;
pub mod framing;
pub mod key_schedule;
mod membership_tag;
pub mod message_signature;
mod message_verifier;
pub mod proposal;
mod secret_tree;
mod transcript_hash;

struct ProvisionalState {
    public_tree: TreeKemPublic,
    private_tree: TreeKemPrivate,
    added_leaves: Vec<KeyPackageRef>,
    removed_leaves: HashMap<KeyPackageRef, KeyPackage>,
    epoch: u64,
    path_update_required: bool,
}

#[derive(Clone, Debug)]
pub struct StateUpdate {
    pub added: Vec<KeyPackageRef>,
    pub removed: Vec<KeyPackage>,
    pub active: bool,
    pub epoch: u64,
}

impl From<&ProvisionalState> for StateUpdate {
    fn from(provisional: &ProvisionalState) -> Self {
        let self_removed = provisional.self_removed();

        let removed: Vec<KeyPackage> = provisional
            .removed_leaves
            .iter()
            .map(|(_, kp)| kp.clone())
            .collect();

        StateUpdate {
            added: provisional.added_leaves.clone(),
            removed,
            active: !self_removed,
            epoch: provisional.epoch,
        }
    }
}

impl ProvisionalState {
    fn self_removed(&self) -> bool {
        self.removed_leaves
            .contains_key(&self.private_tree.key_package_ref)
    }
}

#[derive(Clone, Debug, PartialEq, TlsDeserialize, TlsSerialize, TlsSize)]
pub struct Commit {
    #[tls_codec(with = "crate::tls::DefVec::<u32>")]
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
    EcKeyError(#[from] EcKeyError),
    #[error(transparent)]
    MessageSignatureError(#[from] MessageSignatureError),
    #[error(transparent)]
    TlsCodecError(#[from] tls_codec::Error),
    #[error(transparent)]
    TranscriptHashError(#[from] TranscriptHashError),
    #[error(transparent)]
    KeyPackageError(#[from] KeyPackageError),
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
    LeafSecretError(#[from] LeafSecretError),
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
    #[error("Cipher suite does not match")]
    CipherSuiteMismatch,
    #[error("Invalid key package signature")]
    InvalidKeyPackage,
    #[error("Proposal not found: {0}")]
    MissingProposal(String),
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
    #[error("Only members can commit")]
    OnlyMembersCanCommit,
    #[error("Only members can update")]
    OnlyMembersCanUpdate,
}

#[derive(Clone, Debug, PartialEq, TlsDeserialize, TlsSerialize, TlsSize)]
pub(crate) struct GroupContext {
    #[tls_codec(with = "crate::tls::ByteVec::<u32>")]
    pub group_id: Vec<u8>,
    pub epoch: u64,
    #[tls_codec(with = "crate::tls::ByteVec::<u32>")]
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

impl From<&GroupInfo> for GroupContext {
    fn from(group_info: &GroupInfo) -> Self {
        GroupContext {
            group_id: group_info.group_id.clone(),
            epoch: group_info.epoch,
            tree_hash: group_info.tree_hash.clone(),
            confirmed_transcript_hash: group_info.confirmed_transcript_hash.clone(),
            extensions: group_info.group_context_extensions.clone(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, TlsDeserialize, TlsSerialize, TlsSize)]
struct GroupInfo {
    #[tls_codec(with = "crate::tls::ByteVec::<u32>")]
    pub group_id: Vec<u8>,
    pub epoch: u64,
    #[tls_codec(with = "crate::tls::ByteVec::<u32>")]
    pub tree_hash: Vec<u8>,
    pub confirmed_transcript_hash: ConfirmedTranscriptHash,
    pub group_context_extensions: ExtensionList,
    pub other_extensions: ExtensionList,
    pub confirmation_tag: ConfirmationTag,
    pub signer: KeyPackageRef,
    #[tls_codec(with = "crate::tls::ByteVec::<u32>")]
    pub signature: Vec<u8>,
}

impl GroupInfo {
    fn to_signable_vec(&self) -> Result<Vec<u8>, GroupError> {
        #[derive(TlsSerialize, TlsSize)]
        struct SignableGroupInfo<'a> {
            #[tls_codec(with = "crate::tls::ByteVec::<u32>")]
            pub group_id: &'a Vec<u8>,
            pub epoch: u64,
            #[tls_codec(with = "crate::tls::ByteVec::<u32>")]
            pub tree_hash: &'a Vec<u8>,
            #[tls_codec(with = "crate::tls::ByteVec::<u32>")]
            pub confirmed_transcript_hash: &'a Vec<u8>,
            #[tls_codec(with = "crate::tls::DefVec::<u32>")]
            pub group_context_extensions: &'a Vec<Extension>,
            #[tls_codec(with = "crate::tls::DefVec::<u32>")]
            pub other_extensions: &'a Vec<Extension>,
            #[tls_codec(with = "crate::tls::ByteVec::<u32>")]
            pub confirmation_tag: &'a Tag,
            pub signer: &'a KeyPackageRef,
        }

        SignableGroupInfo {
            group_id: &self.group_id,
            epoch: self.epoch,
            tree_hash: &self.tree_hash,
            confirmed_transcript_hash: &self.confirmed_transcript_hash,
            group_context_extensions: &self.group_context_extensions,
            other_extensions: &self.other_extensions,
            confirmation_tag: &self.confirmation_tag,
            signer: &self.signer,
        }
        .tls_serialize_detached()
        .map_err(Into::into)
    }
}

#[derive(Clone, Debug, TlsDeserialize, TlsSerialize, TlsSize)]
pub struct CommitGeneration {
    pub plaintext: OutboundPlaintext,
    pub secrets: Option<UpdatePathGeneration>,
}

#[derive(Clone, Debug, PartialEq, TlsDeserialize, TlsSerialize, TlsSize)]
pub struct PathSecret {
    #[tls_codec(with = "crate::tls::ByteVec::<u32>")]
    pub path_secret: Vec<u8>,
}

impl From<Vec<u8>> for PathSecret {
    fn from(path_secret: Vec<u8>) -> Self {
        Self { path_secret }
    }
}

#[derive(Clone, Debug, PartialEq, TlsDeserialize, TlsSerialize, TlsSize)]
pub struct GroupSecrets {
    #[tls_codec(with = "crate::tls::ByteVec::<u32>")]
    pub joiner_secret: Vec<u8>,
    pub path_secret: Option<PathSecret>,
    //TODO: PSK not currently supported
}

#[derive(Clone, Debug, PartialEq, TlsDeserialize, TlsSerialize, TlsSize)]
pub struct EncryptedGroupSecrets {
    pub new_member: KeyPackageRef,
    pub encrypted_group_secrets: HpkeCiphertext,
}

#[derive(Clone, Debug, PartialEq, TlsDeserialize, TlsSerialize, TlsSize)]
pub struct Welcome {
    pub protocol_version: ProtocolVersion,
    pub cipher_suite: CipherSuite,
    #[tls_codec(with = "crate::tls::DefVec::<u32>")]
    pub secrets: Vec<EncryptedGroupSecrets>,
    #[tls_codec(with = "crate::tls::ByteVec::<u32>")]
    pub encrypted_group_info: Vec<u8>,
}

#[derive(Clone, Debug, TlsDeserialize, TlsSerialize, TlsSize)]
pub struct Group {
    pub cipher_suite: CipherSuite,
    context: GroupContext,
    private_tree: TreeKemPrivate,
    epoch_repo: EpochRepository,
    interim_transcript_hash: InterimTranscriptHash,
    #[tls_codec(with = "crate::tls::DefMap")]
    pub proposals: HashMap<ProposalRef, PendingProposal>, // Hash of MLS Plaintext to pending proposal
    #[tls_codec(with = "crate::tls::Map::<crate::tls::DefaultSer, crate::tls::ByteVec>")]
    pub pending_updates: HashMap<KeyPackageRef, HpkeSecretKey>, // Hash of key package to key generation
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
    wire_format: WireFormat,
    plaintext: MLSPlaintext,
}

impl Deref for VerifiedPlaintext {
    type Target = MLSPlaintext;

    fn deref(&self) -> &Self::Target {
        &self.plaintext
    }
}

#[derive(Debug, Clone, PartialEq, TlsSerialize, TlsDeserialize, TlsSize)]
pub struct OutboundPlaintext {
    /// The original plaintext
    plaintext: MLSPlaintext,
    /// Plaintext or ciphertext to send over the wire
    message: MLSMessage,
}

impl OutboundPlaintext {
    pub fn message(&self) -> &MLSMessage {
        &self.message
    }
}

impl Deref for OutboundPlaintext {
    type Target = MLSPlaintext;

    fn deref(&self) -> &Self::Target {
        &self.plaintext
    }
}

impl From<OutboundPlaintext> for MLSPlaintext {
    fn from(outbound: OutboundPlaintext) -> Self {
        outbound.plaintext
    }
}

impl From<OutboundPlaintext> for VerifiedPlaintext {
    fn from(outbound: OutboundPlaintext) -> Self {
        VerifiedPlaintext {
            wire_format: outbound.message.wire_format(),
            plaintext: outbound.plaintext,
        }
    }
}

#[derive(Clone, Debug)]
pub enum ProcessedMessage {
    Application(Vec<u8>),
    Commit(StateUpdate),
    Proposal(Proposal),
}

impl Group {
    pub fn new(
        group_id: Vec<u8>,
        key_package_generator: KeyPackageGenerator,
        group_context_extensions: ExtensionList,
    ) -> Result<Self, GroupError> {
        let required_capabilities = group_context_extensions.get_extension()?;
        let creator_key_package = key_package_generator.generate(required_capabilities.as_ref())?;

        let cipher_suite = creator_key_package.key_package.cipher_suite;
        let kdf = Hkdf::from(cipher_suite.kdf_type());

        let (public_tree, private_tree) = TreeKemPublic::derive(creator_key_package)?;

        let init_secret = SecureRng::gen(kdf.extract_size())?;
        let tree_hash = public_tree.tree_hash()?;

        let context = GroupContext::new_group(group_id, tree_hash, group_context_extensions);

        let (epoch, _) = Epoch::derive(
            cipher_suite,
            &init_secret,
            &CommitSecret::empty(cipher_suite),
            public_tree,
            &context,
            LeafIndex(0),
        )?;

        // TODO: Make the repository bounds configurable somehow
        let epoch_repo = EpochRepository::new(epoch, 3);

        Ok(Self {
            cipher_suite,
            private_tree,
            context,
            epoch_repo,
            interim_transcript_hash: InterimTranscriptHash::from(vec![]),
            proposals: Default::default(),
            pending_updates: Default::default(),
        })
    }

    pub fn from_welcome_message(
        welcome: Welcome,
        public_tree: Option<TreeKemPublic>,
        key_package: KeyPackageGeneration,
    ) -> Result<Self, GroupError> {
        //Identify an entry in the secrets array where the key_package_hash value corresponds to
        // one of this client's KeyPackages, using the hash indicated by the cipher_suite field.
        // If no such field exists, or if the ciphersuite indicated in the KeyPackage does not
        // match the one in the Welcome message, return an error.
        let package_ref = key_package.key_package.to_reference()?;

        let encrypted_group_secrets = welcome
            .secrets
            .iter()
            .find(|s| s.new_member == package_ref)
            .ok_or(GroupError::WelcomeKeyPackageNotFound)?;

        //Decrypt the encrypted_group_secrets using HPKE with the algorithms indicated by the
        // cipher suite and the HPKE private key corresponding to the GroupSecrets. If a
        // PreSharedKeyID is part of the GroupSecrets and the client is not in possession of
        // the corresponding PSK, return an error
        //TODO: PSK Support
        let decrypted_group_secrets = welcome.cipher_suite.hpke().open_base(
            &encrypted_group_secrets
                .encrypted_group_secrets
                .clone()
                .into(),
            &key_package.secret_key,
            &[],
            None,
        )?;

        let group_secrets = GroupSecrets::tls_deserialize(&mut &*decrypted_group_secrets)?;

        //From the joiner_secret in the decrypted GroupSecrets object and the PSKs specified in
        // the GroupSecrets, derive the welcome_secret and using that the welcome_key and
        // welcome_nonce.
        let welcome_secret =
            WelcomeSecret::from_joiner_secret(welcome.cipher_suite, &group_secrets.joiner_secret)?;

        //Use the key and nonce to decrypt the encrypted_group_info field.
        let decrypted_group_info = welcome_secret.decrypt(&welcome.encrypted_group_info)?;
        let group_info = GroupInfo::tls_deserialize(&mut &*decrypted_group_info)?;

        //Verify the signature on the GroupInfo object. The signature input comprises all of the
        // fields in the GroupInfo object except the signature field. The public key and algorithm
        // are taken from the credential in the leaf node at position signer_index.
        // If this verification fails, return an error.
        let public_tree = match public_tree {
            Some(tree) => Ok(tree),
            None => {
                let tree_extension = group_info
                    .other_extensions
                    .get_extension::<RatchetTreeExt>()?
                    .ok_or(GroupError::RatchetTreeNotFound)?;
                TreeKemPublic::import_node_data(welcome.cipher_suite, tree_extension.tree_data)
            }
        }?;

        let sender_key_package = public_tree.get_key_package(&group_info.signer)?;

        if !sender_key_package
            .credential
            .verify(&group_info.signature, &group_info.to_signable_vec()?)?
        {
            return Err(GroupError::InvalidSignature);
        }

        let extensions = group_info.group_context_extensions.get_extension()?;

        let key_package_validator = KeyPackageValidator {
            cipher_suite: welcome.cipher_suite,
            required_capabilities: extensions.as_ref(),
            options: Default::default(),
        };

        // Verify the integrity of the ratchet tree
        public_tree.validate(&group_info.tree_hash, &key_package_validator)?;

        // Identify a leaf in the tree array (any even-numbered node) whose key_package field is
        // identical to the the KeyPackage. If no such field exists, return an error. Let index
        // represent the index of this node among the leaves in the tree, namely the index of the
        // node in the tree array divided by two.

        let key_package_ref = key_package.key_package.to_reference()?;

        let self_index = public_tree.package_leaf_index(&key_package_ref)?;

        // Construct a new group state using the information in the GroupInfo object. The new
        // member's position in the tree is index, as defined above. In particular, the confirmed
        // transcript hash for the new state is the prior_confirmed_transcript_hash in the GroupInfo
        // object.
        let context = GroupContext::from(&group_info);

        let mut private_tree =
            TreeKemPrivate::new_self_leaf(self_index, key_package_ref, key_package.secret_key);

        // If the path_secret value is set in the GroupSecrets object
        if let Some(path_secret) = group_secrets.path_secret {
            private_tree.update_secrets(
                welcome.cipher_suite,
                public_tree.package_leaf_index(&group_info.signer)?,
                path_secret.path_secret,
                &public_tree,
            )?;
        }

        // Use the joiner_secret from the GroupSecrets object to generate the epoch secret and
        // other derived secrets for the current epoch.
        let epoch = Epoch::new_joiner(
            welcome.cipher_suite,
            &group_secrets.joiner_secret,
            public_tree,
            &context,
            self_index,
        )?;

        // Verify the confirmation tag in the GroupInfo using the derived confirmation key and the
        // confirmed_transcript_hash from the GroupInfo.
        if !group_info
            .confirmation_tag
            .matches(&epoch, &group_info.confirmed_transcript_hash)?
        {
            return Err(GroupError::InvalidConfirmationTag);
        }

        // Use the confirmed transcript hash and confirmation tag to compute the interim transcript
        // hash in the new state.
        let interim_transcript_hash = InterimTranscriptHash::create(
            welcome.cipher_suite,
            &group_info.confirmed_transcript_hash,
            MLSPlaintextCommitAuthData::from(&group_info.confirmation_tag),
        )?;

        // TODO: Make the repository bounds configurable somehow
        let epoch_repo = EpochRepository::new(epoch, 3);

        Ok(Group {
            cipher_suite: welcome.cipher_suite,
            context,
            private_tree,
            epoch_repo,
            interim_transcript_hash,
            proposals: Default::default(),
            pending_updates: Default::default(),
        })
    }

    #[inline(always)]
    pub fn current_epoch_tree(&self) -> Result<&TreeKemPublic, GroupError> {
        Ok(&self.epoch_repo.current()?.public_tree)
    }

    pub fn current_epoch(&self) -> u64 {
        self.context.epoch
    }

    pub fn current_user_index(&self) -> u32 {
        self.private_tree.self_index.0 as u32
    }

    fn fetch_proposals<'a>(
        &'a self,
        proposals: &'a [ProposalOrRef],
        sender: &KeyPackageRef,
    ) -> Result<Vec<PendingProposal>, GroupError> {
        proposals
            .iter()
            .map(|p| match p {
                ProposalOrRef::Proposal(p) => Ok(PendingProposal {
                    proposal: p.clone(),
                    sender: Sender::Member(sender.clone()),
                }),
                ProposalOrRef::Reference(r) => self
                    .proposals
                    .get(r)
                    .cloned()
                    .ok_or_else(|| GroupError::MissingProposal(hex::encode(r.deref()))),
            })
            .collect::<Result<Vec<PendingProposal>, GroupError>>()
    }

    fn apply_proposals(
        &self,
        sender: &KeyPackageRef,
        proposals: &[ProposalOrRef],
    ) -> Result<ProvisionalState, GroupError> {
        let proposals = self.fetch_proposals(proposals, sender)?;

        let mut provisional_tree = self.current_epoch_tree()?.clone();
        let mut provisional_private_tree = self.private_tree.clone();

        // TODO: When we implement group context proposal this will need to take potential new
        // requirements from that proposal
        let required_capabilities = self.context.extensions.get_extension()?;

        let key_package_validator = KeyPackageValidator {
            cipher_suite: self.cipher_suite,
            required_capabilities: required_capabilities.as_ref(),
            options: Default::default(),
        };
        //TODO: This has to loop through the proposal array 3 times, maybe this should be optimized

        // Apply updates
        let updates = proposals
            .iter()
            .filter_map(|p| {
                p.proposal.as_update().map(|u| match &p.sender {
                    Sender::Member(sender) => Ok((sender.clone(), u)),
                    Sender::Preconfigured(_) | Sender::NewMember => {
                        Err(GroupError::OnlyMembersCanUpdate)
                    }
                })
            })
            .collect::<Result<Vec<_>, _>>()?;

        for (update_sender, update) in updates {
            let validated = key_package_validator.validate(update.key_package.clone())?;

            // Update the leaf in the provisional tree
            provisional_tree.update_leaf(&update_sender, validated)?;

            let key_package_ref = update.key_package.to_reference()?;

            // Update the leaf in the private tree if this is our update
            if let Some(new_leaf_sk) = self.pending_updates.get(&key_package_ref).cloned() {
                provisional_private_tree.update_leaf(
                    provisional_tree.leaf_count(),
                    key_package_ref,
                    new_leaf_sk,
                )?;
            }
        }

        // Apply removes
        let removes: Vec<KeyPackageRef> = proposals
            .iter()
            .filter_map(|p| p.proposal.as_remove().map(|r| r.to_remove.clone()))
            .collect();

        // If there is only one user in the tree, they can't be removed
        if !removes.is_empty() && provisional_tree.leaf_count() == 1 {
            return Err(GroupError::RemoveNotAllowed);
        }

        let old_tree = self.current_epoch_tree()?;

        // Remove elements from the private tree
        removes.iter().try_for_each(|key_package_ref| {
            let leaf = old_tree.package_leaf_index(key_package_ref)?;
            provisional_private_tree.remove_leaf(provisional_tree.leaf_count(), leaf)?;

            Ok::<_, GroupError>(())
        })?;

        // Remove elements from the public tree
        let removed_leaves = provisional_tree
            .remove_leaves(old_tree, removes)?
            .drain(..)
            .collect::<HashMap<_, _>>();

        // Apply adds
        let adds = proposals
            .iter()
            .filter_map(|p| {
                p.proposal
                    .as_add()
                    .map(|a| key_package_validator.validate(a.key_package.clone()))
            })
            .collect::<Result<_, _>>()?;

        let added_leaves = provisional_tree.add_leaves(adds)?;

        // Determine if a path update is required
        let has_update_or_remove = proposals
            .iter()
            .any(|p| p.proposal.is_update() || p.proposal.is_remove());

        let path_update_required = proposals.is_empty() || has_update_or_remove;

        Ok(ProvisionalState {
            public_tree: provisional_tree,
            private_tree: provisional_private_tree,
            added_leaves,
            removed_leaves,
            epoch: self.context.epoch + 1,
            path_update_required,
        })
    }

    pub fn create_proposal(
        &mut self,
        proposal: Proposal,
        signer: &SecretKey,
        wire_format: WireFormat,
    ) -> Result<OutboundPlaintext, GroupError> {
        let plaintext =
            self.construct_mls_plaintext(Content::Proposal(proposal.clone()), signer, wire_format)?;
        let membership_tag = match wire_format {
            // If we are going to encrypt then the tag will be dropped so it shouldn't be included
            // in the hash
            WireFormat::Cipher => None,
            WireFormat::Plain => Some(MembershipTag::create(
                &plaintext,
                &self.context,
                self.epoch_repo.current()?,
            )?),
        };
        let plaintext = MLSPlaintext {
            membership_tag,
            ..plaintext
        };
        let reference = proposal.to_reference(self.cipher_suite)?;

        // Add the proposal ref to the current set
        let pending_proposal = PendingProposal {
            proposal,
            sender: Sender::Member(self.private_tree.key_package_ref.clone()),
        };

        self.proposals.insert(reference, pending_proposal);
        self.format_for_wire(plaintext, wire_format)
    }

    fn construct_mls_plaintext(
        &self,
        content: Content,
        signer: &SecretKey,
        wire_format: WireFormat,
    ) -> Result<MLSPlaintext, GroupError> {
        //Construct an MLSPlaintext object containing the content
        let mut plaintext = MLSPlaintext {
            group_id: self.context.group_id.clone(),
            epoch: self.context.epoch,
            sender: Sender::Member(self.private_tree.key_package_ref.clone()),
            authenticated_data: vec![],
            content,
            signature: MessageSignature::empty(),
            confirmation_tag: None,
            membership_tag: None,
        };

        // Sign the MLSPlaintext using the current epoch's GroupContext as context.
        plaintext.sign(signer, Some(&self.context), wire_format)?;

        Ok(plaintext)
    }

    pub fn commit_proposals(
        &mut self,
        proposals: &[Proposal],
        key_package_generator: &KeyPackageGenerator,
        update_path: bool,
        wire_format: WireFormat,
        ratchet_tree_extension: bool,
    ) -> Result<(CommitGeneration, Option<Welcome>), GroupError> {
        // Construct an initial Commit object with the proposals field populated from Proposals
        // received during the current epoch, and an empty path field. Add passed in proposals
        // by value
        let proposals = [
            self.proposals
                .keys()
                .map(|v| ProposalOrRef::from(v.clone()))
                .collect::<Vec<ProposalOrRef>>(),
            proposals
                .iter()
                .map(|p| ProposalOrRef::from(p.clone()))
                .collect::<Vec<ProposalOrRef>>(),
        ]
        .concat();

        // Generate a provisional GroupContext object by applying the proposals referenced in the
        // initial Commit object, as described in Section 11.1. Update proposals are applied first,
        // followed by Remove proposals, and then finally Add proposals.
        // Add proposals are applied in the order listed in the proposals vector,
        // and always to the leftmost unoccupied leaf in the tree, or the right edge of
        // the tree if all leaves are occupied

        let mut provisional_state =
            self.apply_proposals(&self.private_tree.key_package_ref, &proposals)?;

        let mut provisional_group_context = self.context.clone();
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

            let new_key_package = key_package_generator
                .generate(self.context.extensions.get_extension()?.as_ref())?;

            let update_path = provisional_state.public_tree.encap(
                &self.private_tree,
                new_key_package,
                &context_bytes,
                &provisional_state.added_leaves,
                |package| key_package_generator.sign(package),
            )?;

            Some(update_path)
        } else {
            None
        };

        // Update the tree hash in the provisional group context
        provisional_group_context.tree_hash = provisional_state.public_tree.tree_hash()?;

        let commit_secret =
            CommitSecret::from_update_path(self.cipher_suite, update_path.as_ref())?;

        //TODO: If one or more PreSharedKey proposals are part of the commit, derive the psk_secret
        // as specified in Section 8.2, where the order of PSKs in the derivation corresponds to the
        // order of PreSharedKey proposals in the proposals vector. Otherwise, set psk_secret to a
        // zero-length octet string
        let commit = Commit {
            proposals,
            path: update_path.clone().map(|up| up.update_path),
        };

        //Construct an MLSPlaintext object containing the Commit object
        let mut plaintext = self.construct_mls_plaintext(
            Content::Commit(commit),
            key_package_generator.signing_key,
            wire_format,
        )?;

        // Use the signature, the commit_secret and the psk_secret to advance the key schedule and
        // compute the confirmation_tag value in the MLSPlaintext.
        let confirmed_transcript_hash = ConfirmedTranscriptHash::create(
            self.cipher_suite,
            &self.interim_transcript_hash,
            MLSPlaintextCommitContent::new(&plaintext, wire_format)?,
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
        )?;

        let confirmation_tag = ConfirmationTag::create(
            &next_epoch,
            &provisional_group_context.confirmed_transcript_hash,
        )?;

        plaintext.confirmation_tag = Some(confirmation_tag.clone());

        if wire_format == WireFormat::Plain {
            // Create the membership tag using the current group context and key schedule
            let membership_tag = MembershipTag::create(&plaintext, &self.context, current_epoch)?;
            plaintext.membership_tag = Some(membership_tag);
        }

        // Construct a GroupInfo reflecting the new state
        // Group ID, epoch, tree, and confirmed transcript hash from the new state
        let mut group_info = GroupInfo {
            group_id: self.context.group_id.clone(),
            epoch: provisional_group_context.epoch,
            tree_hash: provisional_group_context.tree_hash,
            confirmed_transcript_hash: provisional_group_context.confirmed_transcript_hash,
            other_extensions: extensions,
            group_context_extensions: provisional_group_context.extensions,
            confirmation_tag, // The confirmation_tag from the MLSPlaintext object
            signer: update_path
                .as_ref()
                .map(|up| up.secrets.private_key.key_package_ref.clone())
                .unwrap_or_else(|| self.private_tree.key_package_ref.clone()),
            signature: vec![],
        };

        // Sign the GroupInfo using the member's private signing key
        group_info.signature = key_package_generator
            .signing_key
            .sign(&group_info.to_signable_vec()?)?;

        // Encrypt the GroupInfo using the key and nonce derived from the joiner_secret for
        // the new epoch
        let welcome_secret = WelcomeSecret::from_joiner_secret(self.cipher_suite, &joiner_secret)?;

        let group_info_data = group_info.tls_serialize_detached()?;
        let encrypted_group_info = welcome_secret.encrypt(&group_info_data)?;

        // Build welcome messages for each added member
        let secrets = provisional_state
            .added_leaves
            .into_iter()
            .map(|i| {
                self.encrypt_group_secrets(
                    &next_epoch.public_tree,
                    i,
                    &joiner_secret,
                    update_path.as_ref(),
                )
            })
            .collect::<Result<Vec<EncryptedGroupSecrets>, GroupError>>()?;

        let welcome = match secrets.len() {
            0 => None,
            _ => Some(Welcome {
                protocol_version: self.cipher_suite.protocol_version(),
                cipher_suite: self.cipher_suite,
                secrets,
                encrypted_group_info,
            }),
        };
        let pending_commit = CommitGeneration {
            plaintext: self.format_for_wire(plaintext, wire_format)?,
            secrets: update_path,
        };

        Ok((pending_commit, welcome))
    }

    fn encrypt_group_secrets(
        &self,
        provisional_tree: &TreeKemPublic,
        new_member: KeyPackageRef,
        joiner_secret: &[u8],
        update_path: Option<&UpdatePathGeneration>,
    ) -> Result<EncryptedGroupSecrets, GroupError> {
        let leaf_index = provisional_tree.package_leaf_index(&new_member)?;

        let path_secret = update_path
            .and_then(|up| up.get_common_path_secret(leaf_index))
            .map(PathSecret::from);

        // Ensure that we have a path secret if one is required
        if path_secret.is_none() && update_path.is_some() {
            return Err(GroupError::InvalidTreeKemPrivateKey);
        }

        let group_secrets = GroupSecrets {
            joiner_secret: joiner_secret.to_vec(),
            path_secret,
        };

        let group_secrets_bytes = group_secrets.tls_serialize_detached()?;
        let key_package = provisional_tree.get_key_package(&new_member)?;

        let encrypted_group_secrets = self.cipher_suite.hpke().seal_base(
            &key_package.hpke_init_key,
            &[],
            None,
            &group_secrets_bytes,
        )?;

        Ok(EncryptedGroupSecrets {
            new_member,
            encrypted_group_secrets: encrypted_group_secrets.into(),
        })
    }

    pub fn add_member_proposal(&self, key_package: KeyPackage) -> Result<Proposal, GroupError> {
        Ok(Proposal::from(AddProposal { key_package }))
    }

    pub fn update_proposal(
        &mut self,
        key_package_generator: &KeyPackageGenerator,
    ) -> Result<Proposal, GroupError> {
        // Update the public key in the key package
        let key_package_generation =
            key_package_generator.generate(self.context.extensions.get_extension()?.as_ref())?;

        // Store the secret key in the pending updates storage for later
        self.pending_updates.insert(
            key_package_generation.key_package.to_reference()?,
            key_package_generation.secret_key,
        );

        Ok(Proposal::Update(UpdateProposal {
            key_package: key_package_generation.key_package.into(),
        }))
    }

    pub fn remove_proposal(
        &mut self,
        key_package_ref: &KeyPackageRef,
    ) -> Result<Proposal, GroupError> {
        self.current_epoch_tree()?
            .package_leaf_index(key_package_ref)?;

        Ok(Proposal::Remove(RemoveProposal {
            to_remove: key_package_ref.clone(),
        }))
    }

    pub fn format_for_wire(
        &mut self,
        plaintext: MLSPlaintext,
        wire_format: WireFormat,
    ) -> Result<OutboundPlaintext, GroupError> {
        let message = match wire_format {
            WireFormat::Plain => MLSMessage::Plain(plaintext.clone()),
            WireFormat::Cipher => MLSMessage::Cipher(self.encrypt_plaintext(plaintext.clone())?),
        };
        Ok(OutboundPlaintext { plaintext, message })
    }

    fn encrypt_plaintext(&mut self, plaintext: MLSPlaintext) -> Result<MLSCiphertext, GroupError> {
        let content_type = ContentType::from(&plaintext.content);

        // Build a ciphertext content using the plaintext content and signature
        let ciphertext_content = MLSCiphertextContent {
            content: plaintext.content,
            signature: plaintext.signature,
            confirmation_tag: plaintext.confirmation_tag,
            padding: vec![], //TODO: Implement a padding mechanism
        };

        // Build ciphertext aad using the plaintext message
        let aad = MLSCiphertextContentAAD {
            group_id: plaintext.group_id,
            epoch: plaintext.epoch,
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
            sender: match plaintext.sender {
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

    pub fn encrypt_application_message(
        &mut self,
        message: &[u8],
        signer: &SecretKey,
    ) -> Result<MLSCiphertext, GroupError> {
        // A group member that has observed one or more proposals within an epoch MUST send a Commit message
        // before sending application data
        if !self.proposals.is_empty() {
            return Err(GroupError::CommitRequired);
        }

        let mut plaintext = MLSPlaintext {
            group_id: self.context.group_id.clone(),
            epoch: self.context.epoch,
            sender: Sender::Member(self.private_tree.key_package_ref.clone()),
            authenticated_data: vec![],
            content: Content::Application(message.to_vec()),
            signature: MessageSignature::empty(),
            confirmation_tag: None,
            membership_tag: None,
        };

        plaintext.sign(signer, Some(&self.context), WireFormat::Cipher)?;

        self.encrypt_plaintext(plaintext)
    }

    pub fn process_incoming_message<F>(
        &mut self,
        message: MLSMessage,
        external_key_id_to_signing_key: F,
    ) -> Result<ProcessedMessage, GroupError>
    where
        F: FnMut(&[u8]) -> Option<PublicKey>,
    {
        let mut verifier = MessageVerifier {
            msg_epoch: self.epoch_repo.get_mut(message.epoch())?,
            context: &self.context,
            private_tree: &self.private_tree,
            external_key_id_to_signing_key,
        };
        let plaintext = verifier.verify(message)?;
        match &plaintext.sender {
            Sender::Member(sender) if *sender == self.private_tree.key_package_ref => {
                Err(GroupError::CantProcessMessageFromSelf)
            }
            _ => Ok(()),
        }?;
        match plaintext.plaintext.content {
            Content::Application(data) => Ok(ProcessedMessage::Application(data)),
            Content::Commit(_) => {
                if plaintext.epoch == self.context.epoch {
                    self.process_commit(plaintext, None)
                        .map(ProcessedMessage::Commit)
                } else {
                    Err(GroupError::InvalidPlaintextEpoch)
                }
                //TODO: If the Commit included a ReInit proposal, the client MUST NOT use the group to send
                // messages anymore. Instead, it MUST wait for a Welcome message from the committer
                // and check that
            }
            Content::Proposal(p) => {
                if plaintext.plaintext.epoch == self.context.epoch {
                    let pending_proposal = PendingProposal {
                        proposal: p.clone(),
                        sender: plaintext.plaintext.sender,
                    };
                    self.proposals
                        .insert(p.to_reference(self.cipher_suite)?, pending_proposal);
                    Ok(ProcessedMessage::Proposal(p))
                } else {
                    Err(GroupError::InvalidPlaintextEpoch)
                }
            }
        }
    }

    pub fn process_pending_commit(
        &mut self,
        commit: CommitGeneration,
    ) -> Result<StateUpdate, GroupError> {
        self.process_commit(commit.plaintext.into(), commit.secrets)
    }

    // This function takes a provisional copy of the tree and returns an updated tree and epoch key schedule
    fn process_commit(
        &mut self,
        plaintext: VerifiedPlaintext,
        local_pending: Option<UpdatePathGeneration>,
    ) -> Result<StateUpdate, GroupError> {
        //TODO: PSK Verify that all PSKs specified in any PreSharedKey proposals in the proposals
        // vector are available.

        let commit_content =
            MLSPlaintextCommitContent::new(plaintext.deref(), plaintext.wire_format)?;
        let sender = match &plaintext.sender {
            Sender::Member(sender) => Ok(sender),
            Sender::Preconfigured(_) | Sender::NewMember => Err(GroupError::OnlyMembersCanCommit),
        }?;

        //Generate a provisional GroupContext object by applying the proposals referenced in the
        // initial Commit object, as described in Section 11.1. Update proposals are applied first,
        // followed by Remove proposals, and then finally Add proposals. Add proposals are applied
        // in the order listed in the proposals vector, and always to the leftmost unoccupied leaf
        // in the tree, or the right edge of the tree if all leaves are occupied.

        let mut provisional_state =
            self.apply_proposals(sender, &commit_content.commit.proposals)?;

        let state_update = StateUpdate::from(&provisional_state);

        //Verify that the path value is populated if the proposals vector contains any Update
        // or Remove proposals, or if it's empty. Otherwise, the path value MAY be omitted.
        if provisional_state.path_update_required && commit_content.commit.path.is_none() {
            return Err(GroupError::CommitMissingPath);
        }

        if provisional_state.self_removed() {
            return Ok(state_update);
        }

        let updated_secrets = match &commit_content.commit.path {
            None => None,
            Some(update_path) => {
                let required_capabilities = self.context.extensions.get_extension()?;

                let options = if local_pending.is_some() {
                    [KeyPackageValidationOptions::SkipSignatureCheck].into()
                } else {
                    Default::default()
                };

                let key_package_validator = KeyPackageValidator {
                    cipher_suite: self.cipher_suite,
                    required_capabilities: required_capabilities.as_ref(),
                    options,
                };

                let update_path_validator = UpdatePathValidator::new(key_package_validator);
                let validated_update_path = update_path_validator.validate(update_path.clone())?;

                let secrets = if let Some(pending) = local_pending {
                    // Receiving from yourself is a special case, we already have the new private keys
                    provisional_state
                        .public_tree
                        .apply_self_update(&validated_update_path, sender)?;
                    Ok(pending.secrets)
                } else {
                    provisional_state.public_tree.decap(
                        provisional_state.private_tree,
                        sender,
                        &validated_update_path,
                        &provisional_state.added_leaves,
                        &self.context.tls_serialize_detached()?,
                    )
                }?;

                Some(secrets)
            }
        };

        let commit_secret =
            CommitSecret::from_tree_secrets(self.cipher_suite, updated_secrets.as_ref())?;

        let mut provisional_group_context = self.context.clone();
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

        // TODO: If the proposals vector contains any PreSharedKey proposals, derive the psk_secret
        // as specified in Section 8.2, where the order of PSKs in the derivation corresponds to the
        // order of PreSharedKey proposals in the proposals vector. Otherwise, set psk_secret to 0

        // Use the commit_secret, the psk_secret, the provisional GroupContext, and the init secret
        // from the previous epoch to compute the epoch secret and derived secrets for the new epoch

        let (next_epoch, _) = Epoch::evolved_from(
            self.epoch_repo.current()?,
            &commit_secret,
            provisional_state.public_tree,
            &provisional_group_context,
        )?;

        // Use the confirmation_key for the new epoch to compute the confirmation tag for
        // this message, as described below, and verify that it is the same as the
        // confirmation_tag field in the MLSPlaintext object.
        let confirmation_tag = ConfirmationTag::create(
            &next_epoch,
            &provisional_group_context.confirmed_transcript_hash,
        )?;

        if Some(confirmation_tag) != plaintext.confirmation_tag {
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
        self.proposals = Default::default();
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
}

#[cfg(test)]
pub(crate) mod test_utils {
    use super::*;
    use crate::{
        credential::{BasicCredential, Credential, CredentialConvertible},
        extension::{CapabilitiesExt, LifetimeExt, MlsExtension, RequiredCapabilitiesExt},
        key_package::KeyPackageGenerator,
    };
    use std::time::SystemTime;

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

    pub(crate) fn extensions() -> ExtensionList {
        let lifetime_ext = LifetimeExt::years(1, SystemTime::now()).unwrap();

        let capabilities_ext = CapabilitiesExt::default();

        let mut extensions = ExtensionList::new();
        extensions.set_extension(lifetime_ext).unwrap();
        extensions.set_extension(capabilities_ext).unwrap();

        extensions
    }

    pub(crate) fn group_extensions() -> ExtensionList {
        let required_capabilities = RequiredCapabilitiesExt {
            extensions: vec![RatchetTreeExt::IDENTIFIER],
            proposals: vec![],
        };

        let mut extensions = ExtensionList::new();
        extensions.set_extension(required_capabilities).unwrap();
        extensions
    }

    pub(crate) fn test_member(
        cipher_suite: CipherSuite,
        identifier: &[u8],
    ) -> (KeyPackageGeneration, SecretKey) {
        let signing_key = cipher_suite.generate_secret_key().unwrap();

        let key_package_generator = KeyPackageGenerator {
            cipher_suite,
            credential: &credential(&signing_key, identifier),
            extensions: &extensions(),
            signing_key: &signing_key,
        };

        let key_package = key_package_generator.generate(None).unwrap();
        (key_package, signing_key)
    }

    pub(crate) fn test_group(cipher_suite: CipherSuite) -> (Group, SecretKey) {
        let signing_key = cipher_suite.generate_secret_key().unwrap();

        let key_package_generator = KeyPackageGenerator {
            cipher_suite,
            credential: &credential(&signing_key, b"alice"),
            extensions: &extensions(),
            signing_key: &signing_key,
        };

        let group = Group::new(
            b"test group".to_vec(),
            key_package_generator,
            group_extensions(),
        )
        .unwrap();

        (group, signing_key)
    }
}

#[cfg(test)]
mod test {
    use super::{
        test_utils::{credential, extensions, group_extensions, test_group, test_member},
        *,
    };

    #[test]
    fn test_create_group() {
        for cipher_suite in CipherSuite::all() {
            let (group, secret_key) = test_group(cipher_suite);
            assert_eq!(group.cipher_suite, cipher_suite);
            assert_eq!(group.context.epoch, 0);
            assert_eq!(group.context.group_id, b"test group".to_vec());
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
                    .get_key_packages()[0]
                    .credential
                    .public_key()
                    .unwrap(),
                secret_key.to_public().unwrap()
            );
        }
    }

    #[test]
    fn test_pending_proposals_application_data() {
        let cipher_suite = CipherSuite::Curve25519Aes128V1;

        let (mut test_group, signing_key) = test_group(cipher_suite);

        // Create a proposal
        let (bob_key_package, _) = test_member(cipher_suite, b"bob");

        let proposal = test_group
            .add_member_proposal(bob_key_package.key_package.into())
            .unwrap();

        test_group
            .create_proposal(proposal, &signing_key, WireFormat::Plain)
            .unwrap();

        // We should not be able to send application messages until a commit happens
        let res = test_group.encrypt_application_message(b"test", &signing_key);
        assert!(matches!(res, Err(GroupError::CommitRequired)));

        let generator = KeyPackageGenerator {
            cipher_suite,
            credential: &credential(&signing_key, b"alice"),
            extensions: &extensions(),
            signing_key: &signing_key,
        };

        // We should be able to send application messages after a commit
        let (commit, _) = test_group
            .commit_proposals(&[], &generator, true, WireFormat::Plain, false)
            .unwrap();

        test_group.process_pending_commit(commit).unwrap();

        assert!(test_group
            .encrypt_application_message(b"test", &signing_key)
            .is_ok());
    }

    #[test]
    fn test_invalid_commit_self_update() {
        let cipher_suite = CipherSuite::Curve25519Aes128V1;

        let (mut test_group, signing_key) = test_group(cipher_suite);

        let generator = KeyPackageGenerator {
            cipher_suite,
            credential: &credential(&signing_key, b"alice"),
            extensions: &extensions(),
            signing_key: &signing_key,
        };

        // Create an update proposal
        let proposal = test_group.update_proposal(&generator).unwrap();

        // There should be an error because path_update is set to `true` while there is a pending
        // update proposal for the commiter
        let res =
            test_group.commit_proposals(&[proposal], &generator, true, WireFormat::Plain, false);

        assert!(matches!(res, Err(GroupError::InvalidCommitSelfUpdate)));
    }

    #[test]
    fn test_invalid_commit_self_update_cached() {
        let cipher_suite = CipherSuite::Curve25519Aes128V1;

        let (mut test_group, signing_key) = test_group(cipher_suite);

        let generator = KeyPackageGenerator {
            cipher_suite,
            credential: &credential(&signing_key, b"alice"),
            extensions: &extensions(),
            signing_key: &signing_key,
        };

        // Create an update proposal
        let proposal = test_group.update_proposal(&generator).unwrap();

        test_group
            .create_proposal(proposal, &signing_key, WireFormat::Plain)
            .unwrap();

        // There should be an error because path_update is set to `true` while there is a pending
        // update proposal for the commiter
        let res = test_group.commit_proposals(&[], &generator, true, WireFormat::Plain, false);

        assert!(matches!(res, Err(GroupError::InvalidCommitSelfUpdate)));
    }

    #[test]
    fn test_invalid_add_bad_key_package() {
        let cipher_suite = CipherSuite::Curve25519Aes128V1;

        let (mut test_group, signing_key) = test_group(cipher_suite);
        let (mut bob_keys, _) = test_member(cipher_suite, b"bob");
        bob_keys.key_package.signature = SecureRng::gen(32).unwrap();

        let proposal = test_group
            .add_member_proposal(bob_keys.key_package.into())
            .unwrap();

        let generator = KeyPackageGenerator {
            cipher_suite,
            credential: &credential(&signing_key, b"alice"),
            extensions: &extensions(),
            signing_key: &signing_key,
        };

        let res =
            test_group.commit_proposals(&[proposal], &generator, false, WireFormat::Plain, false);

        assert!(matches!(res, Err(GroupError::KeyPackageValidationError(_))));
    }

    #[test]
    fn test_invalid_update_bad_key_package() {
        let cipher_suite = CipherSuite::Curve25519Aes128V1;

        let (mut test_group, signing_key) = test_group(cipher_suite);
        let (mut bob_keys, _) = test_member(cipher_suite, b"bob");
        bob_keys.key_package.signature = SecureRng::gen(32).unwrap();

        let generator = KeyPackageGenerator {
            cipher_suite,
            credential: &credential(&signing_key, b"alice"),
            extensions: &extensions(),
            signing_key: &signing_key,
        };

        let mut proposal = test_group.update_proposal(&generator).unwrap();

        if let Proposal::Update(ref mut update) = proposal {
            update.key_package.extensions = ExtensionList::new()
        } else {
            panic!("Invalid update proposal")
        }

        let res =
            test_group.commit_proposals(&[proposal], &generator, false, WireFormat::Plain, false);

        assert!(matches!(res, Err(GroupError::KeyPackageValidationError(_))));
    }

    fn test_welcome_processing(tree_ext: bool) {
        let cipher_suite = CipherSuite::P256Aes128V1;
        let (mut test_group, signing_key) = test_group(cipher_suite);

        let generator = KeyPackageGenerator {
            cipher_suite,
            credential: &credential(&signing_key, b"alice"),
            extensions: &extensions(),
            signing_key: &signing_key,
        };

        let (bob_key_package, _) = test_member(cipher_suite, b"bob");

        // Add bob to the group
        let add_bob_proposal = test_group
            .add_member_proposal(bob_key_package.key_package.clone().into())
            .unwrap();

        let (commit_generation, welcome) = test_group
            .commit_proposals(
                &[add_bob_proposal],
                &generator,
                false,
                WireFormat::Plain,
                tree_ext,
            )
            .unwrap();

        // Apply the commit to the original group
        test_group
            .process_pending_commit(commit_generation)
            .unwrap();

        let tree = if tree_ext {
            None
        } else {
            Some(test_group.current_epoch_tree().unwrap().clone())
        };

        // Group from Bob's perspective
        let bob_group =
            Group::from_welcome_message(welcome.unwrap(), tree, bob_key_package).unwrap();

        assert_eq!(test_group, bob_group);
    }

    #[test]
    fn test_welcome_processing_exported_tree() {
        test_welcome_processing(false)
    }

    #[test]
    fn test_welcome_processing_tree_extension() {
        test_welcome_processing(true)
    }

    #[test]
    fn test_welcome_processing_missing_tree() {
        let cipher_suite = CipherSuite::P256Aes128V1;
        let (mut test_group, signing_key) = test_group(cipher_suite);
        let (bob_key_package, _) = test_member(cipher_suite, b"bob");

        let generator = KeyPackageGenerator {
            cipher_suite,
            credential: &credential(&signing_key, b"alice"),
            extensions: &extensions(),
            signing_key: &signing_key,
        };

        // Add bob to the group
        let add_bob_proposal = test_group
            .add_member_proposal(bob_key_package.key_package.clone().into())
            .unwrap();

        let (_, welcome) = test_group
            .commit_proposals(
                &[add_bob_proposal],
                &generator,
                false,
                WireFormat::Plain,
                false,
            )
            .unwrap();

        // Group from Bob's perspective
        let bob_group = Group::from_welcome_message(welcome.unwrap(), None, bob_key_package);

        assert!(matches!(bob_group, Err(GroupError::RatchetTreeNotFound)));
    }
}
//TODO: More Group unit tests
