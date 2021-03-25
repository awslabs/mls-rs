use crate::ratchet_tree::{RatchetTree, RatchetTreeError, UpdatePath, TreeKemPrivate, UpdatePathGeneration};
use crate::epoch::{EpochKeySchedule, CommitSecret, EpochKeyScheduleError, WelcomeSecret};
use crate::key_package::{KeyPackage, KeyPackageGeneration, KeyPackageGenerator};
use thiserror::Error;
use crate::ciphersuite::{CipherSuiteError};
use serde::{Serialize, Deserialize};
use num_enum::{IntoPrimitive, TryFromPrimitive};

use cfg_if::cfg_if;
use std::collections::HashMap;
use rand_core::{CryptoRng, RngCore};
use crate::extension::Extension;
use crate::tree_node::{LeafIndex};
use crate::hash::Mac;
use crate::hpke::HPKECiphertext;
use crate::protocol_version::ProtocolVersion;
use crate::signature::{Verifier, SignatureError, Signable};
use crate::group::Proposal::Add;
use crate::framing::{MLSPlaintext, Content, Sender, MLSPlaintextCommitAuthData, MLSPlaintextCommitContent, CommitConversionError, SenderType};
use crate::group::GroupError::InvalidPlaintextEpoch;
use crate::transcript_hash::{ConfirmedTranscriptHash, TranscriptHashError, InterimTranscriptHash};
use std::convert::TryFrom;
use std::option::Option::Some;

cfg_if! {
    if #[cfg(test)] {
        use crate::ciphersuite::test_util::MockCipherSuite as CipherSuite;
    } else {
        use crate::ciphersuite::{CipherSuite};
    }
}

#[repr(u8)]
#[derive(Clone, Debug, PartialEq, IntoPrimitive, TryFromPrimitive, Serialize, Deserialize)]
pub enum ProposalType {
    Reserved = 0,
    Add,
    Update,
    Remove,
    //TODO: Psk,
    //TODO: ReInit,
    //TODO: ExternalInit,
    //TODO: AppAck
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct AddProposal {
    pub key_package: KeyPackage
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct UpdateProposal {
    pub key_package: KeyPackage
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct RemoveProposal {
    pub to_remove: u32
}

//TODO: This should serialize with msg_type being a proposal type above
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum Proposal {
    Add(AddProposal),
    Update(UpdateProposal),
    Remove(RemoveProposal),
    //TODO: PSK
    //TODO: Psk,
    //TODO: ReInit,
    //TODO: ExternalInit,
    //TODO: AppAck
}

impl Proposal {
    pub fn is_add(&self) -> bool {
        match self {
            Self::Add(_) => true,
            _ => false
        }
    }

    pub fn is_update(&self) -> bool {
        match self {
            Self::Update(_) => true,
            _ => false
        }
    }

    pub fn is_remove(&self) -> bool {
        match self {
            Self::Remove(_) => true,
            _ => false
        }
    }
}

impl From<AddProposal> for Proposal {
    fn from(ap: AddProposal) -> Self {
        Proposal::Add(ap)
    }
}

impl From<Proposal> for ProposalType {
    fn from(p: Proposal) -> Self {
        match p {
            Proposal::Add(_) => ProposalType::Add,
            Proposal::Update(_) => ProposalType::Update,
            Proposal::Remove(_) => ProposalType::Remove
        }
    }
}

#[repr(u8)]
#[derive(Clone, Debug, PartialEq, IntoPrimitive, TryFromPrimitive, Serialize, Deserialize)]
pub enum ProposalOrRefType {
    Reserved = 0,
    Proposal,
    Reference,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum ProposalOrRef {
    Proposal(Proposal),
    Reference(Vec<u8>)
}

impl From<Proposal> for ProposalOrRef {
    fn from(proposal: Proposal) -> Self {
        Self::Proposal(proposal)
    }
}

impl From<Vec<u8>> for ProposalOrRef {
    fn from(v: Vec<u8>) -> Self {
        Self::Reference(v)
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Commit {
    pub proposals: Vec<ProposalOrRef>,
    pub path: Option<UpdatePath>
}

#[derive(Error, Debug)]
pub enum GroupError {
    #[error(transparent)]
    CipherSuiteError(#[from] CipherSuiteError),
    #[error(transparent)]
    RatchetTreeError(#[from] RatchetTreeError),
    #[error(transparent)]
    EpochError(#[from] EpochKeyScheduleError),
    #[error(transparent)]
    SignatureError(#[from] SignatureError),
    #[error(transparent)]
    BincodeError(#[from] bincode::Error),
    #[error(transparent)]
    TranscriptHashError(#[from] TranscriptHashError),
    #[error(transparent)]
    CommitConversionError(#[from] CommitConversionError),
    #[error("Cipher suite does not match")]
    CipherSuiteMismatch,
    #[error("Invalid key package signature")]
    InvalidKeyPackage,
    #[error("Proposal not found")]
    MissingProposal(Vec<u8>),
    #[error("Invalid commit, missing required path")]
    InvalidCommit,
    #[error("plaintext message for incorrect epoch")]
    InvalidPlaintextEpoch,
    #[error("invalid signature found")]
    InvalidSignature,
    #[error("invalid confirmation tag")]
    InvalidConfirmationTag,
    #[error("corrupt private key, missing required values")]
    InvalidTreeKemPrivateKey,
    #[error("key package not found, unable to process")]
    WelcomeKeyPackageNotFound,
    #[error("ratchet tree integrity failure")]
    InvalidRatchetTree
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct GroupContext {
    group_id: Vec<u8>,
    epoch: u64,
    tree_hash: Vec<u8>,
    confirmed_transcript_hash: Vec<u8>,
    extensions: Vec<Extension>
}

impl GroupContext {
    pub fn new_group(group_id: Vec<u8>, tree_hash: Vec<u8>, extensions: Vec<Extension>) -> Self {
        GroupContext {
            group_id,
            epoch: 0,
            tree_hash,
            confirmed_transcript_hash: vec![],
            extensions
        }
    }
}

impl From<&GroupInfo> for GroupContext {
    fn from(group_info: &GroupInfo) -> Self {
        GroupContext {
            group_id: group_info.group_id.clone(),
            epoch: group_info.epoch.clone(),
            tree_hash: group_info.tree_hash.clone(),
            confirmed_transcript_hash: group_info.confirmed_transcript_hash.clone(),
            extensions: group_info.extensions.clone()
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct GroupInfo {
    pub group_id: Vec<u8>,
    pub epoch: u64,
    pub tree_hash: Vec<u8>,
    pub confirmed_transcript_hash: Vec<u8>,
    pub extensions: Vec<Extension>,
    pub confirmation_tag: Mac,
    pub signer_index: u32,
    pub signature: Vec<u8>
}

impl Signable for GroupInfo {
    type E = bincode::Error;

    fn to_signable_vec(&self) -> Result<Vec<u8>, Self::E> {
        #[derive(Serialize)]
        struct SignableGroupInfo<'a> {
            pub group_id: &'a Vec<u8>,
            pub epoch: u64,
            pub tree_hash: &'a Vec<u8>,
            pub confirmed_transcript_hash: &'a Vec<u8>,
            pub extensions: &'a Vec<Extension>,
            pub confirmation_tag: &'a Mac,
            pub signer_index: u32,
        }

        bincode::serialize(&SignableGroupInfo {
            group_id: &self.group_id,
            epoch: self.epoch,
            tree_hash: &self.tree_hash,
            confirmed_transcript_hash: &self.confirmed_transcript_hash,
            extensions: &self.extensions,
            confirmation_tag: &self.confirmation_tag,
            signer_index: self.signer_index
        })
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct PathSecret {
    pub path_secret: Vec<u8>
}

impl From<Vec<u8>> for PathSecret {
    fn from(path_secret: Vec<u8>) -> Self {
        Self {
            path_secret
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct GroupSecrets {
    pub joiner_secret: Vec<u8>,
    pub path_secret: Option<PathSecret>,
    //TODO: PSK not currently supported
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct EncryptedGroupSecrets {
    pub key_package_hash: Vec<u8>,
    pub encrypted_group_secrets: HPKECiphertext,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Welcome {
    pub protocol_version: ProtocolVersion,
    pub cipher_suite: CipherSuite,
    pub secrets: Vec<EncryptedGroupSecrets>,
    pub encrypted_group_info: Vec<u8>
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Group {
    pub cipher_suite: CipherSuite,
    pub context: GroupContext,
    pub public_tree: RatchetTree,
    pub private_tree: TreeKemPrivate,
    pub key_schedule: EpochKeySchedule, //TODO: Need to support out of order packets by holding a few old epoch values too
    interim_transcript_hash: InterimTranscriptHash,
    pub proposals: HashMap<Vec<u8>, Proposal> // Hash of MLS Plaintext to proposal
}

impl PartialEq for Group {
    fn eq(&self, other: &Self) -> bool {
        self.cipher_suite == other.cipher_suite &&
            self.context == other.context &&
            self.public_tree == other.public_tree &&
            self.key_schedule == other.key_schedule &&
            self.interim_transcript_hash == other.interim_transcript_hash &&
            self.proposals == other.proposals
    }
}

struct GroupStateUpdate {
    pub ratchet_tree: RatchetTree,
    pub private_tree_update: Option<TreeKemPrivate>,
    pub key_schedule: EpochKeySchedule,
    pub confirmation_tag: Mac,
    pub interim_transcript_hash: InterimTranscriptHash,
    pub group_context: GroupContext,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct PendingCommit {
    pub plaintext: MLSPlaintext,
    update_path_data: Option<UpdatePathGeneration>,
    pub welcome: Option<Welcome>
}

impl Group {
    pub fn new<RNG: CryptoRng + RngCore + 'static>(
        rng: &mut RNG,
        group_id: Vec<u8>,
        creator_key_package: KeyPackageGeneration
    ) -> Result<Self, GroupError> {
        let cipher_suite = creator_key_package.key_package.cipher_suite.clone();
        let extensions = creator_key_package.key_package.extensions.clone();
        let (public_tree, private_tree) = RatchetTree::new(creator_key_package)?;
        let init_secret = cipher_suite.generate_init_secret(rng)?;
        let tree_hash = public_tree.tree_hash()?;

        let context = GroupContext::new_group(group_id, tree_hash, extensions.clone());
        let epoch = EpochKeySchedule::derive(
            cipher_suite.clone(),
            &init_secret,
            &[],
            1,
            &context,
            LeafIndex(0)
        )?.key_schedule;

         Ok(Self {
             cipher_suite: cipher_suite.clone(),
             public_tree,
             private_tree,
             context,
             key_schedule: epoch,
             interim_transcript_hash: InterimTranscriptHash::new(cipher_suite, vec![]),
             proposals: Default::default()
         })
    }

    pub fn from_welcome_message(
        welcome: Welcome,
        public_tree: RatchetTree,
        key_package: KeyPackageGeneration
    ) -> Result<Self, GroupError> {
        //Identify an entry in the secrets array where the key_package_hash value corresponds to
        // one of this client's KeyPackages, using the hash indicated by the cipher_suite field.
        // If no such field exists, or if the ciphersuite indicated in the KeyPackage does not
        // match the one in the Welcome message, return an error.
        let encrypted_group_secrets = welcome.secrets
            .iter()
            .find(|s| s.key_package_hash == key_package.key_package_hash)
            .ok_or(GroupError::WelcomeKeyPackageNotFound)?;

        //Decrypt the encrypted_group_secrets using HPKE with the algorithms indicated by the
        // ciphersuite and the HPKE private key corresponding to the GroupSecrets. If a
        // PreSharedKeyID is part of the GroupSecrets and the client is not in possession of
        // the corresponding PSK, return an error
        //TODO: PSK Support
        let decrypted_group_secrets = welcome.cipher_suite
            .hpke_open(&encrypted_group_secrets.encrypted_group_secrets,
                       &key_package.secret_key,
                       &[])?;

        let group_secrets = bincode::deserialize::<GroupSecrets>(&decrypted_group_secrets)?;

        //From the joiner_secret in the decrypted GroupSecrets object and the PSKs specified in
        // the GroupSecrets, derive the welcome_secret and using that the welcome_key and
        // welcome_nonce.
        let welcome_secret = WelcomeSecret::from_joiner_secret(&welcome.cipher_suite,
                                                               &group_secrets.joiner_secret)?;

        //Use the key and nonce to decrypt the encrypted_group_info field.
        let decrypted_group_info = welcome_secret.decrypt(&welcome.cipher_suite,
                                                          &welcome.encrypted_group_info)?;
        let group_info = bincode::deserialize::<GroupInfo>(&decrypted_group_info)?;

        //Verify the signature on the GroupInfo object. The signature input comprises all of the
        // fields in the GroupInfo object except the signature field. The public key and algorithm
        // are taken from the credential in the leaf node at position signer_index.
        // If this verification fails, return an error.

        let sender_leaf = LeafIndex(group_info.signer_index.clone() as usize);
        let sender_key_package = public_tree.get_key_package(sender_leaf)?;
        if !sender_key_package.credential.verify(&group_info.signature, &group_info)? {
            return Err(GroupError::InvalidSignature);
        }

        // Verify the integrity of the ratchet tree
        if !public_tree.is_valid(&group_info.tree_hash)? {
            return Err(GroupError::InvalidRatchetTree)
        }

        // Identify a leaf in the tree array (any even-numbered node) whose key_package field is
        // identical to the the KeyPackage. If no such field exists, return an error. Let index
        // represent the index of this node among the leaves in the tree, namely the index of the
        // node in the tree array divided by two.
        let self_index = public_tree
            .find_leaf(&key_package.key_package)
            .ok_or(GroupError::InvalidRatchetTree)?;

        // Construct a new group state using the information in the GroupInfo object. The new
        // member's position in the tree is index, as defined above. In particular, the confirmed
        // transcript hash for the new state is the prior_confirmed_transcript_hash in the GroupInfo
        // object.
        let context = GroupContext::from(&group_info);

        // TODO: Verify the tree by making sure the private keys match the expected public ones
        let private_tree = TreeKemPrivate::new_from_secret(
            &welcome.cipher_suite,
            self_index,
            key_package.secret_key,
            LeafIndex(group_info.signer_index as usize),
            public_tree.leaf_count(),
            &group_secrets
        )?;

        // Use the joiner_secret from the GroupSecrets object to generate the epoch secret and
        // other derived secrets for the current epoch.
        let key_schedule = EpochKeySchedule::new_joiner(
            welcome.cipher_suite.clone(),
            &group_secrets.joiner_secret,
            public_tree.leaf_count(),
            &context,
            self_index
        )?;

        // Verify the confirmation tag in the GroupInfo using the derived confirmation key and the
        // confirmed_transcript_hash from the GroupInfo.
        // TODO: This is duplicate code
        let confirmation_tag = welcome.cipher_suite.clone()
            .hmac(&key_schedule.confirmation_key,
                  &group_info.confirmed_transcript_hash)?;

        if confirmation_tag != group_info.confirmation_tag {
            return Err(GroupError::InvalidConfirmationTag);
        }

        // Use the confirmed transcript hash and confirmation tag to compute the interim transcript
        // hash in the new state.
        let confirmed_transcript_hash = ConfirmedTranscriptHash::new(
            welcome.cipher_suite.clone(),
            group_info.confirmed_transcript_hash
        );

        let interim_transcript_hash = confirmed_transcript_hash
            .get_interim_transcript_hash(group_info.confirmation_tag)?;

        Ok(Group {
            cipher_suite: welcome.cipher_suite.clone(),
            context,
            public_tree,
            private_tree,
            key_schedule,
            interim_transcript_hash,
            proposals: Default::default()
        })
    }

    fn fetch_proposals<'a>(
        &'a self,
        proposals: &'a Vec<ProposalOrRef>
    ) -> Result<Vec<&'a Proposal>, GroupError> {
        proposals.iter().map(|p| {
            match p {
                ProposalOrRef::Proposal(p) => Ok(p),
                ProposalOrRef::Reference(id) => self.proposals
                    .get(id)
                    .ok_or(GroupError::MissingProposal(id.clone()))
            }
        }).collect::<Result<Vec<&Proposal>, GroupError>>()
    }

    fn apply_proposals(
        &self,
        proposals: &Vec<ProposalOrRef>
    ) -> Result<(RatchetTree, Vec<LeafIndex>, bool), GroupError> {
        let proposals = self.fetch_proposals(proposals)?;

        let mut provisional_tree = self.public_tree.clone();

        // TODO: Process updates
        // TODO: Process removes

        let added_leaves = proposals.iter().filter_map(|p| {
            match p {
                Add(add) => Some(add),
                _ => None
            }
        }).flat_map(|a| { //TODO: This ignores underlying errors, must detect
            provisional_tree.add_nodes(vec![a.key_package.clone()])
        })
            .flatten()
            .collect();

        Ok((provisional_tree, added_leaves, self.path_update_required(&proposals)))
    }

    // TODO: Add a filter here so that the user can choose not to send a specific proposal
    pub fn commit_proposals<RNG: CryptoRng + RngCore + 'static, KPG: KeyPackageGenerator>(
        &self,
        proposals: Vec<Proposal>,
        update_path: bool,
        rng: &mut RNG,
        key_package_generator: &KPG
    ) -> Result<PendingCommit, GroupError> {
        // Construct an initial Commit object with the proposals field populated from Proposals
        // received during the current epoch, and an empty path field. Add passed in proposals
        // by value
        let proposals = [
            self.proposals.keys()
                .map(|v| ProposalOrRef::from(v.clone())).collect::<Vec<ProposalOrRef>>(),
            proposals.iter()
                .map(|p| ProposalOrRef::from(p.clone())).collect::<Vec<ProposalOrRef>>()
        ].concat();

        // Generate a provisional GroupContext object by applying the proposals referenced in the
        // initial Commit object, as described in Section 11.1. Update proposals are applied first,
        // followed by Remove proposals, and then finally Add proposals.
        // Add proposals are applied in the order listed in the proposals vector,
        // and always to the leftmost unoccupied leaf in the tree, or the right edge of
        // the tree if all leaves are occupied

        let (
            mut provisional_tree,
            added_leaves,
            path_update_required
        ) = self.apply_proposals(&proposals)?;

        let mut provisional_group_context = self.context.clone();
        provisional_group_context.epoch += 1;

        //Decide whether to populate the path field: If the path field is required based on the
        // proposals that are in the commit (see above), then it MUST be populated. Otherwise, the
        // sender MAY omit the path field at its discretion.
        if path_update_required && !update_path {
            return Err(GroupError::InvalidCommit);
        }

        let update_path = match update_path {
            false => None,
            true => {
                //If populating the path field: Create an UpdatePath using the new tree. Any new
                // member (from an add proposal) MUST be exluded from the resolution during the
                // computation of the UpdatePath. The GroupContext for this operation uses the
                // group_id, epoch, tree_hash, and confirmed_transcript_hash values in the initial
                // GroupContext object. The leaf_key_package for this UpdatePath must have a
                // parent_hash extension.
                let context_bytes = bincode::serialize(&self.context)?;
                let update_path = provisional_tree.gen_update_path(
                    &self.private_tree,
                    rng,
                    key_package_generator,
                    &context_bytes,
                    &added_leaves
                )?;

                // Update the tree in the provisional state by applying the direct path
                provisional_tree.apply_update_path(self.private_tree.self_index,
                                                   &update_path.update_path)?;

                Some(update_path)
            }
        };

        // Update the tree hash in the provisional group context
        provisional_group_context.tree_hash = provisional_tree.tree_hash()?;

        let commit_secret = CommitSecret::from_update_path(&self.cipher_suite,
                                                           update_path.as_ref())?;

        //TODO: If one or more PreSharedKey proposals are part of the commit, derive the psk_secret
        // as specified in Section 8.2, where the order of PSKs in the derivation corresponds to the
        // order of PreSharedKey proposals in the proposals vector. Otherwise, set psk_secret to a
        // zero-length octet string
        let commit = Commit {
            proposals,
            path: update_path.clone().map(|up| up.update_path)
        };

        //Construct an MLSPlaintext object containing the Commit object
        let mut plaintext = MLSPlaintext {
            group_id: self.context.group_id.clone(),
            epoch: self.context.epoch,
            sender: Sender {
                sender_type: SenderType::Member,
                sender: *self.private_tree.self_index as u32
            },
            authenticated_data: vec![],
            content: Content::Commit(commit),
            signature: vec![],
            confirmation_tag: None,
            membership_tag: None
        };

        // Sign the MLSPlaintext using the current epoch's GroupContext as context.
        plaintext.signature = key_package_generator
            .sign(&plaintext.signable_representation(&self.context))?;

        // Use the signature, the commit_secret and the psk_secret to advance the key schedule and
        // compute the confirmation_tag value in the MLSPlaintext.
        let plaintext_data = MLSPlaintextCommitContent::try_from(&plaintext)?;

        let confirmed_transcript_hash = self.interim_transcript_hash
            .get_confirmed_transcript_hash(&plaintext_data)?;

        provisional_group_context.confirmed_transcript_hash = confirmed_transcript_hash.value;

        let new_key_schedule = EpochKeySchedule::evolved_from(
            &self.key_schedule,
            &commit_secret,
            provisional_tree.leaf_count(),
            &provisional_group_context
        )?;

        let confirmation_tag = self.cipher_suite
            .hmac(&new_key_schedule.key_schedule.confirmation_key,
                  &provisional_group_context.confirmed_transcript_hash)?;

        plaintext.confirmation_tag = Some(confirmation_tag.clone());

        // Construct a GroupInfo reflecting the new state
        // Group ID, epoch, tree, and confirmed transcript hash from the new state
        let mut group_info = GroupInfo {
            group_id: self.context.group_id.clone(),
            epoch: provisional_group_context.epoch,
            tree_hash: provisional_group_context.tree_hash,
            confirmed_transcript_hash: provisional_group_context.confirmed_transcript_hash,
            extensions: self.context.extensions.clone(),
            confirmation_tag, // The confirmation_tag from the MLSPlaintext object
            signer_index: *self.private_tree.self_index as u32,
            signature: vec![]
        };

        // Sign the GroupInfo using the member's private signing key
        group_info.signature = key_package_generator.sign(&group_info)?;

        // Encrypt the GroupInfo using the key and nonce derived from the joiner_secret for
        // the new epoch
        let welcome_secret = WelcomeSecret::from_joiner_secret(&self.cipher_suite,
                                                               &new_key_schedule.joiner_secret)?;

        let group_info_data = bincode::serialize(&group_info)?;
        let encrypted_group_info = welcome_secret.encrypt(&self.cipher_suite,
                                                          &group_info_data)?;


        // Build welcome messages for each added member
        let secrets = added_leaves.iter().map(|i| {
            self.encrypt_group_secrets(
                rng,
                &provisional_tree,
                i,
                &new_key_schedule.joiner_secret,
                update_path.as_ref()
            )
        })
            .collect::<Result<Vec<EncryptedGroupSecrets>, GroupError>>()?;

        let welcome = match secrets.len() {
            0 => None,
            _ => Some(
                Welcome {
                    protocol_version: self.cipher_suite.get_protocol_version(),
                    cipher_suite: self.cipher_suite.clone(),
                    secrets,
                    encrypted_group_info
                }
            )
        };

        Ok(PendingCommit {
            plaintext,
            update_path_data: update_path,
            welcome
        })
    }

    fn encrypt_group_secrets<RNG: CryptoRng + RngCore + 'static>(
        &self,
        rng: &mut RNG,
        provisional_tree: &RatchetTree,
        leaf_index: &LeafIndex,
        joiner_secret: &Vec<u8>,
        update_path: Option<&UpdatePathGeneration>
    ) -> Result<EncryptedGroupSecrets, GroupError> {
        let path_secret = update_path
            .and_then(|up| up.get_common_path_secret(*leaf_index))
            .map(|ps| PathSecret::from(ps));

        // Ensure that we have a path secret if one is required
        if path_secret.is_none() && update_path.is_some() {
            return Err(GroupError::InvalidTreeKemPrivateKey)
        }

        let group_secrets = GroupSecrets {
            joiner_secret: joiner_secret.clone(),
            path_secret
        };

        let group_secrets_bytes = bincode::serialize(&group_secrets)?;
        let key_package = provisional_tree.get_key_package(*leaf_index)?;

        let key_package_hash = self.cipher_suite
            .hash(&bincode::serialize(&key_package)?)?;

        let encrypted_group_secrets = self.cipher_suite.hpke_seal(
            rng,
            &key_package.hpke_init_key,
            &[],
            &group_secrets_bytes
        )?;

        Ok(EncryptedGroupSecrets {
            key_package_hash,
            encrypted_group_secrets
        })
    }

    fn path_update_required(&self, proposals: &Vec<&Proposal>) -> bool {
        let has_update_or_remove = proposals
            .iter()
            .find(|p| p.is_update() || p.is_remove() )
            .is_some();

        proposals.len() == 0 || has_update_or_remove
    }

    pub fn add_member_proposals(
        &self,
        key_packages: &Vec<KeyPackage>
    ) -> Result<Vec<Proposal>, GroupError> {
        // Verify that the packages are all the correct cipher suite and mls version
        // TODO: Make sure the packages are the correct best cipher suite etc
        key_packages.iter().map(|key_package| {
            if key_package.cipher_suite != self.cipher_suite {
                return Err(GroupError::CipherSuiteMismatch)
            }

            // Create proposal
            Ok(Proposal::from(AddProposal { key_package: key_package.clone() }))
        }).collect()
    }

    pub fn process_pending_commit(&mut self, pending: PendingCommit) -> Result<(), GroupError> {
        self.process_plaintext_internal(pending.plaintext, pending.update_path_data)
            .map(|_| ())
    }

    fn process_plaintext_internal(
        &mut self,
        plaintext: MLSPlaintext,
        local_pending: Option<UpdatePathGeneration>
    ) -> Result<Option<Vec<u8>>, GroupError> {
        // Verify that the epoch field of the enclosing MLSPlaintext message is equal
        // to the epoch field of the current GroupContext object
        if plaintext.epoch != self.context.epoch {
            return Err(InvalidPlaintextEpoch);
        }

        //Verify that the signature on the MLSPlaintext message verifies using the public key
        // from the credential stored at the leaf in the tree indicated by the sender field.
        let sender_cred = &self.public_tree
            .get_key_package(plaintext.sender.clone().into())?.credential;

        if !sender_cred.verify(
            &plaintext.signature,
            &plaintext.signable_representation(&self.context)
        )? {
            return Err(GroupError::InvalidSignature);
        }

        //TODO: PSK Verify that all PSKs specified in any PreSharedKey proposals in the proposals
        // vector are available.

        // Process the contents of the packet
        match &plaintext.content {
            Content::Application(_) => { Ok(None) } //TODO: Decrypt application packet
            Content::Proposal(p) => {
                let hash = bincode::serialize(&plaintext)?;
                self.proposals.insert(hash, p.clone());
                Ok(None)
            }
            Content::Commit(_) => {
                let commit_content = MLSPlaintextCommitContent::try_from(&plaintext)?;
                let auth_data = MLSPlaintextCommitAuthData::try_from(&plaintext)?;

                let res = self.process_commit(plaintext.sender.into(),
                                              local_pending, commit_content, auth_data)?;

                // Use the confirmation_key for the new epoch to compute the confirmation tag for
                // this message, as described below, and verify that it is the same as the
                // confirmation_tag field in the MLSPlaintext object.

                let confirmation_tag = plaintext.confirmation_tag
                    .ok_or(GroupError::InvalidConfirmationTag)?;

                if res.confirmation_tag != confirmation_tag {
                    return Err(GroupError::InvalidConfirmationTag)
                }

                // If the above checks are successful, consider the updated GroupContext object
                // as the current state of the group
                self.public_tree = res.ratchet_tree;
                self.context = res.group_context;

                if let Some(private_tree) = res.private_tree_update {
                    self.private_tree = private_tree;
                }
                self.key_schedule = res.key_schedule;
                self.interim_transcript_hash = res.interim_transcript_hash;

                // Clear the proposals list
                self.proposals = Default::default();

                Ok(None)
            }
        }

        //TODO: If the Commit included a ReInit proposal, the client MUST NOT use the group to send
        // messages anymore. Instead, it MUST wait for a Welcome message from the committer
        // and check that
    }

    pub fn process_plaintext(
        &mut self,
        plaintext: MLSPlaintext
    ) -> Result<Option<Vec<u8>>, GroupError> {
        self.process_plaintext_internal(plaintext, None)
    }

    // This function takes a provisional copy of the tree and returns an updated tree and epoch key schedule
    fn process_commit(
        &self,
        sender: LeafIndex,
        local_pending: Option<UpdatePathGeneration>,
        commit_content: MLSPlaintextCommitContent,
        auth_data: MLSPlaintextCommitAuthData
    ) -> Result<GroupStateUpdate, GroupError> {
        //Generate a provisional GroupContext object by applying the proposals referenced in the
        // initial Commit object, as described in Section 11.1. Update proposals are applied first,
        // followed by Remove proposals, and then finally Add proposals. Add proposals are applied
        // in the order listed in the proposals vector, and always to the leftmost unoccupied leaf
        // in the tree, or the right edge of the tree if all leaves are occupied.

        let (
            mut provisional_tree,
            added,
            path_update_required
        ) = self.apply_proposals(&commit_content.commit.proposals)?;

        //Verify that the path value is populated if the proposals vector contains any Update
        // or Remove proposals, or if it's empty. Otherwise, the path value MAY be omitted.
        if path_update_required && commit_content.commit.path.is_none() {
            return Err(GroupError::InvalidCommit);
        }

        let updated_secrets = match &commit_content.commit.path {
            None => None,
            Some(update_path) => {
                // Receiving from yourself is a special case, we already have the new private keys
                let secrets = if let Some(pending) = local_pending {
                    Ok(pending.secrets)
                } else {
                    provisional_tree.refresh_private_key(
                        &self.private_tree,
                        sender,
                        update_path,
                        added,
                        &bincode::serialize(&self.context)?
                    )
                }?;

                provisional_tree.apply_update_path(sender, update_path)?;
                Some(secrets)
            }
        };

        let commit_secret =  CommitSecret::from_tree_secrets(&self.cipher_suite,
                                                             updated_secrets.as_ref())?;

        let mut provisional_group_context = self.context.clone();
        // Bump up the epoch in the provisional group context
        provisional_group_context.epoch += 1;

        // Update the new GroupContext's confirmed and interim transcript hashes using the new Commit.
        let confirmed_transcript_hash = self.interim_transcript_hash
            .get_confirmed_transcript_hash(&commit_content)?;

        let interim_transcript_hash = confirmed_transcript_hash
            .get_interim_transcript_hash(auth_data.confirmation_tag)?;

        provisional_group_context.confirmed_transcript_hash = confirmed_transcript_hash.value;
        provisional_group_context.tree_hash = provisional_tree.tree_hash()?;

        // TODO: If the proposals vector contains any PreSharedKey proposals, derive the psk_secret
        // as specified in Section 8.2, where the order of PSKs in the derivation corresponds to the
        // order of PreSharedKey proposals in the proposals vector. Otherwise, set psk_secret to 0

        // Use the commit_secret, the psk_secret, the provisional GroupContext, and the init secret
        // from the previous epoch to compute the epoch secret and derived secrets for the new epoch
        let new_epoch = EpochKeySchedule::evolved_from(
            &self.key_schedule,
            &commit_secret,
            provisional_tree.leaf_count(),
            &provisional_group_context
        )?;

        let confirmation_tag = self.cipher_suite
            .hmac(&new_epoch.key_schedule.confirmation_key,
                  &provisional_group_context.confirmed_transcript_hash)?;

        Ok(GroupStateUpdate {
            ratchet_tree: provisional_tree,
            private_tree_update: updated_secrets.map(|us| us.private_key),
            key_schedule: new_epoch.key_schedule,
            confirmation_tag,
            interim_transcript_hash,
            group_context: provisional_group_context,
        })
    }
}
