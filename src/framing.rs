use crate::group::{Proposal, Commit, GroupContext};
use crate::tree_node::LeafIndex;
use crate::signature::Signable;
use std::convert::{TryFrom};
use serde::{Serialize, Deserialize};
use crate::hash::Mac;
use thiserror::Error;

#[derive(Copy, Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum ContentType {
    Reserved = 0,
    Application,
    Proposal,
    Commit
}

impl From<&Content> for ContentType {
    fn from(content: &Content) -> Self {
        match content {
            Content::Application(_) => ContentType::Application,
            Content::Proposal(_) => ContentType::Proposal,
            Content::Commit(_) => ContentType::Commit,
        }
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum SenderType {
    Reserved = 0,
    Member,
    Preconfigured,
    NewMember
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Sender {
    pub sender_type: SenderType,
    pub sender: u32
}

impl Into<LeafIndex> for Sender {
    fn into(self) -> LeafIndex {
        LeafIndex(self.sender as usize)
    }
}

// TODO: We need to serialize this with proper TLS encoding
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum Content {
    Application(Vec<u8>),
    Proposal(Proposal),
    Commit(Commit)
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct MLSPlaintext {
    pub group_id: Vec<u8>,
    pub epoch: u64,
    pub sender: Sender,
    pub authenticated_data: Vec<u8>,
    pub content: Content,
    pub signature: Vec<u8>,
    pub confirmation_tag: Option<Mac>,
    pub membership_tag: Option<Vec<u8>>
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub (crate) struct MLSPlaintextTBS {
    context: Option<GroupContext>,
    group_id: Vec<u8>,
    epoch: u64,
    sender: Sender,
    authenticated_data: Vec<u8>,
    content: Content
}

impl MLSPlaintext {
    pub (crate) fn signable_representation(&self, group_context: &GroupContext) -> MLSPlaintextTBS {
        let context = match self.sender.sender_type {
            SenderType::Member => Some(group_context.clone()),
            _ => None,
        };

        MLSPlaintextTBS {
            context,
            group_id: self.group_id.clone(),
            epoch: self.epoch,
            sender: self.sender.clone(),
            authenticated_data: self.authenticated_data.clone(),
            content: self.content.clone()
        }
    }
}

impl Signable for MLSPlaintextTBS {
    type E = bincode::Error;

    fn to_signable_vec(&self) -> Result<Vec<u8>, Self::E> {
        bincode::serialize(&self)
    }
}

#[derive(Error, Debug)]
pub enum CommitConversionError {
    #[error("attempted to add non commit message to the transcript hash")]
    NonCommitMessage,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub (crate) struct MLSPlaintextCommitContent {
    pub group_id: Vec<u8>,
    pub epoch: u64,
    pub sender: Sender,
    pub content_type: ContentType,
    pub commit: Commit,
    pub signature: Vec<u8>
}

impl TryFrom<&MLSPlaintext> for MLSPlaintextCommitContent {
    type Error = CommitConversionError;

    fn try_from(value: &MLSPlaintext) -> Result<Self, Self::Error> {
        match &value.content {
            Content::Commit(c) => {
                Ok(MLSPlaintextCommitContent {
                    group_id: value.group_id.clone(),
                    epoch: value.epoch,
                    sender: value.sender.clone(),
                    content_type: ContentType::Commit,
                    commit: c.clone(),
                    signature: value.signature.clone()
                })
            }
            _ => Err(CommitConversionError::NonCommitMessage)
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub (crate) struct MLSPlaintextCommitAuthData {
    pub confirmation_tag: Mac
}

impl TryFrom<&MLSPlaintext> for MLSPlaintextCommitAuthData {
    type Error = CommitConversionError;

    fn try_from(plaintext: &MLSPlaintext) -> Result<Self, Self::Error> {
        Ok(MLSPlaintextCommitAuthData {
            confirmation_tag: plaintext.confirmation_tag.as_ref()
                .ok_or(CommitConversionError::NonCommitMessage)?.clone()
        })
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct MLSCiphertextContent {
    pub content: Content,
    pub signature: Vec<u8>,
    pub confirmation_tag: Option<Mac>,
    pub padding: Vec<u8>
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct MLSCiphertextContentAAD {
    pub group_id: Vec<u8>,
    pub epoch: u64,
    pub content_type: ContentType,
    pub authenticated_data: Vec<u8>
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct MLSCiphertext {
    pub group_id: Vec<u8>,
    pub epoch: u64,
    pub content_type: ContentType,
    pub authenticated_data: Vec<u8>,
    pub encrypted_sender_data: Vec<u8>,
    pub ciphertext: Vec<u8>
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct MLSSenderData {
    pub sender: u32,
    pub generation: u32,
    pub reuse_guard: Vec<u8>
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct MLSSenderDataAAD {
    pub group_id: Vec<u8>,
    pub epoch: u64,
    pub content_type: ContentType
}