use crate::group::{Proposal, Commit, GroupContext};
use crate::tree_node::LeafIndex;
use crate::signature::Signable;
use std::convert::{TryFrom};
use serde::{Serialize, Deserialize, Serializer, Deserializer};
use serde_with::skip_serializing_none;
use serde::de::Error;
use crate::hash::Mac;
use thiserror::Error;

#[derive(Copy, Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum ContentType {
    Reserved = 0,
    Application,
    Proposal,
    Commit
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

#[derive(Clone, Debug, PartialEq)]
pub enum Content {
    Application(Vec<u8>),
    Proposal(Proposal),
    Commit(Commit)
}

#[skip_serializing_none]
#[derive(Serialize, Deserialize)]
struct SerializedContent {
    content_type: ContentType,
    application_data: Option<Vec<u8>>,
    proposal: Option<Proposal>,
    commit: Option<Commit>
}

impl From<&Content> for SerializedContent {
    fn from(c: &Content) -> Self {
        match c {
            Content::Application(d) => {
                SerializedContent {
                    content_type: ContentType::Application,
                    application_data: Some(d.clone()),
                    proposal: None,
                    commit: None
                }
            }
            Content::Proposal(p) => {
                SerializedContent {
                    content_type: ContentType::Proposal,
                    application_data: None,
                    proposal: Some(p.clone()),
                    commit: None
                }
            }
            Content::Commit(c) => {
                SerializedContent {
                    content_type: ContentType::Application,
                    application_data: None,
                    proposal: None,
                    commit: Some(c.clone())
                }
            }
        }
    }
}

impl Serialize for Content {
    fn serialize<S>(&self, serializer: S) -> Result<<S as Serializer>::Ok, <S as Serializer>::Error> where
        S: Serializer {
        let serialized_content = SerializedContent::from(self);
        serialized_content.serialize(serializer)
    }
}

impl <'de> Deserialize<'de> for Content {
    fn deserialize<D>(deserializer: D) -> Result<Self, <D as Deserializer<'de>>::Error> where
        D: Deserializer<'de> {
        let deserialized = SerializedContent::deserialize(deserializer)?;
        match deserialized.content_type {
            ContentType::Reserved => {
                Err(D::Error::custom("reserved content not allowed"))
            }
            ContentType::Application => {
                deserialized.application_data
                    .ok_or_else(|| D::Error::custom("missing application data"))
                    .map(Content::Application)
            }
            ContentType::Proposal => {
                deserialized.proposal
                    .ok_or_else(|| D::Error::custom("missing proposal data"))
                    .map(Content::Proposal)
            }
            ContentType::Commit => {
                deserialized.commit
                    .ok_or_else(|| D::Error::custom("missing proposal data"))
                    .map(Content::Commit)
            }
        }
    }
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
                    content_type: ContentType::Reserved,
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

pub struct MLSCiphertext {
    pub group_id: Vec<u8>,
    pub epoch: u64,
    pub content_type: ContentType,
    pub authenticated_data: Vec<u8>,
    pub encrypted_sender_data: Vec<u8>,
    pub ciphertext: Vec<u8>
}