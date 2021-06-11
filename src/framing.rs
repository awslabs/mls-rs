use crate::confirmation_tag::ConfirmationTag;
use crate::group::{Commit, Proposal};
use crate::membership_tag::MembershipTag;
use crate::message_signature::MessageSignature;
use crate::tree_kem::node::LeafIndex;
use serde::{Deserialize, Serialize};
use std::convert::TryFrom;
use thiserror::Error;

#[derive(Copy, Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum ContentType {
    Reserved = 0,
    Application,
    Proposal,
    Commit,
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
    NewMember,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Sender {
    pub sender_type: SenderType,
    pub sender: u32,
}

impl From<Sender> for LeafIndex {
    fn from(s: Sender) -> Self {
        LeafIndex(s.sender as usize)
    }
}

// TODO: We need to serialize this with proper TLS encoding
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum Content {
    Application(Vec<u8>),
    Proposal(Proposal),
    Commit(Commit),
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct MLSPlaintext {
    pub group_id: Vec<u8>,
    pub epoch: u64,
    pub sender: Sender,
    pub authenticated_data: Vec<u8>,
    pub content: Content,
    pub signature: MessageSignature,
    pub confirmation_tag: Option<ConfirmationTag>,
    pub membership_tag: Option<MembershipTag>,
}

#[derive(Error, Debug, PartialEq)]
pub enum CommitConversionError {
    #[error("attempted to add non commit message to the transcript hash")]
    NonCommitMessage,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub(crate) struct MLSPlaintextCommitContent {
    pub group_id: Vec<u8>,
    pub epoch: u64,
    pub sender: Sender,
    pub content_type: ContentType,
    pub commit: Commit,
    pub signature: MessageSignature,
}

impl TryFrom<&MLSPlaintext> for MLSPlaintextCommitContent {
    type Error = CommitConversionError;

    fn try_from(value: &MLSPlaintext) -> Result<Self, Self::Error> {
        match &value.content {
            Content::Commit(c) => Ok(MLSPlaintextCommitContent {
                group_id: value.group_id.clone(),
                epoch: value.epoch,
                sender: value.sender.clone(),
                content_type: ContentType::Commit,
                commit: c.clone(),
                signature: value.signature.clone(),
            }),
            _ => Err(CommitConversionError::NonCommitMessage),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub(crate) struct MLSPlaintextCommitAuthData<'a> {
    pub confirmation_tag: &'a ConfirmationTag,
}

impl<'a> TryFrom<&'a MLSPlaintext> for MLSPlaintextCommitAuthData<'a> {
    type Error = CommitConversionError;

    fn try_from(plaintext: &'a MLSPlaintext) -> Result<Self, Self::Error> {
        let confirmation_tag = plaintext
            .confirmation_tag
            .as_ref()
            .ok_or(CommitConversionError::NonCommitMessage)?;

        Ok(MLSPlaintextCommitAuthData { confirmation_tag })
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct MLSCiphertextContent {
    pub content: Content,
    pub signature: MessageSignature,
    pub confirmation_tag: Option<ConfirmationTag>,
    pub padding: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct MLSCiphertextContentAAD {
    pub group_id: Vec<u8>,
    pub epoch: u64,
    pub content_type: ContentType,
    pub authenticated_data: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct MLSCiphertext {
    pub group_id: Vec<u8>,
    pub epoch: u64,
    pub content_type: ContentType,
    pub authenticated_data: Vec<u8>,
    pub encrypted_sender_data: Vec<u8>,
    pub ciphertext: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct MLSSenderData {
    pub sender: u32,
    pub generation: u32,
    pub reuse_guard: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct MLSSenderDataAAD {
    pub group_id: Vec<u8>,
    pub epoch: u64,
    pub content_type: ContentType,
}

#[cfg(test)]
pub mod test_utils {
    use super::*;

    pub fn get_test_plaintext(test_content: Vec<u8>) -> MLSPlaintext {
        MLSPlaintext {
            group_id: vec![],
            epoch: 0,
            sender: Sender {
                sender_type: SenderType::Member,
                sender: 0,
            },
            authenticated_data: vec![],
            content: Content::Application(test_content),
            signature: MessageSignature::empty(),
            confirmation_tag: None,
            membership_tag: None,
        }
    }
}
