use super::proposal::Proposal;
use super::*;
use serde::{Deserialize, Serialize};

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

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub(crate) struct MLSPlaintextCommitContent {
    pub group_id: Vec<u8>,
    pub epoch: u64,
    pub sender: Sender,
    pub content_type: ContentType,
    pub commit: Commit,
    pub signature: MessageSignature,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub(crate) struct MLSPlaintextCommitAuthData<'a> {
    pub confirmation_tag: &'a ConfirmationTag,
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
    pub reuse_guard: [u8; 4],
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
