use super::proposal::Proposal;
use super::*;
use tls_codec_derive::{TlsDeserialize, TlsSerialize, TlsSize};

#[derive(Copy, Clone, Debug, PartialEq, TlsDeserialize, TlsSerialize, TlsSize)]
#[repr(u16)]
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

#[derive(Copy, Clone, Debug, PartialEq, TlsDeserialize, TlsSerialize, TlsSize)]
#[repr(u16)]
pub enum SenderType {
    Reserved = 0,
    Member,
    Preconfigured,
    NewMember,
}

#[derive(Clone, Debug, PartialEq, TlsDeserialize, TlsSerialize, TlsSize)]
pub struct Sender {
    pub sender_type: SenderType,
    pub sender: u32,
}

#[derive(Clone, Debug, PartialEq, TlsDeserialize, TlsSerialize, TlsSize)]
#[repr(u8)]
pub enum Content {
    Application(#[tls_codec(with = "crate::tls::ByteVec::<u32>")] Vec<u8>),
    Proposal(Proposal),
    Commit(Commit),
}

#[derive(Clone, Debug, PartialEq, TlsDeserialize, TlsSerialize, TlsSize)]
pub struct MLSPlaintext {
    #[tls_codec(with = "crate::tls::ByteVec::<u32>")]
    pub group_id: Vec<u8>,
    pub epoch: u64,
    pub sender: Sender,
    #[tls_codec(with = "crate::tls::ByteVec::<u32>")]
    pub authenticated_data: Vec<u8>,
    pub content: Content,
    pub signature: MessageSignature,
    pub confirmation_tag: Option<ConfirmationTag>,
    pub membership_tag: Option<MembershipTag>,
}

#[derive(Clone, Debug, PartialEq, TlsDeserialize, TlsSerialize, TlsSize)]
pub(crate) struct MLSPlaintextCommitContent {
    #[tls_codec(with = "crate::tls::ByteVec::<u32>")]
    pub group_id: Vec<u8>,
    pub epoch: u64,
    pub sender: Sender,
    #[tls_codec(with = "crate::tls::ByteVec::<u32>")]
    pub authenticated_data: Vec<u8>,
    pub content_type: ContentType,
    pub commit: Commit,
    pub signature: MessageSignature,
}

#[derive(Clone, Debug, PartialEq, TlsSerialize, TlsSize)]
pub(crate) struct MLSPlaintextCommitAuthData<'a> {
    pub confirmation_tag: Option<&'a ConfirmationTag>,
}

#[derive(Clone, Debug, PartialEq, TlsDeserialize, TlsSerialize, TlsSize)]
pub struct MLSCiphertextContent {
    pub content: Content,
    pub signature: MessageSignature,
    pub confirmation_tag: Option<ConfirmationTag>,
    #[tls_codec(with = "crate::tls::ByteVec::<u32>")]
    pub padding: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, TlsDeserialize, TlsSerialize, TlsSize)]
pub struct MLSCiphertextContentAAD {
    #[tls_codec(with = "crate::tls::ByteVec::<u32>")]
    pub group_id: Vec<u8>,
    pub epoch: u64,
    pub content_type: ContentType,
    #[tls_codec(with = "crate::tls::ByteVec::<u32>")]
    pub authenticated_data: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, TlsDeserialize, TlsSerialize, TlsSize)]
pub struct MLSCiphertext {
    #[tls_codec(with = "crate::tls::ByteVec::<u32>")]
    pub group_id: Vec<u8>,
    pub epoch: u64,
    pub content_type: ContentType,
    #[tls_codec(with = "crate::tls::ByteVec::<u32>")]
    pub authenticated_data: Vec<u8>,
    #[tls_codec(with = "crate::tls::ByteVec::<u32>")]
    pub encrypted_sender_data: Vec<u8>,
    #[tls_codec(with = "crate::tls::ByteVec::<u32>")]
    pub ciphertext: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, TlsDeserialize, TlsSerialize, TlsSize)]
pub struct MLSSenderData {
    pub sender: u32,
    pub generation: u32,
    pub reuse_guard: [u8; 4],
}

#[derive(Clone, Debug, PartialEq, TlsDeserialize, TlsSerialize, TlsSize)]
pub struct MLSSenderDataAAD {
    #[tls_codec(with = "crate::tls::ByteVec::<u32>")]
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
