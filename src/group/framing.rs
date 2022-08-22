use super::proposal::Proposal;
use super::*;
use crate::{
    protocol_version::{MaybeProtocolVersion, ProtocolVersion},
    tree_kem::leaf_node::LeafNode,
};
use std::io::{Read, Write};
use tls_codec::{Deserialize, Serialize, Size};
use tls_codec_derive::{TlsDeserialize, TlsSerialize, TlsSize};

#[derive(Copy, Clone, Debug, PartialEq, Eq, TlsDeserialize, TlsSerialize, TlsSize)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[repr(u8)]
pub enum ContentType {
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

#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    TlsDeserialize,
    TlsSerialize,
    TlsSize,
    serde::Deserialize,
    serde::Serialize,
)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[repr(u8)]
pub enum Sender {
    #[tls_codec(discriminant = 1)]
    Member(LeafIndex),
    External(u32),
    NewMemberCommit,
    NewMemberProposal,
}

impl From<LeafIndex> for Sender {
    fn from(leaf_index: LeafIndex) -> Self {
        Sender::Member(leaf_index)
    }
}

#[derive(Clone, Debug, PartialEq, TlsDeserialize, TlsSerialize, TlsSize)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[repr(u8)]
pub(crate) enum Content {
    Application(#[tls_codec(with = "crate::tls::ByteVec")] Vec<u8>),
    Proposal(Proposal),
    Commit(Commit),
}

impl Content {
    pub fn content_type(&self) -> ContentType {
        self.into()
    }
}

#[derive(Clone, Debug, PartialEq)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub(crate) struct MLSPlaintext {
    pub content: MLSContent,
    pub auth: MLSContentAuthData,
    pub membership_tag: Option<MembershipTag>,
}

impl Size for MLSPlaintext {
    fn tls_serialized_len(&self) -> usize {
        self.content.tls_serialized_len()
            + self.auth.tls_serialized_len()
            + self
                .membership_tag
                .as_ref()
                .map_or(0, |tag| tag.tls_serialized_len())
    }
}

impl Serialize for MLSPlaintext {
    fn tls_serialize<W: Write>(&self, writer: &mut W) -> Result<usize, tls_codec::Error> {
        Ok(self.content.tls_serialize(writer)?
            + self.auth.tls_serialize(writer)?
            + self
                .membership_tag
                .as_ref()
                .map_or(Ok(0), |tag| tag.tls_serialize(writer))?)
    }
}

impl Deserialize for MLSPlaintext {
    fn tls_deserialize<R: Read>(bytes: &mut R) -> Result<Self, tls_codec::Error> {
        let content = MLSContent::tls_deserialize(bytes)?;
        let auth = MLSContentAuthData::tls_deserialize(bytes, content.content_type())?;

        let membership_tag = match content.sender {
            Sender::Member(_) => Some(MembershipTag::tls_deserialize(bytes)?),
            _ => None,
        };

        Ok(Self {
            content,
            auth,
            membership_tag,
        })
    }
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct MLSCiphertextContent {
    pub content: Content,
    pub auth: MLSContentAuthData,
    pub padding: Vec<u8>,
}

impl Size for MLSCiphertextContent {
    fn tls_serialized_len(&self) -> usize {
        // Padding has arbitrary size
        self.content.tls_serialized_len() + self.auth.tls_serialized_len() + self.padding.len()
    }
}

impl Serialize for MLSCiphertextContent {
    fn tls_serialize<W: Write>(&self, writer: &mut W) -> Result<usize, tls_codec::Error> {
        // Padding has arbitrary size
        Ok(self.content.tls_serialize(writer)?
            + self.auth.tls_serialize(writer)?
            + writer.write(&self.padding)?)
    }
}

impl Deserialize for MLSCiphertextContent {
    fn tls_deserialize<R: Read>(bytes: &mut R) -> Result<Self, tls_codec::Error> {
        let content = Content::tls_deserialize(bytes)?;
        let auth = MLSContentAuthData::tls_deserialize(bytes, content.content_type())?;

        let mut padding = Vec::new();
        bytes.read_to_end(&mut padding)?;

        if padding.iter().any(|&i| i != 0u8) {
            return Err(tls_codec::Error::DecodingError(
                "non-zero padding bytes discovered".to_string(),
            ));
        }

        Ok(Self {
            content,
            auth,
            padding,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, TlsDeserialize, TlsSerialize, TlsSize)]
pub struct MLSCiphertextContentAAD {
    #[tls_codec(with = "crate::tls::ByteVec")]
    pub group_id: Vec<u8>,
    pub epoch: u64,
    pub content_type: ContentType,
    #[tls_codec(with = "crate::tls::ByteVec")]
    pub authenticated_data: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq, TlsDeserialize, TlsSerialize, TlsSize)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct MLSCiphertext {
    #[tls_codec(with = "crate::tls::ByteVec")]
    pub group_id: Vec<u8>,
    pub epoch: u64,
    pub content_type: ContentType,
    #[tls_codec(with = "crate::tls::ByteVec")]
    pub authenticated_data: Vec<u8>,
    #[tls_codec(with = "crate::tls::ByteVec")]
    pub encrypted_sender_data: Vec<u8>,
    #[tls_codec(with = "crate::tls::ByteVec")]
    pub ciphertext: Vec<u8>,
}

impl From<&MLSCiphertext> for MLSCiphertextContentAAD {
    fn from(ciphertext: &MLSCiphertext) -> Self {
        Self {
            group_id: ciphertext.group_id.clone(),
            epoch: ciphertext.epoch,
            content_type: ciphertext.content_type,
            authenticated_data: ciphertext.authenticated_data.clone(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, TlsDeserialize, TlsSerialize, TlsSize)]
pub struct MLSSenderData {
    pub sender: LeafIndex,
    pub generation: u32,
    pub reuse_guard: [u8; 4],
}

#[derive(Clone, Debug, PartialEq, Eq, TlsDeserialize, TlsSerialize, TlsSize)]
pub struct MLSSenderDataAAD {
    #[tls_codec(with = "crate::tls::ByteVec")]
    pub group_id: Vec<u8>,
    pub epoch: u64,
    pub content_type: ContentType,
}

#[derive(Clone, Debug, PartialEq, TlsDeserialize, TlsSerialize, TlsSize)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct MLSMessage {
    pub(crate) version: MaybeProtocolVersion,
    pub(crate) payload: MLSMessagePayload,
}

#[allow(dead_code)]
impl MLSMessage {
    pub(crate) fn new(version: ProtocolVersion, payload: MLSMessagePayload) -> MLSMessage {
        Self {
            version: version.into(),
            payload,
        }
    }

    #[inline(always)]
    pub(crate) fn into_plaintext(self) -> Option<MLSPlaintext> {
        match self.payload {
            MLSMessagePayload::Plain(plaintext) => Some(plaintext),
            _ => None,
        }
    }

    #[inline(always)]
    pub(crate) fn into_ciphertext(self) -> Option<MLSCiphertext> {
        match self.payload {
            MLSMessagePayload::Cipher(ciphertext) => Some(ciphertext),
            _ => None,
        }
    }

    #[inline(always)]
    pub(crate) fn into_welcome(self) -> Option<Welcome> {
        match self.payload {
            MLSMessagePayload::Welcome(welcome) => Some(welcome),
            _ => None,
        }
    }

    #[inline(always)]
    pub(crate) fn into_group_info(self) -> Option<GroupInfo> {
        match self.payload {
            MLSMessagePayload::GroupInfo(info) => Some(info),
            _ => None,
        }
    }

    #[inline(always)]
    pub(crate) fn into_key_package(self) -> Option<KeyPackage> {
        match self.payload {
            MLSMessagePayload::KeyPackage(kp) => Some(kp),
            _ => None,
        }
    }
}

#[allow(clippy::large_enum_variant)]
#[derive(Clone, Debug, PartialEq, TlsDeserialize, TlsSerialize, TlsSize)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[repr(u8)]
pub(crate) enum MLSMessagePayload {
    #[tls_codec(discriminant = 1)]
    Plain(MLSPlaintext),
    Cipher(MLSCiphertext),
    Welcome(Welcome),
    GroupInfo(GroupInfo),
    KeyPackage(KeyPackage),
}

impl MLSMessage {
    pub fn wire_format(&self) -> WireFormat {
        match self.payload {
            MLSMessagePayload::Plain(_) => WireFormat::Plain,
            MLSMessagePayload::Cipher(_) => WireFormat::Cipher,
            MLSMessagePayload::Welcome(_) => WireFormat::Welcome,
            MLSMessagePayload::GroupInfo(_) => WireFormat::GroupInfo,
            MLSMessagePayload::KeyPackage(_) => WireFormat::KeyPackage,
        }
    }

    // TODO: This function should be replaced with a special client for servers parsing
    // plaintext control messages
    pub fn commit_sender_update(&self) -> Option<&LeafNode> {
        match &self.payload {
            MLSMessagePayload::Plain(m) => match &m.content.content {
                Content::Commit(commit) => commit.path.as_ref().map(|cp| &cp.leaf_node),
                _ => None,
            },
            _ => None,
        }
    }
}

impl From<MLSPlaintext> for MLSMessagePayload {
    fn from(m: MLSPlaintext) -> Self {
        Self::Plain(m)
    }
}

#[derive(
    Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, TlsDeserialize, TlsSerialize, TlsSize,
)]
#[repr(u8)]
pub enum WireFormat {
    Plain = 1,
    Cipher,
    Welcome,
    GroupInfo,
    KeyPackage,
}

impl From<ControlEncryptionMode> for WireFormat {
    fn from(mode: ControlEncryptionMode) -> Self {
        match mode {
            ControlEncryptionMode::Plaintext => WireFormat::Plain,
            ControlEncryptionMode::Encrypted(_) => WireFormat::Cipher,
        }
    }
}

#[derive(Clone, Debug, PartialEq, TlsDeserialize, TlsSerialize, TlsSize)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub(crate) struct MLSContent {
    #[tls_codec(with = "crate::tls::ByteVec")]
    pub group_id: Vec<u8>,
    pub epoch: u64,
    pub sender: Sender,
    #[tls_codec(with = "crate::tls::ByteVec")]
    pub authenticated_data: Vec<u8>,
    pub content: Content,
}

impl MLSContent {
    pub fn content_type(&self) -> ContentType {
        self.content.content_type()
    }
}

#[cfg(test)]
pub(crate) mod test_utils {

    use super::*;

    pub(crate) fn get_test_auth_content(test_content: Vec<u8>) -> MLSAuthenticatedContent {
        MLSAuthenticatedContent {
            wire_format: WireFormat::Plain,
            content: MLSContent {
                group_id: Vec::new(),
                epoch: 0,
                sender: Sender::Member(LeafIndex(1)),
                authenticated_data: Vec::new(),
                content: Content::Application(test_content),
            },
            auth: MLSContentAuthData {
                signature: MessageSignature::empty(),
                confirmation_tag: None,
            },
        }
    }

    pub(crate) fn get_test_ciphertext_content() -> MLSCiphertextContent {
        MLSCiphertextContent {
            content: Content::Application(SecureRng::gen(1024).unwrap()),
            auth: MLSContentAuthData {
                signature: MessageSignature::from(SecureRng::gen(128).unwrap()),
                confirmation_tag: None,
            },
            padding: vec![],
        }
    }
}

#[cfg(test)]
mod tests {
    use assert_matches::assert_matches;

    use crate::group::framing::test_utils::get_test_ciphertext_content;

    use super::*;

    #[test]
    fn test_mls_ciphertext_content_tls_encoding() {
        let mut ciphertext_content = get_test_ciphertext_content();
        ciphertext_content.padding = vec![0u8; 128];

        let encoded = ciphertext_content.tls_serialize_detached().unwrap();
        let decoded = MLSCiphertextContent::tls_deserialize(&mut &*encoded).unwrap();

        assert_eq!(ciphertext_content, decoded);
    }

    #[test]
    fn test_mls_ciphertext_content_non_zero_padding_error() {
        let mut ciphertext_content = get_test_ciphertext_content();
        ciphertext_content.padding = vec![1u8; 128];

        let encoded = ciphertext_content.tls_serialize_detached().unwrap();
        let decoded = MLSCiphertextContent::tls_deserialize(&mut &*encoded);

        assert_matches!(decoded, Err(tls_codec::Error::DecodingError(e)) if e == "non-zero padding bytes discovered");
    }
}
