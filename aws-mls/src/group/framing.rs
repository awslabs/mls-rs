use super::proposal::Proposal;
use super::*;
use crate::{client::MlsError, protocol_version::ProtocolVersion};
use alloc::vec::Vec;
use aws_mls_codec::{MlsDecode, MlsEncode, MlsSize};
use zeroize::Zeroize;

#[cfg(feature = "private_message")]
use alloc::string::ToString;

#[derive(Copy, Clone, Debug, PartialEq, Eq, MlsSize, MlsEncode, MlsDecode)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[repr(u8)]
pub enum ContentType {
    Application = 1u8,
    Proposal = 2u8,
    Commit = 3u8,
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
    Copy,
    Debug,
    PartialEq,
    Eq,
    MlsSize,
    MlsEncode,
    MlsDecode,
    serde::Deserialize,
    serde::Serialize,
)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[repr(u8)]
#[non_exhaustive]
/// Description of a [`MLSMessage`] sender
pub enum Sender {
    /// Current group member index.
    Member(u32) = 1u8,
    /// An external entity sending a proposal proposal identified by an index
    /// in the current
    /// [`ExternalSendersExt`](crate::extension::ExternalSendersExt) stored in
    /// group context extensions.
    External(u32) = 2u8,
    /// A new member proposing their own addition to the group.
    NewMemberProposal = 3u8,
    /// A member sending an external commit.
    #[cfg(feature = "external_commit")]
    NewMemberCommit = 4u8,
}

impl From<LeafIndex> for Sender {
    fn from(leaf_index: LeafIndex) -> Self {
        Sender::Member(*leaf_index)
    }
}

impl From<u32> for Sender {
    fn from(leaf_index: u32) -> Self {
        Sender::Member(leaf_index)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, MlsSize, MlsEncode, MlsDecode, Zeroize)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[zeroize(drop)]
pub struct ApplicationData(#[mls_codec(with = "aws_mls_codec::byte_vec")] Vec<u8>);

impl From<Vec<u8>> for ApplicationData {
    fn from(data: Vec<u8>) -> Self {
        Self(data)
    }
}

impl Deref for ApplicationData {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl ApplicationData {
    /// Underlying message content.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

#[derive(Clone, Debug, PartialEq, MlsSize, MlsEncode, MlsDecode)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[repr(u8)]
pub(crate) enum Content {
    Application(ApplicationData) = 1u8,
    Proposal(Proposal) = 2u8,
    Commit(Commit) = 3u8,
}

impl Content {
    pub fn content_type(&self) -> ContentType {
        self.into()
    }
}

#[derive(Clone, Debug, PartialEq)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub(crate) struct PublicMessage {
    pub content: FramedContent,
    pub auth: FramedContentAuthData,
    pub membership_tag: Option<MembershipTag>,
}

impl MlsSize for PublicMessage {
    fn mls_encoded_len(&self) -> usize {
        self.content.mls_encoded_len()
            + self.auth.mls_encoded_len()
            + self
                .membership_tag
                .as_ref()
                .map_or(0, |tag| tag.mls_encoded_len())
    }
}

impl MlsEncode for PublicMessage {
    fn mls_encode(&self, writer: &mut Vec<u8>) -> Result<(), aws_mls_codec::Error> {
        self.content.mls_encode(writer)?;
        self.auth.mls_encode(writer)?;

        self.membership_tag
            .as_ref()
            .map_or(Ok(()), |tag| tag.mls_encode(writer))
    }
}

impl MlsDecode for PublicMessage {
    fn mls_decode(reader: &mut &[u8]) -> Result<Self, aws_mls_codec::Error> {
        let content = FramedContent::mls_decode(reader)?;
        let auth = FramedContentAuthData::mls_decode(reader, content.content_type())?;

        let membership_tag = match content.sender {
            Sender::Member(_) => Some(MembershipTag::mls_decode(reader)?),
            _ => None,
        };

        Ok(Self {
            content,
            auth,
            membership_tag,
        })
    }
}

#[cfg(feature = "private_message")]
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct PrivateContentTBE {
    pub content: Content,
    pub auth: FramedContentAuthData,
    pub padding: Vec<u8>,
}

#[cfg(feature = "private_message")]
impl MlsSize for PrivateContentTBE {
    fn mls_encoded_len(&self) -> usize {
        let content_len_without_type = match &self.content {
            Content::Application(c) => c.mls_encoded_len(),
            Content::Proposal(c) => c.mls_encoded_len(),
            Content::Commit(c) => c.mls_encoded_len(),
        };

        // Padding has arbitrary size
        content_len_without_type + self.auth.mls_encoded_len() + self.padding.len()
    }
}

#[cfg(feature = "private_message")]
impl MlsEncode for PrivateContentTBE {
    fn mls_encode(&self, writer: &mut Vec<u8>) -> Result<(), aws_mls_codec::Error> {
        match &self.content {
            Content::Application(c) => c.mls_encode(writer),
            Content::Proposal(c) => c.mls_encode(writer),
            Content::Commit(c) => c.mls_encode(writer),
        }?;

        // Padding has arbitrary size
        self.auth.mls_encode(writer)?;
        writer.extend_from_slice(&self.padding);
        Ok(())
    }
}

#[cfg(feature = "private_message")]
impl PrivateContentTBE {
    pub(crate) fn mls_decode(
        reader: &mut &[u8],
        content_type: ContentType,
    ) -> Result<Self, aws_mls_codec::Error> {
        let content = match content_type {
            ContentType::Application => Content::Application(ApplicationData::mls_decode(reader)?),
            ContentType::Proposal => Content::Proposal(Proposal::mls_decode(reader)?),
            ContentType::Commit => Content::Commit(Commit::mls_decode(reader)?),
        };

        let auth = FramedContentAuthData::mls_decode(reader, content.content_type())?;

        let padding = reader.to_vec();

        if padding.iter().any(|&i| i != 0u8) {
            return Err(aws_mls_codec::Error::Custom(
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

#[cfg(feature = "private_message")]
#[derive(Clone, Debug, PartialEq, Eq, MlsSize, MlsEncode, MlsDecode)]
pub struct PrivateContentAAD {
    #[mls_codec(with = "aws_mls_codec::byte_vec")]
    pub group_id: Vec<u8>,
    pub epoch: u64,
    pub content_type: ContentType,
    #[mls_codec(with = "aws_mls_codec::byte_vec")]
    pub authenticated_data: Vec<u8>,
}

#[cfg(feature = "private_message")]
#[derive(Clone, Debug, PartialEq, Eq, MlsSize, MlsEncode, MlsDecode)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct PrivateMessage {
    #[mls_codec(with = "aws_mls_codec::byte_vec")]
    pub group_id: Vec<u8>,
    pub epoch: u64,
    pub content_type: ContentType,
    #[mls_codec(with = "aws_mls_codec::byte_vec")]
    pub authenticated_data: Vec<u8>,
    #[mls_codec(with = "aws_mls_codec::byte_vec")]
    pub encrypted_sender_data: Vec<u8>,
    #[mls_codec(with = "aws_mls_codec::byte_vec")]
    pub ciphertext: Vec<u8>,
}

#[cfg(feature = "private_message")]
impl From<&PrivateMessage> for PrivateContentAAD {
    fn from(ciphertext: &PrivateMessage) -> Self {
        Self {
            group_id: ciphertext.group_id.clone(),
            epoch: ciphertext.epoch,
            content_type: ciphertext.content_type,
            authenticated_data: ciphertext.authenticated_data.clone(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, MlsSize, MlsEncode, MlsDecode)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
/// A MLS protocol message for sending data over the wire.
pub struct MLSMessage {
    pub(crate) version: ProtocolVersion,
    pub(crate) payload: MLSMessagePayload,
}

#[allow(dead_code)]
impl MLSMessage {
    pub(crate) fn new(version: ProtocolVersion, payload: MLSMessagePayload) -> MLSMessage {
        Self { version, payload }
    }

    #[inline(always)]
    pub(crate) fn into_plaintext(self) -> Option<PublicMessage> {
        match self.payload {
            MLSMessagePayload::Plain(plaintext) => Some(plaintext),
            _ => None,
        }
    }

    #[cfg(feature = "private_message")]
    #[inline(always)]
    pub(crate) fn into_ciphertext(self) -> Option<PrivateMessage> {
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

    /// The wire format value describing the contents of this message.
    pub fn wire_format(&self) -> WireFormat {
        match self.payload {
            MLSMessagePayload::Plain(_) => WireFormat::PublicMessage,
            #[cfg(feature = "private_message")]
            MLSMessagePayload::Cipher(_) => WireFormat::PrivateMessage,
            MLSMessagePayload::Welcome(_) => WireFormat::Welcome,
            MLSMessagePayload::GroupInfo(_) => WireFormat::GroupInfo,
            MLSMessagePayload::KeyPackage(_) => WireFormat::KeyPackage,
        }
    }

    /// The epoch that this message belongs to.
    ///
    /// Returns `None` if the message is [`WireFormat::KeyPackage`]
    /// or [`WireFormat::Welcome`]
    pub fn epoch(&self) -> Option<u64> {
        match &self.payload {
            MLSMessagePayload::Plain(p) => Some(p.content.epoch),
            #[cfg(feature = "private_message")]
            MLSMessagePayload::Cipher(c) => Some(c.epoch),
            MLSMessagePayload::GroupInfo(gi) => Some(gi.group_context.epoch),
            _ => None,
        }
    }

    pub fn cipher_suite(&self) -> Option<CipherSuite> {
        match &self.payload {
            MLSMessagePayload::GroupInfo(i) => Some(i.group_context.cipher_suite),
            MLSMessagePayload::Welcome(w) => Some(w.cipher_suite),
            MLSMessagePayload::KeyPackage(k) => Some(k.cipher_suite),
            _ => None,
        }
    }

    /// Deserialize a message from transport.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, MlsError> {
        Self::mls_decode(&mut &*bytes).map_err(Into::into)
    }

    /// Serialize a message for transport.
    pub fn to_bytes(&self) -> Result<Vec<u8>, MlsError> {
        self.mls_encode_to_vec().map_err(Into::into)
    }
}

#[allow(clippy::large_enum_variant)]
#[derive(Clone, Debug, PartialEq, MlsSize, MlsEncode, MlsDecode)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[repr(u16)]
pub(crate) enum MLSMessagePayload {
    Plain(PublicMessage) = 1u16,
    #[cfg(feature = "private_message")]
    Cipher(PrivateMessage) = 2u16,
    Welcome(Welcome) = 3u16,
    GroupInfo(GroupInfo) = 4u16,
    KeyPackage(KeyPackage) = 5u16,
}

impl From<PublicMessage> for MLSMessagePayload {
    fn from(m: PublicMessage) -> Self {
        Self::Plain(m)
    }
}

#[derive(
    Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, MlsSize, MlsEncode, MlsDecode,
)]
#[repr(u16)]
#[non_exhaustive]
/// Content description of an [`MLSMessage`]
pub enum WireFormat {
    PublicMessage = 1u16,
    #[cfg(feature = "private_message")]
    PrivateMessage = 2u16,
    Welcome = 3u16,
    GroupInfo = 4u16,
    KeyPackage = 5u16,
}

#[cfg(feature = "private_message")]
impl From<ControlEncryptionMode> for WireFormat {
    fn from(mode: ControlEncryptionMode) -> Self {
        match mode {
            ControlEncryptionMode::Plaintext => WireFormat::PublicMessage,
            ControlEncryptionMode::Encrypted(_) => WireFormat::PrivateMessage,
        }
    }
}

#[derive(Clone, Debug, PartialEq, MlsSize, MlsEncode, MlsDecode)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub(crate) struct FramedContent {
    #[mls_codec(with = "aws_mls_codec::byte_vec")]
    pub group_id: Vec<u8>,
    pub epoch: u64,
    pub sender: Sender,
    #[mls_codec(with = "aws_mls_codec::byte_vec")]
    pub authenticated_data: Vec<u8>,
    pub content: Content,
}

impl FramedContent {
    pub fn content_type(&self) -> ContentType {
        self.content.content_type()
    }
}

#[cfg(test)]
pub(crate) mod test_utils {

    use crate::group::test_utils::random_bytes;

    use super::*;

    pub(crate) fn get_test_auth_content(test_content: Vec<u8>) -> AuthenticatedContent {
        AuthenticatedContent {
            wire_format: WireFormat::PublicMessage,
            content: FramedContent {
                group_id: Vec::new(),
                epoch: 0,
                sender: Sender::Member(1),
                authenticated_data: Vec::new(),
                content: Content::Application(test_content.into()),
            },
            auth: FramedContentAuthData {
                signature: MessageSignature::empty(),
                confirmation_tag: None,
            },
        }
    }

    #[cfg(feature = "private_message")]
    pub(crate) fn get_test_ciphertext_content() -> PrivateContentTBE {
        PrivateContentTBE {
            content: Content::Application(random_bytes(1024).into()),
            auth: FramedContentAuthData {
                signature: MessageSignature::from(random_bytes(128)),
                confirmation_tag: None,
            },
            padding: vec![],
        }
    }

    impl AsRef<[u8]> for ApplicationData {
        fn as_ref(&self) -> &[u8] {
            &self.0
        }
    }
}

#[cfg(feature = "private_message")]
#[cfg(test)]
mod tests {
    use assert_matches::assert_matches;

    use crate::group::framing::test_utils::get_test_ciphertext_content;

    use super::*;

    #[test]
    fn test_mls_ciphertext_content_mls_encoding() {
        let mut ciphertext_content = get_test_ciphertext_content();
        ciphertext_content.padding = vec![0u8; 128];

        let encoded = ciphertext_content.mls_encode_to_vec().unwrap();
        let decoded =
            PrivateContentTBE::mls_decode(&mut &*encoded, (&ciphertext_content.content).into())
                .unwrap();

        assert_eq!(ciphertext_content, decoded);
    }

    #[test]
    fn test_mls_ciphertext_content_non_zero_padding_error() {
        let mut ciphertext_content = get_test_ciphertext_content();
        ciphertext_content.padding = vec![1u8; 128];

        let encoded = ciphertext_content.mls_encode_to_vec().unwrap();
        let decoded =
            PrivateContentTBE::mls_decode(&mut &*encoded, (&ciphertext_content.content).into());

        assert_matches!(decoded, Err(aws_mls_codec::Error::Custom(e)) if e == "non-zero padding bytes discovered");
    }
}
