use crate::{
    credential::Credential,
    tree_kem::{leaf_node::LeafNode, leaf_node_ref::LeafNodeRef},
};

use super::proposal::Proposal;
use super::*;
use std::io::{Read, Write};
use tls_codec::{Deserialize, Serialize, Size};
use tls_codec_derive::{TlsDeserialize, TlsSerialize, TlsSize};

#[derive(Copy, Clone, Debug, PartialEq, TlsDeserialize, TlsSerialize, TlsSize)]
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
    TlsDeserialize,
    TlsSerialize,
    TlsSize,
    serde::Deserialize,
    serde::Serialize,
)]
#[repr(u8)]
pub enum Sender {
    #[tls_codec(discriminant = 1)]
    Member(LeafNodeRef),
    Preconfigured(#[tls_codec(with = "crate::tls::ByteVec")] Vec<u8>),
    NewMember,
}

#[derive(Clone, Debug, PartialEq, TlsDeserialize, TlsSerialize, TlsSize)]
#[repr(u8)]
pub enum Content {
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
pub struct MLSPlaintext {
    pub content: MLSMessageContent,
    pub auth: MLSMessageAuth,
    pub membership_tag: Option<MembershipTag>,
}

impl MLSPlaintext {
    pub fn new(
        group_id: Vec<u8>,
        epoch: u64,
        sender: Sender,
        content: Content,
        authenticated_data: Vec<u8>,
    ) -> Self {
        Self {
            content: MLSMessageContent {
                group_id,
                epoch,
                sender,
                authenticated_data,
                content,
            },
            auth: MLSMessageAuth {
                signature: MessageSignature::empty(),
                confirmation_tag: None,
            },
            membership_tag: None,
        }
    }

    pub fn new_signed<S: Signer>(
        context: &GroupContext,
        sender: Sender,
        content: Content,
        signer: &S,
        encryption_mode: ControlEncryptionMode,
        authenticated_data: Vec<u8>,
    ) -> Result<MLSPlaintext, SignatureError> {
        // Construct an MLSPlaintext object containing the content
        let mut plaintext = MLSPlaintext::new(
            context.group_id.clone(),
            context.epoch,
            sender,
            content,
            authenticated_data,
        );

        let signing_context = MessageSigningContext {
            group_context: Some(context),
            encrypted: matches!(encryption_mode, ControlEncryptionMode::Encrypted(_)),
        };

        // Sign the MLSPlaintext using the current epoch's GroupContext as context.
        plaintext.sign(signer, &signing_context)?;

        Ok(plaintext)
    }

    pub fn credential(
        &self,
        public_tree: &TreeKemPublic,
    ) -> Result<Option<Credential>, RatchetTreeError> {
        Ok(match &self.content.sender {
            Sender::Member(leaf_node_ref) => Some(
                public_tree
                    .get_leaf_node(leaf_node_ref)?
                    .signing_identity
                    .credential
                    .clone(),
            ),
            _ => match &self.content.content {
                Content::Proposal(Proposal::Add(AddProposal { key_package })) => {
                    Some(key_package.leaf_node.signing_identity.credential.clone())
                }
                _ => None,
            },
        })
    }
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
        let content = MLSMessageContent::tls_deserialize(bytes)?;
        let auth = MLSMessageAuth::tls_deserialize(bytes, content.content_type())?;
        let membership_tag = match content.sender {
            Sender::Member(_) => Some(MembershipTag::tls_deserialize(bytes)?),
            Sender::NewMember | Sender::Preconfigured(_) => None,
        };
        Ok(Self {
            content,
            auth,
            membership_tag,
        })
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct MLSCiphertextContent {
    pub content: Content,
    pub auth: MLSMessageAuth,
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
        let auth = MLSMessageAuth::tls_deserialize(bytes, content.content_type())?;

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

#[derive(Clone, Debug, PartialEq, TlsDeserialize, TlsSerialize, TlsSize)]
pub struct MLSCiphertextContentAAD {
    #[tls_codec(with = "crate::tls::ByteVec")]
    pub group_id: Vec<u8>,
    pub epoch: u64,
    pub content_type: ContentType,
    #[tls_codec(with = "crate::tls::ByteVec")]
    pub authenticated_data: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, TlsDeserialize, TlsSerialize, TlsSize)]
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

#[derive(Clone, Debug, PartialEq, TlsDeserialize, TlsSerialize, TlsSize)]
pub struct MLSSenderData {
    pub sender: LeafNodeRef,
    pub generation: u32,
    pub reuse_guard: [u8; 4],
}

#[derive(Clone, Debug, PartialEq, TlsDeserialize, TlsSerialize, TlsSize)]
pub struct MLSSenderDataAAD {
    #[tls_codec(with = "crate::tls::ByteVec")]
    pub group_id: Vec<u8>,
    pub epoch: u64,
    pub content_type: ContentType,
}

#[derive(Clone, Debug, PartialEq, TlsDeserialize, TlsSerialize, TlsSize)]
pub struct MLSMessage {
    pub version: ProtocolVersion,
    pub payload: MLSMessagePayload,
}

#[allow(clippy::large_enum_variant)]
#[derive(Clone, Debug, PartialEq, TlsDeserialize, TlsSerialize, TlsSize)]
#[repr(u8)]
pub enum MLSMessagePayload {
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
            MLSMessagePayload::GroupInfo(_) => WireFormat::PublicGroupState,
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
    PublicGroupState,
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
pub struct MLSMessageContent {
    #[tls_codec(with = "crate::tls::ByteVec")]
    pub group_id: Vec<u8>,
    pub epoch: u64,
    pub sender: Sender,
    #[tls_codec(with = "crate::tls::ByteVec")]
    pub authenticated_data: Vec<u8>,
    pub content: Content,
}

impl MLSMessageContent {
    pub fn content_type(&self) -> ContentType {
        self.content.content_type()
    }
}

#[cfg(test)]
pub mod test_utils {

    use super::*;

    pub fn get_test_plaintext(test_content: Vec<u8>) -> MLSPlaintext {
        MLSPlaintext {
            content: MLSMessageContent {
                group_id: Vec::new(),
                epoch: 0,
                sender: Sender::Member([0u8; 16].into()),
                authenticated_data: Vec::new(),
                content: Content::Application(test_content),
            },
            auth: MLSMessageAuth {
                signature: MessageSignature::empty(),
                confirmation_tag: None,
            },
            membership_tag: None,
        }
    }

    pub fn get_test_ciphertext_content() -> MLSCiphertextContent {
        MLSCiphertextContent {
            content: Content::Application(SecureRng::gen(1024).unwrap()),
            auth: MLSMessageAuth {
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
