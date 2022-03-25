use crate::group::framing::{ContentType, MLSMessageContent, MLSPlaintext, Sender, WireFormat};
use crate::group::{ConfirmationTag, GroupContext};
use crate::signer::Signable;
use std::{
    io::{Read, Write},
    ops::Deref,
};
use tls_codec::{Deserialize, Serialize, Size};
use tls_codec_derive::{TlsDeserialize, TlsSerialize, TlsSize};

#[derive(Clone, Debug, PartialEq)]
pub struct MLSMessageAuth {
    pub signature: MessageSignature,
    pub confirmation_tag: Option<ConfirmationTag>,
}

impl MLSMessageAuth {
    pub(crate) fn tls_serialized_len(&self) -> usize {
        self.signature.tls_serialized_len()
            + self
                .confirmation_tag
                .as_ref()
                .map_or(0, |tag| tag.tls_serialized_len())
    }

    pub(crate) fn tls_serialize<W: Write>(
        &self,
        writer: &mut W,
    ) -> Result<usize, tls_codec::Error> {
        Ok(self.signature.tls_serialize(writer)?
            + self
                .confirmation_tag
                .as_ref()
                .map_or(Ok(0), |tag| tag.tls_serialize(writer))?)
    }

    pub(crate) fn tls_deserialize<R: Read>(
        bytes: &mut R,
        content_type: ContentType,
    ) -> Result<Self, tls_codec::Error> {
        Ok(MLSMessageAuth {
            signature: MessageSignature::tls_deserialize(bytes)?,
            confirmation_tag: match content_type {
                ContentType::Commit => Some(ConfirmationTag::tls_deserialize(bytes)?),
                ContentType::Application | ContentType::Proposal => None,
            },
        })
    }
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct MLSMessageContentAuth<'a> {
    pub(crate) wire_format: WireFormat,
    pub(crate) content: &'a MLSMessageContent,
    pub(crate) auth: &'a MLSMessageAuth,
}

impl Size for MLSMessageContentAuth<'_> {
    fn tls_serialized_len(&self) -> usize {
        self.wire_format.tls_serialized_len()
            + self.content.tls_serialized_len()
            + self.auth.tls_serialized_len()
    }
}

impl Serialize for MLSMessageContentAuth<'_> {
    fn tls_serialize<W: Write>(&self, writer: &mut W) -> Result<usize, tls_codec::Error> {
        Ok(self.wire_format.tls_serialize(writer)?
            + self.content.tls_serialize(writer)?
            + self.auth.tls_serialize(writer)?)
    }
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct MLSMessageContentTBS {
    pub(crate) wire_format: WireFormat,
    pub(crate) content: MLSMessageContent,
    pub(crate) context: Option<GroupContext>,
}

impl Size for MLSMessageContentTBS {
    fn tls_serialized_len(&self) -> usize {
        self.wire_format.tls_serialized_len()
            + self.content.tls_serialized_len()
            + self
                .context
                .as_ref()
                .map_or(0, |ctx| ctx.tls_serialized_len())
    }
}

impl Serialize for MLSMessageContentTBS {
    fn tls_serialize<W: Write>(&self, writer: &mut W) -> Result<usize, tls_codec::Error> {
        Ok(self.wire_format.tls_serialize(writer)?
            + self.content.tls_serialize(writer)?
            + self
                .context
                .as_ref()
                .map_or(Ok(0), |ctx| ctx.tls_serialize(writer))?)
    }
}

impl Deserialize for MLSMessageContentTBS {
    fn tls_deserialize<R: Read>(bytes: &mut R) -> Result<Self, tls_codec::Error> {
        let wire_format = WireFormat::tls_deserialize(bytes)?;
        let content = MLSMessageContent::tls_deserialize(bytes)?;
        let context = match content.sender {
            Sender::Member(_) | Sender::NewMember => Some(GroupContext::tls_deserialize(bytes)?),
            Sender::Preconfigured(_) => None,
        };
        Ok(Self {
            wire_format,
            content,
            context,
        })
    }
}

impl MLSMessageContentTBS {
    /// The group context must not be `None` when the sender is `Member` or `NewMember`.
    pub(crate) fn from_plaintext(
        plaintext: &MLSPlaintext,
        group_context: Option<&GroupContext>,
        encrypted: bool,
    ) -> Self {
        MLSMessageContentTBS {
            wire_format: if encrypted {
                WireFormat::Cipher
            } else {
                WireFormat::Plain
            },
            content: plaintext.content.clone(),
            context: match plaintext.content.sender {
                Sender::Member(_) | Sender::NewMember => group_context.cloned(),
                Sender::Preconfigured(_) => None,
            },
        }
    }
}

pub(crate) struct MessageSigningContext<'a> {
    pub group_context: Option<&'a GroupContext>,
    pub encrypted: bool,
}

impl<'a> Signable<'a> for MLSPlaintext {
    const SIGN_LABEL: &'static str = "MLSMessageContentTBS";

    type SigningContext = MessageSigningContext<'a>;

    fn signature(&self) -> &[u8] {
        &self.auth.signature
    }

    fn signable_content(
        &self,
        context: &MessageSigningContext,
    ) -> Result<Vec<u8>, tls_codec::Error> {
        MLSMessageContentTBS::from_plaintext(self, context.group_context, context.encrypted)
            .tls_serialize_detached()
    }

    fn write_signature(&mut self, signature: Vec<u8>) {
        self.auth.signature = MessageSignature::from(signature)
    }
}

#[derive(Clone, Debug, PartialEq, TlsDeserialize, TlsSerialize, TlsSize)]
pub struct MessageSignature(#[tls_codec(with = "crate::tls::ByteVec::<u16>")] Vec<u8>);

impl MessageSignature {
    pub(crate) fn empty() -> Self {
        MessageSignature(vec![])
    }
}

impl Deref for MessageSignature {
    type Target = Vec<u8>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl From<Vec<u8>> for MessageSignature {
    fn from(v: Vec<u8>) -> Self {
        MessageSignature(v)
    }
}
