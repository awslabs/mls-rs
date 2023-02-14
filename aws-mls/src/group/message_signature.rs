use super::framing::Content;
use crate::group::framing::{ContentType, FramedContent, PublicMessage, Sender, WireFormat};
use crate::group::{ConfirmationTag, GroupContext};
use crate::provider::crypto::{CipherSuiteProvider, SignatureSecretKey};
use crate::signer::{Signable, SignatureError};
use aws_mls_core::protocol_version::ProtocolVersion;
use std::{
    io::{Read, Write},
    ops::Deref,
};
use tls_codec::{Deserialize, Serialize, Size};
use tls_codec_derive::{TlsDeserialize, TlsSerialize, TlsSize};

#[derive(Clone, Debug, PartialEq)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct FramedContentAuthData {
    pub signature: MessageSignature,
    pub confirmation_tag: Option<ConfirmationTag>,
}

impl FramedContentAuthData {
    pub(crate) fn tls_deserialize<R: Read>(
        bytes: &mut R,
        content_type: ContentType,
    ) -> Result<Self, tls_codec::Error> {
        Ok(FramedContentAuthData {
            signature: MessageSignature::tls_deserialize(bytes)?,
            confirmation_tag: match content_type {
                ContentType::Commit => Some(ConfirmationTag::tls_deserialize(bytes)?),
                ContentType::Application | ContentType::Proposal => None,
            },
        })
    }
}
#[derive(Clone, Debug, PartialEq, TlsSize, TlsSerialize)]
pub struct AuthenticatedContent {
    pub(crate) wire_format: WireFormat,
    pub(crate) content: FramedContent,
    pub(crate) auth: FramedContentAuthData,
}

impl From<PublicMessage> for AuthenticatedContent {
    fn from(p: PublicMessage) -> Self {
        Self {
            wire_format: WireFormat::PublicMessage,
            content: p.content,
            auth: p.auth,
        }
    }
}

impl AuthenticatedContent {
    pub(crate) fn new(
        context: &GroupContext,
        sender: Sender,
        content: Content,
        authenticated_data: Vec<u8>,
        wire_format: WireFormat,
    ) -> AuthenticatedContent {
        AuthenticatedContent {
            wire_format,
            content: FramedContent {
                group_id: context.group_id.clone(),
                epoch: context.epoch,
                sender,
                authenticated_data,
                content,
            },
            auth: FramedContentAuthData {
                signature: MessageSignature::empty(),
                confirmation_tag: None,
            },
        }
    }

    pub(crate) fn new_signed<P: CipherSuiteProvider>(
        signature_provider: &P,
        context: &GroupContext,
        sender: Sender,
        content: Content,
        signer: &SignatureSecretKey,
        wire_format: WireFormat,
        authenticated_data: Vec<u8>,
    ) -> Result<AuthenticatedContent, SignatureError> {
        // Construct an MLSPlaintext object containing the content
        let mut plaintext =
            AuthenticatedContent::new(context, sender, content, authenticated_data, wire_format);

        let signing_context = MessageSigningContext {
            group_context: Some(context),
            protocol_version: context.protocol_version,
        };

        // Sign the MLSPlaintext using the current epoch's GroupContext as context.
        plaintext.sign(signature_provider, signer, &signing_context)?;

        Ok(plaintext)
    }
}

impl Size for FramedContentAuthData {
    fn tls_serialized_len(&self) -> usize {
        self.signature.tls_serialized_len()
            + self
                .confirmation_tag
                .as_ref()
                .map_or(0, |tag| tag.tls_serialized_len())
    }
}

impl Serialize for FramedContentAuthData {
    fn tls_serialize<W: Write>(&self, writer: &mut W) -> Result<usize, tls_codec::Error> {
        Ok(self.signature.tls_serialize(writer)?
            + self
                .confirmation_tag
                .as_ref()
                .map_or(Ok(0), |tag| tag.tls_serialize(writer))?)
    }
}

impl Deserialize for AuthenticatedContent {
    fn tls_deserialize<R: Read>(bytes: &mut R) -> Result<Self, tls_codec::Error> {
        let wire_format = WireFormat::tls_deserialize(bytes)?;
        let content = FramedContent::tls_deserialize(bytes)?;
        let auth_data = FramedContentAuthData::tls_deserialize(bytes, content.content_type())?;

        Ok(AuthenticatedContent {
            wire_format,
            content,
            auth: auth_data,
        })
    }
}

impl serde::Serialize for AuthenticatedContent {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let tls_serialize = self
            .tls_serialize_detached()
            .map_err(serde::ser::Error::custom)?;

        serializer.serialize_bytes(&tls_serialize)
    }
}

impl<'de> serde::Deserialize<'de> for AuthenticatedContent {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let data: Vec<u8> = Vec::deserialize(deserializer)?;
        AuthenticatedContent::tls_deserialize(&mut &*data).map_err(serde::de::Error::custom)
    }
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct AuthenticatedContentTBS<'a> {
    pub(crate) protocol_version: ProtocolVersion,
    pub(crate) wire_format: WireFormat,
    pub(crate) content: &'a FramedContent,
    pub(crate) context: Option<&'a GroupContext>,
}

impl<'a> Size for AuthenticatedContentTBS<'a> {
    fn tls_serialized_len(&self) -> usize {
        self.protocol_version.tls_serialized_len()
            + self.wire_format.tls_serialized_len()
            + self.content.tls_serialized_len()
            + self
                .context
                .as_ref()
                .map_or(0, |ctx| ctx.tls_serialized_len())
    }
}

impl<'a> Serialize for AuthenticatedContentTBS<'a> {
    fn tls_serialize<W: Write>(&self, writer: &mut W) -> Result<usize, tls_codec::Error> {
        Ok(self.protocol_version.tls_serialize(writer)?
            + self.wire_format.tls_serialize(writer)?
            + self.content.tls_serialize(writer)?
            + self
                .context
                .as_ref()
                .map_or(Ok(0), |ctx| ctx.tls_serialize(writer))?)
    }
}

impl<'a> AuthenticatedContentTBS<'a> {
    /// The group context must not be `None` when the sender is `Member` or `NewMember`.
    pub(crate) fn from_authenticated_content(
        auth_content: &'a AuthenticatedContent,
        group_context: Option<&'a GroupContext>,
        protocol_version: ProtocolVersion,
    ) -> Self {
        AuthenticatedContentTBS {
            protocol_version,
            wire_format: auth_content.wire_format,
            content: &auth_content.content,
            context: match auth_content.content.sender {
                Sender::Member(_) | Sender::NewMemberCommit => group_context,
                Sender::External(_) | Sender::NewMemberProposal => None,
            },
        }
    }
}

#[derive(Debug)]
pub(crate) struct MessageSigningContext<'a> {
    pub group_context: Option<&'a GroupContext>,
    pub protocol_version: ProtocolVersion,
}

impl<'a> Signable<'a> for AuthenticatedContent {
    const SIGN_LABEL: &'static str = "FramedContentTBS";

    type SigningContext = MessageSigningContext<'a>;

    fn signature(&self) -> &[u8] {
        &self.auth.signature
    }

    fn signable_content(
        &self,
        context: &MessageSigningContext,
    ) -> Result<Vec<u8>, tls_codec::Error> {
        AuthenticatedContentTBS::from_authenticated_content(
            self,
            context.group_context,
            context.protocol_version,
        )
        .tls_serialize_detached()
    }

    fn write_signature(&mut self, signature: Vec<u8>) {
        self.auth.signature = MessageSignature::from(signature)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, TlsDeserialize, TlsSerialize, TlsSize)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct MessageSignature(#[tls_codec(with = "crate::tls::ByteVec")] Vec<u8>);

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
