use super::framing::Content;
use crate::group::framing::{ContentType, MLSContent, MLSPlaintext, Sender, WireFormat};
use crate::group::{ConfirmationTag, GroupContext};
use crate::signer::{Signable, SignatureError, Signer};
use std::{
    io::{Read, Write},
    ops::Deref,
};
use tls_codec::{Deserialize, Serialize, Size};
use tls_codec_derive::{TlsDeserialize, TlsSerialize, TlsSize};

#[derive(Clone, Debug, PartialEq)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct MLSContentAuthData {
    pub signature: MessageSignature,
    pub confirmation_tag: Option<ConfirmationTag>,
}

impl MLSContentAuthData {
    pub(crate) fn tls_deserialize<R: Read>(
        bytes: &mut R,
        content_type: ContentType,
    ) -> Result<Self, tls_codec::Error> {
        Ok(MLSContentAuthData {
            signature: MessageSignature::tls_deserialize(bytes)?,
            confirmation_tag: match content_type {
                ContentType::Commit => Some(ConfirmationTag::tls_deserialize(bytes)?),
                ContentType::Application | ContentType::Proposal => None,
            },
        })
    }
}
#[derive(Clone, Debug, PartialEq, TlsSize, TlsSerialize)]
pub struct MLSAuthenticatedContent {
    pub(crate) wire_format: WireFormat,
    pub(crate) content: MLSContent,
    pub(crate) auth: MLSContentAuthData,
}

impl From<MLSPlaintext> for MLSAuthenticatedContent {
    fn from(p: MLSPlaintext) -> Self {
        Self {
            wire_format: WireFormat::Plain,
            content: p.content,
            auth: p.auth,
        }
    }
}

impl MLSAuthenticatedContent {
    pub fn new(
        context: &GroupContext,
        sender: Sender,
        content: Content,
        authenticated_data: Vec<u8>,
        wire_format: WireFormat,
    ) -> MLSAuthenticatedContent {
        MLSAuthenticatedContent {
            wire_format,
            content: MLSContent {
                group_id: context.group_id.clone(),
                epoch: context.epoch,
                sender,
                authenticated_data,
                content,
            },
            auth: MLSContentAuthData {
                signature: MessageSignature::empty(),
                confirmation_tag: None,
            },
        }
    }

    pub fn new_signed<S: Signer>(
        context: &GroupContext,
        sender: Sender,
        content: Content,
        signer: &S,
        wire_format: WireFormat,
        authenticated_data: Vec<u8>,
    ) -> Result<MLSAuthenticatedContent, SignatureError> {
        // Construct an MLSPlaintext object containing the content
        let mut plaintext =
            MLSAuthenticatedContent::new(context, sender, content, authenticated_data, wire_format);

        let signing_context = MessageSigningContext {
            group_context: Some(context),
        };

        // Sign the MLSPlaintext using the current epoch's GroupContext as context.
        plaintext.sign(signer, &signing_context)?;

        Ok(plaintext)
    }
}

impl Size for MLSContentAuthData {
    fn tls_serialized_len(&self) -> usize {
        self.signature.tls_serialized_len()
            + self
                .confirmation_tag
                .as_ref()
                .map_or(0, |tag| tag.tls_serialized_len())
    }
}

impl Serialize for MLSContentAuthData {
    fn tls_serialize<W: Write>(&self, writer: &mut W) -> Result<usize, tls_codec::Error> {
        Ok(self.signature.tls_serialize(writer)?
            + self
                .confirmation_tag
                .as_ref()
                .map_or(Ok(0), |tag| tag.tls_serialize(writer))?)
    }
}

impl Deserialize for MLSAuthenticatedContent {
    fn tls_deserialize<R: Read>(bytes: &mut R) -> Result<Self, tls_codec::Error> {
        let wire_format = WireFormat::tls_deserialize(bytes)?;
        let content = MLSContent::tls_deserialize(bytes)?;
        let auth_data = MLSContentAuthData::tls_deserialize(bytes, content.content_type())?;

        Ok(MLSAuthenticatedContent {
            wire_format,
            content,
            auth: auth_data,
        })
    }
}

impl serde::Serialize for MLSAuthenticatedContent {
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

impl<'de> serde::Deserialize<'de> for MLSAuthenticatedContent {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let data: Vec<u8> = Vec::deserialize(deserializer)?;
        MLSAuthenticatedContent::tls_deserialize(&mut &*data).map_err(serde::de::Error::custom)
    }
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct MLSContentTBS<'a> {
    pub(crate) wire_format: WireFormat,
    pub(crate) content: &'a MLSContent,
    pub(crate) context: Option<&'a GroupContext>,
}

impl<'a> Size for MLSContentTBS<'a> {
    fn tls_serialized_len(&self) -> usize {
        self.wire_format.tls_serialized_len()
            + self.content.tls_serialized_len()
            + self
                .context
                .as_ref()
                .map_or(0, |ctx| ctx.tls_serialized_len())
    }
}

impl<'a> Serialize for MLSContentTBS<'a> {
    fn tls_serialize<W: Write>(&self, writer: &mut W) -> Result<usize, tls_codec::Error> {
        Ok(self.wire_format.tls_serialize(writer)?
            + self.content.tls_serialize(writer)?
            + self
                .context
                .as_ref()
                .map_or(Ok(0), |ctx| ctx.tls_serialize(writer))?)
    }
}

impl<'a> MLSContentTBS<'a> {
    /// The group context must not be `None` when the sender is `Member` or `NewMember`.
    pub(crate) fn from_authenticated_content(
        auth_content: &'a MLSAuthenticatedContent,
        group_context: Option<&'a GroupContext>,
    ) -> Self {
        MLSContentTBS {
            wire_format: auth_content.wire_format,
            content: &auth_content.content,
            context: match auth_content.content.sender {
                Sender::Member(_) | Sender::NewMemberCommit => group_context,
                Sender::External(_) | Sender::NewMemberProposal => None,
            },
        }
    }
}

pub(crate) struct MessageSigningContext<'a> {
    pub group_context: Option<&'a GroupContext>,
}

impl<'a> Signable<'a> for MLSAuthenticatedContent {
    const SIGN_LABEL: &'static str = "MLSContentTBS";

    type SigningContext = MessageSigningContext<'a>;

    fn signature(&self) -> &[u8] {
        &self.auth.signature
    }

    fn signable_content(
        &self,
        context: &MessageSigningContext,
    ) -> Result<Vec<u8>, tls_codec::Error> {
        MLSContentTBS::from_authenticated_content(self, context.group_context)
            .tls_serialize_detached()
    }

    fn write_signature(&mut self, signature: Vec<u8>) {
        self.auth.signature = MessageSignature::from(signature)
    }
}

#[derive(Clone, Debug, PartialEq, TlsDeserialize, TlsSerialize, TlsSize)]
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
