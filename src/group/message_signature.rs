use crate::client_config::Signer;
use crate::credential::CredentialError;
use crate::group::framing::{
    Content, ContentType, MLSMessageContent, MLSPlaintext, Sender, WireFormat,
};
use crate::group::{AddProposal, ConfirmationTag, GroupContext, Proposal};
use crate::tree_kem::{RatchetTreeError, TreeKemPublic};
use ferriscrypt::asym::ec_key::{EcKeyError, PublicKey};
use std::{
    io::{Read, Write},
    ops::Deref,
};
use thiserror::Error;
use tls_codec::{Deserialize, Serialize, Size};
use tls_codec_derive::{TlsDeserialize, TlsSerialize, TlsSize};

#[derive(Error, Debug)]
pub enum MessageSignatureError {
    #[error(transparent)]
    SignerError(Box<dyn std::error::Error>),
    #[error(transparent)]
    VerifierError(#[from] EcKeyError),
    #[error(transparent)]
    RatchetTreeError(#[from] RatchetTreeError),
    #[error(transparent)]
    SerializationError(#[from] tls_codec::Error),
    #[error(transparent)]
    CredentialError(#[from] CredentialError),
    #[error("New members can only propose adding themselves")]
    NewMembersCanOnlyProposeAddingThemselves,
    #[error("Signing key of preconfigured external sender is unknown")]
    UnknownSigningKeyForExternalSender,
}

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
    /// The group context should not be `None` when the sender is a member.
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
                Sender::Member(_) => group_context.cloned(),
                Sender::NewMember | Sender::Preconfigured(_) => None,
            },
        }
    }
}

impl MLSPlaintext {
    pub(crate) fn sign<S: Signer>(
        &mut self,
        signer: &S,
        group_context: Option<&GroupContext>,
        encrypted: bool,
    ) -> Result<(), MessageSignatureError> {
        self.auth.signature = MessageSignature::create(signer, self, group_context, encrypted)?;
        Ok(())
    }

    pub(crate) fn verify_signature<F>(
        &self,
        tree: &TreeKemPublic,
        group_context: &GroupContext,
        encrypted: bool,
        external_key_id_to_signing_key: F,
    ) -> Result<bool, MessageSignatureError>
    where
        F: FnMut(&[u8]) -> Option<PublicKey>,
    {
        self.auth.signature.is_valid(
            self,
            tree,
            group_context,
            encrypted,
            external_key_id_to_signing_key,
        )
    }
}

#[derive(Clone, Debug, PartialEq, TlsDeserialize, TlsSerialize, TlsSize)]
pub struct MessageSignature(#[tls_codec(with = "crate::tls::ByteVec::<u16>")] Vec<u8>);

impl MessageSignature {
    pub(crate) fn empty() -> Self {
        MessageSignature(vec![])
    }

    fn create<S: Signer>(
        signer: &S,
        plaintext: &MLSPlaintext,
        group_context: Option<&GroupContext>,
        encrypted: bool,
    ) -> Result<Self, MessageSignatureError> {
        let to_be_signed =
            MLSMessageContentTBS::from_plaintext(plaintext, group_context, encrypted);

        let signature_data = signer
            .sign(&to_be_signed.tls_serialize_detached()?)
            .map_err(|e| MessageSignatureError::SignerError(Box::new(e)))?;

        Ok(MessageSignature(signature_data))
    }

    fn is_valid<F>(
        &self,
        plaintext: &MLSPlaintext,
        tree: &TreeKemPublic,
        group_context: &GroupContext,
        encrypted: bool,
        mut external_key_id_to_signing_key: F,
    ) -> Result<bool, MessageSignatureError>
    where
        F: FnMut(&[u8]) -> Option<PublicKey>,
    {
        let to_be_verified =
            MLSMessageContentTBS::from_plaintext(plaintext, Some(group_context), encrypted)
                .tls_serialize_detached()?;
        // Verify that the signature on the MLSPlaintext message verifies using the public key
        // from the credential stored at the leaf in the tree indicated by the sender field.
        match &plaintext.content.sender {
            Sender::Member(sender) => Ok(tree
                .get_key_package(sender)?
                .credential
                .verify(&plaintext.auth.signature, &to_be_verified)?),
            Sender::Preconfigured(external_key_id) => {
                match external_key_id_to_signing_key(external_key_id) {
                    Some(signing_key) => {
                        Ok(signing_key.verify(&plaintext.auth.signature, &to_be_verified)?)
                    }
                    None => Err(MessageSignatureError::UnknownSigningKeyForExternalSender),
                }
            }
            Sender::NewMember => match &plaintext.content.content {
                Content::Proposal(Proposal::Add(AddProposal { key_package })) => Ok(key_package
                    .credential
                    .verify(&plaintext.auth.signature, &to_be_verified)?),
                _ => Err(MessageSignatureError::NewMembersCanOnlyProposeAddingThemselves),
            },
        }
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
