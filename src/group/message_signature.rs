use crate::credential::CredentialError;
use crate::group::framing::{Content, MLSPlaintext, Sender, SenderType};
use crate::group::GroupContext;
use crate::tree_kem::node::LeafIndex;
use crate::tree_kem::{RatchetTree, RatchetTreeError};
use ferriscrypt::asym::ec_key::{EcKeyError, SecretKey};
use ferriscrypt::{Signer, Verifier};
use std::borrow::Borrow;
use std::ops::Deref;
use thiserror::Error;
use tls_codec::Serialize;
use tls_codec_derive::{TlsDeserialize, TlsSerialize, TlsSize};

#[derive(Error, Debug)]
pub enum MessageSignatureError {
    #[error(transparent)]
    SignatureError(#[from] EcKeyError),
    #[error(transparent)]
    RatchetTreeError(#[from] RatchetTreeError),
    #[error(transparent)]
    SerializationError(#[from] tls_codec::Error),
    #[error(transparent)]
    CredentialError(#[from] CredentialError),
}

#[derive(Clone, Debug, PartialEq, TlsDeserialize, TlsSerialize, TlsSize)]
pub(crate) struct MLSPlaintextTBS {
    context: Option<GroupContext>,
    #[tls_codec(with = "crate::tls::ByteVec::<u32>")]
    group_id: Vec<u8>,
    epoch: u64,
    sender: Sender,
    #[tls_codec(with = "crate::tls::ByteVec::<u32>")]
    authenticated_data: Vec<u8>,
    content: Content,
}

impl MLSPlaintextTBS {
    pub(crate) fn from_plaintext(plaintext: &MLSPlaintext, group_context: &GroupContext) -> Self {
        let context = match plaintext.sender.sender_type {
            SenderType::Member => Some(group_context.clone()),
            _ => None,
        };

        MLSPlaintextTBS {
            context,
            group_id: plaintext.group_id.clone(),
            epoch: plaintext.epoch,
            sender: plaintext.sender.clone(),
            authenticated_data: plaintext.authenticated_data.clone(),
            content: plaintext.content.clone(),
        }
    }
}

impl MLSPlaintext {
    pub(crate) fn sign(
        &mut self,
        signer: &SecretKey,
        group_context: &GroupContext,
    ) -> Result<(), MessageSignatureError> {
        self.signature = MessageSignature::create(signer, self, group_context)?;
        Ok(())
    }

    pub(crate) fn verify_signature(
        &self,
        tree: &RatchetTree,
        group_context: &GroupContext,
    ) -> Result<bool, MessageSignatureError> {
        self.signature.is_valid(self, tree, group_context)
    }
}

#[derive(Clone, Debug, PartialEq, TlsDeserialize, TlsSerialize, TlsSize)]
pub struct MessageSignature(#[tls_codec(with = "crate::tls::ByteVec::<u32>")] Vec<u8>);

impl MessageSignature {
    pub(crate) fn empty() -> Self {
        MessageSignature { 0: vec![] }
    }

    fn create(
        signer: &SecretKey,
        plaintext: &MLSPlaintext,
        group_context: &GroupContext,
    ) -> Result<Self, MessageSignatureError> {
        let to_be_signed = MLSPlaintextTBS::from_plaintext(plaintext, group_context);
        let signature_data = signer.sign(&to_be_signed.tls_serialize_detached()?)?;

        Ok(MessageSignature(signature_data))
    }

    fn is_valid(
        &self,
        plaintext: &MLSPlaintext,
        tree: &RatchetTree,
        group_context: &GroupContext,
    ) -> Result<bool, MessageSignatureError> {
        //Verify that the signature on the MLSPlaintext message verifies using the public key
        // from the credential stored at the leaf in the tree indicated by the sender field.
        let sender_cred = tree
            .get_key_package(LeafIndex(plaintext.sender.sender))?
            .credential
            .borrow();

        let to_be_verified = MLSPlaintextTBS::from_plaintext(plaintext, group_context);

        let is_signature_valid = sender_cred.verify(
            &plaintext.signature,
            &to_be_verified.tls_serialize_detached()?,
        )?;

        Ok(is_signature_valid)
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
