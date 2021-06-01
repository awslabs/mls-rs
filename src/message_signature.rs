use crate::crypto::signature::{Signable, SignatureError, Signer, Verifier};
use crate::framing::{Content, MLSPlaintext, Sender, SenderType};
use crate::group::GroupContext;
use crate::tree_kem::node::LeafIndex;
use crate::tree_kem::{RatchetTree, RatchetTreeError};
use serde::{Deserialize, Serialize};
use std::borrow::Borrow;
use std::ops::Deref;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum MessageSignatureError {
    #[error(transparent)]
    SignatureError(#[from] SignatureError),
    #[error(transparent)]
    RatchetTreeError(#[from] RatchetTreeError),
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub(crate) struct MLSPlaintextTBS {
    context: Option<GroupContext>,
    group_id: Vec<u8>,
    epoch: u64,
    sender: Sender,
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
    pub(crate) fn sign<S: Signer>(
        &mut self,
        signer: &S,
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

impl Signable for MLSPlaintextTBS {
    type E = bincode::Error;
    fn to_signable_vec(&self) -> Result<Vec<u8>, Self::E> {
        bincode::serialize(&self)
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct MessageSignature(Vec<u8>);

impl MessageSignature {
    pub(crate) fn empty() -> Self {
        MessageSignature { 0: vec![] }
    }

    fn create<S: Signer>(
        signer: &S,
        plaintext: &MLSPlaintext,
        group_context: &GroupContext,
    ) -> Result<Self, MessageSignatureError> {
        let signature_data =
            signer.sign(&MLSPlaintextTBS::from_plaintext(plaintext, group_context))?;

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
            .get_key_package(LeafIndex::from(plaintext.sender.clone()))?
            .credential
            .borrow();

        let is_signature_valid = sender_cred.verify(
            &plaintext.signature,
            &MLSPlaintextTBS::from_plaintext(plaintext, group_context),
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
