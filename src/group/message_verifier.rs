use crate::{
    group::{
        ContentType, EpochRepository, GroupContext, GroupError, KeyType, MLSCiphertext,
        MLSCiphertextContent, MLSCiphertextContentAAD, MLSMessage, MLSPlaintext, MLSSenderData,
        MLSSenderDataAAD, Sender, VerifiedPlaintext, WireFormat,
    },
    tree_kem::TreeKemPrivate,
};
use tls_codec::{Deserialize, Serialize};

pub(crate) struct MessageVerifier<'a> {
    pub(crate) epoch_repo: &'a mut EpochRepository,
    pub(crate) context: &'a GroupContext,
    pub(crate) private_tree: &'a TreeKemPrivate,
}

impl MessageVerifier<'_> {
    pub(crate) fn verify(&mut self, message: MLSMessage) -> Result<VerifiedPlaintext, GroupError> {
        match message {
            MLSMessage::Plain(m) => self.verify_plaintext(m),
            MLSMessage::Cipher(m) => self.decrypt_ciphertext(m),
        }
    }

    fn verify_plaintext(&self, plaintext: MLSPlaintext) -> Result<VerifiedPlaintext, GroupError> {
        let msg_epoch = self.epoch_repo.get(plaintext.epoch)?;

        let tag = plaintext
            .membership_tag
            .as_ref()
            .ok_or(GroupError::InvalidMembershipTag)?;
        if !tag.matches(&plaintext, self.context, msg_epoch)? {
            return Err(GroupError::InvalidMembershipTag);
        }

        //Verify that the signature on the MLSPlaintext message verifies using the public key
        // from the credential stored at the leaf in the tree indicated by the sender field.
        if !plaintext.verify_signature(&msg_epoch.public_tree, self.context, WireFormat::Plain)? {
            return Err(GroupError::InvalidSignature);
        }

        Ok(VerifiedPlaintext {
            wire_format: WireFormat::Plain,
            plaintext,
        })
    }

    fn decrypt_ciphertext(
        &mut self,
        ciphertext: MLSCiphertext,
    ) -> Result<VerifiedPlaintext, GroupError> {
        // Get the epoch associated with this ciphertext
        let msg_epoch = self.epoch_repo.get_mut(ciphertext.epoch)?;

        // Decrypt the sender data with the derived sender_key and sender_nonce from the current
        // epoch's key schedule
        let (sender_key, sender_nonce) =
            msg_epoch.get_sender_data_params(&ciphertext.ciphertext)?;

        let sender_data_aad = MLSSenderDataAAD {
            group_id: self.context.group_id.clone(),
            epoch: self.context.epoch,
            content_type: ciphertext.content_type,
        };

        let decrypted_sender = sender_key.decrypt_from_vec(
            &ciphertext.encrypted_sender_data,
            Some(&sender_data_aad.tls_serialize_detached()?),
            sender_nonce,
        )?;

        let sender_data = MLSSenderData::tls_deserialize(&mut &*decrypted_sender)?;
        if self.private_tree.key_package_ref == sender_data.sender {
            return Err(GroupError::CantProcessMessageFromSelf);
        }

        // Grab an encryption key from the current epoch's key schedule
        let key_type = match &ciphertext.content_type {
            ContentType::Application => KeyType::Application,
            _ => KeyType::Handshake,
        };

        let decryption_key = msg_epoch.get_decryption_key(
            msg_epoch
                .public_tree
                .package_leaf_index(&sender_data.sender)?,
            sender_data.generation,
            key_type,
        )?;

        // Build ciphertext aad using the ciphertext message
        let aad = MLSCiphertextContentAAD {
            group_id: ciphertext.group_id.clone(),
            epoch: ciphertext.epoch,
            content_type: ciphertext.content_type,
            authenticated_data: vec![],
        };

        // Decrypt the content of the message using the
        let decrypted_content = decryption_key.decrypt(
            &ciphertext.ciphertext,
            &aad.tls_serialize_detached()?,
            &sender_data.reuse_guard,
        )?;

        let ciphertext_content = MLSCiphertextContent::tls_deserialize(&mut &*decrypted_content)?;

        // Build the MLS plaintext object and process it
        let plaintext = MLSPlaintext {
            group_id: ciphertext.group_id.clone(),
            epoch: ciphertext.epoch,
            sender: Sender::Member(sender_data.sender),
            authenticated_data: vec![],
            content: ciphertext_content.content,
            signature: ciphertext_content.signature,
            confirmation_tag: ciphertext_content.confirmation_tag,
            membership_tag: None, // Membership tag is always None for ciphertext messages
        };

        //Verify that the signature on the MLSPlaintext message verifies using the public key
        // from the credential stored at the leaf in the tree indicated by the sender field.
        if !plaintext.verify_signature(&msg_epoch.public_tree, self.context, WireFormat::Cipher)? {
            return Err(GroupError::InvalidSignature);
        }

        Ok(VerifiedPlaintext {
            wire_format: WireFormat::Cipher,
            plaintext,
        })
    }
}
