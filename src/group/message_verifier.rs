use crate::{
    group::{
        ContentType, Epoch, GroupContext, GroupError, KeyType, MLSCiphertext, MLSCiphertextContent,
        MLSCiphertextContentAAD, MLSMessage, MLSPlaintext, MLSSenderData, MLSSenderDataAAD, Sender,
        VerifiedPlaintext, WireFormat,
    },
    tree_kem::TreeKemPrivate,
};
use ferriscrypt::asym::ec_key::PublicKey;
use tls_codec::{Deserialize, Serialize};

pub(crate) struct MessageVerifier<'a, F> {
    pub(crate) msg_epoch: &'a mut Epoch,
    pub(crate) context: &'a GroupContext,
    pub(crate) private_tree: &'a TreeKemPrivate,
    pub(crate) external_key_id_to_signing_key: F,
}

impl<F> MessageVerifier<'_, F>
where
    F: FnMut(&[u8]) -> Option<PublicKey>,
{
    pub(crate) fn verify(&mut self, message: MLSMessage) -> Result<VerifiedPlaintext, GroupError> {
        match message {
            MLSMessage::Plain(m) => self.verify_plaintext(m),
            MLSMessage::Cipher(m) => self.decrypt_ciphertext(m),
        }
    }

    fn verify_plaintext(
        &mut self,
        plaintext: MLSPlaintext,
    ) -> Result<VerifiedPlaintext, GroupError> {
        match plaintext.sender {
            Sender::Member(_) => {
                plaintext
                    .membership_tag
                    .as_ref()
                    .map(|tag| tag.matches(&plaintext, self.context, self.msg_epoch))
                    .transpose()?
                    .filter(|&matched| matched)
                    .ok_or(GroupError::InvalidMembershipTag)?;
            }
            Sender::NewMember | Sender::Preconfigured(_) => {
                plaintext
                    .membership_tag
                    .is_none()
                    .then(|| ())
                    .ok_or(GroupError::InvalidMembershipTag)?;
            }
        }

        //Verify that the signature on the MLSPlaintext message verifies using the public key
        // from the credential stored at the leaf in the tree indicated by the sender field.
        if !plaintext.verify_signature(
            &self.msg_epoch.public_tree,
            self.context,
            WireFormat::Plain,
            &mut self.external_key_id_to_signing_key,
        )? {
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
        // Decrypt the sender data with the derived sender_key and sender_nonce from the current
        // epoch's key schedule
        let (sender_key, sender_nonce) = self
            .msg_epoch
            .get_sender_data_params(&ciphertext.ciphertext)?;

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

        let decryption_key = self.msg_epoch.get_decryption_key(
            self.msg_epoch
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
        if !plaintext.verify_signature(
            &self.msg_epoch.public_tree,
            self.context,
            WireFormat::Cipher,
            &mut self.external_key_id_to_signing_key,
        )? {
            return Err(GroupError::InvalidSignature);
        }

        Ok(VerifiedPlaintext {
            wire_format: WireFormat::Cipher,
            plaintext,
        })
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        cipher_suite::CipherSuite,
        extension::ExtensionList,
        group::{
            membership_tag::MembershipTag,
            proposal::{AddProposal, Proposal},
            test_utils::{test_group, test_member},
            Content, Group, GroupError, MLSMessage, MLSPlaintext, MessageSignature,
            MessageVerifier, Sender, WireFormat,
        },
        key_package::KeyPackageGenerator,
    };
    use assert_matches::assert_matches;
    use ferriscrypt::asym::ec_key::{PublicKey, SecretKey};

    const TEST_CIPHER_SUITE: CipherSuite = CipherSuite::Curve25519Aes128V1;
    const TEST_GROUP: &[u8] = b"group";
    const TED_EXTERNAL_KEY_ID: &[u8] = b"ted";

    fn make_verifier<F>(group: &mut Group, f: F) -> MessageVerifier<'_, F>
    where
        F: FnMut(&[u8]) -> Option<PublicKey>,
    {
        let epoch = group.current_epoch();
        MessageVerifier {
            msg_epoch: group.epoch_repo.get_mut(epoch).unwrap(),
            context: &group.context,
            private_tree: &group.private_tree,
            external_key_id_to_signing_key: f,
        }
    }

    fn make_plaintext(sender: Sender, epoch: u64) -> MLSPlaintext {
        MLSPlaintext {
            group_id: TEST_GROUP.to_vec(),
            epoch,
            sender,
            authenticated_data: Vec::new(),
            content: Content::Application(b"foo".to_vec()),
            signature: MessageSignature::empty(),
            confirmation_tag: None,
            membership_tag: None,
        }
    }

    fn add_membership_tag(message: &mut MLSPlaintext, group: &Group) {
        let epoch = group.current_epoch();
        message.membership_tag = Some(
            MembershipTag::create(
                message,
                &group.context,
                group.epoch_repo.get(epoch).unwrap(),
            )
            .unwrap(),
        );
    }

    struct TestMember {
        signing_key: SecretKey,
        group: Group,
    }

    impl TestMember {
        fn make_member_plaintext(&self) -> MLSPlaintext {
            make_plaintext(
                Sender::Member(self.group.private_tree.key_package_ref.clone()),
                self.group.current_epoch(),
            )
        }

        fn sign(&self, message: &mut MLSPlaintext, wire_format: WireFormat) {
            message
                .sign(&self.signing_key, Some(&self.group.context), wire_format)
                .unwrap();
        }
    }

    struct TestEnv {
        alice: TestMember,
        bob: TestMember,
    }

    impl TestEnv {
        fn new() -> Self {
            let (key_pkg_gen, signing_key) = test_member(TEST_CIPHER_SUITE, b"alice");

            let alice_key_package_generator = KeyPackageGenerator {
                cipher_suite: key_pkg_gen.key_package.cipher_suite,
                credential: &key_pkg_gen.key_package.credential.clone(),
                extensions: &key_pkg_gen.key_package.extensions.clone(),
                signing_key: &signing_key.clone(),
            };

            let group = Group::new(
                TEST_GROUP.to_vec(),
                alice_key_package_generator.clone(),
                ExtensionList::new(),
            )
            .unwrap();

            let mut alice = TestMember { signing_key, group };

            let (key_pkg_gen, signing_key) = test_member(TEST_CIPHER_SUITE, b"bob");
            let proposal = alice
                .group
                .add_proposal(key_pkg_gen.key_package.clone().into())
                .unwrap();

            let (commit_generation, welcome) = alice
                .group
                .commit_proposals(
                    vec![proposal],
                    &alice_key_package_generator,
                    false,
                    WireFormat::Plain,
                    false,
                )
                .unwrap();

            alice
                .group
                .process_pending_commit(commit_generation)
                .unwrap();
            let group = Group::from_welcome_message(
                welcome.unwrap(),
                Some(alice.group.current_epoch_tree().unwrap().clone()),
                key_pkg_gen,
            )
            .unwrap();
            let bob = TestMember { signing_key, group };
            Self { alice, bob }
        }
    }

    #[test]
    fn valid_plaintext_is_verified() {
        let mut env = TestEnv::new();
        let mut message = env.alice.make_member_plaintext();
        env.alice.sign(&mut message, WireFormat::Plain);
        add_membership_tag(&mut message, &env.alice.group);
        let message = MLSMessage::Plain(message);
        let mut verifier = make_verifier(&mut env.bob.group, |_| None);
        let _ = verifier.verify(message).unwrap();
    }

    #[test]
    fn valid_ciphertext_is_verified() {
        let mut env = TestEnv::new();
        let mut message = env.alice.make_member_plaintext();
        env.alice.sign(&mut message, WireFormat::Cipher);
        let message = env.alice.group.encrypt_plaintext(message).unwrap();
        let message = MLSMessage::Cipher(message);
        let mut verifier = make_verifier(&mut env.bob.group, |_| None);
        let _ = verifier.verify(message).unwrap();
    }

    #[test]
    fn wire_format_is_signed() {
        let mut env = TestEnv::new();
        let mut message = env.alice.make_member_plaintext();
        env.alice.sign(&mut message, WireFormat::Plain);
        let message = env.alice.group.encrypt_plaintext(message).unwrap();
        let message = MLSMessage::Cipher(message);
        let mut verifier = make_verifier(&mut env.bob.group, |_| None);
        let res = verifier.verify(message);
        assert_matches!(res, Err(GroupError::InvalidSignature));
    }

    #[test]
    fn plaintext_from_member_requires_membership_tag() {
        let mut env = TestEnv::new();
        let mut message = env.alice.make_member_plaintext();
        env.alice.sign(&mut message, WireFormat::Plain);
        let message = MLSMessage::Plain(message);
        let mut verifier = make_verifier(&mut env.bob.group, |_| None);
        let res = verifier.verify(message);
        assert_matches!(res, Err(GroupError::InvalidMembershipTag));
    }

    #[test]
    fn valid_proposal_from_new_member_is_verified() {
        let (key_pkg_gen, signer) = test_member(TEST_CIPHER_SUITE, b"bob");
        let mut test_group = test_group(TEST_CIPHER_SUITE);

        let mut message = MLSPlaintext {
            content: Content::Proposal(Proposal::Add(AddProposal {
                key_package: key_pkg_gen.key_package.into(),
            })),
            ..make_plaintext(Sender::NewMember, test_group.group.current_epoch())
        };

        message.sign(&signer, None, WireFormat::Plain).unwrap();
        let message = MLSMessage::Plain(message);
        let mut verifier = make_verifier(&mut test_group.group, |_| None);
        let _ = verifier.verify(message).unwrap();
    }

    #[test]
    fn proposal_from_new_member_must_not_have_membership_tag() {
        let (key_pkg_gen, signer) = test_member(TEST_CIPHER_SUITE, b"bob");
        let mut test_group = test_group(TEST_CIPHER_SUITE);

        let mut message = MLSPlaintext {
            content: Content::Proposal(Proposal::Add(AddProposal {
                key_package: key_pkg_gen.key_package.into(),
            })),
            ..make_plaintext(Sender::NewMember, test_group.group.current_epoch())
        };

        message.sign(&signer, None, WireFormat::Plain).unwrap();
        add_membership_tag(&mut message, &test_group.group);
        let message = MLSMessage::Plain(message);
        let mut verifier = make_verifier(&mut test_group.group, |_| None);
        let res = verifier.verify(message);
        assert_matches!(res, Err(GroupError::InvalidMembershipTag));
    }

    #[test]
    fn valid_proposal_from_preconfigured_external_is_verified() {
        let (bob_key_pkg_gen, _) = test_member(TEST_CIPHER_SUITE, b"bob");
        let (_, ted_signer) = test_member(TEST_CIPHER_SUITE, b"ted");
        let mut test_group = test_group(TEST_CIPHER_SUITE);

        let mut message = MLSPlaintext {
            content: Content::Proposal(Proposal::Add(AddProposal {
                key_package: bob_key_pkg_gen.key_package.into(),
            })),
            ..make_plaintext(
                Sender::Preconfigured(TED_EXTERNAL_KEY_ID.to_vec()),
                test_group.group.current_epoch(),
            )
        };

        message.sign(&ted_signer, None, WireFormat::Plain).unwrap();
        let message = MLSMessage::Plain(message);
        let mut verifier = make_verifier(&mut test_group.group, |external_id| {
            (external_id == TED_EXTERNAL_KEY_ID).then(|| ted_signer.to_public().unwrap())
        });
        let _ = verifier.verify(message).unwrap();
    }

    #[test]
    fn proposal_from_preconfigured_external_must_not_have_membership_tag() {
        let (bob_key_pkg_gen, _) = test_member(TEST_CIPHER_SUITE, b"bob");
        let (_, ted_signer) = test_member(TEST_CIPHER_SUITE, b"ted");
        let mut test_group = test_group(TEST_CIPHER_SUITE);

        let mut message = MLSPlaintext {
            content: Content::Proposal(Proposal::Add(AddProposal {
                key_package: bob_key_pkg_gen.key_package.into(),
            })),
            ..make_plaintext(
                Sender::Preconfigured(TED_EXTERNAL_KEY_ID.to_vec()),
                test_group.group.current_epoch(),
            )
        };

        message.sign(&ted_signer, None, WireFormat::Plain).unwrap();
        add_membership_tag(&mut message, &test_group.group);
        let message = MLSMessage::Plain(message);

        let mut verifier = make_verifier(&mut test_group.group, |external_id| {
            (external_id == TED_EXTERNAL_KEY_ID).then(|| ted_signer.to_public().unwrap())
        });

        let res = verifier.verify(message);
        assert_matches!(res, Err(GroupError::InvalidMembershipTag));
    }

    #[test]
    fn ciphertext_from_self_fails_verification() {
        let mut env = TestEnv::new();
        let mut message = env.alice.make_member_plaintext();
        env.alice.sign(&mut message, WireFormat::Cipher);
        let message = env.alice.group.encrypt_plaintext(message).unwrap();
        let message = MLSMessage::Cipher(message);
        let mut verifier = make_verifier(&mut env.alice.group, |_| None);
        let res = verifier.verify(message);
        assert_matches!(res, Err(GroupError::CantProcessMessageFromSelf));
    }
}
