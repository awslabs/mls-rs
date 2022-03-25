use crate::{
    group::{
        Commit, ContentType, Epoch, GroupContext, GroupError, KeyType, MLSCiphertext,
        MLSCiphertextContent, MLSCiphertextContentAAD, MLSMessageContent, MLSPlaintext,
        MLSSenderData, MLSSenderDataAAD, Sender, VerifiedPlaintext,
    },
    key_package::KeyPackageRef,
    signer::Signable,
    tree_kem::TreeKemPrivate,
    AddProposal, Proposal,
};
use ferriscrypt::asym::ec_key::PublicKey;
use tls_codec::{Deserialize, Serialize};

use super::{framing::Content, message_signature::MessageSigningContext};

pub(crate) struct MessageVerifier<'a, F> {
    pub(crate) msg_epoch: &'a mut Epoch,
    pub(crate) context: &'a GroupContext,
    pub(crate) private_tree: &'a TreeKemPrivate,
    pub(crate) external_key_id_to_signing_key: F,
}

impl<F> MessageVerifier<'_, F>
where
    F: Fn(&[u8]) -> Option<PublicKey>,
{
    fn public_key_for_sender(
        &self,
        sender: &Sender,
        content: &Content,
    ) -> Result<PublicKey, GroupError> {
        match sender {
            Sender::Member(leaf_ref) => self.public_key_for_member(leaf_ref),
            Sender::Preconfigured(external_key_id) => {
                self.public_key_for_preconfigured(external_key_id)
            }
            Sender::NewMember => self.public_key_for_new_member(content),
        }
    }

    fn public_key_for_member(&self, leaf_ref: &KeyPackageRef) -> Result<PublicKey, GroupError> {
        self.msg_epoch
            .public_tree
            .get_key_package(leaf_ref)?
            .credential
            .public_key()
            .map_err(Into::into)
    }

    fn public_key_for_preconfigured(
        &self,
        external_key_id: &[u8],
    ) -> Result<PublicKey, GroupError> {
        (self.external_key_id_to_signing_key)(external_key_id)
            .ok_or(GroupError::UnknownSigningKeyForExternalSender)
    }

    fn public_key_for_new_member(&self, content: &Content) -> Result<PublicKey, GroupError> {
        match content {
            Content::Commit(Commit {
                path: Some(path), ..
            }) => Ok(path.leaf_key_package.credential.public_key()?),
            Content::Proposal(Proposal::Add(AddProposal { key_package })) => {
                Ok(key_package.credential.public_key()?)
            }
            _ => Err(GroupError::NewMembersCanOnlyProposeAddingThemselves),
        }
    }

    pub(crate) fn verify_plaintext(
        &mut self,
        plaintext: MLSPlaintext,
    ) -> Result<VerifiedPlaintext, GroupError> {
        // Verify the membership tag if needed
        match plaintext.content.sender {
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

        // Verify that the signature on the MLSPlaintext message verifies using the public key
        // from the credential stored at the leaf in the tree indicated by the sender field.
        self.verify_plaintext_signature(plaintext, false)
    }

    fn verify_plaintext_signature(
        &self,
        plaintext: MLSPlaintext,
        from_ciphertext: bool,
    ) -> Result<VerifiedPlaintext, GroupError> {
        let sender_public_key =
            self.public_key_for_sender(&plaintext.content.sender, &plaintext.content.content)?;

        let context = MessageSigningContext {
            group_context: Some(self.context),
            encrypted: from_ciphertext,
        };

        plaintext.verify(&sender_public_key, &context)?;

        Ok(VerifiedPlaintext {
            encrypted: context.encrypted,
            plaintext,
        })
    }

    pub(crate) fn decrypt_ciphertext(
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
            content: MLSMessageContent {
                group_id: ciphertext.group_id.clone(),
                epoch: ciphertext.epoch,
                sender: Sender::Member(sender_data.sender),
                authenticated_data: Vec::new(),
                content: ciphertext_content.content,
            },
            auth: ciphertext_content.auth,
            membership_tag: None, // Membership tag is always None for ciphertext messages
        };

        //Verify that the signature on the MLSPlaintext message verifies using the public key
        // from the credential stored at the leaf in the tree indicated by the sender field.
        self.verify_plaintext_signature(plaintext, true)
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        cipher_suite::CipherSuite,
        client_config::InMemoryPskStore,
        extension::ExtensionList,
        group::{
            membership_tag::MembershipTag,
            message_signature::MessageSigningContext,
            padding::PaddingMode,
            proposal::{AddProposal, Proposal},
            test_utils::{test_group, test_member},
            Content, ControlEncryptionMode, Group, GroupError, MLSMessagePayload, MLSPlaintext,
            MessageVerifier, Sender,
        },
        key_package::KeyPackageGenerator,
        signer::{Signable, SignatureError},
        ProtocolVersion,
    };
    use assert_matches::assert_matches;
    use ferriscrypt::asym::ec_key::{PublicKey, SecretKey};

    #[cfg(target_arch = "wasm32")]
    use wasm_bindgen_test::{wasm_bindgen_test as test, wasm_bindgen_test_configure};

    #[cfg(target_arch = "wasm32")]
    wasm_bindgen_test_configure!(run_in_browser);

    const TEST_PROTOCOL_VERSION: ProtocolVersion = ProtocolVersion::Mls10;
    const TEST_CIPHER_SUITE: CipherSuite = CipherSuite::Curve25519Aes128V1;
    const TEST_GROUP: &[u8] = b"group";
    const TED_EXTERNAL_KEY_ID: &[u8] = b"ted";

    fn make_verifier<F>(group: &mut Group, f: F) -> MessageVerifier<'_, F>
    where
        F: Fn(&[u8]) -> Option<PublicKey>,
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
        MLSPlaintext::new(
            TEST_GROUP.to_vec(),
            epoch,
            sender,
            Content::Application(b"foo".to_vec()),
        )
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

        fn sign(&self, message: &mut MLSPlaintext, encrypted: bool) {
            let signing_context = MessageSigningContext {
                group_context: Some(&self.group.context),
                encrypted,
            };

            message.sign(&self.signing_key, &signing_context).unwrap();
        }
    }

    struct TestEnv {
        alice: TestMember,
        bob: TestMember,
    }

    impl TestEnv {
        fn new() -> Self {
            let (key_pkg_gen, signing_key) =
                test_member(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE, b"alice");

            let alice_key_package_generator = KeyPackageGenerator {
                protocol_version: key_pkg_gen.key_package.version,
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

            let (key_pkg_gen, signing_key) =
                test_member(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE, b"bob");
            let proposal = alice
                .group
                .add_proposal(key_pkg_gen.key_package.clone().into())
                .unwrap();

            let secret_store = InMemoryPskStore::default();

            let (commit_generation, welcome) = alice
                .group
                .commit_proposals(
                    vec![proposal],
                    &alice_key_package_generator,
                    false,
                    ControlEncryptionMode::Plaintext,
                    false,
                    &secret_store,
                )
                .unwrap();

            let welcome = match welcome.unwrap().payload {
                MLSMessagePayload::Welcome(w) => w,
                _ => panic!("Expected Welcome message"),
            };

            alice
                .group
                .process_pending_commit(commit_generation, &secret_store)
                .unwrap();
            let group = Group::from_welcome_message(
                TEST_PROTOCOL_VERSION,
                welcome,
                Some(alice.group.current_epoch_tree().unwrap().clone()),
                key_pkg_gen,
                &secret_store,
                |_, _| true,
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
        env.alice.sign(&mut message, false);
        add_membership_tag(&mut message, &env.alice.group);
        let mut verifier = make_verifier(&mut env.bob.group, |_| None);
        let _ = verifier.verify_plaintext(message).unwrap();
    }

    #[test]
    fn valid_ciphertext_is_verified() {
        let mut env = TestEnv::new();
        let mut message = env.alice.make_member_plaintext();
        env.alice.sign(&mut message, true);
        let message = env
            .alice
            .group
            .encrypt_plaintext(message, PaddingMode::None)
            .unwrap();
        let mut verifier = make_verifier(&mut env.bob.group, |_| None);
        let _ = verifier.decrypt_ciphertext(message).unwrap();
    }

    #[test]
    fn wire_format_is_signed() {
        let mut env = TestEnv::new();
        let mut message = env.alice.make_member_plaintext();
        env.alice.sign(&mut message, false);
        let message = env
            .alice
            .group
            .encrypt_plaintext(message, PaddingMode::None)
            .unwrap();
        let mut verifier = make_verifier(&mut env.bob.group, |_| None);
        let res = verifier.decrypt_ciphertext(message);
        assert_matches!(
            res,
            Err(GroupError::SignatureError(
                SignatureError::SignatureValidationFailed(_)
            ))
        );
    }

    #[test]
    fn plaintext_from_member_requires_membership_tag() {
        let mut env = TestEnv::new();
        let mut message = env.alice.make_member_plaintext();
        env.alice.sign(&mut message, false);
        let mut verifier = make_verifier(&mut env.bob.group, |_| None);
        let res = verifier.verify_plaintext(message);
        assert_matches!(res, Err(GroupError::InvalidMembershipTag));
    }

    #[test]
    fn valid_proposal_from_new_member_is_verified() {
        let (key_pkg_gen, signer) = test_member(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE, b"bob");
        let mut test_group = test_group(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE);

        let mut message = make_plaintext(Sender::NewMember, test_group.group.current_epoch());
        message.content.content = Content::Proposal(Proposal::Add(AddProposal {
            key_package: key_pkg_gen.key_package.into(),
        }));

        let signing_context = MessageSigningContext {
            group_context: Some(test_group.group.context()),
            encrypted: false,
        };

        message.sign(&signer, &signing_context).unwrap();
        let mut verifier = make_verifier(&mut test_group.group, |_| None);
        let _ = verifier.verify_plaintext(message).unwrap();
    }

    #[test]
    fn proposal_from_new_member_must_not_have_membership_tag() {
        let (key_pkg_gen, signer) = test_member(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE, b"bob");
        let mut test_group = test_group(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE);

        let mut message = make_plaintext(Sender::NewMember, test_group.group.current_epoch());
        message.content.content = Content::Proposal(Proposal::Add(AddProposal {
            key_package: key_pkg_gen.key_package.into(),
        }));

        let signing_context = MessageSigningContext {
            group_context: Some(test_group.group.context()),
            encrypted: false,
        };

        message.sign(&signer, &signing_context).unwrap();
        add_membership_tag(&mut message, &test_group.group);
        let mut verifier = make_verifier(&mut test_group.group, |_| None);
        let res = verifier.verify_plaintext(message);
        assert_matches!(res, Err(GroupError::InvalidMembershipTag));
    }

    #[test]
    fn valid_proposal_from_preconfigured_external_is_verified() {
        let (bob_key_pkg_gen, _) = test_member(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE, b"bob");
        let (_, ted_signer) = test_member(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE, b"ted");
        let mut test_group = test_group(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE);

        let mut message = make_plaintext(
            Sender::Preconfigured(TED_EXTERNAL_KEY_ID.to_vec()),
            test_group.group.current_epoch(),
        );
        message.content.content = Content::Proposal(Proposal::Add(AddProposal {
            key_package: bob_key_pkg_gen.key_package.into(),
        }));

        let signing_context = MessageSigningContext {
            group_context: None,
            encrypted: false,
        };

        message.sign(&ted_signer, &signing_context).unwrap();
        let mut verifier = make_verifier(&mut test_group.group, |external_id| {
            (external_id == TED_EXTERNAL_KEY_ID).then(|| ted_signer.to_public().unwrap())
        });
        let _ = verifier.verify_plaintext(message).unwrap();
    }

    #[test]
    fn proposal_from_preconfigured_external_must_not_have_membership_tag() {
        let (bob_key_pkg_gen, _) = test_member(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE, b"bob");
        let (_, ted_signer) = test_member(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE, b"ted");
        let mut test_group = test_group(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE);

        let mut message = make_plaintext(
            Sender::Preconfigured(TED_EXTERNAL_KEY_ID.to_vec()),
            test_group.group.current_epoch(),
        );
        message.content.content = Content::Proposal(Proposal::Add(AddProposal {
            key_package: bob_key_pkg_gen.key_package.into(),
        }));

        let signing_context = MessageSigningContext {
            group_context: None,
            encrypted: false,
        };

        message.sign(&ted_signer, &signing_context).unwrap();
        add_membership_tag(&mut message, &test_group.group);

        let mut verifier = make_verifier(&mut test_group.group, |external_id| {
            (external_id == TED_EXTERNAL_KEY_ID).then(|| ted_signer.to_public().unwrap())
        });

        let res = verifier.verify_plaintext(message);
        assert_matches!(res, Err(GroupError::InvalidMembershipTag));
    }

    #[test]
    fn ciphertext_from_self_fails_verification() {
        let mut env = TestEnv::new();
        let mut message = env.alice.make_member_plaintext();
        env.alice.sign(&mut message, true);
        let message = env
            .alice
            .group
            .encrypt_plaintext(message, PaddingMode::None)
            .unwrap();
        let mut verifier = make_verifier(&mut env.alice.group, |_| None);
        let res = verifier.decrypt_ciphertext(message);
        assert_matches!(res, Err(GroupError::CantProcessMessageFromSelf));
    }
}
