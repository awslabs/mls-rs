use std::collections::HashMap;

use crate::{
    cipher_suite::{CipherSuite, SignaturePublicKey},
    group::{
        ContentType, GroupContext, GroupError, KeyType, MLSCiphertext, MLSCiphertextContent,
        MLSContent, MLSPlaintext, MLSSenderData, MLSSenderDataAAD, Sender,
    },
    signer::Signable,
    signing_identity::SigningIdentity,
    tree_kem::{node::LeafIndex, TreeKemPublic},
    AddProposal, Proposal,
};
use ferriscrypt::asym::ec_key::PublicKey;
use tls_codec::{Deserialize, Serialize};

use super::{
    epoch::Epoch,
    framing::{Content, WireFormat},
    key_schedule::KeySchedule,
    message_signature::{MLSAuthenticatedContent, MessageSigningContext},
};

pub(crate) enum SignaturePublicKeysContainer<'a> {
    RatchetTree(&'a TreeKemPublic),
    List(&'a HashMap<LeafIndex, SignaturePublicKey>),
}

pub fn verify_plaintext_authentication(
    plaintext: MLSPlaintext,
    key_schedule: Option<&KeySchedule>,
    self_index: Option<LeafIndex>,
    current_tree: &TreeKemPublic,
    context: &GroupContext,
    external_signers: &[SigningIdentity],
) -> Result<MLSAuthenticatedContent, GroupError> {
    let tag = plaintext.membership_tag.clone();
    let auth_content = MLSAuthenticatedContent::from(plaintext);

    // Verify the membership tag if needed
    match &auth_content.content.sender {
        Sender::Member(index) => {
            if let Some(key_schedule) = key_schedule {
                let expected_tag = &key_schedule.get_membership_tag(&auth_content, context)?;

                let plaintext_tag = tag.as_ref().ok_or(GroupError::InvalidMembershipTag)?;

                if expected_tag != plaintext_tag {
                    return Err(GroupError::InvalidMembershipTag);
                }
            }

            if self_index == Some(*index) {
                return Err(GroupError::CantProcessMessageFromSelf);
            }
        }
        Sender::NewMemberCommit | Sender::NewMemberProposal | Sender::External(_) => {
            tag.is_none()
                .then(|| ())
                .ok_or(GroupError::MembershipTagForNonMember)?;
        }
    }

    // Verify that the signature on the MLSAuthenticatedContent verifies using the public key
    // from the credential stored at the leaf in the tree indicated by the sender field.
    verify_auth_content_signature(
        SignaturePublicKeysContainer::RatchetTree(current_tree),
        context,
        &auth_content,
        external_signers,
    )?;

    Ok(auth_content)
}

pub(crate) fn decrypt_ciphertext(
    ciphertext: MLSCiphertext,
    msg_epoch: &mut Epoch,
) -> Result<MLSAuthenticatedContent, GroupError> {
    // Decrypt the sender data with the derived sender_key and sender_nonce from the message
    // epoch's key schedule
    let (sender_key, sender_nonce) = msg_epoch.get_sender_data_params(&ciphertext.ciphertext)?;

    let sender_data_aad = MLSSenderDataAAD {
        group_id: msg_epoch.context.group_id.clone(),
        epoch: msg_epoch.context.epoch,
        content_type: ciphertext.content_type,
    };

    let decrypted_sender = sender_key.decrypt_from_vec(
        &ciphertext.encrypted_sender_data,
        Some(&sender_data_aad.tls_serialize_detached()?),
        sender_nonce,
    )?;

    let sender_data = MLSSenderData::tls_deserialize(&mut &*decrypted_sender)?;
    if msg_epoch.self_index == sender_data.sender {
        return Err(GroupError::CantProcessMessageFromSelf);
    }

    // Grab a decryption key from the message epoch's key schedule
    let key_type = match &ciphertext.content_type {
        ContentType::Application => KeyType::Application,
        _ => KeyType::Handshake,
    };

    // Decrypt the content of the message using the grabbed key
    let decrypted_content = msg_epoch.decrypt(
        sender_data.sender,
        sender_data.generation,
        key_type,
        &ciphertext,
        &sender_data.reuse_guard,
    )?;

    let ciphertext_content = MLSCiphertextContent::tls_deserialize(&mut &*decrypted_content)?;

    // Build the MLS plaintext object and process it
    let auth_content = MLSAuthenticatedContent {
        wire_format: WireFormat::Cipher,
        content: MLSContent {
            group_id: ciphertext.group_id.clone(),
            epoch: ciphertext.epoch,
            sender: Sender::Member(sender_data.sender),
            authenticated_data: ciphertext.authenticated_data,
            content: ciphertext_content.content,
        },
        auth: ciphertext_content.auth,
    };

    // Verify that the signature on the MLSPlaintext message verifies using the public key
    // from the credential stored at the leaf in the tree indicated by the sender field.
    verify_auth_content_signature(
        SignaturePublicKeysContainer::List(&msg_epoch.signature_public_keys),
        &msg_epoch.context,
        &auth_content,
        &[],
    )?;

    Ok(auth_content)
}

pub(crate) fn verify_auth_content_signature(
    signature_keys_container: SignaturePublicKeysContainer,
    context: &GroupContext,
    auth_content: &MLSAuthenticatedContent,
    external_signers: &[SigningIdentity],
) -> Result<(), GroupError> {
    let sender_public_key = signing_identity_for_sender(
        signature_keys_container,
        &auth_content.content.sender,
        &auth_content.content.content,
        external_signers,
        context.cipher_suite,
    )?;

    let context = MessageSigningContext {
        group_context: Some(context),
    };

    auth_content.verify(&sender_public_key, &context)?;

    Ok(())
}

fn signing_identity_for_sender(
    signature_keys_container: SignaturePublicKeysContainer,
    sender: &Sender,
    content: &Content,
    external_signers: &[SigningIdentity],
    cipher_suite: CipherSuite,
) -> Result<PublicKey, GroupError> {
    match sender {
        Sender::Member(leaf_index) => {
            signing_identity_for_member(signature_keys_container, *leaf_index, cipher_suite)
        }
        Sender::External(external_key_index) => {
            signing_identity_for_external(cipher_suite, *external_key_index, external_signers)
        }
        Sender::NewMemberCommit => signing_identity_for_new_member_commit(content, cipher_suite),
        Sender::NewMemberProposal => {
            signing_identity_for_new_member_proposal(content, cipher_suite)
        }
    }
}

fn signing_identity_for_member(
    signature_keys_container: SignaturePublicKeysContainer,
    leaf_index: LeafIndex,
    cipher_suite: CipherSuite,
) -> Result<PublicKey, GroupError> {
    match signature_keys_container {
        SignaturePublicKeysContainer::RatchetTree(tree) => Ok(tree
            .get_leaf_node(leaf_index)?
            .signing_identity
            .public_key(tree.cipher_suite)?),
        SignaturePublicKeysContainer::List(list) => list
            .get(&leaf_index)
            .ok_or(GroupError::LeafNotFound(*leaf_index))
            .and_then(|sig_key| {
                PublicKey::from_uncompressed_bytes(sig_key, cipher_suite.signature_key_curve())
                    .map_err(GroupError::from)
            }),
    }
}

fn signing_identity_for_external(
    cipher_suite: CipherSuite,
    index: u32,
    external_signers: &[SigningIdentity],
) -> Result<PublicKey, GroupError> {
    let external_identity = external_signers
        .get(index as usize)
        .ok_or(GroupError::UnknownSigningIdentityForExternalSender)?;

    external_identity
        .public_key(cipher_suite)
        .map_err(Into::into)
}

fn signing_identity_for_new_member_commit(
    content: &Content,
    cipher_suite: CipherSuite,
) -> Result<PublicKey, GroupError> {
    match content {
        Content::Commit(commit) => {
            if let Some(path) = &commit.path {
                Ok(path.leaf_node.signing_identity.public_key(cipher_suite)?)
            } else {
                Err(GroupError::MissingUpdatePathInExternalCommit)
            }
        }
        _ => Err(GroupError::ExpectedCommitForNewMemberCommit),
    }
}

fn signing_identity_for_new_member_proposal(
    content: &Content,
    cipher_suite: CipherSuite,
) -> Result<PublicKey, GroupError> {
    match content {
        Content::Proposal(proposal) => {
            if let Proposal::Add(AddProposal { key_package }) = proposal {
                Ok(key_package
                    .leaf_node
                    .signing_identity
                    .public_key(cipher_suite)?)
            } else {
                Err(GroupError::ExpectedAddProposalForNewMemberProposal)
            }
        }
        _ => Err(GroupError::ExpectedAddProposalForNewMemberProposal),
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        cipher_suite::CipherSuite,
        client_config::{test_utils::test_config, ClientConfig, InMemoryClientConfig, Preferences},
        group::{
            framing::{MLSCiphertext, WireFormat},
            membership_tag::MembershipTag,
            message_signature::{MLSAuthenticatedContent, MessageSigningContext},
            message_verifier::decrypt_ciphertext,
            proposal::{AddProposal, Proposal},
            test_utils::{test_group, test_group_custom, test_member, TestGroup},
            Content, Group, GroupError, MLSMessagePayload, MLSPlaintext, Sender,
        },
        key_package::KeyPackageGeneration,
        signer::{Signable, Signer},
        signing_identity::test_utils::get_test_signing_identity,
        tree_kem::node::LeafIndex,
        EpochRepository, ProtocolVersion, RemoveProposal,
    };
    use assert_matches::assert_matches;

    #[cfg(target_arch = "wasm32")]
    use wasm_bindgen_test::wasm_bindgen_test as test;

    use super::verify_plaintext_authentication;

    const TEST_PROTOCOL_VERSION: ProtocolVersion = ProtocolVersion::Mls10;
    const TEST_CIPHER_SUITE: CipherSuite = CipherSuite::Curve25519Aes128;

    fn make_signed_plaintext(group: &mut Group<InMemoryClientConfig>) -> MLSPlaintext {
        group
            .commit_proposals(vec![], None, vec![])
            .unwrap()
            .0
            .into_plaintext()
            .unwrap()
    }

    fn make_signed_ciphertext(group: &mut Group<InMemoryClientConfig>) -> MLSCiphertext {
        group
            .commit_proposals(vec![], None, vec![])
            .unwrap()
            .0
            .into_ciphertext()
            .unwrap()
    }

    fn decrypt(
        ciphertext: MLSCiphertext,
        group: &mut Group<InMemoryClientConfig>,
    ) -> Result<MLSAuthenticatedContent, GroupError> {
        let mut epoch = group
            .config
            .epoch_repo()
            .get(group.group_id(), group.current_epoch())
            .unwrap()
            .unwrap();

        let res = decrypt_ciphertext(ciphertext, epoch.inner_mut());

        group.config.epoch_repo().insert(epoch).unwrap();

        res
    }

    struct TestEnv {
        alice: TestGroup,
        bob: TestGroup,
    }

    impl TestEnv {
        fn new(encrypt_controls: bool) -> Self {
            let mut alice = test_group_custom(
                TEST_PROTOCOL_VERSION,
                TEST_CIPHER_SUITE,
                None,
                None,
                Some(
                    Preferences::default()
                        .with_ratchet_tree_extension(true)
                        .with_control_encryption(encrypt_controls),
                ),
            );

            let (bob_key_pkg, bob_signing_key) =
                test_member(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE, b"bob");

            let proposal = alice
                .group
                .add_proposal(bob_key_pkg.key_package.clone())
                .unwrap();

            let (_, welcome) = alice
                .group
                .commit_proposals(vec![proposal], None, vec![])
                .unwrap();

            let welcome = match welcome.unwrap().payload {
                MLSMessagePayload::Welcome(w) => w,
                _ => panic!("Expected Welcome message"),
            };

            alice.group.process_pending_commit().unwrap();

            let bob = Group::join(
                TEST_PROTOCOL_VERSION,
                welcome,
                None,
                test_config(
                    bob_signing_key,
                    bob_key_pkg,
                    alice.group.config.preferences(),
                ),
            )
            .unwrap();

            Self {
                alice,
                bob: TestGroup { group: bob },
            }
        }
    }

    #[test]
    fn valid_plaintext_is_verified() {
        let mut env = TestEnv::new(false);

        let message = make_signed_plaintext(&mut env.alice.group);

        verify_plaintext_authentication(
            message,
            Some(&env.bob.group.key_schedule),
            None,
            &env.bob.group.core.current_tree,
            env.bob.group.context(),
            &[],
        )
        .unwrap();
    }

    #[test]
    fn valid_ciphertext_is_verified() {
        let mut env = TestEnv::new(true);
        let message = make_signed_ciphertext(&mut env.alice.group);

        decrypt(message, &mut env.bob.group).unwrap();
    }

    #[test]
    fn plaintext_from_member_requires_membership_tag() {
        let mut env = TestEnv::new(false);
        let mut message = make_signed_plaintext(&mut env.alice.group);
        message.membership_tag = None;

        let res = verify_plaintext_authentication(
            message,
            Some(&env.bob.group.key_schedule),
            None,
            &env.bob.group.core.current_tree,
            env.bob.group.context(),
            &[],
        );

        assert_matches!(res, Err(GroupError::InvalidMembershipTag));
    }

    fn test_new_member_proposal<F, S>(
        key_pkg_gen: KeyPackageGeneration,
        signer: &S,
        test_group: &TestGroup,
        mut edit: F,
    ) -> MLSPlaintext
    where
        F: FnMut(&mut MLSAuthenticatedContent),
        S: Signer,
    {
        let mut content = MLSAuthenticatedContent::new_signed(
            test_group.group.context(),
            Sender::NewMemberProposal,
            Content::Proposal(Proposal::Add(AddProposal {
                key_package: key_pkg_gen.key_package,
            })),
            signer,
            WireFormat::Plain,
            vec![],
        )
        .unwrap();

        edit(&mut content);

        let signing_context = MessageSigningContext {
            group_context: Some(test_group.group.context()),
        };

        content.sign(signer, &signing_context).unwrap();

        MLSPlaintext {
            content: content.content,
            auth: content.auth,
            membership_tag: None,
        }
    }

    #[test]
    fn valid_proposal_from_new_member_is_verified() {
        let test_group = test_group(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE);
        let (key_pkg_gen, signer) = test_member(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE, b"bob");
        let message = test_new_member_proposal(key_pkg_gen, &signer, &test_group, |_| {});

        verify_plaintext_authentication(
            message,
            Some(&test_group.group.key_schedule),
            None,
            &test_group.group.core.current_tree,
            test_group.group.context(),
            &[],
        )
        .unwrap();
    }

    #[test]
    fn proposal_from_new_member_must_not_have_membership_tag() {
        let test_group = test_group(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE);
        let (key_pkg_gen, signer) = test_member(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE, b"bob");

        let mut message = test_new_member_proposal(key_pkg_gen, &signer, &test_group, |_| {});
        message.membership_tag = Some(MembershipTag::from(vec![]));

        let res = verify_plaintext_authentication(
            message,
            Some(&test_group.group.key_schedule),
            None,
            &test_group.group.core.current_tree,
            test_group.group.context(),
            &[],
        );

        assert_matches!(res, Err(GroupError::MembershipTagForNonMember));
    }

    #[test]
    fn new_member_proposal_sender_must_be_add_proposal() {
        let test_group = test_group(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE);
        let (key_pkg_gen, signer) = test_member(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE, b"bob");

        let message = test_new_member_proposal(key_pkg_gen, &signer, &test_group, |mut msg| {
            msg.content.content = Content::Proposal(Proposal::Remove(RemoveProposal {
                to_remove: LeafIndex(0),
            }))
        });

        let res = verify_plaintext_authentication(
            message,
            Some(&test_group.group.key_schedule),
            None,
            &test_group.group.core.current_tree,
            test_group.group.context(),
            &[],
        );

        assert_matches!(
            res,
            Err(GroupError::ExpectedAddProposalForNewMemberProposal)
        );
    }

    #[test]
    fn new_member_commit_must_be_external_commit() {
        let test_group = test_group(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE);
        let (key_pkg_gen, signer) = test_member(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE, b"bob");

        let message = test_new_member_proposal(key_pkg_gen, &signer, &test_group, |mut msg| {
            msg.content.sender = Sender::NewMemberCommit;
        });

        let res = verify_plaintext_authentication(
            message,
            Some(&test_group.group.key_schedule),
            None,
            &test_group.group.core.current_tree,
            test_group.group.context(),
            &[],
        );

        assert_matches!(res, Err(GroupError::ExpectedCommitForNewMemberCommit));
    }

    #[test]
    fn valid_proposal_from_external_is_verified() {
        let (bob_key_pkg_gen, _) = test_member(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE, b"bob");

        let (ted_signing, ted_secret) =
            get_test_signing_identity(TEST_CIPHER_SUITE, b"ted".to_vec());

        let test_group = test_group(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE);

        let message =
            test_new_member_proposal(bob_key_pkg_gen, &ted_secret, &test_group, |mut msg| {
                msg.content.sender = Sender::External(0)
            });

        verify_plaintext_authentication(
            message,
            Some(&test_group.group.key_schedule),
            None,
            &test_group.group.core.current_tree,
            test_group.group.context(),
            &[ted_signing],
        )
        .unwrap();
    }

    #[test]
    fn external_proposal_must_be_from_valid_sender() {
        let (bob_key_pkg_gen, _) = test_member(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE, b"bob");
        let (_, ted_secret) = get_test_signing_identity(TEST_CIPHER_SUITE, b"ted".to_vec());
        let test_group = test_group(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE);

        let message =
            test_new_member_proposal(bob_key_pkg_gen, &ted_secret, &test_group, |mut msg| {
                msg.content.sender = Sender::External(0)
            });

        let res = verify_plaintext_authentication(
            message,
            Some(&test_group.group.key_schedule),
            None,
            &test_group.group.core.current_tree,
            test_group.group.context(),
            &[],
        );

        assert_matches!(
            res,
            Err(GroupError::UnknownSigningIdentityForExternalSender)
        );
    }

    #[test]
    fn proposal_from_external_sender_must_not_have_membership_tag() {
        let (bob_key_pkg_gen, _) = test_member(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE, b"bob");

        let (ted_signing, ted_secret) =
            get_test_signing_identity(TEST_CIPHER_SUITE, b"ted".to_vec());

        let test_group = test_group(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE);

        let mut message =
            test_new_member_proposal(bob_key_pkg_gen, &ted_secret, &test_group, |_| {});

        message.membership_tag = Some(MembershipTag::from(vec![]));

        let res = verify_plaintext_authentication(
            message,
            Some(&test_group.group.key_schedule),
            None,
            &test_group.group.core.current_tree,
            test_group.group.context(),
            &[ted_signing],
        );

        assert_matches!(res, Err(GroupError::MembershipTagForNonMember));
    }

    #[test]
    fn plaintext_from_self_fails_verification() {
        let mut env = TestEnv::new(false);

        let message = make_signed_plaintext(&mut env.alice.group);

        let res = verify_plaintext_authentication(
            message,
            Some(&env.alice.group.key_schedule),
            Some(LeafIndex::new(env.alice.group.current_user_index())),
            &env.alice.group.core.current_tree,
            env.alice.group.context(),
            &[],
        );

        assert_matches!(res, Err(GroupError::CantProcessMessageFromSelf))
    }

    #[test]
    fn ciphertext_from_self_fails_verification() {
        let mut env = TestEnv::new(true);
        let message = make_signed_ciphertext(&mut env.alice.group);

        let res = decrypt(message, &mut env.alice.group);

        assert_matches!(res, Err(GroupError::CantProcessMessageFromSelf));
    }
}
