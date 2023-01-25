use std::collections::HashMap;

use crate::{
    extension::ExternalSendersExt,
    group::{GroupContext, GroupError, MLSPlaintext, Sender},
    identity::SigningIdentity,
    provider::crypto::{CipherSuiteProvider, SignaturePublicKey},
    signer::Signable,
    tree_kem::{node::LeafIndex, TreeKemPublic},
};

use super::{
    framing::Content,
    key_schedule::KeySchedule,
    message_signature::{MLSAuthenticatedContent, MessageSigningContext},
    proposal::{AddProposal, Proposal},
    state::GroupState,
};

#[derive(Debug)]
pub(crate) enum SignaturePublicKeysContainer<'a> {
    RatchetTree(&'a TreeKemPublic),
    List(&'a HashMap<LeafIndex, SignaturePublicKey>),
}

pub(crate) fn verify_plaintext_authentication<P: CipherSuiteProvider>(
    cipher_suite_provider: &P,
    plaintext: MLSPlaintext,
    key_schedule: Option<&KeySchedule>,
    self_index: Option<LeafIndex>,
    state: &GroupState,
) -> Result<MLSAuthenticatedContent, GroupError> {
    let tag = plaintext.membership_tag.clone();
    let auth_content = MLSAuthenticatedContent::from(plaintext);
    let context = &state.context;
    let external_signers = external_signers(context);
    let current_tree = &state.public_tree;

    // Verify the membership tag if needed
    match &auth_content.content.sender {
        Sender::Member(index) => {
            if let Some(key_schedule) = key_schedule {
                let expected_tag = &key_schedule.get_membership_tag(
                    &auth_content,
                    context,
                    cipher_suite_provider,
                )?;

                let plaintext_tag = tag.as_ref().ok_or(GroupError::InvalidMembershipTag)?;

                if expected_tag != plaintext_tag {
                    return Err(GroupError::InvalidMembershipTag);
                }
            }

            if self_index == Some(LeafIndex(*index)) {
                return Err(GroupError::CantProcessMessageFromSelf);
            }
        }
        Sender::NewMemberCommit | Sender::NewMemberProposal | Sender::External(_) => {
            tag.is_none()
                .then_some(())
                .ok_or(GroupError::MembershipTagForNonMember)?;
        }
    }

    // Verify that the signature on the MLSAuthenticatedContent verifies using the public key
    // from the credential stored at the leaf in the tree indicated by the sender field.
    verify_auth_content_signature(
        cipher_suite_provider,
        SignaturePublicKeysContainer::RatchetTree(current_tree),
        context,
        &auth_content,
        &external_signers,
    )?;

    Ok(auth_content)
}

fn external_signers(context: &GroupContext) -> Vec<SigningIdentity> {
    context
        .extensions
        .get_extension::<ExternalSendersExt>()
        .unwrap_or(None)
        .map_or(vec![], |extern_senders_ext| {
            extern_senders_ext.allowed_senders
        })
}

pub(crate) fn verify_auth_content_signature<P: CipherSuiteProvider>(
    cipher_suite_provider: &P,
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
    )?;

    let context = MessageSigningContext {
        group_context: Some(context),
    };

    auth_content
        .verify(cipher_suite_provider, &sender_public_key, &context)
        .map_err(|_| GroupError::InvalidSignature)?;

    Ok(())
}

fn signing_identity_for_sender(
    signature_keys_container: SignaturePublicKeysContainer,
    sender: &Sender,
    content: &Content,
    external_signers: &[SigningIdentity],
) -> Result<SignaturePublicKey, GroupError> {
    match sender {
        Sender::Member(leaf_index) => {
            signing_identity_for_member(signature_keys_container, LeafIndex(*leaf_index))
        }
        Sender::External(external_key_index) => {
            signing_identity_for_external(*external_key_index, external_signers)
        }
        Sender::NewMemberCommit => signing_identity_for_new_member_commit(content),
        Sender::NewMemberProposal => signing_identity_for_new_member_proposal(content),
    }
}

fn signing_identity_for_member(
    signature_keys_container: SignaturePublicKeysContainer,
    leaf_index: LeafIndex,
) -> Result<SignaturePublicKey, GroupError> {
    match signature_keys_container {
        SignaturePublicKeysContainer::RatchetTree(tree) => Ok(tree
            .get_leaf_node(leaf_index)?
            .signing_identity
            .signature_key
            .clone()), // TODO: We can probably get rid of this clone
        SignaturePublicKeysContainer::List(list) => list
            .get(&leaf_index)
            .ok_or(GroupError::LeafNotFound(*leaf_index))
            .cloned(),
    }
}

fn signing_identity_for_external(
    index: u32,
    external_signers: &[SigningIdentity],
) -> Result<SignaturePublicKey, GroupError> {
    external_signers
        .get(index as usize)
        .map(|spk| spk.signature_key.clone())
        .ok_or(GroupError::UnknownSigningIdentityForExternalSender)
}

fn signing_identity_for_new_member_commit(
    content: &Content,
) -> Result<SignaturePublicKey, GroupError> {
    match content {
        Content::Commit(commit) => {
            if let Some(path) = &commit.path {
                Ok(path.leaf_node.signing_identity.signature_key.clone())
            } else {
                Err(GroupError::MissingUpdatePathInExternalCommit)
            }
        }
        _ => Err(GroupError::ExpectedCommitForNewMemberCommit),
    }
}

fn signing_identity_for_new_member_proposal(
    content: &Content,
) -> Result<SignaturePublicKey, GroupError> {
    match content {
        Content::Proposal(proposal) => {
            if let Proposal::Add(AddProposal { key_package }) = proposal {
                Ok(key_package.leaf_node.signing_identity.signature_key.clone())
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
        client::test_utils::test_client_with_key_pkg,
        client_builder::{test_utils::TestClientConfig, Preferences},
        extension::{ExtensionList, ExternalSendersExt},
        group::{
            framing::WireFormat,
            membership_tag::MembershipTag,
            message_signature::{MLSAuthenticatedContent, MessageSignature, MessageSigningContext},
            proposal::{AddProposal, Proposal, RemoveProposal},
            test_utils::{test_group, test_group_custom, test_member, TestGroup},
            Content, Group, GroupError, MLSPlaintext, Sender,
        },
        identity::test_utils::get_test_signing_identity,
        key_package::KeyPackageGeneration,
        protocol_version::ProtocolVersion,
        provider::crypto::{test_utils::test_cipher_suite_provider, SignatureSecretKey},
        signer::Signable,
        tree_kem::node::LeafIndex,
    };
    use assert_matches::assert_matches;

    #[cfg(target_arch = "wasm32")]
    use wasm_bindgen_test::wasm_bindgen_test as test;

    use super::{verify_auth_content_signature, verify_plaintext_authentication};

    const TEST_PROTOCOL_VERSION: ProtocolVersion = ProtocolVersion::Mls10;
    const TEST_CIPHER_SUITE: CipherSuite = CipherSuite::Curve25519Aes128;

    async fn make_signed_plaintext(group: &mut Group<TestClientConfig>) -> MLSPlaintext {
        group
            .commit(vec![])
            .await
            .unwrap()
            .commit_message
            .into_plaintext()
            .unwrap()
    }

    struct TestEnv {
        alice: TestGroup,
        bob: TestGroup,
    }

    impl TestEnv {
        async fn new(encrypt_controls: bool) -> Self {
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
            )
            .await;

            let (bob_client, bob_key_pkg) =
                test_client_with_key_pkg(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE, "bob").await;

            let commit_output = alice
                .group
                .commit_builder()
                .add_member(bob_key_pkg)
                .await
                .unwrap()
                .build()
                .await
                .unwrap();

            alice.group.apply_pending_commit().await.unwrap();

            let (bob, _) = Group::join(
                commit_output.welcome_message.unwrap(),
                None,
                bob_client.config,
            )
            .await
            .unwrap();

            TestEnv {
                alice,
                bob: TestGroup { group: bob },
            }
        }
    }

    #[futures_test::test]
    async fn valid_plaintext_is_verified() {
        let mut env = TestEnv::new(false).await;

        let message = make_signed_plaintext(&mut env.alice.group).await;

        verify_plaintext_authentication(
            &env.bob.group.cipher_suite_provider,
            message,
            Some(&env.bob.group.key_schedule),
            None,
            &env.bob.group.state,
        )
        .unwrap();
    }

    #[futures_test::test]
    async fn valid_auth_content_is_verified() {
        let mut env = TestEnv::new(false).await;

        let message =
            MLSAuthenticatedContent::from(make_signed_plaintext(&mut env.alice.group).await);

        verify_auth_content_signature(
            &env.bob.group.cipher_suite_provider,
            super::SignaturePublicKeysContainer::RatchetTree(&env.bob.group.state.public_tree),
            env.bob.group.context(),
            &message,
            &[],
        )
        .unwrap();
    }

    #[futures_test::test]
    async fn invalid_plaintext_is_not_verified() {
        let mut env = TestEnv::new(false).await;
        let mut message = make_signed_plaintext(&mut env.alice.group).await;
        message.auth.signature = MessageSignature::from(b"test".to_vec());

        message.membership_tag = env
            .alice
            .group
            .key_schedule
            .get_membership_tag(
                &MLSAuthenticatedContent::from(message.clone()),
                env.alice.group.context(),
                &test_cipher_suite_provider(env.alice.group.cipher_suite()),
            )
            .unwrap()
            .into();

        let res = verify_plaintext_authentication(
            &env.bob.group.cipher_suite_provider,
            message,
            Some(&env.bob.group.key_schedule),
            None,
            &env.bob.group.state,
        );

        assert_matches!(res, Err(GroupError::InvalidSignature));
    }

    #[futures_test::test]
    async fn plaintext_from_member_requires_membership_tag() {
        let mut env = TestEnv::new(false).await;
        let mut message = make_signed_plaintext(&mut env.alice.group).await;
        message.membership_tag = None;

        let res = verify_plaintext_authentication(
            &env.bob.group.cipher_suite_provider,
            message,
            Some(&env.bob.group.key_schedule),
            None,
            &env.bob.group.state,
        );

        assert_matches!(res, Err(GroupError::InvalidMembershipTag));
    }

    #[futures_test::test]
    async fn plaintext_fails_with_invalid_membership_tag() {
        let mut env = TestEnv::new(false).await;
        let mut message = make_signed_plaintext(&mut env.alice.group).await;
        message.membership_tag = Some(MembershipTag::from(b"test".to_vec()));

        let res = verify_plaintext_authentication(
            &env.bob.group.cipher_suite_provider,
            message,
            Some(&env.bob.group.key_schedule),
            None,
            &env.bob.group.state,
        );

        assert_matches!(res, Err(GroupError::InvalidMembershipTag));
    }

    fn test_new_member_proposal<F>(
        key_pkg_gen: KeyPackageGeneration,
        signer: &SignatureSecretKey,
        test_group: &TestGroup,
        mut edit: F,
    ) -> MLSPlaintext
    where
        F: FnMut(&mut MLSAuthenticatedContent),
    {
        let mut content = MLSAuthenticatedContent::new_signed(
            &test_group.group.cipher_suite_provider,
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

        content
            .sign(
                &test_group.group.cipher_suite_provider,
                signer,
                &signing_context,
            )
            .unwrap();

        MLSPlaintext {
            content: content.content,
            auth: content.auth,
            membership_tag: None,
        }
    }

    #[futures_test::test]
    async fn valid_proposal_from_new_member_is_verified() {
        let test_group = test_group(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE).await;
        let (key_pkg_gen, signer) =
            test_member(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE, b"bob").await;
        let message = test_new_member_proposal(key_pkg_gen, &signer, &test_group, |_| {});

        verify_plaintext_authentication(
            &test_group.group.cipher_suite_provider,
            message,
            Some(&test_group.group.key_schedule),
            None,
            &test_group.group.state,
        )
        .unwrap();
    }

    #[futures_test::test]
    async fn proposal_from_new_member_must_not_have_membership_tag() {
        let test_group = test_group(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE).await;
        let (key_pkg_gen, signer) =
            test_member(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE, b"bob").await;

        let mut message = test_new_member_proposal(key_pkg_gen, &signer, &test_group, |_| {});
        message.membership_tag = Some(MembershipTag::from(vec![]));

        let res = verify_plaintext_authentication(
            &test_group.group.cipher_suite_provider,
            message,
            Some(&test_group.group.key_schedule),
            None,
            &test_group.group.state,
        );

        assert_matches!(res, Err(GroupError::MembershipTagForNonMember));
    }

    #[futures_test::test]
    async fn new_member_proposal_sender_must_be_add_proposal() {
        let test_group = test_group(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE).await;
        let (key_pkg_gen, signer) =
            test_member(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE, b"bob").await;

        let message = test_new_member_proposal(key_pkg_gen, &signer, &test_group, |mut msg| {
            msg.content.content = Content::Proposal(Proposal::Remove(RemoveProposal {
                to_remove: LeafIndex(0),
            }))
        });

        let res = verify_plaintext_authentication(
            &test_group.group.cipher_suite_provider,
            message,
            Some(&test_group.group.key_schedule),
            None,
            &test_group.group.state,
        );

        assert_matches!(
            res,
            Err(GroupError::ExpectedAddProposalForNewMemberProposal)
        );
    }

    #[futures_test::test]
    async fn new_member_commit_must_be_external_commit() {
        let test_group = test_group(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE).await;
        let (key_pkg_gen, signer) =
            test_member(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE, b"bob").await;

        let message = test_new_member_proposal(key_pkg_gen, &signer, &test_group, |mut msg| {
            msg.content.sender = Sender::NewMemberCommit;
        });

        let res = verify_plaintext_authentication(
            &test_group.group.cipher_suite_provider,
            message,
            Some(&test_group.group.key_schedule),
            None,
            &test_group.group.state,
        );

        assert_matches!(res, Err(GroupError::ExpectedCommitForNewMemberCommit));
    }

    #[futures_test::test]
    async fn valid_proposal_from_external_is_verified() {
        let (bob_key_pkg_gen, _) =
            test_member(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE, b"bob").await;

        let (ted_signing, ted_secret) =
            get_test_signing_identity(TEST_CIPHER_SUITE, b"ted".to_vec());

        let mut test_group = test_group(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE).await;
        let mut extensions = ExtensionList::default();

        extensions
            .set_extension(ExternalSendersExt {
                allowed_senders: vec![ted_signing],
            })
            .unwrap();

        test_group
            .group
            .commit_builder()
            .set_group_context_ext(extensions)
            .unwrap()
            .build()
            .await
            .unwrap();

        test_group.group.apply_pending_commit().await.unwrap();

        let message =
            test_new_member_proposal(bob_key_pkg_gen, &ted_secret, &test_group, |mut msg| {
                msg.content.sender = Sender::External(0)
            });

        verify_plaintext_authentication(
            &test_group.group.cipher_suite_provider,
            message,
            Some(&test_group.group.key_schedule),
            None,
            &test_group.group.state,
        )
        .unwrap();
    }

    #[futures_test::test]
    async fn external_proposal_must_be_from_valid_sender() {
        let (bob_key_pkg_gen, _) =
            test_member(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE, b"bob").await;
        let (_, ted_secret) = get_test_signing_identity(TEST_CIPHER_SUITE, b"ted".to_vec());
        let test_group = test_group(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE).await;

        let message =
            test_new_member_proposal(bob_key_pkg_gen, &ted_secret, &test_group, |mut msg| {
                msg.content.sender = Sender::External(0)
            });

        let res = verify_plaintext_authentication(
            &test_group.group.cipher_suite_provider,
            message,
            Some(&test_group.group.key_schedule),
            None,
            &test_group.group.state,
        );

        assert_matches!(
            res,
            Err(GroupError::UnknownSigningIdentityForExternalSender)
        );
    }

    #[futures_test::test]
    async fn proposal_from_external_sender_must_not_have_membership_tag() {
        let (bob_key_pkg_gen, _) =
            test_member(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE, b"bob").await;

        let (_, ted_secret) = get_test_signing_identity(TEST_CIPHER_SUITE, b"ted".to_vec());

        let test_group = test_group(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE).await;

        let mut message =
            test_new_member_proposal(bob_key_pkg_gen, &ted_secret, &test_group, |_| {});

        message.membership_tag = Some(MembershipTag::from(vec![]));

        let res = verify_plaintext_authentication(
            &test_group.group.cipher_suite_provider,
            message,
            Some(&test_group.group.key_schedule),
            None,
            &test_group.group.state,
        );

        assert_matches!(res, Err(GroupError::MembershipTagForNonMember));
    }

    #[futures_test::test]
    async fn plaintext_from_self_fails_verification() {
        let mut env = TestEnv::new(false).await;

        let message = make_signed_plaintext(&mut env.alice.group).await;

        let res = verify_plaintext_authentication(
            &env.alice.group.cipher_suite_provider,
            message,
            Some(&env.alice.group.key_schedule),
            Some(LeafIndex::new(env.alice.group.current_member_index())),
            &env.alice.group.state,
        );

        assert_matches!(res, Err(GroupError::CantProcessMessageFromSelf))
    }
}
