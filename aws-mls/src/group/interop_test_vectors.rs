use aws_mls_core::crypto::{CipherSuite, CipherSuiteProvider, SignaturePublicKey};
use tls_codec::{Deserialize, Serialize};

use crate::{
    client::test_utils::{TestClientConfig, TEST_PROTOCOL_VERSION},
    client_builder::Preferences,
    crypto::test_utils::{test_cipher_suite_provider, try_test_cipher_suite_provider},
    group::{test_utils::test_group_custom, PaddingMode},
    tree_kem::{leaf_node::test_utils::get_basic_test_node, node::LeafIndex},
};

use super::{
    confirmation_tag::ConfirmationTag,
    epoch::EpochSecrets,
    framing::{Content, WireFormat},
    internal::AuthenticatedContent,
    message_processor::{EventOrContent, MessageProcessor},
    proposal::{Proposal, RemoveProposal},
    secret_tree::test_utils::get_test_tree,
    test_utils::random_bytes,
    Commit, Group, GroupContext, MLSMessage, Sender,
};

const FRAMING_N_LEAVES: u32 = 2;

#[derive(serde::Serialize, serde::Deserialize, Debug, Default, Clone)]
struct FramingTestCase {
    #[serde(flatten)]
    pub context: InteropGroupContext,

    #[serde(with = "hex::serde")]
    pub signature_priv: Vec<u8>,
    #[serde(with = "hex::serde")]
    pub signature_pub: Vec<u8>,

    #[serde(with = "hex::serde")]
    pub encryption_secret: Vec<u8>,
    #[serde(with = "hex::serde")]
    pub sender_data_secret: Vec<u8>,
    #[serde(with = "hex::serde")]
    pub membership_key: Vec<u8>,

    #[serde(with = "hex::serde")]
    pub proposal: Vec<u8>,
    #[serde(with = "hex::serde")]
    pub proposal_priv: Vec<u8>,
    #[serde(with = "hex::serde")]
    pub proposal_pub: Vec<u8>,

    #[serde(with = "hex::serde")]
    pub commit: Vec<u8>,
    #[serde(with = "hex::serde")]
    pub commit_priv: Vec<u8>,
    #[serde(with = "hex::serde")]
    pub commit_pub: Vec<u8>,

    #[serde(with = "hex::serde")]
    pub application: Vec<u8>,
    #[serde(with = "hex::serde")]
    pub application_priv: Vec<u8>,
}

impl FramingTestCase {
    fn random<P: CipherSuiteProvider>(cs: &P) -> Self {
        let mut context = InteropGroupContext::random(cs);
        context.cipher_suite = cs.cipher_suite().into();

        let (signature_priv, signature_pub) = cs.signature_key_generate().unwrap();

        Self {
            context,
            signature_priv: signature_priv.to_vec(),
            signature_pub: signature_pub.to_vec(),
            encryption_secret: random_bytes(cs.kdf_extract_size()),
            sender_data_secret: random_bytes(cs.kdf_extract_size()),
            membership_key: random_bytes(cs.kdf_extract_size()),
            ..Default::default()
        }
    }
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Default, Clone)]
pub struct InteropGroupContext {
    pub cipher_suite: u16,
    #[serde(with = "hex::serde")]
    pub group_id: Vec<u8>,
    pub epoch: u64,
    #[serde(with = "hex::serde")]
    pub tree_hash: Vec<u8>,
    #[serde(with = "hex::serde")]
    pub confirmed_transcript_hash: Vec<u8>,
}

impl InteropGroupContext {
    fn random<P: CipherSuiteProvider>(cs: &P) -> Self {
        Self {
            cipher_suite: cs.cipher_suite().into(),
            group_id: random_bytes(cs.kdf_extract_size()),
            epoch: 0x121212,
            tree_hash: random_bytes(cs.kdf_extract_size()),
            confirmed_transcript_hash: random_bytes(cs.kdf_extract_size()),
        }
    }
}

impl From<InteropGroupContext> for GroupContext {
    fn from(ctx: InteropGroupContext) -> Self {
        Self {
            cipher_suite: ctx.cipher_suite.into(),
            protocol_version: TEST_PROTOCOL_VERSION,
            group_id: ctx.group_id,
            epoch: ctx.epoch,
            tree_hash: ctx.tree_hash,
            confirmed_transcript_hash: ctx.confirmed_transcript_hash.into(),
            extensions: vec![].into(),
        }
    }
}

// The test vector can be found here:
// https://github.com/mlswg/mls-implementations/blob/main/test-vectors/message-protection.json
#[futures_test::test]
async fn framing_proposal() {
    let test_cases: Vec<FramingTestCase> =
        load_test_cases!(framing, generate_framing_test_vector().await);

    for test_case in test_cases.into_iter() {
        let Some(cs) = try_test_cipher_suite_provider(test_case.context.cipher_suite) else {
            continue;
        };

        let mut to_check = vec![
            test_case.proposal_priv.clone(),
            test_case.proposal_pub.clone(),
        ];

        for enable_encryption in [true, false] {
            let proposal = Proposal::tls_deserialize(&mut &*test_case.proposal).unwrap();

            let built = make_group(&test_case, true, enable_encryption, &cs)
                .await
                .proposal_message(proposal, vec![])
                .await
                .unwrap()
                .tls_serialize_detached()
                .unwrap();

            to_check.push(built);
        }

        let proposal = Proposal::tls_deserialize(&mut &*test_case.proposal).unwrap();

        for message in to_check {
            match process_message(&test_case, &message, &cs).await {
                Content::Proposal(p) => assert_eq!(&p, &proposal),
                _ => panic!("received value not proposal"),
            };
        }
    }
}

// The test vector can be found here:
// https://github.com/mlswg/mls-implementations/blob/main/test-vectors/message-protection.json
#[futures_test::test]
async fn framing_application() {
    let test_cases: Vec<FramingTestCase> =
        load_test_cases!(framing, generate_framing_test_vector().await);

    for test_case in test_cases.into_iter() {
        let Some(cs) = try_test_cipher_suite_provider(test_case.context.cipher_suite) else {
            continue;
        };

        let built_priv = make_group(&test_case, true, true, &cs)
            .await
            .encrypt_application_message(&test_case.application, vec![])
            .await
            .unwrap()
            .tls_serialize_detached()
            .unwrap();

        for message in [&test_case.application_priv, &built_priv] {
            match process_message(&test_case, message, &cs).await {
                Content::Application(data) => assert_eq!(data.as_ref(), &test_case.application),
                _ => panic!("decrypted value not application data"),
            };
        }
    }
}

// The test vector can be found here:
// https://github.com/mlswg/mls-implementations/blob/main/test-vectors/message-protection.json
#[futures_test::test]
async fn framing_comit() {
    let test_cases: Vec<FramingTestCase> =
        load_test_cases!(framing, generate_framing_test_vector().await);

    for test_case in test_cases.into_iter() {
        let Some(cs) = try_test_cipher_suite_provider(test_case.context.cipher_suite) else {
            continue;
        };

        let commit = Commit::tls_deserialize(&mut &*test_case.commit).unwrap();

        let mut auth_content = AuthenticatedContent::new_signed(
            &cs,
            &test_case.context.clone().into(),
            Sender::Member(1),
            Content::Commit(commit.clone()),
            &test_case.signature_priv.clone().into(),
            WireFormat::PublicMessage,
            vec![],
        )
        .unwrap();

        auth_content.auth.confirmation_tag = Some(ConfirmationTag::empty(&cs));

        let mut to_check = vec![test_case.commit_priv.clone(), test_case.commit_pub.clone()];

        for enable_encryption in [true, false] {
            let built = make_group(&test_case, true, enable_encryption, &cs)
                .await
                .format_for_wire(auth_content.clone())
                .unwrap()
                .tls_serialize_detached()
                .unwrap();

            to_check.push(built);
        }

        for message in to_check {
            match process_message(&test_case, &message, &cs).await {
                Content::Commit(c) => assert_eq!(&c, &commit),
                _ => panic!("received value not commit"),
            };
        }
        let commit = Commit::tls_deserialize(&mut &*test_case.commit).unwrap();

        match process_message(&test_case, &test_case.commit_priv.clone(), &cs).await {
            Content::Commit(c) => assert_eq!(&c, &commit),
            _ => panic!("received value not commit"),
        };
    }
}

async fn generate_framing_test_vector() -> Vec<FramingTestCase> {
    let mut test_vector = vec![];

    for cs in CipherSuite::all() {
        let cs = test_cipher_suite_provider(cs);

        let mut test_case = FramingTestCase::random(&cs);

        // Generate private application message
        test_case.application = cs.random_bytes_vec(42).unwrap();

        let application_priv = make_group(&test_case, true, true, &cs)
            .await
            .encrypt_application_message(&test_case.application, vec![])
            .await
            .unwrap();

        test_case.application_priv = application_priv.tls_serialize_detached().unwrap();

        // Generate private and public proposal message
        let proposal = Proposal::Remove(RemoveProposal {
            to_remove: LeafIndex(2),
        });

        test_case.proposal = proposal.tls_serialize_detached().unwrap();

        let mut group = make_group(&test_case, true, false, &cs).await;
        let proposal_pub = group.proposal_message(proposal.clone(), vec![]).await;
        test_case.proposal_pub = proposal_pub.unwrap().tls_serialize_detached().unwrap();

        let mut group = make_group(&test_case, true, true, &cs).await;
        let proposal_priv = group.proposal_message(proposal, vec![]).await.unwrap();
        test_case.proposal_priv = proposal_priv.tls_serialize_detached().unwrap();

        // Generate private and public commit message
        let commit = Commit {
            proposals: vec![],
            path: None,
        };

        test_case.commit = commit.tls_serialize_detached().unwrap();

        let mut auth_content = AuthenticatedContent::new_signed(
            &cs,
            group.context(),
            Sender::Member(1),
            Content::Commit(commit.clone()),
            &group.signer().await.unwrap(),
            WireFormat::PublicMessage,
            vec![],
        )
        .unwrap();

        auth_content.auth.confirmation_tag = Some(ConfirmationTag::empty(&cs));

        let mut group = make_group(&test_case, true, false, &cs).await;
        let commit_pub = group.format_for_wire(auth_content.clone()).unwrap();
        test_case.commit_pub = commit_pub.tls_serialize_detached().unwrap();

        let mut auth_content = AuthenticatedContent::new_signed(
            &cs,
            group.context(),
            Sender::Member(1),
            Content::Commit(commit),
            &group.signer().await.unwrap(),
            WireFormat::PrivateMessage,
            vec![],
        )
        .unwrap();

        auth_content.auth.confirmation_tag = Some(ConfirmationTag::empty(&cs));

        let mut group = make_group(&test_case, true, true, &cs).await;
        let commit_priv = group.format_for_wire(auth_content.clone()).unwrap();
        test_case.commit_priv = commit_priv.tls_serialize_detached().unwrap();

        test_vector.push(test_case);
    }

    test_vector
}

async fn make_group<P: CipherSuiteProvider>(
    test_case: &FramingTestCase,
    for_send: bool,
    control_encryption_enabled: bool,
    cs: &P,
) -> Group<TestClientConfig> {
    let preferences = Preferences::default()
        .with_ratchet_tree_extension(true)
        .with_padding_mode(PaddingMode::None)
        .with_control_encryption(control_encryption_enabled);

    let mut group = test_group_custom(
        TEST_PROTOCOL_VERSION,
        test_case.context.cipher_suite.into(),
        None,
        None,
        Some(preferences),
    )
    .await
    .group;

    // Add a leaf for the sender. It will get index 1.
    let mut leaf = get_basic_test_node(cs.cipher_suite(), "leaf").await;

    leaf.signing_identity.signature_key = SignaturePublicKey::from(test_case.signature_pub.clone());

    group
        .state
        .public_tree
        .add_leaves(vec![leaf], &group.config.0.identity_provider, cs)
        .await
        .unwrap();

    // Convince the group that their index is 1 if they send or 0 if they receive.
    group.private_tree.self_index = LeafIndex(if for_send { 1 } else { 0 });

    // Convince the group that their signing key is the one from the test case
    let member = group.current_member_signing_identity().unwrap().clone();
    group.config.0.keychain.delete(&member);

    group.config.0.keychain.insert(
        group.current_member_signing_identity().unwrap().clone(),
        SignaturePublicKey::from(test_case.signature_priv.clone())
            .to_vec()
            .into(),
        cs.cipher_suite(),
    );

    // Set the group context and secrets
    let context = GroupContext::from(test_case.context.clone());
    let secret_tree = get_test_tree(test_case.encryption_secret.clone(), FRAMING_N_LEAVES);

    let secrets = EpochSecrets {
        secret_tree,
        resumption_secret: vec![0_u8; cs.kdf_extract_size()].into(),
        sender_data_secret: test_case.sender_data_secret.clone().into(),
    };

    group.epoch_secrets = secrets;
    group.state.context = context;
    let membership_key = test_case.membership_key.clone();
    group.key_schedule.set_membership_key(membership_key);

    group
}

async fn process_message<P: CipherSuiteProvider>(
    test_case: &FramingTestCase,
    message: &[u8],
    cs: &P,
) -> Content {
    // Enabling encryption doesn't matter for processing
    let mut group = make_group(test_case, false, true, cs).await;
    let message = MLSMessage::tls_deserialize(&mut &*message).unwrap();
    let evt_or_cont = group.get_event_from_incoming_message(message);

    match evt_or_cont.await.unwrap() {
        EventOrContent::Content(content) => content.content.content,
        EventOrContent::Event(_) => panic!("expected content, got event"),
    }
}
