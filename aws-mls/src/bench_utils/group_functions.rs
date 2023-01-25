use aws_mls_core::group::GroupStateStorage;

use crate::{
    cipher_suite::CipherSuite,
    client::test_utils::{get_basic_client_builder, join_group, test_client_with_key_pkg},
    client_builder::{
        test_utils::{TestClientBuilder, TestClientConfig},
        Preferences,
    },
    client_config::ClientConfig,
    extension::ExtensionList,
    group::{
        epoch::PriorEpoch,
        framing::{Content, MLSMessage, Sender, WireFormat},
        message_processor::MessageProcessor,
        message_signature::MLSAuthenticatedContent,
        Commit, Group, GroupError, Snapshot,
    },
    identity::SigningIdentity,
    key_package::{KeyPackageGeneration, KeyPackageRef},
    protocol_version::ProtocolVersion,
    provider::{
        crypto::SignatureSecretKey, group_state::InMemoryGroupStateStorage,
        key_package::InMemoryKeyPackageRepository,
    },
};
use futures::StreamExt;

#[derive(Debug, serde::Serialize, serde::Deserialize)]

struct GroupInfo {
    session: Snapshot,
    epochs: Vec<u8>,
    key_packages: Vec<u8>,
    secrets: Vec<u8>,
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct TestCase {
    info: Vec<GroupInfo>,
}

async fn generate_test_cases() -> Vec<TestCase> {
    let cipher_suite = CipherSuite::Curve25519Aes128;

    futures::stream::iter([10, 50, 100])
        .then(|length| get_group_states(cipher_suite, length))
        .collect()
        .await
}

pub async fn load_test_cases() -> Vec<Vec<Group<TestClientConfig>>> {
    let tests: Vec<TestCase> = load_test_cases!(group_state, generate_test_cases().await, to_vec);

    futures::stream::iter(tests)
        .then(|test| {
            futures::stream::iter(test.info)
                .then(|group_info| async move {
                    let key_packages = serde_json::from_slice::<
                        Vec<(KeyPackageRef, KeyPackageGeneration)>,
                    >(&group_info.key_packages)
                    .unwrap();

                    let secrets = serde_json::from_slice::<
                        Vec<(SigningIdentity, SignatureSecretKey)>,
                    >(&group_info.secrets)
                    .unwrap();

                    let epochs =
                        serde_json::from_slice::<Vec<PriorEpoch>>(&group_info.epochs).unwrap();

                    let group_id = group_info.session.group_id().to_vec();

                    let client_builder = secrets.into_iter().fold(
                        TestClientBuilder::new_for_test(),
                        |builder, (identity, secret_key)| {
                            builder.signing_identity(
                                identity,
                                secret_key,
                                group_info.session.cipher_suite(),
                            )
                        },
                    );

                    client_builder
                        .group_state_storage(InMemoryGroupStateStorage::from_benchmark_data(
                            group_info.session,
                            epochs,
                        ))
                        .key_package_repo(InMemoryKeyPackageRepository::from_benchmark_data(
                            key_packages,
                        ))
                        .build()
                        .load_group(&group_id)
                        .await
                        .unwrap()
                })
                .collect()
        })
        .collect()
        .await
}

// creates group modifying code found in client.rs
pub async fn create_group(cipher_suite: CipherSuite, size: usize) -> Vec<Group<TestClientConfig>> {
    pub const TEST_PROTOCOL_VERSION: ProtocolVersion = ProtocolVersion::Mls10;
    pub const TEST_GROUP: &[u8] = b"group";

    let (alice, alice_identity) = get_basic_client_builder(cipher_suite, "alice");

    let alice = alice
        .preferences(
            Preferences::default()
                .with_ratchet_tree_extension(true)
                .with_control_encryption(true),
        )
        .build();

    let alice_group = alice
        .create_group_with_id(
            TEST_PROTOCOL_VERSION,
            cipher_suite,
            TEST_GROUP.to_vec(),
            alice_identity,
            ExtensionList::new(),
        )
        .await
        .unwrap();

    let mut groups = vec![alice_group];

    for n in 0..size - 1 {
        let (committer_group, other_groups) = groups.split_first_mut().unwrap();

        let (bob, bob_key_pkg) =
            test_client_with_key_pkg(TEST_PROTOCOL_VERSION, cipher_suite, &format!("bob{n}")).await;

        let (bob_group, _) =
            join_group(committer_group, other_groups.iter_mut(), bob_key_pkg, &bob)
                .await
                .unwrap();

        groups.push(bob_group);
    }

    groups
}

pub fn get_snapshot<C>(group: &Group<C>) -> Result<Vec<u8>, serde_json::Error>
where
    C: ClientConfig + Clone,
{
    serde_json::to_vec(&group.snapshot())
}

async fn get_group_states(cipher_suite: CipherSuite, size: usize) -> TestCase {
    let mut groups = create_group(cipher_suite, size).await;

    groups
        .iter_mut()
        .for_each(|group| group.write_to_storage().unwrap());

    let info = groups
        .into_iter()
        .map(|session| {
            let config = &session.config;

            let epoch_repo = config.group_state_storage();
            let exported_epochs = epoch_repo.export_epoch_data(session.group_id()).unwrap();

            let group_state = epoch_repo.state(session.group_id()).unwrap().unwrap();

            let epochs = serde_json::to_vec(&exported_epochs).unwrap();

            let key_repo = config.key_package_repo();
            let exported_key_packages = key_repo.export();
            let key_packages = serde_json::to_vec(&exported_key_packages).unwrap();

            let key_chain = config.keychain();
            let exported_key_chain = key_chain.export();
            let secrets = serde_json::to_vec(&exported_key_chain).unwrap();

            GroupInfo {
                session: group_state,
                epochs,
                key_packages,
                secrets,
            }
        })
        .collect();

    TestCase { info }
}

pub async fn commit_groups<C: ClientConfig>(
    mut container: Vec<Vec<Group<C>>>,
) -> Vec<Vec<Group<C>>> {
    for value in &mut container {
        commit_group(value).await;
    }

    container
}

pub async fn commit_group<C: ClientConfig>(container: &mut [Group<C>]) {
    for committer_index in 0..container.len() {
        let commit = container[committer_index]
            .commit(Vec::new())
            .await
            .unwrap()
            .commit_message;

        for (index, bob) in container.iter_mut().enumerate() {
            if index == committer_index {
                bob.apply_pending_commit().await.unwrap();
            } else {
                bob.process_incoming_message(commit.clone()).await.unwrap();
            }
        }
    }
}

pub fn create_fuzz_commit_message<C>(
    group_id: Vec<u8>,
    epoch: u64,
    authenticated_data: Vec<u8>,
    group: &mut Group<C>,
) -> Result<MLSMessage, GroupError>
where
    C: ClientConfig + Clone,
{
    let mut context = group.context().clone();
    context.group_id = group_id;
    context.epoch = epoch;

    let wire_format = if group.preferences().encrypt_controls {
        WireFormat::Cipher
    } else {
        WireFormat::Plain
    };

    let auth_content = MLSAuthenticatedContent::new_signed(
        group.cipher_suite_provider(),
        &context,
        Sender::Member(0),
        Content::Commit(Commit {
            proposals: Vec::new(),
            path: None,
        }),
        &group.signer()?,
        wire_format,
        authenticated_data,
    )?;

    group.format_for_wire(auth_content)
}
