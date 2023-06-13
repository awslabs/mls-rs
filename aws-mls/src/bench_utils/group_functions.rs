use aws_mls_codec::{MlsDecode, MlsEncode, MlsSize};
use aws_mls_core::{
    crypto::SignatureSecretKey, group::GroupStateStorage, key_package::KeyPackageData,
};
use aws_mls_crypto_openssl::OpensslCryptoProvider;

use crate::{
    cipher_suite::CipherSuite,
    client::{
        test_utils::{
            get_basic_client_builder, test_client_with_key_pkg, TEST_CIPHER_SUITE,
            TEST_PROTOCOL_VERSION,
        },
        MlsError,
    },
    client_builder::{
        test_utils::TestClientBuilder, BaseConfig, Preferences, WithCryptoProvider,
        WithIdentityProvider, WithKeychain,
    },
    client_config::ClientConfig,
    group::{
        epoch::PriorEpoch,
        framing::{Content, MLSMessage, Sender, WireFormat},
        message_processor::MessageProcessor,
        message_signature::AuthenticatedContent,
        snapshot::Snapshot,
        Commit, Group,
    },
    identity::{test_utils::BasicWithCustomProvider, SigningIdentity},
    storage_provider::in_memory::{
        InMemoryGroupStateStorage, InMemoryKeyPackageStorage, InMemoryKeychainStorage,
    },
    ExtensionList,
};

pub type TestClientConfig = WithIdentityProvider<
    BasicWithCustomProvider,
    WithKeychain<InMemoryKeychainStorage, WithCryptoProvider<OpensslCryptoProvider, BaseConfig>>,
>;

#[derive(Debug, MlsEncode, MlsDecode, MlsSize)]
struct GroupInfo {
    session: Snapshot,
    epochs: Vec<u8>,
    key_packages: Vec<u8>,
    secrets: Vec<u8>,
}

#[derive(Debug, MlsEncode, MlsDecode, MlsSize)]
pub struct TestCase {
    info: Vec<GroupInfo>,
}

#[maybe_async::maybe_async]
async fn generate_test_cases() -> Vec<TestCase> {
    let cipher_suite = TEST_CIPHER_SUITE;

    let mut cases = Vec::new();

    for length in [10, 50, 100] {
        cases.push(get_group_states(cipher_suite, length).await)
    }

    cases
}

#[maybe_async::async_impl]
async fn load_or_generate() -> Vec<TestCase> {
    load_test_case_mls!(group_state, generate_test_cases().await, to_vec)
}

#[maybe_async::sync_impl]
fn load_or_generate() -> Vec<TestCase> {
    load_test_case_mls!(group_state, generate_test_cases(), to_vec)
}

#[maybe_async::maybe_async]
pub async fn load_test_cases() -> Vec<Vec<Group<TestClientConfig>>> {
    let tests: Vec<TestCase> = load_or_generate().await;

    let mut group_collection = Vec::new();

    for test in tests {
        let mut groups = Vec::new();

        for group_info in test.info {
            let key_packages = Vec::<(Vec<u8>, KeyPackageData)>::mls_decode(
                &mut group_info.key_packages.as_slice(),
            )
            .unwrap();

            let secrets = Vec::<(SigningIdentity, SignatureSecretKey)>::mls_decode(
                &mut group_info.secrets.as_slice(),
            )
            .unwrap();

            let epochs = Vec::<PriorEpoch>::mls_decode(&mut group_info.epochs.as_slice()).unwrap();

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

            let group = client_builder
                .group_state_storage(InMemoryGroupStateStorage::from_benchmark_data(
                    group_info.session,
                    epochs,
                ))
                .key_package_repo(InMemoryKeyPackageStorage::from_benchmark_data(key_packages))
                .build()
                .load_group(&group_id)
                .await
                .unwrap();

            groups.push(group)
        }

        group_collection.push(groups);
    }

    group_collection
}

// creates group modifying code found in client.rs
#[maybe_async::maybe_async]
pub async fn create_group(cipher_suite: CipherSuite, size: usize) -> Vec<Group<TestClientConfig>> {
    pub const TEST_GROUP: &[u8] = b"group";

    let (alice, alice_identity) = get_basic_client_builder(cipher_suite, "alice");

    let mut preferences = Preferences::default();

    preferences = preferences.with_ratchet_tree_extension(true);

    #[cfg(feature = "private_message")]
    {
        preferences = preferences.with_control_encryption(true);
    }

    let alice = alice.preferences(preferences).build();

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

        let commit_output = committer_group
            .commit_builder()
            .add_member(bob_key_pkg)
            .unwrap()
            .build()
            .await
            .unwrap();

        committer_group.apply_pending_commit().await.unwrap();

        for group in other_groups {
            group
                .process_incoming_message(commit_output.commit_message.clone())
                .await
                .unwrap();
        }

        let (bob_group, _) = bob
            .join_group(
                Some(&committer_group.export_tree().unwrap()),
                commit_output.welcome_message.unwrap(),
            )
            .await
            .unwrap();

        groups.push(bob_group);
    }

    groups
}

pub fn get_snapshot<C>(group: &Group<C>) -> Result<Vec<u8>, aws_mls_codec::Error>
where
    C: ClientConfig + Clone,
{
    group.snapshot().mls_encode_to_vec()
}

#[maybe_async::maybe_async]
async fn get_group_states(cipher_suite: CipherSuite, size: usize) -> TestCase {
    let groups = create_group(cipher_suite, size).await;

    let mut group_info = Vec::new();

    for mut group in groups {
        group.write_to_storage().await.unwrap();

        let config = &group.config;

        let epoch_repo = config.group_state_storage();
        let exported_epochs = epoch_repo.export_epoch_data(group.group_id()).unwrap();

        let group_state = epoch_repo.state(group.group_id()).await.unwrap().unwrap();

        let epochs = exported_epochs.mls_encode_to_vec().unwrap();

        let key_repo = config.key_package_repo();
        let exported_key_packages = key_repo.key_packages();
        let key_packages = exported_key_packages.mls_encode_to_vec().unwrap();

        let key_chain = config.keychain();
        let exported_key_chain = key_chain.identities();
        let secrets = exported_key_chain.mls_encode_to_vec().unwrap();

        let info = GroupInfo {
            session: group_state,
            epochs,
            key_packages,
            secrets,
        };

        group_info.push(info)
    }

    TestCase { info: group_info }
}

#[maybe_async::maybe_async]
pub async fn commit_groups<C: ClientConfig>(
    mut container: Vec<Vec<Group<C>>>,
) -> Vec<Vec<Group<C>>> {
    for value in &mut container {
        commit_group(value).await;
    }

    container
}

#[maybe_async::maybe_async]
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

#[maybe_async::maybe_async]
pub async fn create_fuzz_commit_message<C>(
    group_id: Vec<u8>,
    epoch: u64,
    authenticated_data: Vec<u8>,
    group: &mut Group<C>,
) -> Result<MLSMessage, MlsError>
where
    C: ClientConfig + Clone,
{
    let mut context = group.context().clone();
    context.group_id = group_id;
    context.epoch = epoch;

    #[cfg(feature = "private_message")]
    let wire_format = if group.preferences().encrypt_controls {
        WireFormat::PrivateMessage
    } else {
        WireFormat::PublicMessage
    };

    #[cfg(not(feature = "private_message"))]
    let wire_format = WireFormat::PublicMessage;

    let auth_content = AuthenticatedContent::new_signed(
        group.cipher_suite_provider(),
        &context,
        Sender::Member(0),
        Content::Commit(alloc::boxed::Box::new(Commit {
            proposals: Vec::new(),
            path: None,
        })),
        &group.signer().await?,
        wire_format,
        authenticated_data,
    )?;

    group.format_for_wire(auth_content)
}
