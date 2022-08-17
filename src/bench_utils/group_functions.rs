use crate::{
    cipher_suite::CipherSuite,
    client::test_utils::{get_basic_config, join_group, test_client_with_key_pkg},
    client_config::{ClientConfig, InMemoryClientConfig, Preferences},
    epoch::Epoch,
    epoch::EpochRepository,
    extension::ExtensionList,
    group::{
        framing::{Content, MLSMessage, Sender, WireFormat},
        message_signature::MLSAuthenticatedContent,
        Commit, Group, GroupError, Snapshot,
    },
    key_package::KeyPackageGeneration,
    protocol_version::ProtocolVersion,
    signing_identity::SigningIdentity,
    tree_kem::node::LeafIndex,
};
use ferriscrypt::asym::ec_key::SecretKey;

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

fn generate_test_cases() -> Vec<TestCase> {
    let cipher_suite = CipherSuite::Curve25519Aes128;

    [10, 50, 100]
        .into_iter()
        .map(|length| get_group_states(cipher_suite, length))
        .collect()
}

pub fn load_test_cases() -> Vec<Vec<Group<InMemoryClientConfig>>> {
    let tests: Vec<TestCase> = load_test_cases!(group_state, generate_test_cases, to_vec);

    tests
        .into_iter()
        .map(|test| {
            test.info
                .into_iter()
                .map(|group_info| {
                    let epochs = serde_json::from_slice::<Vec<Epoch>>(&group_info.epochs).unwrap();

                    let key_packages = serde_json::from_slice::<Vec<KeyPackageGeneration>>(
                        &group_info.key_packages,
                    )
                    .unwrap();

                    let secrets = serde_json::from_slice::<Vec<(SigningIdentity, SecretKey)>>(
                        &group_info.secrets,
                    )
                    .unwrap();

                    let config = InMemoryClientConfig::new();

                    for (signing_identity, secret) in secrets {
                        config.keychain().insert(signing_identity, secret);
                    }

                    for epoch in epochs {
                        config.epoch_repo().insert(epoch).unwrap();
                    }

                    for key_pkg_gen in key_packages {
                        config.key_package_repo().insert(key_pkg_gen).unwrap();
                    }

                    Group::from_snapshot(config, group_info.session)
                })
                .collect()
        })
        .collect()
}

// creates group modifying code found in client.rs
pub fn create_group(cipher_suite: CipherSuite, size: usize) -> Vec<Group<InMemoryClientConfig>> {
    pub const TEST_PROTOCOL_VERSION: ProtocolVersion = ProtocolVersion::Mls10;
    pub const TEST_GROUP: &[u8] = b"group";

    let alice = get_basic_config(cipher_suite, "alice")
        .with_preferences(
            Preferences::default()
                .with_ratchet_tree_extension(true)
                .with_control_encryption(true),
        )
        .build_client();

    let alice_group = alice
        .create_group_with_id(
            TEST_PROTOCOL_VERSION,
            cipher_suite,
            TEST_GROUP.to_vec(),
            ExtensionList::new(),
        )
        .unwrap();

    let mut groups = vec![alice_group];

    (0..size - 1).for_each(|n| {
        let (committer_group, other_groups) = groups.split_first_mut().unwrap();

        let (bob, bob_key_pkg) =
            test_client_with_key_pkg(TEST_PROTOCOL_VERSION, cipher_suite, &format!("bob{n}"));

        let bob_group =
            join_group(committer_group, other_groups.iter_mut(), bob_key_pkg, &bob).unwrap();

        groups.push(bob_group);
    });

    groups
}

fn get_group_states(cipher_suite: CipherSuite, size: usize) -> TestCase {
    let sessions = create_group(cipher_suite, size);

    let info = sessions
        .into_iter()
        .map(|session| {
            let config = &session.config;

            let epoch_repo = config.epoch_repo();
            let exported_epochs = epoch_repo.export();
            let epochs = serde_json::to_vec(&exported_epochs).unwrap();

            let key_repo = config.key_package_repo();
            let exported_key_packages = key_repo.export();
            let key_packages = serde_json::to_vec(&exported_key_packages).unwrap();

            let key_chain = config.keychain();
            let exported_key_chain = key_chain.export();
            let secrets = serde_json::to_vec(&exported_key_chain).unwrap();

            let group_state = session.snapshot();

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

pub fn commit_groups(
    mut container: Vec<Vec<Group<InMemoryClientConfig>>>,
) -> Vec<Vec<Group<InMemoryClientConfig>>> {
    for value in &mut container {
        commit_group(value);
    }

    container
}

pub fn commit_group(container: &mut [Group<InMemoryClientConfig>]) {
    for committer_index in 0..container.len() {
        let (commit, _) = container[committer_index]
            .commit_proposals(Vec::new(), Vec::new())
            .unwrap();

        for (index, bob) in container.iter_mut().enumerate() {
            if index == committer_index {
                bob.process_pending_commit().unwrap();
            } else {
                bob.process_incoming_message(commit.clone()).unwrap();
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
        &context,
        Sender::Member(LeafIndex::new(0)),
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
