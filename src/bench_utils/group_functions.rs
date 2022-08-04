use crate::cipher_suite::CipherSuite;
use crate::client::test_utils::{get_basic_config, join_group, test_client_with_key_pkg};
use crate::client::Client;
use crate::client_config::{ClientConfig, InMemoryClientConfig, Preferences};
use crate::extension::ExtensionList;
use crate::group::framing::{Content, MLSMessage, Sender, WireFormat};
use crate::group::message_signature::MLSAuthenticatedContent;
use crate::group::{Commit, Group, GroupError};
use crate::tree_kem::node::LeafIndex;
use crate::ProtocolVersion;
use std::collections::HashMap;

// creates group modifying code found in client.rs
pub fn create_group(
    cipher_suite: CipherSuite,
    size: usize,
    encrypt_controls: bool,
) -> (
    Client<InMemoryClientConfig>,
    Vec<Group<InMemoryClientConfig>>,
) {
    pub const TEST_PROTOCOL_VERSION: ProtocolVersion = ProtocolVersion::Mls10;
    pub const TEST_GROUP: &[u8] = b"group";

    let alice = get_basic_config(cipher_suite, "alice")
        .with_preferences(
            Preferences::default()
                .with_ratchet_tree_extension(true)
                .with_control_encryption(encrypt_controls),
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

    (alice, groups)
}

pub fn commit_groups(
    mut container: HashMap<usize, Vec<Group<InMemoryClientConfig>>>,
) -> HashMap<usize, Vec<Group<InMemoryClientConfig>>> {
    for value in container.values_mut() {
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
