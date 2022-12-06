use assert_matches::assert_matches;
use aws_mls::cipher_suite::{CipherSuite, SignaturePublicKey};
use aws_mls::client::{
    BaseConfig, Client, ClientBuilder, Preferences, WithIdentityProvider, WithKeychain,
};
use aws_mls::extension::ExtensionList;
use aws_mls::group::MLSMessage;
use aws_mls::group::{Event, Group, GroupError};
use aws_mls::identity::SigningIdentity;
use aws_mls::identity::{BasicCredential, Credential, MlsCredential};
use aws_mls::key_package::KeyPackage;
use aws_mls::protocol_version::ProtocolVersion;
use aws_mls::provider::keychain::FirstIdentitySelector;
use aws_mls::provider::{identity::BasicIdentityProvider, keychain::InMemoryKeychain};
use ferriscrypt::rand::SecureRng;
use rand::{prelude::IteratorRandom, prelude::SliceRandom, Rng, SeedableRng};

#[cfg(target_arch = "wasm32")]
use wasm_bindgen_test::{wasm_bindgen_test as test, wasm_bindgen_test_configure};

#[cfg(target_arch = "wasm32")]
wasm_bindgen_test_configure!(run_in_browser);

type TestClientConfig = WithIdentityProvider<
    BasicIdentityProvider,
    WithKeychain<InMemoryKeychain<FirstIdentitySelector>, BaseConfig>,
>;

// The same method exists in `credential::test_utils` but is not compiled without the `test` flag.
pub fn get_test_basic_credential(identity: Vec<u8>) -> Credential {
    BasicCredential {
        credential: identity,
    }
    .to_credential()
    .unwrap()
}

fn test_params() -> impl Iterator<Item = (ProtocolVersion, CipherSuite, bool)> {
    ProtocolVersion::all().flat_map(|p| {
        CipherSuite::all().flat_map(move |cs| {
            [false, true]
                .into_iter()
                .map(move |encrypt| (p, cs, encrypt))
        })
    })
}

fn generate_client(
    cipher_suite: CipherSuite,
    id: Vec<u8>,
    preferences: Preferences,
) -> Client<TestClientConfig> {
    let key = cipher_suite.generate_signing_key().unwrap();
    let credential = get_test_basic_credential(id);

    let signing_identity =
        SigningIdentity::new(credential, SignaturePublicKey::try_from(&key).unwrap());

    ClientBuilder::new()
        .identity_provider(BasicIdentityProvider::new())
        .single_signing_identity(signing_identity, key)
        .preferences(preferences)
        .build()
}

fn test_create(
    protocol_version: ProtocolVersion,
    cipher_suite: CipherSuite,
    preferences: Preferences,
) {
    println!(
        "Testing group creation for cipher suite: {protocol_version:?} {cipher_suite:?}, participants: 1, {preferences:?}"
    );

    let alice = generate_client(cipher_suite, b"alice".to_vec(), preferences.clone());
    let bob = generate_client(cipher_suite, b"bob".to_vec(), preferences);

    let bob_key_pkg = bob
        .generate_key_package(protocol_version, cipher_suite)
        .unwrap();

    // Alice creates a group and adds bob
    let mut alice_group = alice
        .create_group_with_id(
            protocol_version,
            cipher_suite,
            b"group".to_vec(),
            ExtensionList::default(),
        )
        .unwrap();

    let welcome = alice_group
        .commit_builder()
        .add_member(bob_key_pkg)
        .unwrap()
        .build()
        .unwrap()
        .welcome_message;

    // Upon server confirmation, alice applies the commit to her own state
    alice_group.apply_pending_commit().unwrap();

    let tree = alice_group.export_tree().unwrap();

    // Bob receives the welcome message and joins the group
    let (bob_group, _) = bob.join_group(Some(&tree), welcome.unwrap()).unwrap();

    assert!(Group::equal_group_state(&alice_group, &bob_group));
}

#[test]
fn test_create_group() {
    test_params().for_each(|(protocol_version, cs, encrypt_controls)| {
        let preferences = Preferences::default()
            .with_control_encryption(encrypt_controls)
            .with_ratchet_tree_extension(false);

        test_create(protocol_version, cs, preferences);
    });
}

fn get_test_groups(
    protocol_version: ProtocolVersion,
    cipher_suite: CipherSuite,
    num_participants: usize,
    preferences: Preferences,
) -> (Group<TestClientConfig>, Vec<Group<TestClientConfig>>) {
    let (creator_group, receiver_groups, _) = get_test_groups_clients(
        protocol_version,
        cipher_suite,
        num_participants,
        preferences,
    );
    (creator_group, receiver_groups)
}

fn get_test_groups_clients(
    protocol_version: ProtocolVersion,
    cipher_suite: CipherSuite,
    num_participants: usize,
    preferences: Preferences,
) -> (
    Group<TestClientConfig>,
    Vec<Group<TestClientConfig>>,
    Vec<Client<TestClientConfig>>,
) {
    // Create the group with Alice as the group initiator
    let creator = generate_client(cipher_suite, b"alice".to_vec(), preferences.clone());

    let mut creator_group = creator
        .create_group_with_id(
            protocol_version,
            cipher_suite,
            b"group".to_vec(),
            ExtensionList::default(),
        )
        .unwrap();

    // Generate random clients that will be members of the group
    let receiver_clients = (0..num_participants)
        .map(|i| {
            generate_client(
                cipher_suite,
                format!("bob{i}").into_bytes(),
                preferences.clone(),
            )
        })
        .collect::<Vec<_>>();

    let receiver_keys = receiver_clients
        .iter()
        .map(|client| {
            client
                .generate_key_package(protocol_version, cipher_suite)
                .unwrap()
        })
        .collect::<Vec<KeyPackage>>();

    // Add the generated clients to the group the creator made

    let welcome = receiver_keys
        .iter()
        .fold(creator_group.commit_builder(), |builder, item| {
            builder.add_member(item.clone()).unwrap()
        })
        .build()
        .unwrap()
        .welcome_message;

    // Creator can confirm the commit was processed by the server
    let update = creator_group.apply_pending_commit().unwrap();

    assert!(update.active);
    assert_eq!(update.epoch, 1);

    assert!(receiver_keys.into_iter().all(|kpg| creator_group
        .roster()
        .iter()
        .any(|m| m.signing_identity() == kpg.signing_identity())));

    assert!(update.roster_update.removed.is_empty());

    // Export the tree for receivers
    let tree_data = creator_group.export_tree().unwrap();

    // All the receivers will be able to join the group
    let receiver_groups = receiver_clients
        .iter()
        .map(|client| {
            client
                .join_group(Some(&tree_data), welcome.clone().unwrap())
                .unwrap()
                .0
        })
        .collect::<Vec<_>>();

    for one_receiver in &receiver_groups {
        assert!(Group::equal_group_state(&creator_group, one_receiver));
    }

    (creator_group, receiver_groups, receiver_clients)
}

fn add_random_members(
    first_id: usize,
    num_added: usize,
    sender: usize,
    committer: usize,
    groups: &mut Vec<Group<TestClientConfig>>,
    cipher_suite: CipherSuite,
    preferences: Preferences,
) {
    let (key_packages, new_clients): (Vec<_>, Vec<_>) = (0..num_added)
        .map(|i| {
            let id = first_id + i;
            let new_client = generate_client(
                cipher_suite,
                format!("dave-{id}").into(),
                preferences.clone(),
            );

            let key_package = new_client
                .generate_key_package(ProtocolVersion::Mls10, cipher_suite)
                .unwrap();

            (key_package, new_client)
        })
        .unzip();

    let add_proposals: Vec<MLSMessage> = key_packages
        .into_iter()
        .map(|kp| groups[sender].propose_add(kp, vec![]).unwrap())
        .collect();

    for (i, group) in groups.iter_mut().enumerate() {
        if i != sender {
            add_proposals.iter().for_each(|p| {
                group.process_incoming_message(p.clone()).unwrap();
            })
        }
    }

    let commit_output = groups[committer].commit(vec![]).unwrap();

    for (i, group) in groups.iter_mut().enumerate() {
        if i == committer {
            group.apply_pending_commit().unwrap();
        } else {
            group
                .process_incoming_message(commit_output.commit_message.clone())
                .unwrap();
        }
    }

    let tree_data = groups[committer].export_tree().unwrap();

    groups.extend(new_clients.iter().map(|client| {
        client
            .join_group(
                Some(&tree_data),
                commit_output.welcome_message.clone().unwrap(),
            )
            .unwrap()
            .0
    }));
}

fn remove_members(
    removed_members: Vec<usize>,
    sender: usize,
    committer: usize,
    groups: &mut Vec<Group<TestClientConfig>>,
) {
    let remove_proposals: Vec<MLSMessage> = removed_members
        .iter()
        .map(|removed| {
            let to_remove = groups[*removed].group_stats().unwrap().current_index;
            groups[sender].propose_remove(to_remove, vec![]).unwrap()
        })
        .collect();

    for (i, group) in groups.iter_mut().enumerate() {
        if i != sender {
            remove_proposals.iter().for_each(|p| {
                group.process_incoming_message(p.clone()).unwrap();
            })
        }
    }

    let commit = groups[committer].commit(vec![]).unwrap().commit_message;

    for (i, group) in groups.iter_mut().enumerate() {
        if i == committer {
            group.apply_pending_commit().unwrap();
        } else {
            group.process_incoming_message(commit.clone()).unwrap();
        }
    }

    let mut index = 0;
    groups.retain(|_| {
        index += 1;
        !(removed_members.contains(&(index - 1)))
    });
}

#[test]
fn test_many_commits() {
    let cipher_suite = CipherSuite::Curve25519Aes128;
    let preferences = Preferences::default();

    let (creator_group, mut groups) = get_test_groups(
        ProtocolVersion::Mls10,
        cipher_suite,
        10,
        preferences.clone(),
    );

    groups.push(creator_group);
    let mut rng = rand::rngs::StdRng::from_seed([42; 32]);

    let mut random_member_first_index = 0;
    for i in 0..100 {
        println!("running step {}", i);
        let num_removed = rng.gen_range(0..groups.len());
        let mut members = (0..groups.len()).choose_multiple(&mut rng, num_removed + 1);
        let sender = members.pop().unwrap();
        remove_members(members, sender, sender, &mut groups);

        let num_added = rng.gen_range(2..12);
        let sender = rng.gen_range(0..groups.len());

        add_random_members(
            random_member_first_index,
            num_added,
            sender,
            sender,
            &mut groups,
            cipher_suite,
            preferences.clone(),
        );

        random_member_first_index += num_added;
    }
}

fn test_empty_commits(
    protocol_version: ProtocolVersion,
    cipher_suite: CipherSuite,
    participants: usize,
    preferences: Preferences,
) {
    println!(
        "Testing empty commits for cipher suite: {:?}, participants: {}, {:?}",
        cipher_suite, participants, preferences,
    );

    let (mut creator_group, mut receiver_groups) =
        get_test_groups(protocol_version, cipher_suite, participants, preferences);

    // Loop through each participant and send a path update

    for i in 0..receiver_groups.len() {
        // Create the commit
        let commit_output = receiver_groups[i].commit(vec![]).unwrap();

        assert!(commit_output.welcome_message.is_none());

        // Creator group processes the commit
        creator_group
            .process_incoming_message(commit_output.commit_message.clone())
            .unwrap();

        // Receiver groups process the commit
        for (j, one_receiver) in receiver_groups.iter_mut().enumerate() {
            if i == j {
                one_receiver.apply_pending_commit().unwrap();
            } else {
                one_receiver
                    .process_incoming_message(commit_output.commit_message.clone())
                    .unwrap();
            }

            assert!(Group::equal_group_state(one_receiver, &creator_group));
        }
    }
}

#[test]
fn test_group_path_updates() {
    test_params().for_each(|(protocol_version, cs, encrypt_controls)| {
        test_empty_commits(
            protocol_version,
            cs,
            10,
            Preferences::default()
                .with_control_encryption(encrypt_controls)
                .with_ratchet_tree_extension(false),
        );
    });
}

fn test_update_proposals(
    protocol_version: ProtocolVersion,
    cipher_suite: CipherSuite,
    participants: usize,
    preferences: Preferences,
) {
    println!(
        "Testing update proposals for cipher suite: {:?}, participants: {}, {:?}",
        cipher_suite, participants, preferences,
    );

    let (mut creator_group, mut receiver_groups) =
        get_test_groups(protocol_version, cipher_suite, participants, preferences);

    // Create an update from the ith member, have the ith + 1 member commit it
    for i in 0..receiver_groups.len() - 1 {
        let update_proposal_msg = receiver_groups[i].propose_update(vec![]).unwrap();

        // Everyone should process the proposal
        creator_group
            .process_incoming_message(update_proposal_msg.clone())
            .unwrap();

        (0..receiver_groups.len()).for_each(|j| {
            if i != j {
                receiver_groups[j]
                    .process_incoming_message(update_proposal_msg.clone())
                    .unwrap();
            }
        });

        // Everyone receives the commit
        let committer_index = i + 1;

        let commit_output = receiver_groups[committer_index].commit(vec![]).unwrap();

        assert!(commit_output.welcome_message.is_none());

        creator_group
            .process_incoming_message(commit_output.commit_message.clone())
            .unwrap();

        for (j, receiver) in receiver_groups.iter_mut().enumerate() {
            let update = if j == committer_index {
                receiver.apply_pending_commit()
            } else {
                let state_update_message = receiver
                    .process_incoming_message(commit_output.commit_message.clone())
                    .unwrap()
                    .event;

                match state_update_message {
                    Event::Commit(update) => Ok(update),
                    _ => panic!("Expected commit result"),
                }
            }
            .unwrap();

            assert!(update.active);
            assert_eq!(update.epoch, (i as u64) + 2);
            assert!(update.roster_update.added.is_empty());
            assert!(update.roster_update.removed.is_empty());
            assert!(Group::equal_group_state(receiver, &creator_group));
        }
    }
}

#[test]
fn test_group_update_proposals() {
    test_params().for_each(|(protocol_version, cs, encrypt_controls)| {
        test_update_proposals(
            protocol_version,
            cs,
            10,
            Preferences::default()
                .with_control_encryption(encrypt_controls)
                .with_ratchet_tree_extension(false),
        );
    });
}

fn test_remove_proposals(
    protocol_version: ProtocolVersion,
    cipher_suite: CipherSuite,
    participants: usize,
    preferences: Preferences,
) {
    println!(
        "Testing remove proposals for cipher suite: {:?}, participants: {}, {:?}",
        cipher_suite, participants, preferences,
    );

    let (mut creator_group, mut receiver_groups) =
        get_test_groups(protocol_version, cipher_suite, participants, preferences);

    let mut epoch_count = 1;

    // Remove people from the group one at a time
    while receiver_groups.len() > 1 {
        let group_to_remove = receiver_groups.choose(&mut rand::thread_rng()).unwrap();
        let to_remove_index = group_to_remove.current_member_index();

        let commit_output = creator_group
            .commit_builder()
            .remove_member(to_remove_index)
            .unwrap()
            .build()
            .unwrap();

        assert!(commit_output.welcome_message.is_none());

        // Process the removal in the creator group
        creator_group.apply_pending_commit().unwrap();

        epoch_count += 1;

        // Process the removal in the other receiver groups
        for one_group in receiver_groups.iter_mut() {
            let expect_inactive = one_group.current_member_index() == to_remove_index;

            let state_update = one_group
                .process_incoming_message(commit_output.commit_message.clone())
                .unwrap();

            let update = match state_update.event {
                Event::Commit(update) => update,
                _ => panic!("Expected commit result"),
            };

            assert_eq!(update.epoch, epoch_count as u64);
            assert!(update.roster_update.added.is_empty());

            if expect_inactive {
                assert!(!update.active)
            } else {
                assert!(update
                    .roster_update
                    .removed
                    .iter()
                    .any(|member| member.index() == to_remove_index));
                assert!(update.active)
            }
        }

        receiver_groups.retain(|group| group.current_member_index() != to_remove_index);

        for one_group in receiver_groups.iter() {
            assert!(Group::equal_group_state(one_group, &creator_group))
        }
    }
}

#[test]
fn test_group_remove_proposals() {
    test_params().for_each(|(protocol_version, cs, encrypt_controls)| {
        test_remove_proposals(
            protocol_version,
            cs,
            10,
            Preferences::default()
                .with_control_encryption(encrypt_controls)
                .with_ratchet_tree_extension(false),
        );
    });
}

fn test_application_messages(
    protocol_version: ProtocolVersion,
    cipher_suite: CipherSuite,
    participants: usize,
    message_count: usize,
    preferences: Preferences,
) {
    println!(
        "Testing application messages for cipher suite: {:?} {:?}, participants: {}, message count: {}, {:?}",
        protocol_version, cipher_suite, participants, message_count, preferences,
    );

    let (mut creator_group, mut receiver_groups) =
        get_test_groups(protocol_version, cipher_suite, participants, preferences);

    // Loop through each participant and send application messages
    for i in 0..receiver_groups.len() {
        let test_message = SecureRng::gen(1024).unwrap();

        for _ in 0..message_count {
            // Encrypt the application message
            let ciphertext = receiver_groups[i]
                .encrypt_application_message(&test_message, vec![])
                .unwrap();

            // Creator receives the application message
            creator_group
                .process_incoming_message(ciphertext.clone())
                .unwrap();

            // Everyone else receives the application message
            (0..receiver_groups.len()).for_each(|j| {
                if i != j {
                    let decrypted = receiver_groups[j]
                        .process_incoming_message(ciphertext.clone())
                        .unwrap();

                    assert_matches!(decrypted.event, Event::ApplicationMessage(m) if m == test_message);
                }
            });
        }
    }
}

#[test]
fn test_out_of_order_application_messages() {
    let (mut alice_group, mut receiver_groups) = get_test_groups(
        ProtocolVersion::Mls10,
        CipherSuite::Curve25519Aes128,
        1,
        Preferences::default(),
    );

    let bob_group = receiver_groups.get_mut(0).unwrap();

    let mut ciphertexts = vec![alice_group
        .encrypt_application_message(&[0], vec![])
        .unwrap()];

    ciphertexts.push(
        alice_group
            .encrypt_application_message(&[1], vec![])
            .unwrap(),
    );

    let commit = alice_group.commit(vec![]).unwrap().commit_message;

    alice_group.apply_pending_commit().unwrap();

    bob_group.process_incoming_message(commit).unwrap();

    ciphertexts.push(
        alice_group
            .encrypt_application_message(&[2], vec![])
            .unwrap(),
    );

    ciphertexts.push(
        alice_group
            .encrypt_application_message(&[3], vec![])
            .unwrap(),
    );

    for i in [3, 2, 1, 0] {
        assert_matches!(
            bob_group.process_incoming_message(ciphertexts[i].clone()).unwrap().event,
            Event::ApplicationMessage(m) if m == [i as u8]
        );
    }
}

#[test]
fn test_group_application_messages() {
    test_params().for_each(|(protocol_version, cs, encrypt_controls)| {
        test_application_messages(
            protocol_version,
            cs,
            10,
            20,
            Preferences::default()
                .with_control_encryption(encrypt_controls)
                .with_ratchet_tree_extension(false),
        );
    });
}

fn processing_message_from_self_returns_error(
    protocol_version: ProtocolVersion,
    cipher_suite: CipherSuite,
    preferences: Preferences,
) {
    println!(
        "Verifying that processing one's own message returns an error for cipher suite: {:?}, {:?}",
        cipher_suite, preferences,
    );

    let (mut creator_group, _) = get_test_groups(protocol_version, cipher_suite, 1, preferences);

    let commit = creator_group.commit(Vec::new()).unwrap().commit_message;

    let error = creator_group.process_incoming_message(commit).unwrap_err();

    assert_matches!(error, GroupError::CantProcessMessageFromSelf);
}

#[test]
fn test_processing_message_from_self_returns_error() {
    test_params().for_each(|(protocol_version, cs, encrypt_controls)| {
        processing_message_from_self_returns_error(
            protocol_version,
            cs,
            Preferences::default()
                .with_control_encryption(encrypt_controls)
                .with_ratchet_tree_extension(false),
        );
    });
}

fn external_commits_work(protocol_version: ProtocolVersion, cipher_suite: CipherSuite) {
    let creator = generate_client(cipher_suite, b"alice-0".to_vec(), Default::default());

    let creator_group = creator
        .create_group_with_id(
            protocol_version,
            cipher_suite,
            b"group".to_vec(),
            ExtensionList::default(),
        )
        .unwrap();

    const PARTICIPANT_COUNT: usize = 10;

    let others = (1..PARTICIPANT_COUNT)
        .map(|i| {
            generate_client(
                cipher_suite,
                format!("alice-{i}").into_bytes(),
                Default::default(),
            )
        })
        .collect::<Vec<_>>();

    let mut rng = rand::thread_rng();

    let mut groups = others
        .iter()
        .fold(vec![creator_group], |mut groups, client| {
            let existing_group = groups.choose_mut(&mut rng).unwrap();
            let group_info = existing_group.group_info_message(true).unwrap();

            let (new_group, commit) = client
                .commit_external(
                    group_info,
                    Some(&existing_group.export_tree().unwrap()),
                    None,
                    vec![],
                    vec![],
                )
                .unwrap();

            groups.iter_mut().for_each(|group| {
                group.process_incoming_message(commit.clone()).unwrap();
            });

            groups.push(new_group);
            groups
        });

    assert!(groups
        .iter()
        .all(|group| group.roster().len() == PARTICIPANT_COUNT));

    for i in 0..groups.len() {
        let payload = (&mut rng)
            .sample_iter(rand::distributions::Standard)
            .take(256)
            .collect::<Vec<_>>();
        let message = groups[i]
            .encrypt_application_message(&payload, Vec::new())
            .unwrap();
        groups
            .iter_mut()
            .enumerate()
            .filter(|&(j, _)| i != j)
            .all(|(_, group)| {
                let processed = group.process_incoming_message(message.clone()).unwrap();
                matches!(processed.event, Event::ApplicationMessage(bytes) if bytes == payload)
            });
    }
}

#[test]
fn test_external_commits() {
    test_params()
        .filter(|&(_, _, encrypted)| !encrypted)
        .for_each(|(protocol_version, cipher_suite, _)| {
            external_commits_work(protocol_version, cipher_suite);
        });
}

#[test]
fn test_remove_nonexisting_leaf() {
    let (_, mut groups) = get_test_groups(
        ProtocolVersion::Mls10,
        CipherSuite::Curve25519Aes128,
        10,
        Preferences::default(),
    );

    groups[0].propose_remove(5, vec![]).unwrap();

    // Leaf index out of bounds
    assert!(groups[0].propose_remove(13, vec![]).is_err());

    groups[0].commit(vec![]).unwrap();
    groups[0].apply_pending_commit().unwrap();

    // Removing blank leaf causes error
    assert!(groups[0].propose_remove(5, vec![]).is_err());
}

fn get_reinit_client(
    suite1: CipherSuite,
    suite2: CipherSuite,
    id: &str,
) -> Client<TestClientConfig> {
    let credential = get_test_basic_credential(id.as_bytes().to_vec());

    let sk1 = suite1.generate_signing_key().unwrap();
    let sk2 = suite2.generate_signing_key().unwrap();
    let id1 = SigningIdentity::new(
        credential.clone(),
        SignaturePublicKey::try_from(&sk1).unwrap(),
    );
    let id2 = SigningIdentity::new(credential, SignaturePublicKey::try_from(&sk2).unwrap());

    ClientBuilder::new()
        .identity_provider(BasicIdentityProvider::new())
        .keychain(InMemoryKeychain::default())
        .signing_identity(id1, sk1)
        .signing_identity(id2, sk2)
        .build()
}

#[test]
fn reinit_works() {
    let suite1 = CipherSuite::Curve25519Aes128;
    let suite2 = CipherSuite::P256Aes128;
    let version = ProtocolVersion::Mls10;

    // Create a group with 2 parties
    let alice = get_reinit_client(suite1, suite2, "alice");
    let bob = get_reinit_client(suite1, suite2, "bob");

    let mut alice_group = alice
        .create_group(version, suite1, ExtensionList::new())
        .unwrap();

    let kp = bob.generate_key_package(version, suite1).unwrap();

    let welcome = alice_group
        .commit_builder()
        .add_member(kp)
        .unwrap()
        .build()
        .unwrap()
        .welcome_message;

    alice_group.apply_pending_commit().unwrap();
    let tree = alice_group.export_tree().unwrap();

    let (mut bob_group, _) = bob.join_group(Some(&tree), welcome.unwrap()).unwrap();

    // Alice proposes reinit
    let reinit_proposal_message = alice_group
        .propose_reinit(
            None,
            ProtocolVersion::Mls10,
            suite2,
            ExtensionList::default(),
            vec![],
        )
        .unwrap();

    // Bob commits the reinit
    bob_group
        .process_incoming_message(reinit_proposal_message)
        .unwrap();

    let commit = bob_group.commit(vec![]).unwrap().commit_message;

    // Both process Bob's commit
    let state_update = bob_group.apply_pending_commit().unwrap();
    assert!(!state_update.active && state_update.pending_reinit);

    let message = alice_group.process_incoming_message(commit).unwrap();

    if let Event::Commit(state_update) = message.event {
        assert!(!state_update.active && state_update.pending_reinit);
    }

    // They can't create new epochs anymore
    assert!(alice_group.commit(vec![]).is_err());

    assert!(bob_group.commit(vec![]).is_err());

    // Alice finishes the reinit by creating the new group
    let kp = bob.generate_key_package(version, suite2).unwrap();

    let (mut alice_group, welcome) = alice_group
        .finish_reinit_commit(|_| Some(kp.clone()))
        .unwrap();

    // Alice invited Bob
    let welcome = welcome.unwrap();
    let tree = alice_group.export_tree().unwrap();

    let (mut bob_group, _) = bob_group.finish_reinit_join(welcome, Some(&tree)).unwrap();

    // They can talk
    let carol = get_reinit_client(suite1, suite2, "carol");
    let kp = carol.generate_key_package(version, suite2).unwrap();

    let commit_output = alice_group
        .commit_builder()
        .add_member(kp)
        .unwrap()
        .build()
        .unwrap();

    alice_group.apply_pending_commit().unwrap();
    bob_group
        .process_incoming_message(commit_output.commit_message)
        .unwrap();

    let tree = alice_group.export_tree().unwrap();
    carol
        .join_group(Some(&tree), commit_output.welcome_message.unwrap())
        .unwrap();
}
