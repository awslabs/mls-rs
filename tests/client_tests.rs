use assert_matches::assert_matches;
use aws_mls::cipher_suite::CipherSuite;
use aws_mls::client::Client;
use aws_mls::client_config::{InMemoryClientConfig, Preferences};
use aws_mls::credential::{BasicCredential, Credential};
use aws_mls::extension::{ExtensionList, LifetimeExt};
use aws_mls::key_package::KeyPackageGeneration;
use aws_mls::message::ProcessedMessagePayload;
use aws_mls::session::{GroupError, Session, SessionError};
use aws_mls::{LeafNodeRef, ProtocolVersion};
use ferriscrypt::rand::SecureRng;
use rand::{prelude::SliceRandom, Rng};

#[cfg(target_arch = "wasm32")]
use wasm_bindgen_test::{wasm_bindgen_test as test, wasm_bindgen_test_configure};

#[cfg(target_arch = "wasm32")]
wasm_bindgen_test_configure!(run_in_browser);

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
) -> Client<InMemoryClientConfig> {
    let key = cipher_suite.generate_secret_key().unwrap();
    let credential = BasicCredential::new(id, key.to_public().unwrap()).unwrap();

    InMemoryClientConfig::default()
        .with_credential(Credential::Basic(credential), key)
        .with_preferences(preferences)
        .build_client()
}

fn test_create(
    protocol_version: ProtocolVersion,
    cipher_suite: CipherSuite,
    preferences: Preferences,
) {
    println!(
        "Testing session creation for cipher suite: {protocol_version:?} {cipher_suite:?}, participants: 1, {preferences:?}"
    );

    let alice = generate_client(cipher_suite, b"alice".to_vec(), preferences.clone());
    let bob = generate_client(cipher_suite, b"bob".to_vec(), preferences);

    let key_lifetime = LifetimeExt::years(1).unwrap();

    let bob_key = bob
        .gen_key_package(protocol_version, cipher_suite, key_lifetime.clone())
        .unwrap();

    // Alice creates a session and adds bob
    let mut alice_session = alice
        .create_session(
            protocol_version,
            cipher_suite,
            key_lifetime,
            b"group".to_vec(),
            ExtensionList::default(),
        )
        .unwrap();

    let add_bob = alice_session
        .add_proposal(&bob_key.key_package.to_vec().unwrap())
        .unwrap();

    let packets = alice_session.commit(vec![add_bob]).unwrap();

    // Upon server confirmation, alice applies the commit to her own state
    alice_session.apply_pending_commit().unwrap();

    let tree = alice_session.export_tree().unwrap();

    // Bob receives the welcome message and joins the group
    let bob_session = bob
        .join_session(None, Some(&tree), &packets.welcome_packet.unwrap())
        .unwrap();

    assert!(alice_session.has_equal_state(&bob_session));
}

#[test]
fn test_create_session() {
    test_params().for_each(|(protocol_version, cs, encrypt_controls)| {
        let preferences = Preferences::default()
            .with_control_encryption(encrypt_controls)
            .with_ratchet_tree_extension(false);

        test_create(protocol_version, cs, preferences);
    });
}

fn get_test_sessions(
    protocol_version: ProtocolVersion,
    cipher_suite: CipherSuite,
    num_participants: usize,
    preferences: Preferences,
) -> (
    Session<InMemoryClientConfig>,
    Vec<Session<InMemoryClientConfig>>,
) {
    // Create the group with Alice as the group initiator
    let creator = generate_client(cipher_suite, b"alice".to_vec(), preferences.clone());
    let key_lifetime = LifetimeExt::years(1).unwrap();

    let mut creator_session = creator
        .create_session(
            protocol_version,
            cipher_suite,
            key_lifetime.clone(),
            b"group".to_vec(),
            ExtensionList::default(),
        )
        .unwrap();

    // Generate random clients that will be members of the group
    let receiver_clients = std::iter::repeat_with(|| {
        generate_client(cipher_suite, b"test".to_vec(), preferences.clone())
    })
    .take(num_participants)
    .collect::<Vec<_>>();

    let receiver_keys = receiver_clients
        .iter()
        .map(|client| {
            client
                .gen_key_package(protocol_version, cipher_suite, key_lifetime.clone())
                .unwrap()
        })
        .collect::<Vec<KeyPackageGeneration>>();

    // Add the generated clients to the group the creator made
    let add_members_proposals = receiver_keys
        .iter()
        .map(|kg| kg.key_package.to_vec().unwrap())
        .map(|key_bytes| creator_session.add_proposal(&key_bytes).unwrap())
        .collect();
    let commit = creator_session.commit(add_members_proposals).unwrap();

    // Creator can confirm the commit was processed by the server
    let update = creator_session.apply_pending_commit().unwrap();

    assert!(update.active);
    assert_eq!(update.epoch, 1);

    assert_eq!(
        update.added,
        receiver_keys
            .iter()
            .map(|kpg| kpg
                .key_package
                .leaf_node
                .to_reference(cipher_suite)
                .unwrap())
            .collect::<Vec<LeafNodeRef>>()
    );

    assert!(update.removed.is_empty());

    // Export the tree for receivers
    let tree_data = creator_session.export_tree().unwrap();

    // All the receivers will be able to join the session
    let receiver_sessions = receiver_clients
        .iter()
        .map(|client| {
            client
                .join_session(
                    None,
                    Some(&tree_data),
                    commit.welcome_packet.as_ref().unwrap(),
                )
                .unwrap()
        })
        .collect::<Vec<_>>();

    for one_receiver in &receiver_sessions {
        assert!(creator_session.has_equal_state(one_receiver))
    }

    (creator_session, receiver_sessions)
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

    let (mut creator_session, mut receiver_sessions) =
        get_test_sessions(protocol_version, cipher_suite, participants, preferences);

    // Loop through each participant and send a path update

    for i in 0..receiver_sessions.len() {
        // Create the commit
        let commit = receiver_sessions[i].commit(vec![]).unwrap();
        assert!(commit.welcome_packet.is_none());

        // Creator group processes the commit
        creator_session
            .process_incoming_bytes(&commit.commit_packet)
            .unwrap();

        // Receiver groups process the commit
        for (j, one_receiver) in receiver_sessions.iter_mut().enumerate() {
            if i == j {
                one_receiver.apply_pending_commit().unwrap();
            } else {
                one_receiver
                    .process_incoming_bytes(&commit.commit_packet)
                    .unwrap();
            }
            assert!(one_receiver.has_equal_state(&creator_session));
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

    let (mut creator_session, mut receiver_sessions) =
        get_test_sessions(protocol_version, cipher_suite, participants, preferences);

    // Create an update from the ith member, have the ith + 1 member commit it
    for i in 0..receiver_sessions.len() - 1 {
        let update_proposal = receiver_sessions[i].propose_update().unwrap();

        // Everyone should process the proposal
        creator_session
            .process_incoming_bytes(&update_proposal)
            .unwrap();

        (0..receiver_sessions.len()).for_each(|j| {
            if i != j {
                receiver_sessions[j]
                    .process_incoming_bytes(&update_proposal)
                    .unwrap();
            }
        });

        // Everyone receives the commit
        let committer_index = i + 1;
        let commit = receiver_sessions[committer_index].commit(vec![]).unwrap();
        assert!(commit.welcome_packet.is_none());

        creator_session
            .process_incoming_bytes(&commit.commit_packet)
            .unwrap();

        for (j, receiver) in receiver_sessions.iter_mut().enumerate() {
            let update = if j == committer_index {
                receiver.apply_pending_commit()
            } else {
                let state_update_message = receiver
                    .process_incoming_bytes(&commit.commit_packet)
                    .unwrap()
                    .message;

                match state_update_message {
                    ProcessedMessagePayload::Commit(update) => Ok(update),
                    _ => panic!("Expected commit result"),
                }
            }
            .unwrap();

            assert!(update.active);
            assert_eq!(update.epoch, (i as u64) + 2);
            assert!(update.added.is_empty());
            assert!(update.removed.is_empty());
            assert!(receiver.has_equal_state(&creator_session));
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

    let (mut creator_session, mut receiver_sessions) =
        get_test_sessions(protocol_version, cipher_suite, participants, preferences);

    let mut epoch_count = 1;

    // Remove people from the group one at a time
    while receiver_sessions.len() > 1 {
        let session_to_remove = receiver_sessions.choose(&mut rand::thread_rng()).unwrap();
        let to_remove = session_to_remove.current_key_package().unwrap().clone();
        let to_remove_ref = to_remove.to_reference(cipher_suite).unwrap();

        let removal = creator_session.remove_proposal(&to_remove_ref).unwrap();

        let commit = creator_session.commit(vec![removal]).unwrap();
        assert!(commit.welcome_packet.is_none());

        // Process the removal in the creator group
        creator_session.apply_pending_commit().unwrap();

        epoch_count += 1;

        // Process the removal in the other receiver groups
        for one_session in receiver_sessions.iter_mut() {
            let expect_inactive = one_session.current_user_ref() == &to_remove_ref;

            let state_update = one_session
                .process_incoming_bytes(&commit.commit_packet)
                .unwrap();

            let update = match state_update.message {
                ProcessedMessagePayload::Commit(update) => update,
                _ => panic!("Expected commit result"),
            };

            assert_eq!(update.epoch, epoch_count as u64);
            assert_eq!(update.removed, vec![to_remove.clone()]);
            assert!(update.added.is_empty());

            if expect_inactive {
                assert!(!update.active)
            } else {
                assert!(update.active)
            }
        }

        receiver_sessions.retain(|session| session.current_user_ref() != &to_remove_ref);

        for one_session in receiver_sessions.iter() {
            assert!(one_session.has_equal_state(&creator_session));
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

    let (mut creator_session, mut receiver_sessions) =
        get_test_sessions(protocol_version, cipher_suite, participants, preferences);

    // Loop through each participant and send application messages
    for i in 0..receiver_sessions.len() {
        let test_message = SecureRng::gen(1024).unwrap();

        for _ in 0..message_count {
            // Encrypt the application message
            let ciphertext = receiver_sessions[i]
                .encrypt_application_data(&test_message)
                .unwrap();

            // Creator receives the application message
            creator_session.process_incoming_bytes(&ciphertext).unwrap();

            // Everyone else receives the application message
            (0..receiver_sessions.len()).for_each(|j| {
                if i != j {
                    let decrypted = receiver_sessions[j]
                        .process_incoming_bytes(&ciphertext)
                        .unwrap();
                    assert_matches!(decrypted.message, ProcessedMessagePayload::Application(m) if m == test_message);
                }
            });
        }
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

    let (mut creator_session, _) =
        get_test_sessions(protocol_version, cipher_suite, 1, preferences);
    let commit = creator_session.commit(Vec::new()).unwrap();

    let error = creator_session
        .process_incoming_bytes(&commit.commit_packet)
        .unwrap_err();

    assert_matches!(
        error,
        SessionError::ProtocolError(GroupError::CantProcessMessageFromSelf)
    );
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

    let mut creator_session = creator
        .create_session(
            protocol_version,
            cipher_suite,
            LifetimeExt::years(1).unwrap(),
            b"group".to_vec(),
            ExtensionList::default(),
        )
        .unwrap();

    // An external commit cannot be the first commit in a session as it requires
    // interim_transcript_hash to be computed from the confirmed_transcript_hash and
    // confirmation_tag, which is not the case for the initial interim_transcript_hash.
    creator_session.commit(Vec::new()).unwrap();
    creator_session.apply_pending_commit().unwrap();

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

    let mut sessions = others
        .iter()
        .fold(vec![creator_session], |mut sessions, client| {
            let existing_session = sessions.choose_mut(&mut rng).unwrap();
            let group_info = existing_session.group_info_message().unwrap();

            let (new_session, commit) = client
                .commit_external(
                    LifetimeExt::years(1).unwrap(),
                    group_info,
                    Some(&existing_session.export_tree().unwrap()),
                )
                .unwrap();

            sessions.iter_mut().for_each(|session| {
                session.process_incoming_bytes(&commit).unwrap();
            });

            sessions.push(new_session);
            sessions
        });

    assert!(sessions
        .iter()
        .all(|session| session.participant_count() as usize == PARTICIPANT_COUNT));

    for i in 0..sessions.len() {
        let payload = (&mut rng)
            .sample_iter(rand::distributions::Standard)
            .take(256)
            .collect::<Vec<_>>();
        let message = sessions[i].encrypt_application_data(&payload).unwrap();
        sessions
            .iter_mut()
            .enumerate()
            .filter(|&(j, _)| i != j)
            .all(|(_, session)| {
                let processed = session.process_incoming_bytes(&message).unwrap();
                matches!(processed.message, ProcessedMessagePayload::Application(bytes) if bytes == payload)
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
