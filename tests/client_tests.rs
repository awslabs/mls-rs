use assert_matches::assert_matches;
use aws_mls::cipher_suite::CipherSuite;
use aws_mls::client::Client;
use aws_mls::client_config::{ClientConfig, DefaultClientConfig, KeyPackageGenerationMap};
use aws_mls::extension::{ExtensionList, LifetimeExt};
use aws_mls::key_package::{KeyPackageGeneration, KeyPackageRef};
use aws_mls::session::{GroupError, ProcessedMessage, Session, SessionError};
use ferriscrypt::rand::SecureRng;
use std::{
    fmt::{self, Display},
    time::SystemTime,
};

struct ConfigDescription<'a, C>(&'a C);

impl<C: ClientConfig> Display for ConfigDescription<'_, C> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "encrypt controls: {}, ratchet tree extension: {}",
            self.0.encrypt_controls(),
            self.0.ratchet_tree_extension()
        )
    }
}

fn test_params() -> impl Iterator<Item = (CipherSuite, bool)> {
    CipherSuite::all().flat_map(|cs| [false, true].into_iter().map(move |encrypt| (cs, encrypt)))
}

fn generate_client<C>(cipher_suite: CipherSuite, id: Vec<u8>, config: C) -> Client<C>
where
    C: ClientConfig + Clone,
{
    Client::generate_basic(cipher_suite, id, config).unwrap()
}

fn test_create(cipher_suite: CipherSuite, config: DefaultClientConfig) {
    println!(
        "Testing session creation for cipher suite: {:?}, participants: {}, {}",
        cipher_suite,
        1,
        ConfigDescription(&config),
    );

    let alice = Client::generate_basic(cipher_suite, b"alice".to_vec(), config.clone()).unwrap();

    let bob_key_pkg_gen_repo = KeyPackageGenerationMap::default();
    let config = config.with_key_packages(bob_key_pkg_gen_repo.clone());
    let bob = Client::generate_basic(cipher_suite, b"bob".to_vec(), config).unwrap();

    let key_lifetime = LifetimeExt::years(1, SystemTime::now()).unwrap();
    let bob_key = bob.gen_key_package(key_lifetime.clone()).unwrap();
    bob_key_pkg_gen_repo.insert(bob_key.clone()).unwrap();

    // Alice creates a session and adds bob
    let mut alice_session = alice
        .create_session(key_lifetime, b"group".to_vec(), ExtensionList::new())
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
    test_params().for_each(|(cs, encrypt_controls)| {
        test_create(
            cs,
            DefaultClientConfig::default()
                .with_control_encryption(encrypt_controls)
                .with_ratchet_tree_extension(false),
        );
    });
}

fn get_test_sessions(
    cipher_suite: CipherSuite,
    num_participants: usize,
    config: DefaultClientConfig,
) -> (Session, Vec<Session>) {
    // Create the group with Alice as the group initiator
    let creator = generate_client(cipher_suite, b"alice".to_vec(), config.clone());
    let key_lifetime = LifetimeExt::years(1, SystemTime::now()).unwrap();

    let mut creator_session = creator
        .create_session(key_lifetime.clone(), b"group".to_vec(), Default::default())
        .unwrap();

    let receiver_key_pkg_gen_repos = std::iter::repeat_with(|| KeyPackageGenerationMap::default())
        .take(num_participants)
        .collect::<Vec<_>>();

    // Generate random clients that will be members of the group
    let receiver_clients = receiver_key_pkg_gen_repos
        .iter()
        .cloned()
        .map(|repo| {
            let config = config.clone().with_key_packages(repo);
            generate_client(cipher_suite, b"test".to_vec(), config)
        })
        .collect::<Vec<_>>();

    let receiver_keys = receiver_clients
        .iter()
        .map(|client| client.gen_key_package(key_lifetime.clone()).unwrap())
        .collect::<Vec<KeyPackageGeneration>>();

    receiver_keys
        .iter()
        .cloned()
        .zip(&receiver_key_pkg_gen_repos)
        .for_each(|(key_pkg_gen, repo)| {
            repo.insert(key_pkg_gen).unwrap();
        });

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
            .map(|kpg| kpg.key_package.to_reference().unwrap())
            .collect::<Vec<KeyPackageRef>>()
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

fn test_empty_commits(cipher_suite: CipherSuite, participants: usize, config: DefaultClientConfig) {
    println!(
        "Testing empty commits for cipher suite: {:?}, participants: {}, {}",
        cipher_suite,
        participants,
        ConfigDescription(&config),
    );

    let (mut creator_session, mut receiver_sessions) =
        get_test_sessions(cipher_suite, participants, config);

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
    test_params().for_each(|(cs, encrypt_controls)| {
        test_empty_commits(
            cs,
            10,
            DefaultClientConfig::default()
                .with_control_encryption(encrypt_controls)
                .with_ratchet_tree_extension(false),
        );
    });
}

fn test_update_proposals(
    cipher_suite: CipherSuite,
    participants: usize,
    config: DefaultClientConfig,
) {
    println!(
        "Testing update proposals for cipher suite: {:?}, participants: {}, {}",
        cipher_suite,
        participants,
        ConfigDescription(&config),
    );

    let (mut creator_session, mut receiver_sessions) =
        get_test_sessions(cipher_suite, participants, config);

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
                let state_update = receiver
                    .process_incoming_bytes(&commit.commit_packet)
                    .unwrap();
                match state_update {
                    ProcessedMessage::Commit(update) => Ok(update),
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
    test_params().for_each(|(cs, encrypt_controls)| {
        test_update_proposals(
            cs,
            10,
            DefaultClientConfig::default()
                .with_control_encryption(encrypt_controls)
                .with_ratchet_tree_extension(false),
        );
    });
}

fn test_remove_proposals(
    cipher_suite: CipherSuite,
    participants: usize,
    config: DefaultClientConfig,
) {
    println!(
        "Testing remove proposals for cipher suite: {:?}, participants: {}, {}",
        cipher_suite,
        participants,
        ConfigDescription(&config),
    );

    let (mut creator_session, mut receiver_sessions) =
        get_test_sessions(cipher_suite, participants, config);

    let mut epoch_count = 1;

    // Remove people from the group one at a time
    while receiver_sessions.len() > 1 {
        let to_remove = creator_session.roster().last().cloned().cloned().unwrap();

        let removal = creator_session
            .remove_proposal(&to_remove.to_reference().unwrap())
            .unwrap();

        let commit = creator_session.commit(vec![removal]).unwrap();
        assert!(commit.welcome_packet.is_none());

        // Process the removal in the creator group
        creator_session.apply_pending_commit().unwrap();

        epoch_count += 1;

        // Process the removal in the other receiver groups
        for (index, one_session) in receiver_sessions.iter_mut().enumerate() {
            let expect_inactive = one_session.roster().len() - 2;

            let state_update = one_session
                .process_incoming_bytes(&commit.commit_packet)
                .unwrap();

            let update = match state_update {
                ProcessedMessage::Commit(update) => update,
                _ => panic!("Expected commit result"),
            };
            assert_eq!(update.epoch, epoch_count as u64);
            assert_eq!(update.removed, vec![to_remove.clone()]);
            assert!(update.added.is_empty());

            if index != expect_inactive {
                assert!(update.active)
            } else {
                assert!(!update.active)
            }
        }

        // Remove the last group off the list
        receiver_sessions.pop();

        for one_session in receiver_sessions.iter() {
            assert!(one_session.has_equal_state(&creator_session));
        }
    }
}

#[test]
fn test_group_remove_proposals() {
    test_params().for_each(|(cs, encrypt_controls)| {
        test_remove_proposals(
            cs,
            10,
            DefaultClientConfig::default()
                .with_control_encryption(encrypt_controls)
                .with_ratchet_tree_extension(false),
        );
    });
}

fn test_application_messages(
    cipher_suite: CipherSuite,
    participants: usize,
    message_count: usize,
    config: DefaultClientConfig,
) {
    println!(
        "Testing application messages for cipher suite: {:?}, participants: {}, message count: {}, {}",
        cipher_suite, participants, message_count, ConfigDescription(&config),
    );

    let (mut creator_session, mut receiver_sessions) =
        get_test_sessions(cipher_suite, participants, config);

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
                    assert_matches!(decrypted, ProcessedMessage::Application(m) if m == test_message);
                }
            });
        }
    }
}

#[test]
fn test_group_application_messages() {
    test_params().for_each(|(cs, encrypt_controls)| {
        test_application_messages(
            cs,
            10,
            20,
            DefaultClientConfig::default()
                .with_control_encryption(encrypt_controls)
                .with_ratchet_tree_extension(false),
        );
    });
}

fn processing_message_from_self_returns_error(
    cipher_suite: CipherSuite,
    config: DefaultClientConfig,
) {
    println!(
        "Verifying that processing one's own message returns an error for cipher suite: {:?}, {}",
        cipher_suite,
        ConfigDescription(&config),
    );
    let (mut creator_session, _) = get_test_sessions(cipher_suite, 1, config);
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
    test_params().for_each(|(cs, encrypt_controls)| {
        processing_message_from_self_returns_error(
            cs,
            DefaultClientConfig::default()
                .with_control_encryption(encrypt_controls)
                .with_ratchet_tree_extension(false),
        );
    });
}
