use ferriscrypt::asym::ec_key::{generate_keypair, Curve};
use ferriscrypt::rand::SecureRng;
use mls::cipher_suite::CipherSuite;
use mls::client::Client;
use mls::credential::{BasicCredential, Credential};
use mls::extension::LifetimeExt;
use mls::key_package::KeyPackageGeneration;
use mls::session::{Session, SessionOpts};
use std::time::SystemTime;

fn generate_client(cipher_suite: CipherSuite, id: Vec<u8>) -> Client {
    let (public_key, secret_key) =
        generate_keypair(Curve::from(cipher_suite.signature_scheme())).unwrap();
    let credential = Credential::Basic(BasicCredential::new(id, public_key).unwrap());
    Client::new(cipher_suite, secret_key, credential).unwrap()
}

fn test_create(cipher_suite: CipherSuite, opts: SessionOpts) {
    println!(
        "Testing session creation for cipher suite: {:?}, participants: {}, opts: {:?}",
        cipher_suite, 1, opts
    );

    let alice = Client::generate_basic(cipher_suite, b"alice".to_vec()).unwrap();
    let bob = Client::generate_basic(cipher_suite, b"bob".to_vec()).unwrap();

    let key_lifetime = LifetimeExt::years(1, SystemTime::now()).unwrap();

    let alice_key = alice.gen_key_package(&key_lifetime).unwrap();
    let bob_key = bob.gen_key_package(&key_lifetime).unwrap();

    // Alice creates a session and adds bob
    let mut alice_session = alice
        .create_session(alice_key, b"group".to_vec(), opts.clone())
        .unwrap();
    let add_bob = alice_session
        .add_proposal(&bob_key.key_package.to_vec().unwrap())
        .unwrap();

    let packets = alice_session.commit(vec![add_bob]).unwrap();

    // Upon server confirmation, alice applies the commit to her own state
    alice_session
        .handle_handshake_data(&packets.commit_packet)
        .unwrap();

    let tree = alice_session.export_tree().unwrap();

    // Bob receives the welcome message and joins the group
    let bob_session = bob
        .join_session(
            bob_key,
            &tree,
            &packets.welcome_packet.unwrap(),
            opts.clone(),
        )
        .unwrap();

    assert!(alice_session.has_equal_state(&bob_session));
}

#[test]
fn test_create_session() {
    CipherSuite::all().iter().for_each(|cs| {
        test_create(
            cs.clone(),
            SessionOpts {
                encrypt_controls: false,
                commit_reflection: true,
            },
        );

        test_create(
            cs.clone(),
            SessionOpts {
                encrypt_controls: true,
                commit_reflection: true,
            },
        )
    });
}

fn get_test_sessions(
    cipher_suite: CipherSuite,
    num_participants: usize,
    opts: SessionOpts,
) -> (Session, Vec<Session>) {
    // Create the group with Alice as the group initiator
    let creator = generate_client(cipher_suite, b"alice".to_vec());
    let key_lifetime = LifetimeExt::years(1, SystemTime::now()).unwrap();

    let creator_key = creator.gen_key_package(&key_lifetime).unwrap();
    let mut creator_session = creator
        .create_session(creator_key, b"group".to_vec(), opts.clone())
        .unwrap();

    // Generate random clients that will be members of the group
    let receiver_clients = (0..num_participants)
        .into_iter()
        .map(|_| generate_client(cipher_suite, b"test".to_vec()))
        .collect::<Vec<Client>>();

    let receiver_keys = receiver_clients
        .iter()
        .map(|client| client.gen_key_package(&key_lifetime).unwrap())
        .collect::<Vec<KeyPackageGeneration>>();

    // Add the generated clients to the group the creator made
    let add_members_proposals = receiver_keys
        .iter()
        .map(|kg| kg.key_package.to_vec().unwrap())
        .map(|key_bytes| creator_session.add_proposal(&key_bytes).unwrap())
        .collect();
    let commit = creator_session.commit(add_members_proposals).unwrap();

    // Creator can confirm the commit was processed by the server
    let state_update = creator_session
        .handle_handshake_data(&commit.commit_packet)
        .unwrap();

    let update = state_update.unwrap();
    assert!(update.active);
    assert_eq!(update.epoch, 1);

    let credentials = receiver_keys
        .iter()
        .map(|k| k.key_package.credential.clone())
        .collect::<Vec<Credential>>();

    assert_eq!(update.added, credentials);
    assert!(update.removed.is_empty());

    // Export the tree for receivers
    let tree_data = creator_session.export_tree().unwrap();

    // All the receivers will be able to join the session
    let receiver_sessions = receiver_clients
        .iter()
        .zip(receiver_keys.iter())
        .map(|(client, key)| {
            client
                .join_session(
                    key.clone(),
                    &tree_data,
                    &commit.welcome_packet.as_ref().unwrap(),
                    opts.clone(),
                )
                .unwrap()
        })
        .collect::<Vec<Session>>();

    for one_receiver in &receiver_sessions {
        assert!(creator_session.has_equal_state(&one_receiver))
    }

    (creator_session, receiver_sessions)
}

fn test_empty_commits(cipher_suite: CipherSuite, participants: usize, opts: SessionOpts) {
    println!(
        "Testing empty commits for cipher suite: {:?}, participants: {}, opts: {:?}",
        cipher_suite, participants, opts
    );

    let (mut creator_session, mut receiver_sessions) =
        get_test_sessions(cipher_suite, participants, opts);

    // Loop through each participant and send a path update

    for i in 0..receiver_sessions.len() {
        // Create the commit
        let commit = receiver_sessions[i].commit(vec![]).unwrap();
        assert!(commit.welcome_packet.is_none());

        // Creator group processes the commit
        creator_session
            .handle_handshake_data(&commit.commit_packet)
            .unwrap();

        // Receiver groups process the commit
        for one_receiver in receiver_sessions.iter_mut() {
            one_receiver
                .handle_handshake_data(&commit.commit_packet)
                .unwrap();
            assert!(one_receiver.has_equal_state(&creator_session));
        }
    }
}

#[test]
fn test_group_path_updates() {
    CipherSuite::all().iter().for_each(|&cs| {
        test_empty_commits(
            cs,
            10,
            SessionOpts {
                encrypt_controls: false,
                commit_reflection: true,
            },
        );
        test_empty_commits(
            cs,
            10,
            SessionOpts {
                encrypt_controls: true,
                commit_reflection: true,
            },
        );
    })
}

fn test_update_proposals(cipher_suite: CipherSuite, participants: usize, opts: SessionOpts) {
    println!(
        "Testing update proposals for cipher suite: {:?}, participants: {}, opts: {:?}",
        cipher_suite, participants, opts
    );

    let (mut creator_session, mut receiver_sessions) =
        get_test_sessions(cipher_suite, participants, opts);

    // Create an update from the ith member, have the ith + 1 member commit it
    for i in 0..receiver_sessions.len() - 1 {
        let update_proposal = receiver_sessions[i].propose_update().unwrap();

        // Everyone should process the proposal
        creator_session
            .handle_handshake_data(&update_proposal)
            .unwrap();

        for j in 0..receiver_sessions.len() {
            if i != j {
                receiver_sessions[j]
                    .handle_handshake_data(&update_proposal)
                    .unwrap();
            }
        }

        // Everyone receives the commit
        let commit = receiver_sessions[i + 1].commit(vec![]).unwrap();
        assert!(commit.welcome_packet.is_none());

        creator_session
            .handle_handshake_data(&commit.commit_packet)
            .unwrap();

        for j in 0..receiver_sessions.len() {
            let state_update = receiver_sessions[j]
                .handle_handshake_data(&commit.commit_packet)
                .unwrap();
            let update = state_update.unwrap();
            assert!(update.active);
            assert_eq!(update.epoch, (i as u64) + 2);
            assert!(update.added.is_empty());
            assert!(update.removed.is_empty());
            assert!(receiver_sessions[j].has_equal_state(&creator_session));
        }
    }
}

#[test]
fn test_group_update_proposals() {
    CipherSuite::all().iter().for_each(|&cs| {
        test_update_proposals(
            cs,
            10,
            SessionOpts {
                encrypt_controls: false,
                commit_reflection: true,
            },
        );
        test_update_proposals(
            cs,
            10,
            SessionOpts {
                encrypt_controls: true,
                commit_reflection: true,
            },
        );
    })
}

fn test_remove_proposals(cipher_suite: CipherSuite, participants: usize, opts: SessionOpts) {
    println!(
        "Testing remove proposals for cipher suite: {:?}, participants: {}, opts: {:?}",
        cipher_suite, participants, opts
    );

    let (mut creator_session, mut receiver_sessions) =
        get_test_sessions(cipher_suite, participants, opts);

    let mut epoch_count = 1;

    // Remove people from the group one at a time
    while receiver_sessions.len() > 1 {
        let removal = creator_session
            .remove_proposal((creator_session.participant_count() - 1) as u32)
            .unwrap();

        let commit = creator_session.commit(vec![removal]).unwrap();
        assert!(commit.welcome_packet.is_none());

        // Process the removal in the creator group
        creator_session
            .handle_handshake_data(&commit.commit_packet)
            .unwrap();

        epoch_count += 1;

        // Process the removal in the other receiver groups
        for (index, one_session) in receiver_sessions.iter_mut().enumerate() {
            let removed_cred = one_session.roster().last().unwrap().clone();
            let expect_inactive = one_session.roster().len() - 2;

            let state_update = one_session
                .handle_handshake_data(&commit.commit_packet)
                .unwrap();

            let update = state_update.unwrap();
            assert_eq!(update.epoch, epoch_count as u64);
            assert_eq!(update.removed, vec![removed_cred]);
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
    CipherSuite::all().iter().for_each(|&cs| {
        test_remove_proposals(
            cs,
            10,
            SessionOpts {
                encrypt_controls: false,
                commit_reflection: true,
            },
        );
        test_remove_proposals(
            cs,
            10,
            SessionOpts {
                encrypt_controls: true,
                commit_reflection: true,
            },
        );
    })
}

fn test_application_messages(
    cipher_suite: CipherSuite,
    participants: usize,
    message_count: usize,
    opts: SessionOpts,
) {
    println!(
        "Testing application messages for cipher suite: {:?}, participants: {}, message count: {}, opts: {:?}",
        cipher_suite, participants, message_count, opts
    );

    let (mut creator_session, mut receiver_sessions) =
        get_test_sessions(cipher_suite, participants, opts);

    // Loop through each participant and send application messages
    for i in 0..receiver_sessions.len() {
        let test_message = SecureRng::gen(1024).unwrap();

        for _ in 0..message_count {
            // Encrypt the application message
            let ciphertext = receiver_sessions[i]
                .encrypt_application_data(&test_message)
                .unwrap();

            // Creator receives the application message
            creator_session
                .decrypt_application_data(&ciphertext)
                .unwrap();

            // Everyone else receives the application message
            for j in 0..receiver_sessions.len() {
                if i != j {
                    let decrypted = receiver_sessions[j]
                        .decrypt_application_data(&ciphertext)
                        .unwrap();
                    assert_eq!(&decrypted, &test_message);
                }
            }
        }
    }
}

#[test]
fn test_group_application_messages() {
    CipherSuite::all().iter().for_each(|&cs| {
        test_application_messages(
            cs,
            10,
            20,
            SessionOpts {
                encrypt_controls: false,
                commit_reflection: true,
            },
        );
        test_application_messages(
            cs,
            10,
            20,
            SessionOpts {
                encrypt_controls: true,
                commit_reflection: true,
            },
        );
    })
}
