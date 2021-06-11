use mls::ciphersuite::CipherSuite;
use mls::ciphersuite::CipherSuite::{
    Mls10128Dhkemp256Aes128gcmSha256P256, Mls10128Dhkemx25519Aes128gcmSha256Ed25519,
    Mls10128Dhkemx25519Chacha20poly1305Sha256Ed25519, Mls10256Dhkemp521Aes256gcmSha512P521,
};
use mls::client::Client;
use mls::credential::{BasicCredential, Credential};
use mls::crypto::asym::AsymmetricKey;
use mls::crypto::rand::OpenSslRng;
use mls::crypto::signature::ed25519::EdDsa25519;
use mls::crypto::signature::SignatureScheme;
use mls::group::{Event, Group};
use mls::key_package::{KeyPackage, KeyPackageGeneration, KeyPackageGenerator};

fn generate_client(id: Vec<u8>) -> Client {
    let signature_scheme = EdDsa25519::new_random(OpenSslRng).unwrap();
    let signature_key = signature_scheme.as_public_signature_key().unwrap();
    let basic = BasicCredential {
        signature_key: signature_key.signature_key,
        identity: id,
        signature_scheme: signature_key.signature_scheme,
    };

    Client {
        signature_key: signature_scheme.get_signer().to_bytes().unwrap(),
        credential: Credential::Basic(basic),
        capabilities: Default::default(),
        key_lifetime: 42,
    }
}

fn test_create(cipher_suite: CipherSuite, update_path: bool) {
    let mut rng = OpenSslRng;

    let alice = generate_client(b"alice".to_vec());
    let bob = generate_client(b"bob".to_vec());

    let alice_key = alice.gen_key_package(&mut rng, &cipher_suite).unwrap();
    let bob_key = bob.gen_key_package(&mut rng, &cipher_suite).unwrap();

    // Alice creates a group and adds bob to the group
    let mut test_group = Group::new(&mut rng, b"group".to_vec(), alice_key.clone()).unwrap();

    let add_members = test_group
        .add_member_proposals(&vec![bob_key.key_package.clone()])
        .unwrap();

    let commit = test_group
        .commit_proposals(add_members, update_path, &mut rng, &alice, &alice)
        .unwrap();

    // Upon server confirmation, alice applies the commit to her own state
    test_group.process_pending_commit(commit.clone()).unwrap();

    // Bob receives the welcome message and joins the group
    let bob_group = Group::from_welcome_message(
        commit.welcome.unwrap(),
        test_group.public_tree.clone(),
        bob_key,
    )
    .unwrap();

    assert_eq!(test_group, bob_group);
}

fn get_cipher_suites() -> Vec<CipherSuite> {
    [
        Mls10128Dhkemx25519Aes128gcmSha256Ed25519,
        Mls10256Dhkemp521Aes256gcmSha512P521,
        Mls10128Dhkemx25519Chacha20poly1305Sha256Ed25519,
        Mls10128Dhkemp256Aes128gcmSha256P256,
    ]
    .to_vec()
}

#[test]
fn test_create_group_no_update() {
    get_cipher_suites()
        .iter()
        .for_each(|cs| test_create(cs.clone(), false))
}

#[test]
fn test_create_group_update() {
    get_cipher_suites()
        .iter()
        .for_each(|cs| test_create(cs.clone(), true))
}

struct TestGroupCreation {
    creator: Client,
    creator_key: KeyPackageGeneration,
    creator_group: Group,
    receiver_clients: Vec<Client>,
    receiver_private_keys: Vec<KeyPackageGeneration>,
    receiver_groups: Vec<Group>,
}

fn get_test_group(cipher_suite: CipherSuite, num_participants: usize) -> TestGroupCreation {
    // Create the group with Alice as the group initiator
    let alice = generate_client(b"alice".to_vec());

    let alice_key = alice
        .gen_key_package(&mut OpenSslRng, &cipher_suite)
        .unwrap();

    let mut test_group = Group::new(&mut OpenSslRng, b"group".to_vec(), alice_key.clone()).unwrap();

    // Generate random clients that will be members of the group
    let clients = (0..num_participants)
        .into_iter()
        .map(|_| generate_client(b"test".to_vec()))
        .collect::<Vec<Client>>();

    let test_keys = clients
        .iter()
        .map(|client| {
            client
                .gen_key_package(&mut OpenSslRng, &cipher_suite)
                .unwrap()
        })
        .collect::<Vec<KeyPackageGeneration>>();

    // Add the generated clients to the group Alice created
    let add_members_proposal = test_group
        .add_member_proposals(
            &test_keys
                .iter()
                .map(|g| g.key_package.clone())
                .collect::<Vec<KeyPackage>>(),
        )
        .unwrap();

    let commit = test_group
        .commit_proposals(add_members_proposal, true, &mut OpenSslRng, &alice, &alice)
        .unwrap();

    let events = test_group.process_pending_commit(commit.clone()).unwrap();
    assert_eq!(events.len(), 1);
    let credentials = test_keys
        .iter()
        .map(|k| k.key_package.credential.clone())
        .collect();
    assert_eq!(events[0], Event::MembersAdded(credentials));

    // Create groups for each participant by processing Alice's welcome message
    let receiver_groups = test_keys
        .iter()
        .map(|kp| {
            Group::from_welcome_message(
                commit.welcome.as_ref().unwrap().clone(),
                test_group.public_tree.clone(),
                kp.clone(),
            )
            .unwrap()
        })
        .collect::<Vec<Group>>();

    TestGroupCreation {
        creator: alice,
        creator_key: alice_key,
        creator_group: test_group,
        receiver_clients: clients,
        receiver_private_keys: test_keys,
        receiver_groups,
    }
}

fn test_path_updates(cipher_suite: CipherSuite) {
    println!(
        "Testing path updates for cipher suite: {:?}",
        cipher_suite.clone()
    );

    let mut test_group_data = get_test_group(cipher_suite, 10);

    // Loop through each participant and send a path update
    for i in 0..test_group_data.receiver_groups.len() {
        let pending = test_group_data.receiver_groups[i]
            .commit_proposals(
                vec![],
                true,
                &mut OpenSslRng,
                &test_group_data.receiver_clients[i],
                &test_group_data.receiver_clients[i],
            )
            .unwrap();

        test_group_data
            .creator_group
            .process_plaintext(pending.plaintext.clone())
            .unwrap();

        for j in 0..test_group_data.receiver_groups.len() {
            if i != j {
                test_group_data.receiver_groups[j]
                    .process_plaintext(pending.plaintext.clone())
                    .unwrap();
            } else {
                test_group_data.receiver_groups[j]
                    .process_pending_commit(pending.clone())
                    .unwrap();
            }
        }
    }

    // Validate that all the groups are in the same end state
    test_group_data
        .receiver_groups
        .iter()
        .for_each(|group| assert_eq!(group, &test_group_data.creator_group));
}

#[test]
fn test_group_path_updates() {
    get_cipher_suites()
        .iter()
        .for_each(|cs| test_path_updates(cs.clone()))
}

fn test_update_proposals(cipher_suite: CipherSuite) {
    println!(
        "Testing update proposals for cipher suite: {:?}",
        cipher_suite.clone()
    );

    let mut test_group_data = get_test_group(cipher_suite, 10);

    // Create an update from the ith member, have the ith + 1 member commit it
    for i in 0..test_group_data.receiver_groups.len() - 1 {
        let update_proposal = test_group_data.receiver_groups[i]
            .update_proposal(&mut OpenSslRng, &test_group_data.receiver_clients[i])
            .unwrap();

        let update_proposal_packet = test_group_data.receiver_groups[i]
            .send_proposal(update_proposal, &test_group_data.receiver_clients[i])
            .unwrap();

        // Everyone should process the proposal
        test_group_data
            .creator_group
            .process_plaintext(update_proposal_packet.clone())
            .unwrap();

        for j in 0..test_group_data.receiver_groups.len() {
            if i != j {
                test_group_data.receiver_groups[j]
                    .process_plaintext(update_proposal_packet.clone())
                    .unwrap();
            }
        }

        // Another user will later commit the proposal
        let pending = test_group_data.receiver_groups[i + 1]
            .commit_proposals(
                vec![],
                true,
                &mut OpenSslRng,
                &test_group_data.receiver_clients[i + 1],
                &test_group_data.receiver_clients[i + 1],
            )
            .unwrap();

        test_group_data
            .creator_group
            .process_plaintext(pending.plaintext.clone())
            .unwrap();

        // Everyone then receives the commit
        for j in 0..test_group_data.receiver_groups.len() {
            if i + 1 != j {
                let events = test_group_data.receiver_groups[j]
                    .process_plaintext(pending.plaintext.clone())
                    .unwrap();
                assert_eq!(events.len(), 0);
            } else {
                test_group_data.receiver_groups[j]
                    .process_pending_commit(pending.clone())
                    .unwrap();
            }
        }

        // Validate that all the groups are in the same end state
        test_group_data
            .receiver_groups
            .iter()
            .for_each(|group| assert_eq!(group, &test_group_data.creator_group));
    }
}

#[test]
fn test_group_update_proposals() {
    get_cipher_suites()
        .iter()
        .for_each(|cs| test_update_proposals(cs.clone()))
}

fn test_remove_proposals(cipher_suite: CipherSuite) {
    println!(
        "Testing remove proposals for cipher suite: {:?}",
        cipher_suite.clone()
    );

    let mut test_group_data = get_test_group(cipher_suite, 10);

    // Remove people from the group one at a time
    while test_group_data.receiver_groups.len() > 0 {
        let removal = test_group_data
            .creator_group
            .remove_proposal((test_group_data.creator_group.public_tree.leaf_count() - 1) as u32)
            .unwrap();

        let pending = test_group_data
            .creator_group
            .commit_proposals(
                vec![removal],
                true,
                &mut OpenSslRng,
                &test_group_data.creator,
                &test_group_data.creator,
            )
            .unwrap();

        // Process the removal in the creator group
        test_group_data
            .creator_group
            .process_pending_commit(pending.clone())
            .unwrap();

        // Process the removal in the other receiver groups
        for j in 0..test_group_data.receiver_groups.len() {
            let events = test_group_data.receiver_groups[j]
                .process_plaintext(pending.plaintext.clone())
                .unwrap();

            let removed_index = test_group_data.receiver_groups.len() - 1;
            let removed_cred = test_group_data.receiver_clients[removed_index]
                .credential
                .clone();

            assert_eq!(events.len(), 1);
            assert_eq!(events[0], Event::MembersRemoved(vec![removed_cred]))
        }

        // Validate that all the groups are in the same end state
        test_group_data
            .receiver_groups
            .remove(test_group_data.receiver_groups.len() - 1);

        test_group_data
            .receiver_groups
            .iter()
            .for_each(|group| assert_eq!(group, &test_group_data.creator_group));
    }
}

#[test]
fn test_group_remove_proposals() {
    get_cipher_suites()
        .iter()
        .for_each(|cs| test_remove_proposals(cs.clone()))
}

fn test_application_messages(cipher_suite: CipherSuite, message_count: usize) {
    println!(
        "Testing application messages, cipher suite: {:?}, message count: {}",
        cipher_suite.clone(),
        message_count
    );

    let mut test_group_data = get_test_group(cipher_suite, 10);

    // Loop through each participant and send 5 application messages
    for i in 0..test_group_data.receiver_groups.len() {
        let test_message = b"hello world";

        for _ in 0..message_count {
            let ciphertext = test_group_data.receiver_groups[i]
                .encrypt_application_message(
                    &mut OpenSslRng,
                    test_message.to_vec(),
                    &test_group_data.receiver_clients[i],
                )
                .unwrap();

            test_group_data
                .creator_group
                .process_ciphertext(ciphertext.clone())
                .unwrap();

            for j in 0..test_group_data.receiver_groups.len() {
                if i != j {
                    let events = test_group_data.receiver_groups[j]
                        .process_ciphertext(ciphertext.clone())
                        .unwrap();
                    assert_eq!(events.len(), 1);
                    assert_eq!(events[0], Event::ApplicationData(test_message.to_vec()));
                }
            }
        }
    }
}

#[test]
fn test_group_application_messages() {
    get_cipher_suites()
        .iter()
        .for_each(|cs| test_application_messages(cs.clone(), 20))
}
