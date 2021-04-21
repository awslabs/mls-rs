use mls::asym::AsymmetricKey;
use mls::ciphersuite::CipherSuite;
use mls::client::Client;
use mls::credential::{BasicCredential, Credential};
use mls::framing::MLSPlaintext;
use mls::group::{Group, Welcome};
use mls::key_package::{KeyPackage, KeyPackageGeneration, KeyPackageGenerator};
use mls::rand::OpenSslRng;
use mls::ratchet_tree::RatchetTree;
use mls::signature::ed25519::EdDsa25519;
use mls::signature::SignatureScheme;
use std::time::Instant;

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

fn generate_recipient_key_package(cipher_suite: CipherSuite) -> KeyPackageGeneration {
    let client = generate_client(b"test".to_vec());
    client
        .gen_key_package(&mut OpenSslRng, &cipher_suite)
        .unwrap()
}

fn create_group(create_inputs: &CreateInputs) -> (Group, Welcome) {
    let mut rng = OpenSslRng;
    let mut test_group =
        Group::new(&mut rng, b"group".to_vec(), create_inputs.creator.clone()).unwrap();

    let add_members = test_group
        .add_member_proposals(&create_inputs.members)
        .unwrap();

    let commit = test_group
        .commit_proposals(add_members, true, &mut rng, &create_inputs.client)
        .unwrap();

    let welcome = commit.welcome.clone();
    // Upon server confirmation, apply the commit to your own state
    test_group.process_pending_commit(commit).unwrap();
    (test_group, welcome.unwrap())
}

fn update_path(client: &Client, group: &mut Group) -> MLSPlaintext {
    let commit = group
        .commit_proposals(vec![], true, &mut OpenSslRng, client)
        .unwrap();

    group.process_pending_commit(commit.clone()).unwrap();
    commit.plaintext
}

fn receive_group(inputs: ReceiveInputs) -> Group {
    Group::from_welcome_message(inputs.welcome, inputs.ratchet_tree, inputs.key_package).unwrap()
}

#[derive(Clone, Debug)]
struct CreateInputs {
    client: Client,
    creator: KeyPackageGeneration,
    members: Vec<KeyPackage>,
}

#[derive(Clone, Debug)]
struct ReceiveInputs {
    welcome: Welcome,
    ratchet_tree: RatchetTree,
    key_package: KeyPackageGeneration,
}

fn main() {
    let cipher_suite = CipherSuite::Mls10256Dhkemp521Aes256gcmSha512P521;
    let alice = generate_client(b"alice".to_vec());
    let bob = generate_client(b"bob".to_vec());
    let charlie = generate_client(b"charlie".to_vec());

    let alice_key_package = alice
        .gen_key_package(&mut OpenSslRng, &cipher_suite)
        .unwrap();

    let bob_key_package = bob.gen_key_package(&mut OpenSslRng, &cipher_suite).unwrap();

    let charlie_key_package = charlie
        .gen_key_package(&mut OpenSslRng, &cipher_suite)
        .unwrap();

    let mut recipients = [
        bob_key_package.key_package.clone(),
        charlie_key_package.key_package.clone(),
    ]
    .to_vec();

    let mut other_recipients = (0..1998)
        .into_iter()
        .map(|_| generate_recipient_key_package(cipher_suite.clone()).key_package)
        .collect::<Vec<KeyPackage>>();

    recipients.append(&mut other_recipients);

    let inputs = CreateInputs {
        client: alice,
        creator: alice_key_package,
        members: recipients,
    };

    println!("START ALICE GROUP CREATION");
    let start_create = Instant::now();
    let (mut alice_group, welcome) = create_group(&inputs);
    println!(
        "CREATE: {:?} time: {}",
        alice_group.cipher_suite,
        start_create.elapsed().as_millis()
    );

    let mut bob_group = receive_group(ReceiveInputs {
        welcome: welcome.clone(),
        ratchet_tree: alice_group.public_tree.clone(),
        key_package: bob_key_package,
    });

    let mut charlie_group = receive_group(ReceiveInputs {
        welcome: welcome.clone(),
        ratchet_tree: alice_group.public_tree.clone(),
        key_package: charlie_key_package,
    });

    println!("START BOB PATH UPDATE");
    let start = Instant::now();
    let bob_path_update = update_path(&bob, &mut bob_group);
    println!("UPDATE PATH BOB: {}", start.elapsed().as_millis());

    println!("STARTING CHARLIE DECRYPT");

    alice_group
        .process_plaintext(bob_path_update.clone())
        .unwrap();
    charlie_group.process_plaintext(bob_path_update).unwrap();

    let new_start = Instant::now();
    let plaintext2 = update_path(&charlie, &mut charlie_group);
    println!("UPDATE PATH CHARLIE: {}", new_start.elapsed().as_millis());

    alice_group.process_plaintext(plaintext2.clone()).unwrap();
    bob_group.process_plaintext(plaintext2.clone()).unwrap();
}
