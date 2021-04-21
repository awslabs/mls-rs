use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use mls::asym::AsymmetricKey;
use mls::ciphersuite::CipherSuite;
use mls::client::Client;
use mls::credential::{BasicCredential, Credential};
use mls::extension::Lifetime;
use mls::group::{Group, Welcome};
use mls::key_package::{KeyPackage, KeyPackageGeneration, KeyPackageGenerator};
use mls::rand::OpenSslRng;
use mls::ratchet_tree::RatchetTree;
use mls::signature::ed25519::EdDsa25519;
use mls::signature::SignatureScheme;

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
        key_lifetime: Lifetime {
            not_before: 0,
            not_after: 0,
        },
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
    // Upon server confirmation, alice applies the commit to her own state
    test_group.process_pending_commit(commit).unwrap();
    (test_group, welcome.unwrap())
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

fn create_group_benchmark(c: &mut Criterion) {
    let cipher_suite = CipherSuite::Mls10256Dhkemp521Aes256gcmSha512P521;
    let alice = generate_client(b"alice".to_vec());
    let alice_key_package = alice
        .gen_key_package(&mut OpenSslRng, &cipher_suite)
        .unwrap();
    let recipients = (0..500)
        .into_iter()
        .map(|_| generate_recipient_key_package(cipher_suite.clone()).key_package)
        .collect::<Vec<KeyPackage>>();

    let inputs = CreateInputs {
        client: alice,
        creator: alice_key_package,
        members: recipients,
    };

    c.bench_with_input(BenchmarkId::new("create group", 500), &inputs, |b, s| {
        b.iter(|| create_group(black_box(s)));
    });
}

#[derive(Clone, Debug)]
struct ReceiveInputs {
    welcome: Welcome,
    ratchet_tree: RatchetTree,
    key_package: KeyPackageGeneration,
}

fn receive_group_benchmark(c: &mut Criterion) {
    let cipher_suite = CipherSuite::Mls10256Dhkemp521Aes256gcmSha512P521;
    let alice = generate_client(b"alice".to_vec());
    let alice_key_package = alice
        .gen_key_package(&mut OpenSslRng, &cipher_suite)
        .unwrap();
    let bob = generate_client(b"bob".to_vec());
    let bob_key_package = bob.gen_key_package(&mut OpenSslRng, &cipher_suite).unwrap();
    let mut recipients = (0..499)
        .into_iter()
        .map(|_| generate_recipient_key_package(cipher_suite.clone()).key_package)
        .collect::<Vec<KeyPackage>>();
    recipients.push(bob_key_package.key_package.clone());

    let create_inputs = CreateInputs {
        client: alice,
        creator: alice_key_package,
        members: recipients,
    };

    let (group, welcome) = create_group(&create_inputs);

    let inputs = ReceiveInputs {
        welcome,
        ratchet_tree: group.public_tree,
        key_package: bob_key_package,
    };

    c.bench_with_input(BenchmarkId::new("receive group", 500), &inputs, |b, s| {
        b.iter(|| receive_group(black_box(s.clone())));
    });
}

criterion_group!(benches, create_group_benchmark, receive_group_benchmark);
criterion_main!(benches);
