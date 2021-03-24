extern crate mls;
use mls::group::Group;
use mls::rand::OpenSslRng;
use mls::client::Client;
use mls::extension::Lifetime;
use mls::credential::{Credential, BasicCredential};
use mls::signature::ed25519::EdDsa25519;
use mls::signature::SignatureScheme;
use mls::asym::AsymmetricKey;
use mls::key_package::KeyPackageGenerator;
use mls::ciphersuite::CipherSuite::MLS10_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;

fn generate_client(id: Vec<u8>) -> Client {
    let signature_scheme = EdDsa25519::new_random(OpenSslRng).unwrap();
    let signature_key = signature_scheme.as_public_signature_key().unwrap();
    let basic = BasicCredential {
        signature_key: signature_key.signature_key,
        identity: id,
        signature_scheme: signature_key.signature_scheme
    };

    Client {
        signature_key: signature_scheme.get_signer().to_bytes().unwrap(),
        credential: Credential::Basic(basic),
        capabilities: Default::default(),
        key_lifetime: Lifetime { not_before: 0, not_after: 0 }
    }
}

#[test]
fn test_create_group() {
    let mut rng = OpenSslRng;
    let cipher_suite = MLS10_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;

    let alice = generate_client(b"alice".to_vec());
    let bob = generate_client(b"bob".to_vec());

    let alice_key = alice.gen_key_package(&mut rng, &cipher_suite).unwrap();
    let bob_key = bob.gen_key_package(&mut rng, &cipher_suite).unwrap();

    // Alice creates a group and adds bob to the group
    let mut test_group = Group::new(&mut rng, b"group".to_vec(), alice_key.clone()).unwrap();
    let add_members = test_group.add_member_proposals(&vec![bob_key.key_package.clone()]).unwrap();
    let commit = test_group.commit_proposals(add_members, true, &mut rng, &alice).unwrap();

    // Upon server confirmation, alice applies the commit to her own state
    test_group.process_pending_commit(commit.clone()).unwrap();

    // Bob receives the welcome message and joins the group
    let bob_group = Group::from_welcome_message(commit.welcome.unwrap(), test_group.public_tree.clone(), bob_key).unwrap();

    assert_eq!(test_group.public_tree, bob_group.public_tree);
    assert_eq!(test_group.cipher_suite, bob_group.cipher_suite);
}

// #[bench]
// fn test_group_operation_performance(b: &mut Bencher) {
//
// }