//! Checks for the draft-ietf-mls-pq-ciphersuites-07 suites (§3.1, Table 2), from the
//! provider up to an MLS group.

#![cfg(all(feature = "post-quantum", not(mls_build_async)))]

#[path = "common/hpke_pq.rs"]
mod hpke_pq;

use mls_rs::{
    client_builder::MlsConfig,
    group::ReceivedMessage,
    identity::{
        basic::{BasicCredential, BasicIdentityProvider},
        SigningIdentity,
    },
    Client, Group,
};
use mls_rs_core::crypto::{CipherSuite, CipherSuiteProvider, CryptoProvider};
use mls_rs_crypto_awslc::{AwsLcCipherSuite, AwsLcCryptoProvider};

struct Expected {
    cipher_suite: CipherSuite,
    hpke_kem_id: u16,
    kdf_extract_size: usize,
    aead_key_size: usize,
    hash_len: usize,
    hpke_pk_len: usize,
    hpke_sk_len: usize,
    hpke_enc_len: usize,
    sig_pk_len: usize,
    sig_len: usize,
}

/// draft-ietf-mls-pq-ciphersuites-07 Table 2, draft-ietf-hpke-pq-05 §8.2, FIPS 204 Table 2.
const DRAFT_SUITES: [Expected; 1] = [Expected {
    cipher_suite: CipherSuite::MLKEM768X25519_CHACHA_MLDSA44,
    hpke_kem_id: 0x647a,
    kdf_extract_size: 48,
    aead_key_size: 32,
    hash_len: 48,
    hpke_pk_len: 1216,
    hpke_sk_len: 32,
    hpke_enc_len: 1120,
    sig_pk_len: 1312,
    sig_len: 2420,
}];

fn provider(cs: CipherSuite) -> AwsLcCipherSuite {
    AwsLcCryptoProvider::new()
        .cipher_suite_provider(cs)
        .unwrap_or_else(|| panic!("{cs:?} not supported"))
}

#[test]
fn suites_are_advertised() {
    let supported = AwsLcCryptoProvider::new().supported_cipher_suites();

    for e in &DRAFT_SUITES {
        assert!(supported.contains(&e.cipher_suite), "{:?}", e.cipher_suite);
    }
}

#[test]
fn algorithm_parameters() {
    for e in &DRAFT_SUITES {
        let cs = provider(e.cipher_suite);

        assert_eq!(cs.cipher_suite(), e.cipher_suite);
        assert_eq!(cs.kdf_extract_size(), e.kdf_extract_size);
        assert_eq!(cs.aead_key_size(), e.aead_key_size);
        assert_eq!(cs.aead_nonce_size(), 12);
        assert_eq!(cs.hash(b"abc").unwrap().len(), e.hash_len);
        assert_eq!(cs.mac(&[1u8; 32], b"abc").unwrap().len(), e.hash_len);

        let (sk, pk) = cs.kem_generate().unwrap();
        assert_eq!((sk.len(), pk.len()), (e.hpke_sk_len, e.hpke_pk_len));
        let ct = cs.hpke_seal(&pk, b"info", None, b"pt").unwrap();
        assert_eq!(ct.kem_output.len(), e.hpke_enc_len);
    }
}

#[test]
fn signatures() {
    for e in &DRAFT_SUITES {
        let cs = provider(e.cipher_suite);

        let (sk, pk) = cs.signature_key_generate().unwrap();
        assert_eq!(pk.as_bytes().len(), e.sig_pk_len);

        let sig = cs.sign(&sk, b"message").unwrap();
        assert_eq!(sig.len(), e.sig_len);
        assert_eq!(cs.signature_key_derive_public(&sk).unwrap(), pk);
        cs.verify(&pk, &sig, b"message").unwrap();
        assert!(cs.verify(&pk, &sig, b"other message").is_err());
    }
}

/// DeriveKeyPair uses only the KEM's suite_id (draft-ietf-hpke-hpke-06 §4.4).
#[test]
fn kem_derive_matches_the_hpke_pq_vectors() {
    for e in &DRAFT_SUITES {
        let v = hpke_pq::test_vector(e.hpke_kem_id);

        let (sk, pk) = provider(e.cipher_suite).kem_derive(&v.ikm_r).unwrap();

        assert_eq!(sk.as_ref(), v.sk_rm.as_slice(), "{:?}", e.cipher_suite);
        assert_eq!(pk.as_ref(), v.pk_rm.as_slice(), "{:?}", e.cipher_suite);
    }
}

fn client(cs: CipherSuite, name: &str) -> Client<impl MlsConfig> {
    let (secret, public) = provider(cs).signature_key_generate().unwrap();
    let credential = BasicCredential::new(name.as_bytes().to_vec()).into_credential();

    Client::builder()
        .identity_provider(BasicIdentityProvider)
        .crypto_provider(AwsLcCryptoProvider::new())
        .signing_identity(SigningIdentity::new(credential, public), secret, cs)
        .build()
}

fn send<C: MlsConfig>(from: &mut Group<C>, to: &mut Group<C>, data: &[u8]) {
    let msg = from
        .encrypt_application_message(data, Default::default())
        .unwrap();

    match to.process_incoming_message(msg).unwrap() {
        ReceivedMessage::ApplicationMessage(m) => assert_eq!(m.data(), data),
        other => panic!("unexpected message {other:?}"),
    }
}

/// RFC 9420: an Add with a Welcome (§12.4.3.1), a commit with an UpdatePath (§12.4),
/// application messages (§6.3) and the exporter (§8.5).
fn group_lifecycle(cs: CipherSuite) {
    let alice = client(cs, "alice");
    let bob = client(cs, "bob");
    let mut alice_group = alice.group_builder().unwrap().build().unwrap();

    let key_package = bob
        .generate_key_package_message(Default::default(), Default::default(), None)
        .unwrap();
    let commit = alice_group
        .commit_builder()
        .add_member(key_package)
        .unwrap()
        .build()
        .unwrap();
    alice_group.apply_pending_commit().unwrap();
    let (mut bob_group, _) = bob
        .join_group(None, &commit.welcome_messages[0], None)
        .unwrap();

    // An empty commit always has an UpdatePath.
    let commit = bob_group.commit_builder().build().unwrap();
    bob_group.apply_pending_commit().unwrap();
    alice_group
        .process_incoming_message(commit.commit_message)
        .unwrap();

    send(&mut alice_group, &mut bob_group, b"hello bob");
    send(&mut bob_group, &mut alice_group, b"hello alice");

    assert_eq!(bob_group.cipher_suite(), cs);
    assert_eq!(alice_group.current_epoch(), 2);
    assert_eq!(bob_group.current_epoch(), 2);
    assert_eq!(
        alice_group
            .export_secret(b"pq", b"", 32)
            .unwrap()
            .as_bytes(),
        bob_group.export_secret(b"pq", b"", 32).unwrap().as_bytes()
    );
}

#[test]
fn lifecycle_mlkem768x25519_chacha_mldsa44() {
    group_lifecycle(CipherSuite::MLKEM768X25519_CHACHA_MLDSA44);
}
