//! ML-DSA tests against the Wycheproof vectors of the `wycheproof` crate. Cases with a
//! non-empty context are skipped (draft-ietf-mls-pq-ciphersuites-07 §2).

#![cfg(all(feature = "post-quantum", not(mls_build_async)))]

use mls_rs_core::crypto::{
    CipherSuite, CipherSuiteProvider, SignaturePublicKey, SignatureSecretKey,
};
use mls_rs_crypto_awslc::{AwsLcCipherSuite, AwsLcCipherSuiteBuilder};
use mls_rs_crypto_traits::Curve;
use wycheproof::{mldsa_sign, mldsa_verify, ByteString, TestResult};

const SEED_LEN: usize = 32;

struct Params {
    curve: Curve,
    name: &'static str,
    public_key_len: usize,
    signature_len: usize,
    expanded_secret_key_len: usize,
    verify: mldsa_verify::TestName,
    sign_seed: mldsa_sign::TestName,
    // Pinned so a vector update can't silently skip cases.
    verify_with_context: usize,
    valid_seeds: usize,
    invalid_seeds: usize,
    signed: usize,
}

const PARAMS: [Params; 1] = [
    Params {
        curve: Curve::MlDsa44,
        name: "ML-DSA-44",
        public_key_len: 1312,
        signature_len: 2420,
        expanded_secret_key_len: 2560,
        verify: mldsa_verify::TestName::MlDsa44Verify,
        sign_seed: mldsa_sign::TestName::MlDsa44SignSeed,
        verify_with_context: 7,
        valid_seeds: 25,
        invalid_seeds: 3,
        signed: 71,
    },
];

fn provider(p: &Params) -> AwsLcCipherSuite {
    AwsLcCipherSuiteBuilder::new()
        .signing(p.curve)
        .build(CipherSuite::CURVE25519_AES128)
        .unwrap()
}

fn has_context(ctx: &Option<ByteString>) -> bool {
    ctx.as_ref().is_some_and(|c| !c.is_empty())
}

#[test]
fn wycheproof_verify() {
    for p in &PARAMS {
        wycheproof_verify_for(p);
    }
}

fn wycheproof_verify_for(p: &Params) {
    let set = mldsa_verify::TestSet::load(p.verify).unwrap();
    let cs = provider(p);
    let mut with_context = 0;

    for group in &set.test_groups {
        let pk = SignaturePublicKey::from(group.pubkey.to_vec());

        for t in &group.tests {
            if has_context(&t.ctx) {
                with_context += 1;
                continue;
            }

            let valid = cs.verify(&pk, &t.sig, &t.msg).is_ok();
            assert_eq!(
                valid,
                t.result == TestResult::Valid,
                "{} tcId {} ({}): expected {:?}",
                p.name,
                t.tc_id,
                t.comment,
                t.result
            );
        }
    }

    assert_eq!(with_context, p.verify_with_context, "{}", p.name);
}

#[test]
fn wycheproof_sign_seed() {
    for p in &PARAMS {
        wycheproof_sign_seed_for(p);
    }
}

fn wycheproof_sign_seed_for(p: &Params) {
    let set = mldsa_sign::TestSet::load(p.sign_seed).unwrap();
    let cs = provider(p);
    let (mut valid_seeds, mut invalid_seeds, mut signed) = (0, 0, 0);

    for group in &set.test_groups {
        let seed = group.privseed.as_ref().unwrap();
        let sk = SignatureSecretKey::from(seed.to_vec());

        if seed.len() != SEED_LEN {
            assert!(cs.signature_key_derive_public(&sk).is_err());
            assert!(cs.sign(&sk, b"message").is_err());
            assert!(group.tests.iter().all(|t| t.result == TestResult::Invalid));
            invalid_seeds += 1;
            continue;
        }

        let pk = cs.signature_key_derive_public(&sk).unwrap();
        assert_eq!(pk.as_bytes(), group.pubkey.as_ref().unwrap().as_slice());
        valid_seeds += 1;

        for t in &group.tests {
            let Some(msg) = &t.msg else { continue };

            if has_context(&t.ctx) || t.result != TestResult::Valid {
                continue;
            }

            let sig = cs.sign(&sk, msg).unwrap();
            assert_eq!(sig.len(), p.signature_len, "{} tcId {}", p.name, t.tc_id);
            cs.verify(&pk, &sig, msg)
                .unwrap_or_else(|e| panic!("{} tcId {}: {e:?}", p.name, t.tc_id));
            cs.verify(&pk, &t.sig, msg)
                .unwrap_or_else(|e| panic!("{} tcId {}: {e:?}", p.name, t.tc_id));

            signed += 1;
        }
    }

    assert_eq!(valid_seeds, p.valid_seeds, "{}", p.name);
    assert_eq!(invalid_seeds, p.invalid_seeds, "{}", p.name);
    assert_eq!(signed, p.signed, "{}", p.name);
}

#[test]
fn key_and_signature_sizes() {
    for p in &PARAMS {
        let cs = provider(p);

        let (sk, pk) = cs.signature_key_generate().unwrap();
        assert_eq!(sk.as_bytes().len(), SEED_LEN, "{}", p.name);
        assert_eq!(pk.as_bytes().len(), p.public_key_len, "{}", p.name);
        assert_eq!(cs.signature_key_derive_public(&sk).unwrap(), pk);

        let sig = cs.sign(&sk, b"message").unwrap();
        assert_eq!(sig.len(), p.signature_len, "{}", p.name);
    }
}

#[test]
fn sign_with_label_style_round_trip() {
    for p in &PARAMS {
        sign_with_label_style_round_trip_for(p);
    }
}

fn sign_with_label_style_round_trip_for(p: &Params) {
    let cs = provider(p);
    let (sk, pk) = cs.signature_key_generate().unwrap();

    let sign_content = |label: &[u8], content: &[u8]| {
        let label = [b"MLS 1.0 " as &[u8], label].concat();
        let mut out = vec![label.len() as u8];
        out.extend_from_slice(&label);
        out.push(content.len() as u8);
        out.extend_from_slice(content);
        out
    };

    let msg = sign_content(b"FramedContentTBS", b"content");
    let sig = cs.sign(&sk, &msg).unwrap();
    cs.verify(&pk, &sig, &msg).unwrap();

    let other_label = sign_content(b"LeafNodeTBS", b"content");
    assert!(cs.verify(&pk, &sig, &other_label).is_err());

    let mut tampered = sig.clone();
    tampered[0] ^= 1;
    assert!(cs.verify(&pk, &tampered, &msg).is_err());

    let (_, other_pk) = cs.signature_key_generate().unwrap();
    assert!(cs.verify(&other_pk, &sig, &msg).is_err());
}

/// draft-ietf-mls-pq-ciphersuites-07 §2: only the raw `pkEncode` form is accepted.
#[test]
fn verify_rejects_spki_encoded_public_keys() {
    for p in &PARAMS {
        verify_rejects_spki_encoded_public_keys_for(p);
    }
}

fn verify_rejects_spki_encoded_public_keys_for(p: &Params) {
    let set = mldsa_verify::TestSet::load(p.verify).unwrap();
    let cs = provider(p);

    let (group, t) = set
        .test_groups
        .iter()
        .find_map(|g| {
            g.tests
                .iter()
                .find(|t| t.result == TestResult::Valid && !has_context(&t.ctx))
                .map(|t| (g, t))
        })
        .unwrap();

    let raw = SignaturePublicKey::from(group.pubkey.to_vec());
    cs.verify(&raw, &t.sig, &t.msg).unwrap();

    let spki = SignaturePublicKey::from(group.der.to_vec());
    assert!(cs.verify(&spki, &t.sig, &t.msg).is_err());
}

#[test]
fn sign_rejects_expanded_secret_keys() {
    for p in &PARAMS {
        let cs = provider(p);

        let expanded = SignatureSecretKey::from(vec![1u8; p.expanded_secret_key_len]);
        assert!(cs.sign(&expanded, b"message").is_err(), "{}", p.name);
        assert!(
            cs.signature_key_derive_public(&expanded).is_err(),
            "{}",
            p.name
        );
    }
}
