//! draft-ietf-hpke-pq-05 Appendix A vectors (see `test_data/hpke_pq/README.md`).

#![cfg(feature = "post-quantum")]

use mls_rs_crypto_awslc::AwsLcShake256;
use mls_rs_crypto_hpke::kdf::labeled_derive;
use serde::Deserialize;

#[derive(Deserialize)]
struct TestVector {
    kem_id: u16,
    #[serde(rename = "ikmR", with = "hex::serde")]
    ikm_r: Vec<u8>,
    #[serde(rename = "skRm", with = "hex::serde")]
    sk_rm: Vec<u8>,
}

fn test_vectors() -> Vec<TestVector> {
    serde_json::from_str(include_str!("../test_data/hpke_pq/test_vectors.json")).unwrap()
}

fn seed_len(kem_id: u16) -> u16 {
    match kem_id {
        0x0041 => 64,
        0x647a => 32,
        other => panic!("unexpected kem_id {other:#06x}"),
    }
}

/// draft-ietf-hpke-pq §3, §4: `skRm` is the `LabeledDerive` seed.
#[test]
fn labeled_derive_reproduces_sk_rm() {
    let vectors = test_vectors();
    assert_eq!(vectors.len(), 2);

    for v in vectors {
        let suite_id = [b"KEM" as &[u8], &v.kem_id.to_be_bytes()].concat();

        let seed = labeled_derive(
            &AwsLcShake256,
            &suite_id,
            &v.ikm_r,
            b"DeriveKeyPair",
            b"",
            seed_len(v.kem_id),
        )
        .unwrap();

        assert_eq!(seed, v.sk_rm, "kem_id {:#06x}", v.kem_id);
    }
}
