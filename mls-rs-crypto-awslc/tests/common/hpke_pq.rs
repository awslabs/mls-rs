//! The draft-ietf-hpke-pq-05 Appendix A vectors in `test_data/hpke_pq/test_vectors.json`.

// Each test file that includes this module reads only some of the fields.
#![allow(dead_code)]

use serde::Deserialize;

#[derive(Deserialize)]
pub struct TestVector {
    pub kem_id: u16,
    pub kdf_id: u16,
    pub aead_id: u16,
    #[serde(with = "hex::serde")]
    pub info: Vec<u8>,
    #[serde(rename = "ikmR", with = "hex::serde")]
    pub ikm_r: Vec<u8>,
    #[serde(rename = "skRm", with = "hex::serde")]
    pub sk_rm: Vec<u8>,
    #[serde(rename = "pkRm", with = "hex::serde")]
    pub pk_rm: Vec<u8>,
    #[serde(with = "hex::serde")]
    pub enc: Vec<u8>,
    #[serde(with = "hex::serde")]
    pub shared_secret: Vec<u8>,
    pub encryptions: Vec<Encryption>,
    pub exports: Vec<Export>,
}

#[derive(Deserialize)]
pub struct Encryption {
    #[serde(with = "hex::serde")]
    pub aad: Vec<u8>,
    #[serde(with = "hex::serde")]
    pub ct: Vec<u8>,
    #[serde(with = "hex::serde")]
    pub pt: Vec<u8>,
}

#[derive(Deserialize)]
pub struct Export {
    #[serde(with = "hex::serde")]
    pub exporter_context: Vec<u8>,
    #[serde(rename = "L")]
    pub len: usize,
    #[serde(with = "hex::serde")]
    pub exported_value: Vec<u8>,
}

pub fn test_vectors() -> Vec<TestVector> {
    serde_json::from_str(include_str!("../../test_data/hpke_pq/test_vectors.json")).unwrap()
}

pub fn test_vector(kem_id: u16) -> TestVector {
    test_vectors()
        .into_iter()
        .find(|v| v.kem_id == kem_id)
        .unwrap_or_else(|| panic!("no vector for KEM {kem_id:#06x}"))
}
