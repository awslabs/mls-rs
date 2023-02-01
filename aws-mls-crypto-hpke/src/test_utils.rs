use aws_mls_core::crypto::{
    CipherSuite, CURVE25519_AES128, CURVE25519_CHACHA, CURVE448_AES256, CURVE448_CHACHA,
    P256_AES128, P384_AES256, P521_AES256,
};

use aws_mls_crypto_openssl::{
    ecdh::{Ecdh, KemId},
    kdf::Kdf,
};
use serde::Deserialize;

use crate::{dhkem::DhKem, hpke::ModeId};

#[derive(Deserialize, Debug, Clone)]
pub struct TestCaseAlgo {
    pub kem_id: u16,
    pub kdf_id: u16,
    pub aead_id: u16,
    pub mode: u8,
}

pub fn filter_test_case(algo: &TestCaseAlgo) -> Option<CipherSuite> {
    if ![ModeId::Base as u8, ModeId::Psk as u8].contains(&algo.mode) {
        return None;
    }

    match (algo.kem_id, algo.kdf_id, algo.aead_id) {
        (0x0010, 0x0001, 0x0001) => Some(P256_AES128),
        (0x0011, 0x0002, 0x0002) => Some(P384_AES256),
        (0x0012, 0x0003, 0x0002) => Some(P521_AES256),
        (0x0020, 0x0001, 0x0001) => Some(CURVE25519_AES128),
        (0x0020, 0x0001, 0x0003) => Some(CURVE25519_CHACHA),
        (0x0021, 0x0003, 0x0002) => Some(CURVE448_AES256),
        (0x0021, 0x0003, 0x0003) => Some(CURVE448_CHACHA),
        _ => None,
    }
}

pub fn test_dhkem(cipher_suite: CipherSuite) -> DhKem<Ecdh, Kdf> {
    let kem_id = KemId::new(cipher_suite).unwrap();

    DhKem::new(
        Ecdh::new(cipher_suite).unwrap(),
        Kdf::new(cipher_suite).unwrap(),
        kem_id as u16,
        kem_id.n_secret(),
    )
}
