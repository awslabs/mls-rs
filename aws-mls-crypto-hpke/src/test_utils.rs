use aws_mls_core::crypto::CipherSuite;
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
        (0x0010, 0x0001, 0x0001) => Some(CipherSuite::P256Aes128),
        (0x0011, 0x0002, 0x0002) => Some(CipherSuite::P384Aes256),
        (0x0012, 0x0003, 0x0002) => Some(CipherSuite::P521Aes256),
        (0x0020, 0x0001, 0x0001) => Some(CipherSuite::Curve25519Aes128),
        (0x0020, 0x0001, 0x0003) => Some(CipherSuite::Curve25519ChaCha20),
        (0x0021, 0x0003, 0x0002) => Some(CipherSuite::Curve448Aes256),
        (0x0021, 0x0003, 0x0003) => Some(CipherSuite::Curve448ChaCha20),
        _ => None,
    }
}

pub fn test_dhkem(cipher_suite: CipherSuite) -> DhKem<Ecdh, Kdf> {
    let kem_id = KemId::new(cipher_suite);

    DhKem::new(
        Ecdh::new(cipher_suite),
        Kdf::new(cipher_suite),
        kem_id as u16,
        kem_id.n_secret(),
    )
}
