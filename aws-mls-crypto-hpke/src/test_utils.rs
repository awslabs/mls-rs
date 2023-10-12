// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// Copyright by contributors to this project.
// SPDX-License-Identifier: (Apache-2.0 OR MIT)

use aws_mls_core::crypto::CipherSuite;
use aws_mls_crypto_traits::KemId;
use cfg_if::cfg_if;
use serde::Deserialize;

use crate::{dhkem::DhKem, hpke::ModeId};

cfg_if! {
    if #[cfg(target_arch = "wasm32")] {
        pub use aws_mls_crypto_rustcrypto::{aead::Aead, ecdh, kdf::Kdf};
        pub use aws_mls_crypto_rustcrypto::RustCryptoProvider as TestCryptoProvider;
    } else {
        pub use aws_mls_crypto_openssl::{aead::Aead, ecdh, kdf::Kdf};
        pub use aws_mls_crypto_openssl::OpensslCryptoProvider as TestCryptoProvider;
    }
}

use ecdh::Ecdh;

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

    let mut cs_opt = match (algo.kem_id, algo.kdf_id, algo.aead_id) {
        (0x0010, 0x0001, 0x0001) => Some(CipherSuite::P256_AES128),
        (0x0011, 0x0002, 0x0002) => Some(CipherSuite::P384_AES256),
        (0x0012, 0x0003, 0x0002) => Some(CipherSuite::P521_AES256),
        (0x0020, 0x0001, 0x0001) => Some(CipherSuite::CURVE25519_AES128),
        (0x0020, 0x0001, 0x0003) => Some(CipherSuite::CURVE25519_CHACHA),
        (0x0021, 0x0003, 0x0002) => Some(CipherSuite::CURVE448_AES256),
        (0x0021, 0x0003, 0x0003) => Some(CipherSuite::CURVE448_CHACHA),
        _ => None,
    };

    if let Some(cs) = cs_opt {
        cs_opt = ciphersuite_supported(cs).then_some(cs);
    }

    cs_opt
}

pub fn ciphersuite_supported(cs: CipherSuite) -> bool {
    TestCryptoProvider::new()
        .enabled_cipher_suites
        .contains(&cs)
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
