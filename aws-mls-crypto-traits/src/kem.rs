// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// Copyright by contributors to this project.
// SPDX-License-Identifier: (Apache-2.0 OR MIT)

use aws_mls_core::{
    crypto::{CipherSuite, HpkePublicKey, HpkeSecretKey},
    error::IntoAnyError,
};

use alloc::vec::Vec;

#[cfg(feature = "mock")]
use mockall::automock;

/// A trait that provides the required KEM functions
#[cfg_attr(feature = "mock", automock(type Error = crate::mock::TestError;))]
pub trait KemType {
    type Error: IntoAnyError;

    /// KEM Id, as specified in RFC 9180, Section 5.1 and Table 2.
    fn kem_id(&self) -> u16;

    fn derive(&self, ikm: &[u8]) -> Result<(HpkeSecretKey, HpkePublicKey), Self::Error>;
    fn generate(&self) -> Result<(HpkeSecretKey, HpkePublicKey), Self::Error>;
    fn public_key_validate(&self, key: &HpkePublicKey) -> Result<(), Self::Error>;

    fn encap(&self, remote_key: &HpkePublicKey) -> Result<KemResult, Self::Error>;

    fn decap(
        &self,
        enc: &[u8],
        secret_key: &HpkeSecretKey,
        local_public: &HpkePublicKey,
    ) -> Result<Vec<u8>, Self::Error>;
}

/// Struct to represent the output of the kem [encap](KemType::encap) function
pub struct KemResult {
    shared_secret: Vec<u8>,
    enc: Vec<u8>,
}

impl KemResult {
    pub fn new(shared_secret: Vec<u8>, enc: Vec<u8>) -> Self {
        Self { shared_secret, enc }
    }

    pub fn shared_secret(&self) -> &[u8] {
        &self.shared_secret
    }

    /// Returns the ciphertext encapsulating the shared secret.
    pub fn enc(&self) -> &[u8] {
        &self.enc
    }
}

/// Kem identifiers for HPKE
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u16)]
#[non_exhaustive]
pub enum KemId {
    DhKemP256Sha256 = 0x0010,
    DhKemP384Sha384 = 0x0011,
    DhKemP521Sha512 = 0x0012,
    DhKemX25519Sha256 = 0x0020,
    DhKemX448Sha512 = 0x0021,
}

impl KemId {
    pub fn new(cipher_suite: CipherSuite) -> Option<Self> {
        match cipher_suite {
            CipherSuite::CURVE25519_AES128 | CipherSuite::CURVE25519_CHACHA => {
                Some(KemId::DhKemX25519Sha256)
            }
            CipherSuite::P256_AES128 => Some(KemId::DhKemP256Sha256),
            CipherSuite::CURVE448_AES256 | CipherSuite::CURVE448_CHACHA => {
                Some(KemId::DhKemX448Sha512)
            }
            CipherSuite::P384_AES256 => Some(KemId::DhKemP384Sha384),
            CipherSuite::P521_AES256 => Some(KemId::DhKemP521Sha512),
            _ => None,
        }
    }

    pub fn n_secret(&self) -> usize {
        match self {
            KemId::DhKemP256Sha256 => 32,
            KemId::DhKemP384Sha384 => 48,
            KemId::DhKemP521Sha512 => 64,
            KemId::DhKemX25519Sha256 => 32,
            KemId::DhKemX448Sha512 => 64,
        }
    }
}
