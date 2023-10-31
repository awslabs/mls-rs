// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// Copyright by contributors to this project.
// SPDX-License-Identifier: (Apache-2.0 OR MIT)

use mls_rs_core::{
    crypto::{HpkePublicKey, HpkeSecretKey},
    error::IntoAnyError,
};

use alloc::vec::Vec;

#[cfg(feature = "mock")]
use mockall::automock;

/// A trait that provides the required DH functions, as in RFC 9180,Section 4.1
#[cfg_attr(feature = "mock", automock(type Error = crate::mock::TestError;))]
pub trait DhType {
    type Error: IntoAnyError;

    fn dh(
        &self,
        secret_key: &HpkeSecretKey,
        public_key: &HpkePublicKey,
    ) -> Result<Vec<u8>, Self::Error>;

    /// Generate a fresh key pair. This is the only place where randomness is used in this
    /// module. The function could be implemented in the same way as `derive` with random
    /// `ikm`, but it could also be implemented directly with a crypto provider like OpenSSL.
    fn generate(&self) -> Result<(HpkeSecretKey, HpkePublicKey), Self::Error>;

    /// Outputs the public key corresponding to the given secret key bytes. If the secret
    /// key is malformed, the function should return an error.
    fn to_public(&self, secret_key: &HpkeSecretKey) -> Result<HpkePublicKey, Self::Error>;

    /// If the output is `Some(bitmask)`, then the `Kem::derive` function will generate
    /// the secret key by rejection sampling over random byte sequences with `bitmask`
    /// applied to the most significant byte.
    ///
    /// Typical outputs for ECDH are:
    /// * `None` for curves 25519 and X448 (no rejection sampling is needed),
    /// * `Some(0x01)` for curve P-521 (all bits  of the first byte except the least
    ///   significant one are filtered out),
    /// * `Some(0xFF)`for curves P-256 and P-384 (rejection sampling is needed but no
    ///   bits need to be filtered).
    fn bitmask_for_rejection_sampling(&self) -> Option<u8>;

    fn secret_key_size(&self) -> usize;

    fn public_key_validate(&self, key: &HpkePublicKey) -> Result<(), Self::Error>;
}
