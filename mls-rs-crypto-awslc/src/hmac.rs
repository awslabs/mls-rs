// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// Copyright by contributors to this project.
// SPDX-License-Identifier: (Apache-2.0 OR MIT)

use aws_lc_rs::hmac;
use mls_rs_core::crypto::CipherSuite;
use mls_rs_crypto_hpke::kem_combiner::ghp::RandomOracle;

use crate::AwsLcCryptoError;

#[derive(Clone, Copy, Debug)]
pub struct AwsLcHmac {
    pub algo: hmac::Algorithm,
}

impl AwsLcHmac {
    pub fn new(cipher_suite: CipherSuite) -> Option<Self> {
        let algo = match cipher_suite {
            CipherSuite::CURVE25519_AES128
            | CipherSuite::CURVE25519_CHACHA
            | CipherSuite::P256_AES128 => Some(hmac::HMAC_SHA256),
            CipherSuite::P384_AES256 => Some(hmac::HMAC_SHA384),
            CipherSuite::P521_AES256 => Some(hmac::HMAC_SHA512),
            _ => None,
        }?;

        Some(Self { algo })
    }

    pub fn hmac(&self, key: &[u8], data: &[u8]) -> Result<Vec<u8>, AwsLcCryptoError> {
        let key = hmac::Key::new(self.algo, key);
        Ok(hmac::sign(&key, data).as_ref().to_vec())
    }
}

impl RandomOracle for AwsLcHmac {
    type Error = AwsLcCryptoError;

    fn eval(&self, data: &[u8]) -> Result<Vec<u8>, AwsLcCryptoError> {
        self.hmac(&[], data)
    }
}
