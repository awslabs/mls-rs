// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// Copyright by contributors to this project.
// SPDX-License-Identifier: (Apache-2.0 OR MIT)

use std::ops::Deref;

use mls_rs_core::crypto::CipherSuite;
use openssl::{
    hash::{hash, MessageDigest},
    pkey::PKey,
    sign::Signer,
};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum HashError {
    #[error(transparent)]
    OpensslError(#[from] openssl::error::ErrorStack),
    #[error("unsupported cipher suite")]
    UnsupportedCipherSuite,
}

#[derive(Clone)]
pub struct Hash(MessageDigest);

impl Deref for Hash {
    type Target = MessageDigest;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Hash {
    pub fn new(cipher_suite: CipherSuite) -> Result<Self, HashError> {
        let md = match cipher_suite {
            CipherSuite::CURVE25519_AES128
            | CipherSuite::P256_AES128
            | CipherSuite::CURVE25519_CHACHA => Ok(MessageDigest::sha256()),
            CipherSuite::P384_AES256 => Ok(MessageDigest::sha384()),
            CipherSuite::CURVE448_CHACHA
            | CipherSuite::CURVE448_AES256
            | CipherSuite::P521_AES256 => Ok(MessageDigest::sha512()),
            _ => Err(HashError::UnsupportedCipherSuite),
        }?;

        Ok(Self(md))
    }

    pub fn hash(&self, data: &[u8]) -> Result<Vec<u8>, HashError> {
        Ok(hash(self.0, data)?.to_vec())
    }

    pub fn mac(&self, key: &[u8], data: &[u8]) -> Result<Vec<u8>, HashError> {
        let key = PKey::hmac(key)?;
        let mut signer = Signer::new(self.0, &key)?;
        Ok(signer.sign_oneshot_to_vec(data)?)
    }
}
