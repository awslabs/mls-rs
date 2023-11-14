// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// Copyright by contributors to this project.
// SPDX-License-Identifier: (Apache-2.0 OR MIT)

use std::{fmt::Debug, ops::Deref};

use mls_rs_core::{crypto::CipherSuite, error::IntoAnyError};
use mls_rs_crypto_traits::{KdfId, KdfType};
use openssl::{
    md::{Md, MdRef},
    pkey::Id,
    pkey_ctx::{HkdfMode, PkeyCtx},
};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum KdfError {
    #[error(transparent)]
    OpensslError(#[from] openssl::error::ErrorStack),
    #[error("the provided length of the key {0} is shorter than the minimum length {1}")]
    TooShortKey(usize, usize),
    #[error("unsupported cipher suite")]
    UnsupportedCipherSuite,
}

impl IntoAnyError for KdfError {
    fn into_dyn_error(self) -> Result<Box<dyn std::error::Error + Send + Sync>, Self> {
        Ok(self.into())
    }
}

#[derive(Clone)]
pub struct Kdf {
    message_digest: &'static MdRef,
    kdf_id: KdfId,
}

impl Debug for Kdf {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Kdf with kdf_id {:?}", self.kdf_id)
    }
}

impl Deref for Kdf {
    type Target = MdRef;

    fn deref(&self) -> &Self::Target {
        self.message_digest
    }
}

impl Kdf {
    pub fn new(cipher_suite: CipherSuite) -> Option<Self> {
        let kdf_id = KdfId::new(cipher_suite)?;

        let message_digest = match kdf_id {
            KdfId::HkdfSha256 => Some(Md::sha256()),
            KdfId::HkdfSha384 => Some(Md::sha384()),
            KdfId::HkdfSha512 => Some(Md::sha512()),
            _ => None,
        }?;

        Some(Self {
            message_digest,
            kdf_id,
        })
    }
}

#[cfg_attr(not(mls_build_async), maybe_async::must_be_sync)]
#[cfg_attr(all(target_arch = "wasm32", mls_build_async), maybe_async::must_be_async(?Send))]
#[cfg_attr(
    all(not(target_arch = "wasm32"), mls_build_async),
    maybe_async::must_be_async
)]
impl KdfType for Kdf {
    type Error = KdfError;

    /// # Warning
    /// The length of info can *not* exceed 1024 bytes when using the OpenSSL Engine due to underlying
    /// restrictions in OpenSSL. This function will throw an [OpensslError](KdfError::OpensslError)
    /// in the event info is > 1024 bytes.
    async fn expand(&self, prk: &[u8], info: &[u8], len: usize) -> Result<Vec<u8>, KdfError> {
        if prk.len() < self.extract_size() {
            return Err(KdfError::TooShortKey(prk.len(), self.extract_size()));
        }

        let mut ctx = self.create_hkdf_ctx(HkdfMode::EXPAND_ONLY, prk)?;
        ctx.add_hkdf_info(info)?;

        let mut buf = vec![0u8; len];
        ctx.derive(Some(&mut buf))?;
        Ok(buf)
    }

    async fn extract(&self, salt: &[u8], ikm: &[u8]) -> Result<Vec<u8>, KdfError> {
        if ikm.is_empty() {
            return Err(KdfError::TooShortKey(0, 1));
        }

        let mut ctx = self.create_hkdf_ctx(HkdfMode::EXTRACT_ONLY, ikm)?;
        ctx.set_hkdf_salt(salt)?;

        let mut buf = vec![0u8; self.size()];
        ctx.derive(Some(&mut buf))?;
        Ok(buf)
    }

    fn extract_size(&self) -> usize {
        self.size()
    }

    fn kdf_id(&self) -> u16 {
        self.kdf_id as u16
    }
}

impl Kdf {
    fn create_hkdf_ctx(&self, mode: HkdfMode, key: &[u8]) -> Result<PkeyCtx<()>, KdfError> {
        let mut ctx = PkeyCtx::new_id(Id::HKDF)?;
        ctx.derive_init()?;
        ctx.set_hkdf_mode(mode)?;
        ctx.set_hkdf_md(self)?;
        ctx.set_hkdf_key(key)?;

        Ok(ctx)
    }
}

#[cfg(all(test, not(mls_build_async)))]
mod test {
    use assert_matches::assert_matches;
    use mls_rs_core::crypto::CipherSuite;
    use mls_rs_crypto_traits::KdfType;

    use crate::kdf::{Kdf, KdfError};

    #[test]
    fn no_key() {
        let kdf = Kdf::new(CipherSuite::CURVE25519_AES128).unwrap();
        assert!(kdf.extract(b"key", &[]).is_err());
    }

    #[test]
    fn no_salt() {
        let kdf = Kdf::new(CipherSuite::CURVE25519_AES128).unwrap();
        assert!(kdf.extract(&[], b"key").is_ok());
    }

    #[test]
    fn no_info() {
        let kdf = Kdf::new(CipherSuite::CURVE25519_AES128).unwrap();
        let key = vec![0u8; kdf.extract_size()];
        assert!(kdf.expand(&key, &[], 42).is_ok());
    }

    #[test]
    fn test_short_key() {
        let kdf = Kdf::new(CipherSuite::CURVE25519_AES128).unwrap();
        let key = vec![0u8; kdf.extract_size() - 1];

        assert_matches!(kdf.expand(&key, &[], 42), Err(KdfError::TooShortKey(_, _)));
    }
}
