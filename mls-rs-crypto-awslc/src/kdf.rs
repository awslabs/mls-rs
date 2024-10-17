// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// Copyright by contributors to this project.
// SPDX-License-Identifier: (Apache-2.0 OR MIT)

use std::mem::MaybeUninit;

use crate::aws_lc_sys_impl::{
    EVP_sha256, EVP_sha384, EVP_sha512, HKDF_expand, HKDF_extract, EVP_MD,
};
use aws_lc_rs::error::Unspecified;
use mls_rs_core::crypto::CipherSuite;
use mls_rs_crypto_traits::KdfId;

use crate::AwsLcCryptoError;

#[derive(Clone)]
pub struct AwsLcHkdf(KdfId);

impl AwsLcHkdf {
    pub fn new(cipher_suite: CipherSuite) -> Option<Self> {
        KdfId::new(cipher_suite).map(Self)
    }

    fn hash_function(&self) -> Result<*const EVP_MD, AwsLcCryptoError> {
        match self.0 {
            KdfId::HkdfSha256 => Ok(unsafe { EVP_sha256() }),
            KdfId::HkdfSha384 => Ok(unsafe { EVP_sha384() }),
            KdfId::HkdfSha512 => Ok(unsafe { EVP_sha512() }),
            _ => Err(AwsLcCryptoError::InvalidKeyData),
        }
    }
}

#[cfg_attr(not(mls_build_async), maybe_async::must_be_sync)]
#[cfg_attr(all(target_arch = "wasm32", mls_build_async), maybe_async::must_be_async(?Send))]
#[cfg_attr(
    all(not(target_arch = "wasm32"), mls_build_async),
    maybe_async::must_be_async
)]
impl mls_rs_crypto_traits::KdfType for AwsLcHkdf {
    type Error = AwsLcCryptoError;

    fn kdf_id(&self) -> u16 {
        self.0 as u16
    }

    async fn expand(&self, prk: &[u8], info: &[u8], len: usize) -> Result<Vec<u8>, Self::Error> {
        let mut out = vec![0u8; len];
        let hash = self.hash_function()?;

        unsafe {
            if 1 != HKDF_expand(
                out.as_mut_ptr(),
                out.len(),
                hash,
                prk.as_ptr(),
                prk.len(),
                info.as_ptr(),
                info.len(),
            ) {
                return Err(Unspecified.into());
            };
        }

        Ok(out)
    }

    async fn extract(&self, salt: &[u8], ikm: &[u8]) -> Result<Vec<u8>, Self::Error> {
        let mut out = vec![0u8; self.extract_size()];
        let hash = self.hash_function()?;

        unsafe {
            if 1 != HKDF_extract(
                out.as_mut_ptr(),
                MaybeUninit::<_>::uninit().as_mut_ptr(), // We already know the length
                hash,
                ikm.as_ptr(),
                ikm.len(),
                salt.as_ptr(),
                salt.len(),
            ) {
                return Err(Unspecified.into());
            };
        }

        Ok(out)
    }

    fn extract_size(&self) -> usize {
        self.0.extract_size()
    }
}
