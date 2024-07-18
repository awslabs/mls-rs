// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// Copyright by contributors to this project.
// SPDX-License-Identifier: (Apache-2.0 OR MIT)

use std::{mem::MaybeUninit, os::raw::c_uint, ptr::null_mut};

use aws_lc_rs::{digest, error::Unspecified, hmac};
use aws_lc_sys::{
    EVP_Digest, EVP_sha256, EVP_sha384, EVP_sha512, EVP_shake128, HKDF_expand, HKDF_extract, EVP_MD,
};
use mls_rs_core::crypto::CipherSuite;
use mls_rs_crypto_traits::{Hash, KdfId, VariableLengthHash};

use crate::{check_int_return, AwsLcCryptoError};

#[derive(Clone, Copy)]
pub struct AwsLcHkdf(KdfId);

impl AwsLcHkdf {
    pub fn new(cipher_suite: CipherSuite) -> Option<Self> {
        KdfId::new(cipher_suite).map(Self)
    }

    pub(crate) fn hash_function(&self) -> Result<*const EVP_MD, AwsLcCryptoError> {
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

#[derive(Clone, Copy, Debug)]
pub struct AwsLcHash {
    algo: &'static digest::Algorithm,
}

impl AwsLcHash {
    pub fn new(cipher_suite: CipherSuite) -> Option<Self> {
        let algo = match cipher_suite {
            CipherSuite::CURVE25519_AES128
            | CipherSuite::CURVE25519_CHACHA
            | CipherSuite::P256_AES128 => hmac::HMAC_SHA256,
            CipherSuite::P384_AES256 => hmac::HMAC_SHA384,
            CipherSuite::P521_AES256 => hmac::HMAC_SHA512,
            _ => return None,
        };

        Some(Self {
            algo: algo.digest_algorithm(),
        })
    }

    pub fn new_sha3(sha3: Sha3) -> Option<Self> {
        let algo = match sha3 {
            Sha3::SHA3_256 => &digest::SHA3_256,
            Sha3::SHA3_384 => &digest::SHA3_384,
            Sha3::SHA3_512 => &digest::SHA3_512,
        };

        Some(Self { algo })
    }
}

#[derive(Clone, Copy, Debug)]
#[non_exhaustive]
pub enum Sha3 {
    SHA3_256,
    SHA3_384,
    SHA3_512,
}

impl Hash for AwsLcHash {
    type Error = AwsLcCryptoError;

    fn hash(&self, data: &[u8]) -> Result<Vec<u8>, Self::Error> {
        Ok(digest::digest(self.algo, data).as_ref().to_vec())
    }
}

#[derive(Clone, Copy, Debug)]
pub struct AwsLcShake128;

impl VariableLengthHash for AwsLcShake128 {
    type Error = AwsLcCryptoError;

    fn hash(&self, input: &[u8], out_len: usize) -> Result<Vec<u8>, Self::Error> {
        let mut output = vec![0u8; out_len];

        let mut len: u32 = out_len
            .try_into()
            .map_err(|_| AwsLcCryptoError::CryptoError)?;

        unsafe {
            check_int_return(EVP_Digest(
                input.as_ptr().cast(),
                input.len(),
                output.as_mut_ptr(),
                &mut len as *mut c_uint,
                EVP_shake128(),
                null_mut(),
            ))?;
        }

        Ok(output)
    }
}

#[cfg(test)]
mod tests {

    use mls_rs_crypto_traits::VariableLengthHash;

    use crate::kdf::AwsLcShake128;

    #[test]
    fn shake() {
        let input = b"\x84\xe9\x50\x05\x18\x76\x05\x0d\xc8\x51\xfb\xd9\x9e\x62\x47\xb8";
        let output = AwsLcShake128.hash(input, 16).unwrap();
        let expected = b"\x85\x99\xbd\x89\xf6\x3a\x84\x8c\x49\xca\x59\x3e\xc3\x7a\x12\xc6";

        assert_eq!(&output, expected);
    }
}
