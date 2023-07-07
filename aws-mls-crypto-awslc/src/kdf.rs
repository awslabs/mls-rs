use std::mem::MaybeUninit;

use aws_lc_rs::error::Unspecified;
use aws_lc_sys::{EVP_sha512, HKDF_expand, HKDF_extract};
use aws_mls_crypto_traits::KdfId;

use crate::AwsLcCryptoError;

#[derive(Clone)]
pub struct HkdfSha512(KdfId);

impl HkdfSha512 {
    pub fn new() -> Self {
        Self(KdfId::HkdfSha512)
    }
}

impl Default for HkdfSha512 {
    fn default() -> Self {
        Self::new()
    }
}

impl aws_mls_crypto_traits::KdfType for HkdfSha512 {
    type Error = AwsLcCryptoError;

    fn kdf_id(&self) -> u16 {
        self.0 as u16
    }

    fn expand(&self, prk: &[u8], info: &[u8], len: usize) -> Result<Vec<u8>, Self::Error> {
        let mut out = vec![0u8; len];

        unsafe {
            if 1 != HKDF_expand(
                out.as_mut_ptr(),
                out.len(),
                EVP_sha512(),
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

    fn extract(&self, salt: &[u8], ikm: &[u8]) -> Result<Vec<u8>, Self::Error> {
        let mut out = vec![0u8; self.extract_size()];

        unsafe {
            if 1 != HKDF_extract(
                out.as_mut_ptr(),
                MaybeUninit::<_>::uninit().as_mut_ptr(), // We already know the length
                EVP_sha512(),
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
