// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// Copyright by contributors to this project.
// SPDX-License-Identifier: (Apache-2.0 OR MIT)

use mls_rs_core::{crypto::CipherSuite, error::IntoAnyError};
use mls_rs_crypto_traits::{KdfId, KdfType};

#[derive(Debug)]
#[cfg_attr(feature = "std", derive(thiserror::Error))]
pub enum KdfError {
    #[cfg_attr(feature = "std", error("invalid prk length"))]
    InvalidPrkLength,
    #[cfg_attr(feature = "std", error("invalid length"))]
    InvalidLength,
    #[cfg_attr(
        feature = "std",
        error("the provided length of the key {0} is shorter than the minimum length {1}")
    )]
    TooShortKey(usize, usize),
    #[cfg_attr(feature = "std", error("unsupported cipher suite"))]
    UnsupportedCipherSuite,
    #[cfg_attr(feature = "std", error("CryptoKit error"))]
    CryptoKitError,
}

impl IntoAnyError for KdfError {
    #[cfg(feature = "std")]
    fn into_dyn_error(self) -> Result<Box<dyn std::error::Error + Send + Sync>, Self> {
        Ok(self.into())
    }
}

extern "C" {
    fn hash(
        kdf_id: u16,
        in_ptr: *const u8,
        in_len: u64,
        output_ptr: *mut u8,
        output_len: u64,
    ) -> u64;

    fn hmac(
        kdf_id: u16,
        key_ptr: *const u8,
        key_len: u64,
        data_ptr: *const u8,
        data_len: u64,
        output_ptr: *mut u8,
        output_len: u64,
    ) -> u64;

    fn hkdf_extract(
        kdf_id: u16,
        ikm_ptr: *const u8,
        ikm_len: u64,
        salt_ptr: *const u8,
        salt_len: u64,
        output_ptr: *mut u8,
        output_len: u64,
    ) -> u64;

    fn hkdf_expand(
        kdf_id: u16,
        prk_ptr: *const u8,
        prk_len: u64,
        info_ptr: *const u8,
        info_len: u64,
        output_ptr: *mut u8,
        output_len: u64,
    ) -> u64;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Kdf(KdfId);

impl Kdf {
    pub fn new(cipher_suite: CipherSuite) -> Option<Self> {
        KdfId::new(cipher_suite).map(Self)
    }

    fn ensure_valid_ciphersuite(&self) -> Result<(), KdfError> {
        match self.0 {
            KdfId::HkdfSha256 => Ok(()),
            KdfId::HkdfSha384 => Ok(()),
            KdfId::HkdfSha512 => Ok(()),
            _ => Err(KdfError::UnsupportedCipherSuite),
        }
    }

    pub fn hash(&self, data: &[u8]) -> Result<Vec<u8>, KdfError> {
        self.ensure_valid_ciphersuite()?;

        let mut output = vec![0; self.extract_size()];
        let rv = unsafe {
            hash(
                self.0 as u16,
                data.as_ptr(),
                data.len() as u64,
                output.as_mut_ptr(),
                output.len() as u64,
            )
        };

        if rv != 1 {
            return Err(KdfError::CryptoKitError);
        }

        Ok(output)
    }

    pub fn mac(&self, key: &[u8], data: &[u8]) -> Result<Vec<u8>, KdfError> {
        self.ensure_valid_ciphersuite()?;

        let mut output = vec![0; self.extract_size()];
        let rv = unsafe {
            hmac(
                self.0 as u16,
                key.as_ptr(),
                key.len() as u64,
                data.as_ptr(),
                data.len() as u64,
                output.as_mut_ptr(),
                output.len() as u64,
            )
        };

        if rv != 1 {
            return Err(KdfError::CryptoKitError);
        }

        Ok(output)
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

    async fn extract(&self, salt: &[u8], ikm: &[u8]) -> Result<Vec<u8>, KdfError> {
        if ikm.is_empty() {
            return Err(KdfError::TooShortKey(0, 1));
        }

        if !matches!(
            self.0,
            KdfId::HkdfSha256 | KdfId::HkdfSha384 | KdfId::HkdfSha512
        ) {
            return Err(KdfError::UnsupportedCipherSuite);
        }

        let mut output = vec![0; self.extract_size()];

        let rv = unsafe {
            hkdf_extract(
                self.0 as u16,
                ikm.as_ptr(),
                ikm.len() as u64,
                salt.as_ptr(),
                salt.len() as u64,
                output.as_mut_ptr(),
                output.len() as u64,
            )
        };

        if rv != 1 {
            return Err(KdfError::CryptoKitError);
        }

        Ok(output)
    }

    async fn expand(&self, prk: &[u8], info: &[u8], len: usize) -> Result<Vec<u8>, KdfError> {
        if prk.len() < self.extract_size() {
            return Err(KdfError::TooShortKey(prk.len(), self.extract_size()));
        }

        if !matches!(
            self.0,
            KdfId::HkdfSha256 | KdfId::HkdfSha384 | KdfId::HkdfSha512
        ) {
            return Err(KdfError::UnsupportedCipherSuite);
        }

        let mut output = vec![0; len];

        let rv = unsafe {
            hkdf_expand(
                self.0 as u16,
                prk.as_ptr(),
                prk.len() as u64,
                info.as_ptr(),
                info.len() as u64,
                output.as_mut_ptr(),
                output.len() as u64,
            )
        };

        if rv != 1 {
            return Err(KdfError::CryptoKitError);
        }

        Ok(output)
    }

    fn extract_size(&self) -> usize {
        self.0.extract_size()
    }

    fn kdf_id(&self) -> u16 {
        self.0 as u16
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use hex_literal::hex;

    #[test]
    fn hash() {
        let cipher_suite = CipherSuite::CURVE25519_AES128;
        let input = b"This is a string.";
        let output_expected =
            hex!("a13da8b26228f4c73e6c7447619b4b69a83dc9e94cca8044f3afbf4489da8d5c");

        let kdf = Kdf::new(cipher_suite).unwrap();
        let output_actual = kdf.hash(input).unwrap();
        assert_eq!(output_actual, output_expected);
    }

    #[test]
    fn mac() {
        let cipher_suite = CipherSuite::CURVE25519_AES128;
        let key = b"This is a key.";
        let data = b"This is some data.";
        let output_expected =
            hex!("1b0c3ec1573e60eaff70d314c5fc65661d16c7fac5c5c8c4dfa3af57b839126b");

        let kdf = Kdf::new(cipher_suite).unwrap();
        let output_actual = kdf.mac(key, data).unwrap();
        assert_eq!(output_actual, output_expected);
    }

    #[test]
    fn hkdf() {
        let cipher_suite = CipherSuite::CURVE25519_AES128;
        let ikm = hex!("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
        let salt = hex!("000102030405060708090a0b0c");
        let info = hex!("f0f1f2f3f4f5f6f7f8f9");
        let out_len = 42;
        let prk_expected = hex!("077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5");
        let okm_expected = hex!(
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
        );

        let kdf = Kdf::new(cipher_suite).unwrap();
        let prk_actual = kdf.extract(&salt, &ikm).unwrap();
        let okm_actual = kdf.expand(&prk_actual, &info, out_len).unwrap();

        assert_eq!(prk_actual, prk_expected);
        assert_eq!(okm_actual, okm_expected);
    }
}
