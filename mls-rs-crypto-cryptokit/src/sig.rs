// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// Copyright by contributors to this project.
// SPDX-License-Identifier: (Apache-2.0 OR MIT)

extern crate alloc;

use alloc::vec::Vec;
use core::ops::Deref;
use mls_rs_core::crypto::{CipherSuite, SignaturePublicKey, SignatureSecretKey};
use mls_rs_crypto_traits::Curve;

#[derive(Debug)]
#[cfg_attr(feature = "std", derive(thiserror::Error))]
pub enum EcSignerError {
    #[cfg_attr(feature = "std", error("unsupported curve"))]
    UnsupportedCurve,
    #[cfg_attr(feature = "std", error("invalid signature"))]
    InvalidSignature,
    #[cfg_attr(feature = "std", error("CryptoKit error"))]
    CryptoKitError,
}

#[derive(Clone, Debug, Copy, PartialEq, Eq)]
pub struct EcSigner(Curve);

impl Deref for EcSigner {
    type Target = Curve;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

extern "C" {
    fn signature_key_generate(
        sig_id: u16,
        priv_ptr: *mut u8,
        priv_len: *mut u64,
        pub_ptr: *mut u8,
        pub_len: *mut u64,
    ) -> u64;

    fn signature_key_derive_public(
        sig_id: u16,
        priv_ptr: *const u8,
        priv_len: u64,
        pub_ptr: *mut u8,
        pub_len: *mut u64,
    ) -> u64;

    fn sign(
        sig_id: u16,
        priv_ptr: *const u8,
        priv_len: u64,
        data_ptr: *const u8,
        data_len: u64,
        sig_ptr: *mut u8,
        sig_len: *mut u64,
    ) -> u64;

    fn verify(
        sig_id: u16,
        pub_ptr: *const u8,
        pub_len: u64,
        sig_ptr: *const u8,
        sig_len: u64,
        data_ptr: *const u8,
        data_len: u64,
    ) -> u64;
}

impl EcSigner {
    // Default size used for buffers into which public keys, private keys, and signatures are read.
    const DEFAULT_BUFFER_SIZE: usize = 192;

    fn supported_curve(curve: Curve) -> bool {
        match curve {
            Curve::P256 => true,
            Curve::P384 => true,
            Curve::P521 => true,
            Curve::Ed25519 => true,
            _ => false,
        }
    }

    pub fn new(cipher_suite: CipherSuite) -> Option<Self> {
        Curve::from_ciphersuite(cipher_suite, true)
            .filter(|&c| Self::supported_curve(c))
            .map(Self)
    }

    pub fn new_from_curve(curve: Curve) -> Result<Self, EcSignerError> {
        Self::supported_curve(curve)
            .then(|| Self(curve))
            .ok_or(EcSignerError::UnsupportedCurve)
    }

    pub fn signature_key_generate(
        &self,
    ) -> Result<(SignatureSecretKey, SignaturePublicKey), EcSignerError> {
        let mut priv_buf = [0u8; Self::DEFAULT_BUFFER_SIZE];
        let mut priv_len = priv_buf.len() as u64;
        let mut pub_buf = [0u8; Self::DEFAULT_BUFFER_SIZE];
        let mut pub_len = pub_buf.len() as u64;
        let rv = unsafe {
            signature_key_generate(
                self.0 as u16,
                priv_buf.as_mut_ptr(),
                &mut priv_len,
                pub_buf.as_mut_ptr(),
                &mut pub_len,
            )
        };

        if rv != 1 {
            return Err(EcSignerError::CryptoKitError);
        }

        let priv_len = priv_len as usize;
        let priv_key = SignatureSecretKey::new_slice(&priv_buf[..priv_len]);

        let pub_len = pub_len as usize;
        let pub_key = SignaturePublicKey::new_slice(&pub_buf[..pub_len]);

        return Ok((priv_key, pub_key));
    }

    pub fn signature_key_derive_public(
        &self,
        secret_key: &SignatureSecretKey,
    ) -> Result<SignaturePublicKey, EcSignerError> {
        let mut pub_buf = [0u8; Self::DEFAULT_BUFFER_SIZE];
        let mut pub_len = pub_buf.len() as u64;
        let rv = unsafe {
            signature_key_derive_public(
                self.0 as u16,
                secret_key.as_ptr(),
                secret_key.len() as u64,
                pub_buf.as_mut_ptr(),
                &mut pub_len,
            )
        };

        if rv != 1 {
            return Err(EcSignerError::CryptoKitError);
        }

        let pub_len = pub_len as usize;
        let pub_key = SignaturePublicKey::new_slice(&pub_buf[..pub_len]);

        return Ok(pub_key);
    }

    pub fn sign(
        &self,
        secret_key: &SignatureSecretKey,
        data: &[u8],
    ) -> Result<Vec<u8>, EcSignerError> {
        let mut sig_buf = [0u8; Self::DEFAULT_BUFFER_SIZE];
        let mut sig_len = sig_buf.len() as u64;
        let rv = unsafe {
            sign(
                self.0 as u16,
                secret_key.as_ptr(),
                secret_key.len() as u64,
                data.as_ptr(),
                data.len() as u64,
                sig_buf.as_mut_ptr(),
                &mut sig_len,
            )
        };

        if rv != 1 {
            return Err(EcSignerError::CryptoKitError);
        }

        let sig_len = sig_len as usize;
        return Ok(sig_buf[..sig_len].to_vec());
    }

    pub fn verify(
        &self,
        public_key: &SignaturePublicKey,
        signature: &[u8],
        data: &[u8],
    ) -> Result<(), EcSignerError> {
        let rv = unsafe {
            verify(
                self.0 as u16,
                public_key.as_ptr(),
                public_key.len() as u64,
                signature.as_ptr(),
                signature.len() as u64,
                data.as_ptr(),
                data.len() as u64,
            )
        };

        (rv == 1).then(|| ()).ok_or(EcSignerError::InvalidSignature)
    }
}

#[cfg(all(not(mls_build_async), test))]
mod test {
    extern crate alloc;

    use super::EcSigner;
    use alloc::vec::Vec;
    use mls_rs_core::crypto::CipherSuite;

    fn get_sigs() -> Vec<EcSigner> {
        [
            CipherSuite::P256_AES128,
            CipherSuite::P384_AES256,
            CipherSuite::P521_AES256,
            CipherSuite::CURVE25519_AES128,
        ]
        .into_iter()
        .map(|cs| EcSigner::new(cs).unwrap())
        .collect()
    }

    #[test]
    fn round_trip() {
        for sig in get_sigs() {
            let (priv_key, pub_key) = sig.signature_key_generate().unwrap();
            let pub_key_derived = sig.signature_key_derive_public(&priv_key).unwrap();
            assert_eq!(pub_key, pub_key_derived);

            let data = b"message";
            let signature = sig.sign(&priv_key, data).unwrap();
            sig.verify(&pub_key, &signature, data).unwrap();
        }
    }
}
