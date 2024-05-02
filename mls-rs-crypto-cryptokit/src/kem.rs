// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// Copyright by contributors to this project.
// SPDX-License-Identifier: (Apache-2.0 OR MIT)

extern crate alloc;

use core::ops::Deref;

use alloc::vec::Vec;

use mls_rs_core::{
    crypto::{self, CipherSuite, HpkePublicKey, HpkeSecretKey},
    error::IntoAnyError,
};

#[derive(Debug)]
#[cfg_attr(feature = "std", derive(thiserror::Error))]
pub enum KemError {
    #[cfg_attr(feature = "std", error("unsupported cipher suite"))]
    UnsupportedCipherSuite,
    #[cfg_attr(feature = "std", error("invalid public key"))]
    InvalidPublicKey,
    #[cfg_attr(feature = "std", error("CryptoKit error"))]
    CryptoKitError,
}

impl IntoAnyError for KemError {
    #[cfg(feature = "std")]
    fn into_dyn_error(self) -> Result<Box<dyn std::error::Error + Send + Sync>, Self> {
        Ok(self.into())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
#[repr(u8)]
pub enum KemId {
    DhKemP256Sha256Aes128 = 1,
    DhKemP384Sha384Aes256 = 2,
    DhKemP521Sha512Aes256 = 3,
    DhKemX25519Sha256Aes128 = 4,
    DhKemX25519Sha256ChaChaPoly = 5,
}

impl KemId {
    pub fn from_ciphersuite(cipher_suite: CipherSuite) -> Option<Self> {
        match cipher_suite {
            CipherSuite::P256_AES128 => Some(KemId::DhKemP256Sha256Aes128),
            CipherSuite::P384_AES256 => Some(KemId::DhKemP384Sha384Aes256),
            CipherSuite::P521_AES256 => Some(KemId::DhKemP521Sha512Aes256),
            CipherSuite::CURVE25519_AES128 => Some(KemId::DhKemX25519Sha256Aes128),
            CipherSuite::CURVE25519_CHACHA => Some(KemId::DhKemX25519Sha256ChaChaPoly),
            _ => None,
        }
    }
}

// Opaque types representing Swift objects
#[repr(C)]
struct Sender {
    _phantom: (),
}

#[repr(C)]
struct Recipient {
    _phantom: (),
}

extern "C" {
    // KEM key generation / derivation
    fn kem_generate(
        kem_id: u16,
        priv_ptr: *mut u8,
        priv_len: *mut u64,
        pub_ptr: *mut u8,
        pub_len: *mut u64,
    ) -> u64;

    fn kem_derive(
        kem_id: u16,
        ikm_ptr: *const u8,
        ikm_len: u64,
        priv_ptr: *mut u8,
        priv_len: *mut u64,
        pub_ptr: *mut u8,
        pub_len: *mut u64,
    ) -> u64;

    fn kem_public_key_validate(kem_id: u16, pub_ptr: *const u8, pub_len: u64) -> u64;

    // HPKE Sender context
    fn hpke_setup_s(
        kem_id: u16,
        pub_ptr: *const u8,
        pub_len: u64,
        info_ptr: *const u8,
        info_len: u64,
        enc_ptr: *mut u8,
        enc_len: *mut u64,
    ) -> *mut Sender;

    fn hpke_seal_s(
        sender_ptr: *mut Sender,
        aad_ptr: *const u8,
        aad_len: u64,
        data_ptr: *const u8,
        data_len: u64,
        ct_ptr: *mut u8,
        ct_len: *mut u64,
    ) -> u64;

    fn hpke_export_s(
        sender_ptr: *mut Sender,
        ctx_ptr: *const u8,
        ctx_len: u64,
        out_ptr: *mut u8,
        out_len: u64,
    ) -> u64;

    fn hpke_drop_s(sender_ptr: *mut Sender);

    // HPKE Recipient context
    fn hpke_setup_r(
        kem_id: u16,
        enc_ptr: *const u8,
        enc_len: u64,
        priv_ptr: *const u8,
        priv_len: u64,
        info_ptr: *const u8,
        info_len: u64,
    ) -> *mut Recipient;

    fn hpke_open_r(
        recipient_ptr: *mut Recipient,
        aad_ptr: *const u8,
        aad_len: u64,
        data_ptr: *const u8,
        data_len: u64,
        pt_ptr: *mut u8,
        pt_len: *mut u64,
    ) -> u64;

    fn hpke_export_r(
        recipient_ptr: *mut Recipient,
        ctx_ptr: *const u8,
        ctx_len: u64,
        out_ptr: *mut u8,
        out_len: u64,
    ) -> u64;

    fn hpke_drop_r(recipient_ptr: *mut Recipient);
}

pub struct HpkeContextS(*mut Sender);

// XXX(RLB) I believe these are safe because:
// * For Send: HpkeContextS is a unique owner of the Sender and
// * For Sync: The mutability controls on HpkeContextS correctly limit use of references
unsafe impl Send for HpkeContextS {}
unsafe impl Sync for HpkeContextS {}

impl HpkeContextS {
    const MAX_CIPHER_OVERHEAD: usize = 16;
}

impl crypto::HpkeContextS for HpkeContextS {
    type Error = KemError;

    fn seal(&mut self, aad: Option<&[u8]>, data: &[u8]) -> Result<Vec<u8>, Self::Error> {
        let aad = aad.unwrap_or(&[]);

        let mut ct_buf = vec![0u8; data.len() + Self::MAX_CIPHER_OVERHEAD];
        let mut ct_len = ct_buf.len() as u64;
        let rv = unsafe {
            hpke_seal_s(
                self.0,
                aad.as_ptr(),
                aad.len() as u64,
                data.as_ptr(),
                data.len() as u64,
                ct_buf.as_mut_ptr(),
                &mut ct_len,
            )
        };

        if rv != 1 {
            return Err(KemError::CryptoKitError);
        }

        ct_buf.truncate(ct_len as usize);
        Ok(ct_buf)
    }

    fn export(&self, exporter_context: &[u8], len: usize) -> Result<Vec<u8>, Self::Error> {
        let mut out = vec![0u8; len];
        let rv = unsafe {
            hpke_export_s(
                self.0,
                exporter_context.as_ptr(),
                exporter_context.len() as u64,
                out.as_mut_ptr(),
                out.len() as u64,
            )
        };

        if rv != 1 {
            return Err(KemError::CryptoKitError);
        }

        Ok(out)
    }
}

impl Drop for HpkeContextS {
    fn drop(&mut self) {
        unsafe {
            hpke_drop_s(self.0);
        }
    }
}

pub struct HpkeContextR(*mut Recipient);

// XXX(RLB) I believe these are safe because:
// * For Send: HpkeContextR is a unique owner of the Sender and
// * For Sync: The mutability controls on HpkeContextR correectly limit use of references
unsafe impl Send for HpkeContextR {}
unsafe impl Sync for HpkeContextR {}

impl crypto::HpkeContextR for HpkeContextR {
    type Error = KemError;

    fn open(&mut self, aad: Option<&[u8]>, ciphertext: &[u8]) -> Result<Vec<u8>, Self::Error> {
        let aad = aad.unwrap_or(&[]);

        let mut pt_buf = vec![0u8; ciphertext.len()];
        let mut pt_len = pt_buf.len() as u64;
        let rv = unsafe {
            hpke_open_r(
                self.0,
                aad.as_ptr(),
                aad.len() as u64,
                ciphertext.as_ptr(),
                ciphertext.len() as u64,
                pt_buf.as_mut_ptr(),
                &mut pt_len,
            )
        };

        if rv != 1 {
            return Err(KemError::CryptoKitError);
        }

        pt_buf.truncate(pt_len as usize);
        Ok(pt_buf)
    }

    fn export(&self, exporter_context: &[u8], len: usize) -> Result<Vec<u8>, Self::Error> {
        let mut out = vec![0u8; len];
        let rv = unsafe {
            hpke_export_r(
                self.0,
                exporter_context.as_ptr(),
                exporter_context.len() as u64,
                out.as_mut_ptr(),
                out.len() as u64,
            )
        };

        if rv != 1 {
            return Err(KemError::CryptoKitError);
        }

        Ok(out)
    }
}

impl Drop for HpkeContextR {
    fn drop(&mut self) {
        unsafe {
            hpke_drop_r(self.0);
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Kem(KemId);

impl Deref for Kem {
    type Target = KemId;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Kem {
    // Default size used for buffers into which public keys, private keys, and signatures are read.
    const DEFAULT_BUFFER_SIZE: usize = 192;

    pub fn new(cipher_suite: CipherSuite) -> Option<Self> {
        KemId::from_ciphersuite(cipher_suite).map(Self)
    }

    pub fn generate(&self) -> Result<(HpkeSecretKey, HpkePublicKey), KemError> {
        let mut priv_buf = vec![0u8; Self::DEFAULT_BUFFER_SIZE];
        let mut priv_len = priv_buf.len() as u64;
        let mut pub_buf = vec![0u8; Self::DEFAULT_BUFFER_SIZE];
        let mut pub_len = pub_buf.len() as u64;
        let rv = unsafe {
            kem_generate(
                self.0 as u16,
                priv_buf.as_mut_ptr(),
                &mut priv_len,
                pub_buf.as_mut_ptr(),
                &mut pub_len,
            )
        };

        if rv != 1 {
            return Err(KemError::CryptoKitError);
        }

        priv_buf.truncate(priv_len as usize);
        pub_buf.truncate(pub_len as usize);

        Ok((priv_buf.into(), pub_buf.into()))
    }

    pub fn derive(&self, ikm: &[u8]) -> Result<(HpkeSecretKey, HpkePublicKey), KemError> {
        let mut priv_buf = vec![0u8; Self::DEFAULT_BUFFER_SIZE];
        let mut priv_len = priv_buf.len() as u64;
        let mut pub_buf = vec![0u8; Self::DEFAULT_BUFFER_SIZE];
        let mut pub_len = pub_buf.len() as u64;
        let rv = unsafe {
            kem_derive(
                self.0 as u16,
                ikm.as_ptr(),
                ikm.len() as u64,
                priv_buf.as_mut_ptr(),
                &mut priv_len,
                pub_buf.as_mut_ptr(),
                &mut pub_len,
            )
        };

        if rv != 1 {
            return Err(KemError::CryptoKitError);
        }

        priv_buf.truncate(priv_len as usize);
        pub_buf.truncate(pub_len as usize);

        Ok((priv_buf.into(), pub_buf.into()))
    }

    pub fn public_key_validate(&self, key: &HpkePublicKey) -> Result<(), KemError> {
        let rv = unsafe { kem_public_key_validate(self.0 as u16, key.as_ptr(), key.len() as u64) };

        (rv == 1).then_some(()).ok_or(KemError::CryptoKitError)
    }

    pub fn hpke_setup_s(
        &self,
        remote_key: &HpkePublicKey,
        info: &[u8],
    ) -> Result<(Vec<u8>, HpkeContextS), KemError> {
        let mut enc_buf = vec![0u8; Self::DEFAULT_BUFFER_SIZE];
        let mut enc_len = enc_buf.len() as u64;
        let sender_ptr = unsafe {
            hpke_setup_s(
                self.0 as u16,
                remote_key.as_ptr(),
                remote_key.len() as u64,
                info.as_ptr(),
                info.len() as u64,
                enc_buf.as_mut_ptr(),
                &mut enc_len,
            )
        };

        if sender_ptr.is_null() {
            return Err(KemError::CryptoKitError);
        }

        enc_buf.truncate(enc_len as usize);
        Ok((enc_buf, HpkeContextS(sender_ptr)))
    }

    pub fn hpke_setup_r(
        &self,
        kem_output: &[u8],
        local_secret: &HpkeSecretKey,
        _local_public: &HpkePublicKey,
        info: &[u8],
    ) -> Result<HpkeContextR, KemError> {
        let recipient_ptr = unsafe {
            hpke_setup_r(
                self.0 as u16,
                kem_output.as_ptr(),
                kem_output.len() as u64,
                local_secret.as_ptr(),
                local_secret.len() as u64,
                info.as_ptr(),
                info.len() as u64,
            )
        };

        if recipient_ptr.is_null() {
            return Err(KemError::CryptoKitError);
        }

        Ok(HpkeContextR(recipient_ptr))
    }
}

#[cfg(all(test, not(mls_build_async)))]
mod test {
    extern crate alloc;

    use mls_rs_core::crypto::{CipherSuite, HpkeContextR, HpkeContextS};

    use alloc::vec::Vec;

    use super::Kem;

    fn get_kems() -> Vec<Kem> {
        [
            CipherSuite::P256_AES128,
            CipherSuite::P384_AES256,
            CipherSuite::P521_AES256,
            CipherSuite::CURVE25519_AES128,
            CipherSuite::CURVE25519_CHACHA,
        ]
        .into_iter()
        .map(|c| Kem::new(c).unwrap())
        .collect()
    }

    #[test]
    fn round_trip() {
        let info = b"info";
        let aad = b"aad";
        let message = b"message";
        let export_ctx = b"export_ctx";
        let export_len = 42;

        for kem in get_kems() {
            let (priv_key, pub_key) = kem.generate().unwrap();
            assert!(kem.public_key_validate(&pub_key).is_ok());

            let (enc, mut ctx_s) = kem.hpke_setup_s(&pub_key, info).unwrap();
            let mut ctx_r = kem.hpke_setup_r(&enc, &priv_key, &pub_key, info).unwrap();

            let ct = ctx_s.seal(Some(aad), message).unwrap();
            let pt = ctx_r.open(Some(aad), &ct).unwrap();
            assert_ne!(ct, message);
            assert_eq!(pt, message);

            let export_s = ctx_s.export(export_ctx, export_len).unwrap();
            let export_r = ctx_r.export(export_ctx, export_len).unwrap();
            assert_eq!(export_s.len(), export_len);
            assert_eq!(export_r.len(), export_len);
            assert_eq!(export_s, export_r);
        }
    }
}
