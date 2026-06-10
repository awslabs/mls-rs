extern crate alloc;

use alloc::vec::Vec;

use mls_rs_core::crypto::{HpkePublicKey, HpkeSecretKey};
use mls_rs_crypto_traits::{KemResult, KemType};

use crate::kem::KemError;

// ML-KEM-768 sizes (CryptoKit representation)
//
// WARNING: private-key formats are NOT interchangeable between providers.
//   CryptoKit  — 96 bytes  (integrityCheckedRepresentation, Apple-internal)
//   AWS-LC     — 2400 bytes (FIPS 203 full expanded decapsulation key)
// Never deserialise a CryptoKit secret key into the AWS-LC provider or vice versa.
//
// Public keys (1184 bytes) and ciphertexts (1088 bytes) are compatible across
// providers: both use the same ML-KEM-768 wire format (FIPS 203 / draft-mls-pq).
const ENC_KEY_SIZE: usize = 1184;
const DEC_KEY_SIZE: usize = 96;
const CT_SIZE: usize = 1088;
const SS_SIZE: usize = 32;

extern "C" {
    fn ml_kem_768_generate(
        priv_ptr: *mut u8,
        priv_len: *mut u64,
        pub_ptr: *mut u8,
        pub_len: *mut u64,
    ) -> u64;

    fn ml_kem_768_encap(
        pub_ptr: *const u8,
        pub_len: u64,
        ct_ptr: *mut u8,
        ct_len: *mut u64,
        ss_ptr: *mut u8,
        ss_len: *mut u64,
    ) -> u64;

    fn ml_kem_768_decap(
        ct_ptr: *const u8,
        ct_len: u64,
        priv_ptr: *const u8,
        priv_len: u64,
        ss_ptr: *mut u8,
        ss_len: *mut u64,
    ) -> u64;
}

#[derive(Clone, Debug, Default)]
pub struct MlKem768Kem;

impl MlKem768Kem {
    pub fn new() -> Self {
        Self
    }
}

#[cfg_attr(not(mls_build_async), maybe_async::must_be_sync)]
#[cfg_attr(all(target_arch = "wasm32", mls_build_async), maybe_async::must_be_async(?Send))]
#[cfg_attr(
    all(not(target_arch = "wasm32"), mls_build_async),
    maybe_async::must_be_async
)]
impl KemType for MlKem768Kem {
    type Error = KemError;

    fn kem_id(&self) -> u16 {
        // Private-range KEM ID matching the ML-KEM-768 MLS cipher suite (0xFDEA)
        0xFDEA
    }

    async fn generate(&self) -> Result<(HpkeSecretKey, HpkePublicKey), Self::Error> {
        let mut priv_buf = vec![0u8; DEC_KEY_SIZE];
        let mut priv_len = priv_buf.len() as u64;
        let mut pub_buf = vec![0u8; ENC_KEY_SIZE];
        let mut pub_len = pub_buf.len() as u64;

        let rv = unsafe {
            ml_kem_768_generate(
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

    async fn generate_deterministic(
        &self,
        _ikm: &[u8],
    ) -> Result<(HpkeSecretKey, HpkePublicKey), Self::Error> {
        // CryptoKit's MLKEM768 does not expose a seed-based key generation API.
        Err(KemError::NotSupported)
    }

    fn public_key_validate(&self, _key: &HpkePublicKey) -> Result<(), Self::Error> {
        Ok(())
    }

    async fn encap(&self, remote_key: &HpkePublicKey) -> Result<KemResult, Self::Error> {
        let mut ct_buf = vec![0u8; CT_SIZE];
        let mut ct_len = ct_buf.len() as u64;
        let mut ss_buf = vec![0u8; SS_SIZE];
        let mut ss_len = ss_buf.len() as u64;

        let rv = unsafe {
            ml_kem_768_encap(
                remote_key.as_ptr(),
                remote_key.len() as u64,
                ct_buf.as_mut_ptr(),
                &mut ct_len,
                ss_buf.as_mut_ptr(),
                &mut ss_len,
            )
        };

        if rv != 1 {
            return Err(KemError::CryptoKitError);
        }

        ct_buf.truncate(ct_len as usize);
        ss_buf.truncate(ss_len as usize);
        Ok(KemResult {
            enc: ct_buf,
            shared_secret: ss_buf,
        })
    }

    async fn decap(
        &self,
        enc: &[u8],
        secret_key: &HpkeSecretKey,
        _local_public: &HpkePublicKey,
    ) -> Result<Vec<u8>, Self::Error> {
        let mut ss_buf = vec![0u8; SS_SIZE];
        let mut ss_len = ss_buf.len() as u64;

        let rv = unsafe {
            ml_kem_768_decap(
                enc.as_ptr(),
                enc.len() as u64,
                secret_key.as_ptr(),
                secret_key.len() as u64,
                ss_buf.as_mut_ptr(),
                &mut ss_len,
            )
        };

        if rv != 1 {
            return Err(KemError::CryptoKitError);
        }

        ss_buf.truncate(ss_len as usize);
        Ok(ss_buf)
    }

    fn seed_length_for_derive(&self) -> usize {
        0
    }
}
