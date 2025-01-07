use std::ptr::null_mut;

use crate::aws_lc_sys_impl::{
    EVP_PKEY_CTX_free, EVP_PKEY_CTX_new, EVP_PKEY_decapsulate, EVP_PKEY_free,
    EVP_PKEY_kem_new_raw_secret_key, EVP_PKEY_KEM,
};
use crate::aws_lc_sys_impl::{
    EVP_PKEY_CTX_kem_set_params, EVP_PKEY_CTX_new_id, EVP_PKEY_get_raw_private_key,
    EVP_PKEY_get_raw_public_key, EVP_PKEY_keygen_init, EVP_PKEY,
};
use aws_lc_fips_sys::EVP_PKEY_CTX;
use aws_lc_rs::{
    error::Unspecified,
    kem::{Algorithm, AlgorithmIdentifier, EncapsulationKey},
};
//use aws_lc_sys::EVP_PKEY_keygen_deterministic;

use mls_rs_core::crypto::{CipherSuite, HpkePublicKey, HpkeSecretKey};
use mls_rs_crypto_traits::{KdfType, KemResult, KemType};

use crate::{check_non_null, kdf::AwsLcHkdf, AwsLcCryptoError};

#[derive(Clone)]
pub struct MlKemKem {
    kdf: AwsLcHkdf,
    ml_kem: MlKem,
}

impl MlKemKem {
    pub fn new(cipher_suite: CipherSuite) -> Option<Self> {
        let kdf = match cipher_suite {
            CipherSuite::ML_KEM_512 | CipherSuite::ML_KEM_768 => {
                AwsLcHkdf::new(CipherSuite::CURVE25519_AES128)?
            }
            CipherSuite::ML_KEM_1024 => AwsLcHkdf::new(CipherSuite::P384_AES256)?,
            _ => return None,
        };

        Some(Self {
            kdf,
            ml_kem: MlKem::new(cipher_suite)?,
        })
    }
}

#[derive(Debug, Clone)]
pub enum MlKem {
    MlKem512,
    MlKem768,
    MlKem1024,
}

impl MlKem {
    fn new(cipher_suite: CipherSuite) -> Option<Self> {
        match cipher_suite {
            CipherSuite::ML_KEM_512 => Some(Self::MlKem512),
            CipherSuite::ML_KEM_768 => Some(Self::MlKem768),
            CipherSuite::ML_KEM_1024 => Some(Self::MlKem1024),
            _ => None,
        }
    }

    fn algorithm(&self) -> &'static Algorithm {
        match self {
            MlKem::MlKem512 => &aws_lc_rs::unstable::kem::ML_KEM_512,
            MlKem::MlKem768 => &aws_lc_rs::unstable::kem::ML_KEM_768,
            MlKem::MlKem1024 => &aws_lc_rs::unstable::kem::ML_KEM_1024,
        }
    }
}

impl KemType for MlKemKem {
    type Error = AwsLcCryptoError;

    fn kem_id(&self) -> u16 {
        // TODO not set by any RFC
        15
    }

    fn encap(&self, remote_key: &HpkePublicKey) -> Result<KemResult, Self::Error> {
        let remote_key = EncapsulationKey::new(self.ml_kem.algorithm(), remote_key)?;
        let (enc, shared_secret) = remote_key.encapsulate()?;

        Ok(KemResult {
            enc: enc.as_ref().to_vec(),
            shared_secret: shared_secret.as_ref().to_vec(),
        })
    }

    fn decap(
        &self,
        enc: &[u8],
        secret_key: &HpkeSecretKey,
        _local_public: &HpkePublicKey,
    ) -> Result<Vec<u8>, Self::Error> {
        let nid = self.ml_kem.algorithm().id().nid();
        let len = self.secret_key_size();
        let mut shared_secret = vec![0u8; 32];

        let res = unsafe {
            let pkey = check_non_null(EVP_PKEY_kem_new_raw_secret_key(
                nid,
                secret_key.as_ptr(),
                len,
            ))?;

            let ctx = EVP_PKEY_CTX_new(pkey, null_mut());

            let res = EVP_PKEY_decapsulate(
                ctx,
                shared_secret.as_mut_ptr(),
                &mut 32,
                enc.as_ptr() as *mut u8,
                enc.len(),
            );

            EVP_PKEY_CTX_free(ctx);
            EVP_PKEY_free(pkey);

            res
        };

        (res == 1)
            .then_some(shared_secret)
            .ok_or(Unspecified.into())
    }

    fn generate_deterministic(
        &self,
        ikm: &[u8],
    ) -> Result<(HpkeSecretKey, HpkePublicKey), Self::Error> {
        let nid = self.ml_kem.algorithm().id().nid();
        let secret_key_size = self.secret_key_size();
        let public_key_size = self.public_key_size();

        if ikm.len() == self.seed_length_for_derive() {
            Ok(unsafe { kem_derive(nid, ikm, secret_key_size, public_key_size) }?)
        } else {
            let ikm = self.kdf.expand(ikm, &[], self.seed_length_for_derive())?;
            Ok(unsafe { kem_derive(nid, &ikm, secret_key_size, public_key_size) }?)
        }
    }

    fn public_key_validate(&self, _key: &HpkePublicKey) -> Result<(), Self::Error> {
        Ok(())
    }

    fn seed_length_for_derive(&self) -> usize {
        64
    }

    fn generate(&self) -> Result<(HpkeSecretKey, HpkePublicKey), Self::Error> {
        let mut out = vec![0u8; self.seed_length_for_derive()];
        aws_lc_rs::rand::fill(&mut out)?;

        self.generate_deterministic(&out)
    }

    fn public_key_size(&self) -> usize {
        match self.ml_kem {
            MlKem::MlKem512 => 800,
            MlKem::MlKem768 => 1184,
            MlKem::MlKem1024 => 1568,
        }
    }

    fn secret_key_size(&self) -> usize {
        match self.ml_kem {
            MlKem::MlKem512 => 1632,
            MlKem::MlKem768 => 2400,
            MlKem::MlKem1024 => 3168,
        }
    }

    fn enc_size(&self) -> usize {
        match self.ml_kem {
            MlKem::MlKem512 => 768,
            MlKem::MlKem768 => 1088,
            MlKem::MlKem1024 => 1568,
        }
    }
}

extern "C" {
    #[link_name = "\u{1}_aws_lc_fips_0_13_0_EVP_PKEY_keygen_deterministic"]
    pub fn EVP_PKEY_keygen_deterministic(
        ctx: *mut EVP_PKEY_CTX,
        out_pkey: *mut *mut EVP_PKEY,
        seed: *const u8,
        seed_len: *mut usize,
    ) -> ::std::os::raw::c_int;
}

unsafe fn kem_derive(
    nid: i32,
    ikm: &[u8],
    mut secret_key_len: usize,
    mut public_key_len: usize,
) -> Result<(HpkeSecretKey, HpkePublicKey), Unspecified> {
    let ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_KEM, null_mut());

    if 1 != EVP_PKEY_CTX_kem_set_params(ctx, nid) || 1 != EVP_PKEY_keygen_init(ctx) {
        aws_lc_fips_sys::EVP_PKEY_CTX_free(ctx);
        return Err(Unspecified);
    }

    let mut pkey: *mut EVP_PKEY = null_mut();
    let mut ikm_len = ikm.len();
    println!("AAA");

    if 1 != EVP_PKEY_keygen_deterministic(ctx, &mut pkey, ikm.as_ptr(), &mut ikm_len) {
        aws_lc_fips_sys::EVP_PKEY_CTX_free(ctx);
        return Err(Unspecified);
    }

    let mut secret_key = vec![0u8; secret_key_len];
    let mut public_key = vec![0u8; public_key_len];

    let err = 1 != EVP_PKEY_get_raw_private_key(pkey, secret_key.as_mut_ptr(), &mut secret_key_len)
        || 1 != EVP_PKEY_get_raw_public_key(pkey, public_key.as_mut_ptr(), &mut public_key_len);

    aws_lc_fips_sys::EVP_PKEY_CTX_free(ctx);
    aws_lc_fips_sys::EVP_PKEY_free(pkey);

    (!err)
        .then_some((secret_key.into(), public_key.into()))
        .ok_or(Unspecified)
}

#[cfg(test)]
mod tests {
    use mls_rs_core::crypto::CipherSuite;
    use mls_rs_crypto_traits::{KemResult, KemType};

    use super::MlKemKem;

    #[test]
    fn round_trip() {
        let kem = MlKemKem::new(CipherSuite::ML_KEM_512).unwrap();

        let (secret_key, public_key) = kem.generate_deterministic(&[1u8; 64]).unwrap();
        let KemResult { shared_secret, enc } = kem.encap(&public_key).unwrap();

        assert_eq!(
            kem.decap(&enc, &secret_key, &public_key).unwrap(),
            shared_secret
        );
    }
}
