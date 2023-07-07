use std::{ffi::c_void, mem::MaybeUninit};

use aws_lc_rs::{
    error::Unspecified,
    signature::{self, UnparsedPublicKey},
};

use aws_lc_sys::{
    ECDSA_SIG_free, ECDSA_SIG_to_bytes, ECDSA_do_sign, OPENSSL_free, SHA512, SHA512_DIGEST_LENGTH,
};
use aws_mls_core::crypto::{SignaturePublicKey, SignatureSecretKey};

use crate::{ec::EcPrivateKey, AwsLcCryptoError};

#[derive(Clone)]
pub struct EcdsaP521;

impl EcdsaP521 {
    pub fn import_der_private_key(
        &self,
        bytes: &[u8],
    ) -> Result<SignatureSecretKey, AwsLcCryptoError> {
        Ok(EcPrivateKey::from_der(bytes)
            .map_err(|_| AwsLcCryptoError::InvalidKeyData)?
            .to_vec()?
            .into())
    }

    pub fn signature_key_generate(
        &self,
    ) -> Result<(SignatureSecretKey, SignaturePublicKey), AwsLcCryptoError> {
        let private_key = EcPrivateKey::generate()?;
        let public_key = private_key.public_key()?;

        Ok((private_key.to_vec()?.into(), public_key.to_vec()?.into()))
    }

    pub fn signature_key_derive_public(
        &self,
        secret_key: &SignatureSecretKey,
    ) -> Result<SignaturePublicKey, AwsLcCryptoError> {
        let private_key = EcPrivateKey::from_bytes(secret_key)?;
        let public_key = private_key.public_key()?;

        Ok(public_key.to_vec()?.into())
    }

    pub fn sign(
        &self,
        secret_key: &SignatureSecretKey,
        data: &[u8],
    ) -> Result<Vec<u8>, AwsLcCryptoError> {
        let private_key = EcPrivateKey::from_bytes(secret_key)?;

        unsafe {
            let mut digest_out = MaybeUninit::<[u8; SHA512_DIGEST_LENGTH as usize]>::uninit();

            SHA512(
                data.as_ptr(),
                data.len(),
                digest_out.as_mut_ptr() as *mut u8,
            );

            let signature = ECDSA_do_sign(
                digest_out.as_ptr() as *const u8,
                SHA512_DIGEST_LENGTH as usize,
                private_key.inner,
            );

            if signature.is_null() {
                return Err(Unspecified.into());
            }

            let mut out_bytes = MaybeUninit::<*mut u8>::uninit();
            let mut out_len = MaybeUninit::<usize>::uninit();

            if 1 != ECDSA_SIG_to_bytes(out_bytes.as_mut_ptr(), out_len.as_mut_ptr(), signature) {
                ECDSA_SIG_free(signature);
                return Err(Unspecified.into());
            }

            ECDSA_SIG_free(signature);

            let ret = core::slice::from_raw_parts(out_bytes.assume_init(), out_len.assume_init())
                .to_vec();

            OPENSSL_free(out_bytes.assume_init() as *mut c_void);

            Ok(ret)
        }
    }

    pub fn verify(
        &self,
        public_key: &SignaturePublicKey,
        signature: &[u8],
        data: &[u8],
    ) -> Result<(), AwsLcCryptoError> {
        let public_key =
            UnparsedPublicKey::new(&signature::ECDSA_P521_SHA512_ASN1, public_key.as_ref());

        public_key
            .verify(data, signature)
            .map_err(|_| AwsLcCryptoError::InvalidSignature)
    }
}
