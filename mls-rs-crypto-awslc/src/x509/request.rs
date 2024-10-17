// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// Copyright by contributors to this project.
// SPDX-License-Identifier: (Apache-2.0 OR MIT)

use std::{
    ffi::c_long,
    ptr::{null, null_mut},
};

use crate::{
    aws_lc_sys_impl::{
        i2d_X509_REQ, EVP_sha256, EVP_sha384, EVP_sha512, X509_REQ_add_extensions, X509_REQ_free,
        X509_REQ_new, X509_REQ_set_pubkey, X509_REQ_set_subject_name, X509_REQ_set_version,
        X509_REQ_sign, EVP_MD, X509_REQ,
    },
    ec::EvpPkey,
};
use mls_rs_core::crypto::SignatureSecretKey;
use mls_rs_crypto_traits::Curve;

use crate::{check_int_return, check_non_null, check_res, ecdsa::AwsLcEcdsa, AwsLcCryptoError};

use super::component::{Stack, X509Extension, X509Name};

#[repr(i32)]
pub enum X509RequestVersion {
    V1 = 0i32,
}

pub struct X509Request(*mut X509_REQ);

impl X509Request {
    pub fn new() -> Result<Self, AwsLcCryptoError> {
        unsafe { check_non_null(X509_REQ_new()).map(Self) }
    }

    pub fn set_version(&mut self, version: X509RequestVersion) -> Result<(), AwsLcCryptoError> {
        unsafe { check_res(X509_REQ_set_version(self.0, version as c_long)) }
    }

    pub fn set_subject(&mut self, subject: X509Name) -> Result<(), AwsLcCryptoError> {
        unsafe { check_res(X509_REQ_set_subject_name(self.0, subject.0)) }
    }

    pub fn add_extensions(&mut self, ext: Stack<X509Extension>) -> Result<(), AwsLcCryptoError> {
        unsafe { check_res(X509_REQ_add_extensions(self.0, ext.inner.cast())) }
    }

    fn set_public_key(&mut self, key: EvpPkey) -> Result<(), AwsLcCryptoError> {
        unsafe { check_res(X509_REQ_set_pubkey(self.0, key.0)) }
    }

    pub fn sign(
        mut self,
        signer: &AwsLcEcdsa,
        signature_key: &SignatureSecretKey,
    ) -> Result<Vec<u8>, AwsLcCryptoError> {
        let public_key = signer.signature_key_derive_public(signature_key)?;
        let public_key = signer.evp_public_key(&public_key)?;

        let signature_key = signer.evp_private_key(signature_key)?;

        self.set_public_key(public_key)?;

        unsafe {
            check_res(X509_REQ_sign(
                self.0,
                signature_key.0,
                digest_for_curve(**signer),
            ))?;

            let len = check_int_return(i2d_X509_REQ(self.0, null_mut()))?;
            let mut out = vec![0u8; len as usize];

            check_res(i2d_X509_REQ(self.0, &mut out.as_mut_ptr()))?;

            Ok(out)
        }
    }
}

impl Drop for X509Request {
    fn drop(&mut self) {
        unsafe { X509_REQ_free(self.0) }
    }
}

pub(crate) fn digest_for_curve(curve: Curve) -> *const EVP_MD {
    unsafe {
        match curve {
            Curve::P256 => EVP_sha256(),
            Curve::P384 => EVP_sha384(),
            Curve::P521 => EVP_sha512(),
            _ => null(),
        }
    }
}
