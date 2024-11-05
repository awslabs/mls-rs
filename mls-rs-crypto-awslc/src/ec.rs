// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// Copyright by contributors to this project.
// SPDX-License-Identifier: (Apache-2.0 OR MIT)

use std::{os::raw::c_void, ptr::null_mut};

use crate::aws_lc_sys_impl::{
    d2i_ECPrivateKey, point_conversion_form_t, BN_bin2bn, BN_bn2bin, BN_free, ECDH_compute_key,
    EC_GROUP_free, EC_GROUP_new_by_curve_name, EC_KEY_free, EC_KEY_generate_key, EC_KEY_get0_group,
    EC_KEY_get0_private_key, EC_KEY_get0_public_key, EC_KEY_new_by_curve_name,
    EC_KEY_set_private_key, EC_KEY_set_public_key, EC_POINT_copy, EC_POINT_free, EC_POINT_mul,
    EC_POINT_new, EC_POINT_oct2point, EC_POINT_point2oct, EVP_PKEY_free, EVP_PKEY_new,
    EVP_PKEY_set1_EC_KEY, NID_X9_62_prime256v1, NID_secp384r1, NID_secp521r1, X25519_keypair,
    X25519_public_from_private, EC_POINT, EVP_PKEY, X25519,
};
use aws_lc_rs::error::Unspecified;
use mls_rs_core::crypto::{CipherSuite, HpkePublicKey, HpkeSecretKey};
use mls_rs_crypto_traits::Curve;

use crate::AwsLcCryptoError;

pub(crate) const SUPPORTED_NIST_CURVES: [Curve; 3] = [Curve::P521, Curve::P256, Curve::P384];

#[derive(Clone)]
pub(crate) struct Ecdh(Curve);

impl Ecdh {
    pub fn new(cipher_suite: CipherSuite) -> Option<Self> {
        let curve = Curve::from_ciphersuite(cipher_suite, false)?;

        (SUPPORTED_NIST_CURVES.contains(&curve) || curve == Curve::X25519).then_some(Self(curve))
    }
}

#[cfg_attr(not(mls_build_async), maybe_async::must_be_sync)]
#[cfg_attr(all(target_arch = "wasm32", mls_build_async), maybe_async::must_be_async(?Send))]
#[cfg_attr(
    all(not(target_arch = "wasm32"), mls_build_async),
    maybe_async::must_be_async
)]
impl mls_rs_crypto_traits::DhType for Ecdh {
    type Error = AwsLcCryptoError;

    async fn dh(
        &self,
        secret_key: &HpkeSecretKey,
        public_key: &HpkePublicKey,
    ) -> Result<Vec<u8>, Self::Error> {
        if self.0 == Curve::X25519 {
            x25519(secret_key, public_key)
        } else {
            ecdh(self.0, secret_key, public_key)
        }
    }

    async fn generate(&self) -> Result<(HpkeSecretKey, HpkePublicKey), Self::Error> {
        let (secret, public) = if self.0 == Curve::X25519 {
            x25519_generate()
        } else {
            ec_generate(self.0)
        }?;

        Ok((secret.into(), public.into()))
    }

    async fn to_public(&self, secret_key: &HpkeSecretKey) -> Result<HpkePublicKey, Self::Error> {
        let public = if self.0 == Curve::X25519 {
            x25519_public_key(secret_key)
        } else {
            ec_public_key(self.0, secret_key)
        }?;

        Ok(public.into())
    }

    fn bitmask_for_rejection_sampling(&self) -> Option<u8> {
        self.0.curve_bitmask()
    }

    fn secret_key_size(&self) -> usize {
        self.0.secret_key_size()
    }

    fn public_key_validate(&self, key: &HpkePublicKey) -> Result<(), Self::Error> {
        if self.0 != Curve::X25519 {
            EcPublicKey::from_bytes(key, self.0)?;
        }

        Ok(())
    }
}

pub fn ecdh(
    curve: Curve,
    secret_key: &HpkeSecretKey,
    public_key: &HpkePublicKey,
) -> Result<Vec<u8>, AwsLcCryptoError> {
    let secret_key = EcPrivateKey::from_bytes(secret_key, curve)?;
    let public_key = EcPublicKey::from_bytes(public_key, curve)?;

    let mut shared_secret_data = vec![0u8; curve.secret_key_size()];

    let out_len = unsafe {
        ECDH_compute_key(
            shared_secret_data.as_mut_ptr() as *mut c_void,
            shared_secret_data.len(),
            public_key.inner,
            secret_key.inner,
            None,
        )
    };

    (out_len as usize == shared_secret_data.len())
        .then_some(shared_secret_data)
        .ok_or(Unspecified.into())
}

pub fn x25519(
    secret_key: &HpkeSecretKey,
    public_key: &HpkePublicKey,
) -> Result<Vec<u8>, AwsLcCryptoError> {
    let curve = Curve::X25519;

    (secret_key.len() == curve.secret_key_size() && public_key.len() == curve.public_key_size())
        .then_some(())
        .ok_or(AwsLcCryptoError::InvalidKeyData)?;

    let mut secret = vec![0u8; curve.secret_key_size()];

    // returns one on success and zero on error
    let res = unsafe {
        X25519(
            secret.as_mut_ptr(),
            secret_key.as_ptr(),
            public_key.as_ptr(),
        )
    };

    (res == 1).then_some(secret).ok_or(Unspecified.into())
}

pub fn ec_generate(curve: Curve) -> Result<(Vec<u8>, Vec<u8>), AwsLcCryptoError> {
    let private_key = EcPrivateKey::generate(curve)?;
    let public_key = private_key.public_key()?;

    Ok((private_key.to_vec()?, public_key.to_vec()?))
}

pub fn x25519_generate() -> Result<(Vec<u8>, Vec<u8>), AwsLcCryptoError> {
    let curve = Curve::X25519;

    let mut private_key = vec![0u8; curve.secret_key_size()];
    let mut public_key = vec![0u8; curve.public_key_size()];

    unsafe { X25519_keypair(public_key.as_mut_ptr(), private_key.as_mut_ptr()) }

    Ok((private_key, public_key))
}

pub fn ec_public_key(curve: Curve, secret_key: &[u8]) -> Result<Vec<u8>, AwsLcCryptoError> {
    Ok(EcPrivateKey::from_bytes(secret_key, curve)?
        .public_key()?
        .to_vec()?)
}

pub fn x25519_public_key(secret_key: &[u8]) -> Result<Vec<u8>, AwsLcCryptoError> {
    let mut public_key = vec![0u8; Curve::X25519.public_key_size()];

    unsafe { X25519_public_from_private(public_key.as_mut_ptr(), secret_key.as_ptr()) }

    Ok(public_key)
}

pub struct EcPrivateKey {
    pub(crate) inner: *mut crate::aws_lc_sys_impl::ec_key_st,
    curve: Curve,
}

impl EcPrivateKey {
    pub fn generate(curve: Curve) -> Result<Self, Unspecified> {
        let nid = nid(curve).ok_or(Unspecified)?;

        let key = unsafe { EC_KEY_new_by_curve_name(nid) };

        if key.is_null() {
            return Err(Unspecified);
        }

        unsafe {
            if 1 != EC_KEY_generate_key(key) {
                EC_KEY_free(key);
                return Err(Unspecified);
            }
        }

        Ok(Self { inner: key, curve })
    }

    pub fn from_der(bytes: &[u8], curve: Curve) -> Result<Self, Unspecified> {
        unsafe {
            let mut result_holder = bytes.as_ptr();

            let input_len = bytes.len().try_into().map_err(|_| Unspecified)?;

            let ec_key = d2i_ECPrivateKey(null_mut(), &mut result_holder, input_len);

            if ec_key.is_null() {
                return Err(Unspecified);
            }

            Ok(Self {
                inner: ec_key,
                curve,
            })
        }
    }

    pub fn from_bytes(bytes: &[u8], curve: Curve) -> Result<Self, Unspecified> {
        let bn = unsafe { BN_bin2bn(bytes.as_ptr(), bytes.len(), null_mut()) };

        if bn.is_null() {
            return Err(Unspecified);
        }

        let key = unsafe {
            let key = nid(curve).map(|n| EC_KEY_new_by_curve_name(n));

            match key {
                Some(key) if !key.is_null() => key,
                _ => {
                    BN_free(bn);
                    return Err(Unspecified);
                }
            }
        };

        unsafe {
            if 1 != EC_KEY_set_private_key(key, bn) {
                EC_KEY_free(key);
                BN_free(bn);
                return Err(Unspecified);
            }

            BN_free(bn);
        }

        Ok(Self { inner: key, curve })
    }

    pub fn to_vec(&self) -> Result<Vec<u8>, Unspecified> {
        let mut secret_key_data = vec![0u8; self.curve.secret_key_size()];

        let len = unsafe {
            BN_bn2bin(
                EC_KEY_get0_private_key(self.inner),
                secret_key_data.as_mut_ptr(),
            )
        };

        if len > secret_key_data.len() || len == 0 {
            return Err(Unspecified);
        }

        secret_key_data.truncate(len);

        Ok(secret_key_data)
    }

    pub fn public_key(&self) -> Result<EcPublicKey, Unspecified> {
        let group = unsafe { EC_KEY_get0_group(self.inner) };
        let pub_key = unsafe { EC_POINT_new(group) };

        unsafe {
            if EC_KEY_get0_public_key(self.inner).is_null() {
                let bn = EC_KEY_get0_private_key(self.inner);

                if 1 != EC_POINT_mul(group, pub_key, bn, null_mut(), null_mut(), null_mut()) {
                    EC_POINT_free(pub_key);
                    return Err(Unspecified);
                }

                if 1 != EC_KEY_set_public_key(self.inner, pub_key) {
                    EC_POINT_free(pub_key);
                    return Err(Unspecified);
                }
            } else if 1 != EC_POINT_copy(pub_key, EC_KEY_get0_public_key(self.inner)) {
                EC_POINT_free(pub_key);
                return Err(Unspecified);
            }
        }

        Ok(EcPublicKey {
            inner: pub_key,
            curve: self.curve,
        })
    }
}

impl Drop for EcPrivateKey {
    fn drop(&mut self) {
        unsafe { crate::aws_lc_sys_impl::EC_KEY_free(self.inner) }
    }
}

impl TryInto<EvpPkey> for EcPrivateKey {
    type Error = Unspecified;

    fn try_into(self) -> Result<EvpPkey, Unspecified> {
        unsafe {
            let key = EVP_PKEY_new();

            if key.is_null() {
                return Err(Unspecified);
            }

            if 1 != EVP_PKEY_set1_EC_KEY(key, self.inner) {
                return Err(Unspecified);
            }

            Ok(EvpPkey(key))
        }
    }
}

pub struct EcPublicKey {
    pub(crate) inner: *mut EC_POINT,
    curve: Curve,
}

impl EcPublicKey {
    pub fn from_bytes(bytes: &[u8], curve: Curve) -> Result<Self, Unspecified> {
        let nid = nid(curve).ok_or(Unspecified)?;

        unsafe {
            let group = EC_GROUP_new_by_curve_name(nid);

            let point = EC_POINT_new(group);

            if 1 != EC_POINT_oct2point(group, point, bytes.as_ptr(), bytes.len(), null_mut()) {
                EC_GROUP_free(group);
                EC_POINT_free(point);
                return Err(Unspecified);
            }

            EC_GROUP_free(group);

            Ok(Self {
                inner: point,
                curve,
            })
        }
    }

    pub fn to_vec(&self) -> Result<Vec<u8>, Unspecified> {
        let mut pub_key_data = vec![0u8; self.curve.public_key_size()];
        let nid = nid(self.curve).ok_or(Unspecified)?;

        let out_len = unsafe {
            let group = EC_GROUP_new_by_curve_name(nid);

            let out_len = EC_POINT_point2oct(
                group,
                self.inner,
                point_conversion_form_t::POINT_CONVERSION_UNCOMPRESSED,
                pub_key_data.as_mut_ptr(),
                self.curve.public_key_size(),
                null_mut(),
            );

            EC_GROUP_free(group);

            out_len
        };

        (out_len == pub_key_data.len())
            .then_some(pub_key_data)
            .ok_or(Unspecified)
    }
}

pub struct EvpPkey(pub(crate) *mut EVP_PKEY);

impl Drop for EvpPkey {
    fn drop(&mut self) {
        unsafe { EVP_PKEY_free(self.0) }
    }
}

impl TryInto<EvpPkey> for EcPublicKey {
    type Error = Unspecified;

    fn try_into(self) -> Result<EvpPkey, Unspecified> {
        unsafe {
            let nid = nid(self.curve).ok_or(Unspecified)?;
            let ec_key = EC_KEY_new_by_curve_name(nid);

            if ec_key.is_null() {
                return Err(Unspecified);
            }

            if 1 != EC_KEY_set_public_key(ec_key, self.inner) {
                EC_KEY_free(ec_key);
                return Err(Unspecified);
            }

            let key = EVP_PKEY_new();

            if key.is_null() {
                EC_KEY_free(ec_key);
                return Err(Unspecified);
            }

            let res = EVP_PKEY_set1_EC_KEY(key, ec_key);
            EC_KEY_free(ec_key);

            if res != 1 {
                return Err(Unspecified);
            }

            Ok(EvpPkey(key))
        }
    }
}

impl Drop for EcPublicKey {
    fn drop(&mut self) {
        unsafe { EC_POINT_free(self.inner) }
    }
}

fn nid(curve: Curve) -> Option<i32> {
    match curve {
        Curve::P256 => Some(NID_X9_62_prime256v1),
        Curve::P384 => Some(NID_secp384r1),
        Curve::P521 => Some(NID_secp521r1),
        _ => None,
    }
}
