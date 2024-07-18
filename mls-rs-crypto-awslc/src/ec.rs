// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// Copyright by contributors to this project.
// SPDX-License-Identifier: (Apache-2.0 OR MIT)

use std::ptr::null_mut;

use aws_lc_rs::error::Unspecified;
use aws_lc_sys::{
    d2i_ECPrivateKey, point_conversion_form_t, BN_bin2bn, BN_bn2bin, BN_free, EC_GROUP_free,
    EC_GROUP_new_by_curve_name, EC_KEY_free, EC_KEY_generate_key, EC_KEY_get0_group,
    EC_KEY_get0_private_key, EC_KEY_get0_public_key, EC_KEY_new_by_curve_name,
    EC_KEY_set_private_key, EC_KEY_set_public_key, EC_POINT_copy, EC_POINT_free, EC_POINT_mul,
    EC_POINT_new, EC_POINT_oct2point, EC_POINT_point2oct, EVP_PKEY_free, EVP_PKEY_new,
    EVP_PKEY_set1_EC_KEY, NID_X9_62_prime256v1, NID_secp384r1, NID_secp521r1, EC_POINT, EVP_PKEY,
};
use mls_rs_crypto_traits::Curve;

use crate::AwsLcCryptoError;

pub(crate) const SUPPORTED_NIST_CURVES: [Curve; 3] = [Curve::P521, Curve::P256, Curve::P384];

pub fn ec_public_key(curve: Curve, secret_key: &[u8]) -> Result<Vec<u8>, AwsLcCryptoError> {
    Ok(EcPrivateKey::from_bytes(secret_key, curve)?
        .public_key()?
        .to_vec()?)
}

pub fn ec_generate(curve: Curve) -> Result<(Vec<u8>, Vec<u8>), AwsLcCryptoError> {
    let private_key = EcPrivateKey::generate(curve)?;
    let public_key = private_key.public_key()?;

    Ok((private_key.to_vec()?, public_key.to_vec()?))
}

pub struct EcPrivateKey {
    pub(crate) inner: *mut aws_lc_sys::ec_key_st,
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
        unsafe { aws_lc_sys::EC_KEY_free(self.inner) }
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
