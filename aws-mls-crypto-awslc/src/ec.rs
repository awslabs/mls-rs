use std::{mem::MaybeUninit, os::raw::c_void, ptr::null_mut};

use aws_lc_rs::error::Unspecified;
use aws_lc_sys::{
    d2i_ECPrivateKey, point_conversion_form_t, BN_bin2bn, BN_bn2bin, BN_free, ECDH_compute_key,
    EC_GROUP_free, EC_GROUP_new_by_curve_name, EC_KEY_free, EC_KEY_generate_key, EC_KEY_get0_group,
    EC_KEY_get0_private_key, EC_KEY_get0_public_key, EC_KEY_new_by_curve_name,
    EC_KEY_set_private_key, EC_KEY_set_public_key, EC_POINT_copy, EC_POINT_free, EC_POINT_mul,
    EC_POINT_new, EC_POINT_oct2point, EC_POINT_point2oct, NID_secp521r1, EC_POINT,
};
use aws_mls_core::crypto::{HpkePublicKey, HpkeSecretKey};
use aws_mls_crypto_traits::Curve;

use crate::AwsLcCryptoError;

#[derive(Clone)]
pub(crate) struct Ecdh(Curve);

impl Ecdh {
    pub fn new() -> Self {
        Self(Curve::P521)
    }
}

impl aws_mls_crypto_traits::DhType for Ecdh {
    type Error = AwsLcCryptoError;

    fn dh(
        &self,
        secret_key: &HpkeSecretKey,
        public_key: &HpkePublicKey,
    ) -> Result<Vec<u8>, Self::Error> {
        let secret_key = EcPrivateKey::from_bytes(secret_key)?;
        let public_key = EcPublicKey::from_bytes(public_key)?;

        let mut shared_secret_data = MaybeUninit::<[u8; SHARED_SECRET_LEN]>::uninit();

        unsafe {
            let out_len = ECDH_compute_key(
                shared_secret_data.as_mut_ptr() as *mut c_void,
                SHARED_SECRET_LEN,
                public_key.inner,
                secret_key.inner,
                None,
            );

            if out_len == 0 {
                return Err(Unspecified.into());
            }

            Ok(shared_secret_data.assume_init()[..out_len as usize].to_vec())
        }
    }

    fn generate(&self) -> Result<(HpkeSecretKey, HpkePublicKey), Self::Error> {
        let private_key = EcPrivateKey::generate()?;
        let public_key = private_key.public_key()?;

        Ok((private_key.to_vec()?.into(), public_key.to_vec()?.into()))
    }

    fn to_public(&self, secret_key: &HpkeSecretKey) -> Result<HpkePublicKey, Self::Error> {
        Ok(EcPrivateKey::from_bytes(secret_key)?
            .public_key()?
            .to_vec()?
            .into())
    }

    fn bitmask_for_rejection_sampling(&self) -> Option<u8> {
        self.0.curve_bitmask()
    }

    fn secret_key_size(&self) -> usize {
        self.0.secret_key_size()
    }

    fn public_key_validate(&self, key: &HpkePublicKey) -> Result<(), Self::Error> {
        EcPublicKey::from_bytes(key).map(|_| ()).map_err(Into::into)
    }
}

const ELEM_MAX_BITS: usize = 521;

pub const ELEM_MAX_BYTES: usize = (ELEM_MAX_BITS + 7) / 8;
pub const PUBLIC_KEY_LEN: usize = 1 + (2 * ELEM_MAX_BYTES);
pub const SECRET_KEY_LEN: usize = ELEM_MAX_BYTES;
pub const SHARED_SECRET_LEN: usize = SECRET_KEY_LEN;

pub struct EcPrivateKey {
    pub(crate) inner: *mut aws_lc_sys::ec_key_st,
}

impl EcPrivateKey {
    pub fn generate() -> Result<Self, Unspecified> {
        unsafe {
            let key = EC_KEY_new_by_curve_name(NID_secp521r1);

            if key.is_null() {
                return Err(Unspecified);
            }

            if 1 != EC_KEY_generate_key(key) {
                EC_KEY_free(key);
                return Err(Unspecified);
            }

            Ok(Self { inner: key })
        }
    }

    pub fn from_der(bytes: &[u8]) -> Result<Self, Unspecified> {
        unsafe {
            let mut result_holder = bytes.as_ptr();

            let input_len = bytes.len().try_into().map_err(|_| Unspecified)?;

            let ec_key = d2i_ECPrivateKey(null_mut(), &mut result_holder, input_len);

            if ec_key.is_null() {
                return Err(Unspecified);
            }

            Ok(Self { inner: ec_key })
        }
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Unspecified> {
        unsafe {
            // Private key to bignum
            let bn = BN_bin2bn(bytes.as_ptr(), bytes.len(), null_mut());

            if bn.is_null() {
                return Err(Unspecified);
            }

            let key = EC_KEY_new_by_curve_name(NID_secp521r1);

            if 1 != EC_KEY_set_private_key(key, bn) {
                EC_KEY_free(key);
                BN_free(bn);
                return Err(Unspecified);
            }

            Ok(Self { inner: key })
        }
    }

    pub fn to_vec(&self) -> Result<Vec<u8>, Unspecified> {
        unsafe {
            let mut secret_key_data = MaybeUninit::<[u8; SECRET_KEY_LEN]>::uninit();

            let len = BN_bn2bin(
                EC_KEY_get0_private_key(self.inner),
                secret_key_data.as_mut_ptr() as *mut u8,
            );

            if len == 0 {
                return Err(Unspecified);
            }

            Ok(secret_key_data.assume_init()[..len].to_vec())
        }
    }

    pub fn public_key(&self) -> Result<EcPublicKey, Unspecified> {
        unsafe {
            let group = EC_KEY_get0_group(self.inner);

            if EC_KEY_get0_public_key(self.inner).is_null() {
                let pub_key = EC_POINT_new(group);
                let bn = EC_KEY_get0_private_key(self.inner);

                if 1 != EC_POINT_mul(group, pub_key, bn, null_mut(), null_mut(), null_mut()) {
                    EC_POINT_free(pub_key);
                    return Err(Unspecified);
                }

                if 1 != EC_KEY_set_public_key(self.inner, pub_key) {
                    EC_POINT_free(pub_key);
                    return Err(Unspecified);
                }

                Ok(EcPublicKey { inner: pub_key })
            } else {
                let point = EC_POINT_new(group);

                if 1 != EC_POINT_copy(point, EC_KEY_get0_public_key(self.inner)) {
                    EC_POINT_free(point);
                    return Err(Unspecified);
                }

                Ok(EcPublicKey { inner: point })
            }
        }
    }
}

impl Drop for EcPrivateKey {
    fn drop(&mut self) {
        unsafe { aws_lc_sys::EC_KEY_free(self.inner) }
    }
}

pub struct EcPublicKey {
    pub(crate) inner: *mut EC_POINT,
}

impl EcPublicKey {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Unspecified> {
        unsafe {
            let group = EC_GROUP_new_by_curve_name(NID_secp521r1);

            let point = EC_POINT_new(group);

            if 1 != EC_POINT_oct2point(group, point, bytes.as_ptr(), bytes.len(), null_mut()) {
                EC_GROUP_free(group);
                EC_POINT_free(point);
                return Err(Unspecified);
            }

            EC_GROUP_free(group);

            Ok(Self { inner: point })
        }
    }

    pub fn to_vec(&self) -> Result<Vec<u8>, Unspecified> {
        unsafe {
            let mut pub_key_data = MaybeUninit::<[u8; PUBLIC_KEY_LEN]>::uninit();

            let group = EC_GROUP_new_by_curve_name(NID_secp521r1);

            let out_len = EC_POINT_point2oct(
                group,
                self.inner,
                point_conversion_form_t::POINT_CONVERSION_UNCOMPRESSED,
                pub_key_data.as_mut_ptr() as *mut u8,
                PUBLIC_KEY_LEN,
                null_mut(),
            );

            EC_GROUP_free(group);

            if out_len == 0 {
                return Err(Unspecified);
            }

            Ok(pub_key_data.assume_init().to_vec())
        }
    }
}

impl Drop for EcPublicKey {
    fn drop(&mut self) {
        unsafe { EC_POINT_free(self.inner) }
    }
}
