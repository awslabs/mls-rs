// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// Copyright by contributors to this project.
// SPDX-License-Identifier: (Apache-2.0 OR MIT)

use std::{
    ffi::{c_long, c_void},
    mem,
    ptr::null_mut,
    time::Duration,
};

use crate::aws_lc_sys_impl::{
    d2i_X509, i2d_X509, i2d_X509_NAME, ASN1_INTEGER_free, ASN1_INTEGER_to_BN, ASN1_TIME_free,
    ASN1_TIME_new, ASN1_TIME_set_posix, ASN1_TIME_to_posix, BN_bin2bn, BN_bn2bin, BN_free,
    BN_num_bytes, BN_to_ASN1_INTEGER, EC_KEY_get0_group, EC_KEY_get0_public_key,
    EC_POINT_point2oct, EVP_PKEY_free, EVP_PKEY_get0_EC_KEY, EVP_PKEY_get_raw_public_key,
    NID_subject_alt_name, X509V3_set_ctx, X509_EXTENSION_dup, X509_add_ext, X509_free,
    X509_get0_notAfter, X509_get0_notBefore, X509_get_ext, X509_get_ext_count, X509_get_ext_d2i,
    X509_get_issuer_name, X509_get_pubkey, X509_get_serialNumber, X509_get_subject_name, X509_new,
    X509_set_issuer_name, X509_set_notAfter, X509_set_notBefore, X509_set_pubkey,
    X509_set_serialNumber, X509_set_subject_name, X509_set_version, X509_sign, ASN1_TIME, X509,
};
use mls_rs_core::{
    crypto::{CipherSuite, SignaturePublicKey, SignatureSecretKey},
    time::MlsTime,
};
use mls_rs_identity_x509::{DerCertificate, SubjectAltName, SubjectComponent};

use crate::{
    check_int_return, check_non_null, check_non_null_const, check_res, ecdsa::AwsLcEcdsa,
    AwsLcCryptoError,
};

use super::{
    component::{
        components_from_name, GeneralName, Stack, StackItem, X509Extension, X509ExtensionContext,
        X509Name,
    },
    request::digest_for_curve,
};

pub struct Certificate(*mut X509);

impl Certificate {
    pub fn new() -> Result<Self, AwsLcCryptoError> {
        unsafe { check_non_null(X509_new()).map(Self) }
    }

    pub fn set_subject(&mut self, components: &[SubjectComponent]) -> Result<(), AwsLcCryptoError> {
        unsafe {
            let name = X509Name::new_components(components)?;
            check_res(X509_set_subject_name(self.0, name.0))
        }
    }

    pub fn subject_bytes(&self) -> Result<Vec<u8>, AwsLcCryptoError> {
        unsafe {
            let name = check_non_null(X509_get_subject_name(self.0))?;

            let len = check_int_return(i2d_X509_NAME(name, null_mut()))?;
            let mut out = vec![0u8; len as usize];
            check_res(i2d_X509_NAME(name, &mut out.as_mut_ptr()))?;

            Ok(out)
        }
    }

    pub fn subject_components(&self) -> Result<Vec<SubjectComponent>, AwsLcCryptoError> {
        unsafe {
            let name = check_non_null(X509_get_subject_name(self.0))?;
            let res = components_from_name(name)?;

            Ok(res)
        }
    }

    pub fn set_public_key(
        &mut self,
        cipher_suite: CipherSuite,
        key: &SignaturePublicKey,
    ) -> Result<(), AwsLcCryptoError> {
        let util = AwsLcEcdsa::new(cipher_suite).ok_or(AwsLcCryptoError::UnsupportedCipherSuite)?;
        let signature_key = util.evp_public_key(key)?;

        unsafe { check_res(X509_set_pubkey(self.0, signature_key.0)) }
    }

    pub fn add_extension(&mut self, ext: &X509Extension) -> Result<(), AwsLcCryptoError> {
        unsafe { check_res(X509_add_ext(self.0, ext.0, -1)) }
    }

    pub fn extensions(&self) -> Result<Vec<X509Extension>, AwsLcCryptoError> {
        unsafe {
            (0..X509_get_ext_count(self.0)).try_fold(Vec::new(), |mut extensions, i| {
                let ext = check_non_null(X509_get_ext(self.0, i))?;
                let ext_clone = check_non_null(X509_EXTENSION_dup(ext)).map(X509Extension)?;
                extensions.push(ext_clone);
                Ok(extensions)
            })
        }
    }

    pub fn extension_ctx(&self, issuer: &Certificate) -> X509ExtensionContext<'_> {
        unsafe {
            let mut ctx = mem::zeroed();

            X509V3_set_ctx(&mut ctx, issuer.0, self.0, null_mut(), null_mut(), 0);

            X509ExtensionContext {
                inner: ctx,
                phantom: Default::default(),
            }
        }
    }

    pub fn issuer(&self) -> Result<Vec<SubjectComponent>, AwsLcCryptoError> {
        unsafe {
            let name = check_non_null(X509_get_issuer_name(self.0))?;
            let res = components_from_name(name)?;

            Ok(res)
        }
    }

    pub fn set_issuer(&mut self, issuer: &[SubjectComponent]) -> Result<(), AwsLcCryptoError> {
        unsafe {
            let name = X509Name::new_components(issuer)?;
            check_res(X509_set_issuer_name(self.0, name.0))?;

            Ok(())
        }
    }

    pub fn not_before(&self) -> Result<MlsTime, AwsLcCryptoError> {
        unsafe {
            let time = check_non_null_const(X509_get0_notBefore(self.0.cast_const()))?;
            asn1_time_to_posix(time)
        }
    }

    pub fn not_after(&self) -> Result<MlsTime, AwsLcCryptoError> {
        unsafe {
            let time = check_non_null_const(X509_get0_notAfter(self.0.cast_const()))?;
            asn1_time_to_posix(time)
        }
    }

    pub fn set_not_before(&mut self, not_before: MlsTime) -> Result<(), AwsLcCryptoError> {
        unsafe {
            let time = posix_to_asn1_time(not_before)?;
            let res = X509_set_notBefore(self.0, time);
            ASN1_TIME_free(time);

            check_res(res)
        }
    }

    pub fn set_not_after(&mut self, not_after: MlsTime) -> Result<(), AwsLcCryptoError> {
        unsafe {
            let time = posix_to_asn1_time(not_after)?;
            let res = X509_set_notAfter(self.0, time);
            ASN1_TIME_free(time);

            check_res(res)
        }
    }

    pub fn serial_number(&self) -> Result<Vec<u8>, AwsLcCryptoError> {
        unsafe {
            let number = check_non_null(X509_get_serialNumber(self.0))?;
            let number = check_non_null(ASN1_INTEGER_to_BN(number, null_mut()))?;

            let mut out = vec![0u8; BN_num_bytes(number) as usize];

            BN_bn2bin(number, out.as_mut_ptr());
            BN_free(number);

            Ok(out)
        }
    }

    pub fn set_serial_number(&self, number: &[u8]) -> Result<(), AwsLcCryptoError> {
        unsafe {
            let bn = check_non_null(BN_bin2bn(number.as_ptr(), number.len(), null_mut()))?;

            let serial = BN_to_ASN1_INTEGER(bn, null_mut());
            BN_free(bn);

            check_non_null(serial)?;

            let res = X509_set_serialNumber(self.0, serial);
            ASN1_INTEGER_free(serial);

            check_res(res)
        }
    }

    pub fn public_key(&self) -> Result<SignaturePublicKey, AwsLcCryptoError> {
        unsafe {
            let pub_key = X509_get_pubkey(self.0);
            let ec_key = EVP_PKEY_get0_EC_KEY(pub_key);

            let res = || {
                if !ec_key.is_null() {
                    let mut out_buf = vec![0u8; 256];

                    let len = EC_POINT_point2oct(
                    EC_KEY_get0_group(ec_key),
                    EC_KEY_get0_public_key(ec_key),
                    crate::aws_lc_sys_impl::point_conversion_form_t::POINT_CONVERSION_UNCOMPRESSED,
                    out_buf.as_mut_ptr(),
                    256,
                    null_mut(),
                );

                    if len == 0 {
                        return Err(AwsLcCryptoError::InvalidKeyData);
                    }

                    out_buf.truncate(len);

                    Ok(out_buf.into())
                } else {
                    let mut len = 0;

                    check_res(EVP_PKEY_get_raw_public_key(pub_key, null_mut(), &mut len))?;

                    let mut out = vec![0u8; len];

                    check_res(EVP_PKEY_get_raw_public_key(
                        pub_key,
                        out.as_mut_ptr(),
                        &mut len,
                    ))?;

                    Ok(out.into())
                }
            };

            let res = res();

            EVP_PKEY_free(pub_key);

            res
        }
    }

    pub fn subject_alt_names(&self) -> Result<Vec<SubjectAltName>, AwsLcCryptoError> {
        unsafe {
            let subject_alt_names =
                X509_get_ext_d2i(self.0, NID_subject_alt_name, null_mut(), null_mut());

            if subject_alt_names.is_null() {
                return Ok(Vec::default());
            }

            let stack: Stack<GeneralName> = Stack::from_raw_pointer(subject_alt_names.cast());

            stack
                .into_vec()
                .into_iter()
                .rev()
                .map(|name| name.subject_alt_name())
                .collect()
        }
    }

    pub fn sign(
        &mut self,
        cipher_suite: CipherSuite,
        signature_key: &SignatureSecretKey,
    ) -> Result<(), AwsLcCryptoError> {
        let util = AwsLcEcdsa::new(cipher_suite).ok_or(AwsLcCryptoError::UnsupportedCipherSuite)?;
        let signature_key = util.evp_private_key(signature_key)?;

        unsafe {
            // X509 V3
            check_res(X509_set_version(self.0, 2))?;
            check_res(X509_sign(self.0, signature_key.0, digest_for_curve(*util)))
        }
    }

    pub fn to_der(&self) -> Result<DerCertificate, AwsLcCryptoError> {
        unsafe {
            let len = check_int_return(i2d_X509(self.0, null_mut()))?;
            let mut out = vec![0u8; len as usize];

            check_res(i2d_X509(self.0, &mut out.as_mut_ptr()))?;

            Ok(out.into())
        }
    }

    pub(crate) fn as_ptr(&self) -> *mut X509 {
        self.0
    }
}

impl Drop for Certificate {
    fn drop(&mut self) {
        unsafe { X509_free(self.0) }
    }
}

impl TryFrom<&DerCertificate> for Certificate {
    type Error = AwsLcCryptoError;

    fn try_from(value: &DerCertificate) -> Result<Self, Self::Error> {
        let mut result_holder = value.as_ptr();

        unsafe {
            check_non_null(d2i_X509(
                null_mut(),
                &mut result_holder,
                value.len() as c_long,
            ))
            .map_err(|_| AwsLcCryptoError::CryptoError)
            .map(Certificate)
        }
    }
}

unsafe impl StackItem for Certificate {
    fn from_raw_pointer(ptr: *mut c_void) -> Self {
        Certificate(ptr.cast())
    }

    fn into_raw_pointer(self) -> *mut c_void {
        let inner = self.0;
        core::mem::forget(self);
        inner.cast()
    }
}

unsafe fn asn1_time_to_posix(time: *const ASN1_TIME) -> Result<MlsTime, AwsLcCryptoError> {
    let mut out = 0i64;
    check_res(ASN1_TIME_to_posix(time, &mut out))?;

    Ok(MlsTime::from_duration_since_epoch(Duration::new(
        out as u64, 0,
    )))
}

unsafe fn posix_to_asn1_time(time: MlsTime) -> Result<*mut ASN1_TIME, AwsLcCryptoError> {
    let asn1_time = check_non_null(ASN1_TIME_new())?;

    if ASN1_TIME_set_posix(asn1_time, time.seconds_since_epoch() as i64).is_null() {
        ASN1_TIME_free(asn1_time);
        return Err(AwsLcCryptoError::CryptoError);
    }

    Ok(asn1_time)
}

#[cfg(test)]
mod tests {
    use mls_rs_core::{crypto::CipherSuite, time::MlsTime};
    use mls_rs_identity_x509::{
        CertificateChain, SubjectAltName, SubjectComponent, X509CredentialValidator,
    };

    use crate::{
        ecdsa::AwsLcEcdsa,
        x509::{
            component::{KeyUsage, X509Extension},
            test_utils::{test_root_ca, test_root_ca_key},
            CertificateValidator,
        },
    };

    use super::Certificate;

    #[test]
    fn build_certificate() {
        let ca_key = test_root_ca_key();
        let ca_cert = Certificate::try_from(&test_root_ca()).unwrap();

        let signer = AwsLcEcdsa::new(CipherSuite::P384_AES256).unwrap();
        let (_, public_key) = signer.signature_key_generate().unwrap();

        let subject = vec![SubjectComponent::CommonName("test".to_string())];
        let serial = vec![1, 2, 3];
        let not_before = MlsTime::from(3);
        let not_after = MlsTime::from(5);

        let mut new_cert = Certificate::new().unwrap();

        new_cert
            .set_issuer(&ca_cert.subject_components().unwrap())
            .unwrap();

        new_cert.set_subject(&subject).unwrap();
        new_cert.set_serial_number(&serial).unwrap();

        new_cert
            .set_public_key(CipherSuite::P384_AES256, &public_key)
            .unwrap();

        new_cert.set_not_before(not_before).unwrap();
        new_cert.set_not_after(not_after).unwrap();

        let mut ext_context = new_cert.extension_ctx(&ca_cert);

        let extensions = vec![
            X509Extension::key_usage(false, &[KeyUsage::KeyCertSign]).unwrap(),
            X509Extension::basic_constraints(false, false, None).unwrap(),
            X509Extension::subject_alt_name(&[SubjectAltName::Dns("example.org".to_string())])
                .unwrap(),
            X509Extension::authority_key_identifier(&mut ext_context, false, true, true).unwrap(),
            X509Extension::subject_key_identifier(&mut ext_context, false).unwrap(),
        ];

        extensions
            .iter()
            .for_each(|ext| new_cert.add_extension(ext).unwrap());

        new_cert
            .sign(CipherSuite::CURVE25519_AES128, &ca_key)
            .unwrap();

        let serialized = new_cert.to_der().unwrap();

        // Validate we can read everything that was previously written
        let restored = Certificate::try_from(&serialized).unwrap();
        assert_eq!(restored.subject_components().unwrap(), subject);
        assert_eq!(restored.serial_number().unwrap(), serial);
        assert_eq!(restored.public_key().unwrap(), public_key);
        assert_eq!(restored.not_before().unwrap(), not_before);
        assert_eq!(restored.not_after().unwrap(), not_after);

        assert_eq!(restored.extensions().unwrap(), extensions);

        assert_eq!(
            restored.issuer().unwrap(),
            ca_cert.subject_components().unwrap()
        );

        // The resulting cert should pass validation
        let validator = CertificateValidator::new(vec![ca_cert]).unwrap();
        let chain = CertificateChain::from(vec![restored.to_der().unwrap()]);
        validator.validate_chain(&chain, None).unwrap();
    }
}
