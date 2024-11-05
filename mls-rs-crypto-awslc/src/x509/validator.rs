// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// Copyright by contributors to this project.
// SPDX-License-Identifier: (Apache-2.0 OR MIT)

use std::ffi::{c_long, c_ulong, CStr};

use crate::aws_lc_sys_impl::{
    time_t, X509_STORE_CTX_free, X509_STORE_CTX_get0_param, X509_STORE_CTX_get_error,
    X509_STORE_CTX_init, X509_STORE_CTX_new, X509_STORE_CTX_set0_trusted_stack, X509_STORE_free,
    X509_STORE_new, X509_VERIFY_PARAM_get_flags, X509_VERIFY_PARAM_set_flags,
    X509_VERIFY_PARAM_set_time, X509_verify_cert, X509_verify_cert_error_string, X509_VERIFY_PARAM,
    X509_V_FLAG_NO_CHECK_TIME, X509_V_OK,
};
use mls_rs_core::{crypto::SignaturePublicKey, time::MlsTime};
use mls_rs_identity_x509::{CertificateChain, DerCertificate, X509CredentialValidator};

use crate::{check_non_null, check_res, AwsLcCryptoError};

use super::{certificate::Certificate, component::Stack};

pub struct CertificateValidator {
    ca_certs: Stack<Certificate>,
}

impl CertificateValidator {
    pub fn new_der(ca_certs: &[DerCertificate]) -> Result<Self, AwsLcCryptoError> {
        let ca_certs = certs_to_stack(ca_certs)?;
        Ok(Self { ca_certs })
    }

    pub fn new(ca_certs: Vec<Certificate>) -> Result<Self, AwsLcCryptoError> {
        let ca_certs = ca_certs.into_iter().fold(Stack::new()?, |mut stack, cert| {
            stack.push(cert);
            stack
        });

        Ok(Self { ca_certs })
    }

    pub fn validate(
        &self,
        chain: &CertificateChain,
        timestamp: Option<MlsTime>,
    ) -> Result<SignaturePublicKey, AwsLcCryptoError> {
        let leaf = chain
            .leaf()
            .ok_or(AwsLcCryptoError::CryptoError)
            .and_then(Certificate::try_from)?;

        unsafe {
            let cert_stack = certs_to_stack(chain)?;

            let ctx = check_non_null(X509_STORE_CTX_new())?;
            let store = check_non_null(X509_STORE_new())?;

            if 1 != X509_STORE_CTX_init(ctx, store, leaf.as_ptr(), cert_stack.as_ptr().cast()) {
                X509_STORE_CTX_free(ctx);
                X509_STORE_free(store);
                return Err(AwsLcCryptoError::CryptoError);
            }

            X509_STORE_CTX_set0_trusted_stack(ctx, self.ca_certs.as_ptr().cast());

            set_verify_params(X509_STORE_CTX_get0_param(ctx), timestamp)?;

            let validation_result = X509_verify_cert(ctx);
            let validation_code = X509_STORE_CTX_get_error(ctx);

            X509_STORE_free(store);
            X509_STORE_CTX_free(ctx);

            if validation_result != 1 || validation_code != X509_V_OK {
                let reason =
                    CStr::from_ptr(X509_verify_cert_error_string(validation_code as c_long))
                        .to_str()
                        .map(String::from)
                        .unwrap_or_else(|_| "Unknown".to_string());

                return Err(AwsLcCryptoError::CertValidationFailure(reason));
            }

            core::mem::drop(cert_stack)
        }

        leaf.public_key()
    }
}

impl X509CredentialValidator for CertificateValidator {
    type Error = AwsLcCryptoError;

    fn validate_chain(
        &self,
        chain: &CertificateChain,
        timestamp: Option<MlsTime>,
    ) -> Result<SignaturePublicKey, Self::Error> {
        self.validate(chain, timestamp)
    }
}

fn certs_to_stack(certs: &[DerCertificate]) -> Result<Stack<Certificate>, AwsLcCryptoError> {
    let stack = certs.iter().try_fold(Stack::new()?, |mut stack, cert| {
        let cert = Certificate::try_from(cert)?;
        stack.push(cert);
        Ok::<_, AwsLcCryptoError>(stack)
    })?;

    Ok(stack)
}

unsafe fn set_verify_params(
    params: *mut X509_VERIFY_PARAM,
    timestamp: Option<MlsTime>,
) -> Result<(), AwsLcCryptoError> {
    unsafe {
        if let Some(timestamp) = timestamp {
            X509_VERIFY_PARAM_set_time(
                params,
                time_t::try_from(timestamp.seconds_since_epoch())
                    .map_err(|_| AwsLcCryptoError::CryptoError)?,
            );
        } else {
            let flags = X509_VERIFY_PARAM_get_flags(params) | X509_V_FLAG_NO_CHECK_TIME as c_ulong;
            check_res(X509_VERIFY_PARAM_set_flags(params, flags))?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use assert_matches::assert_matches;
    use mls_rs_core::time::MlsTime;
    use mls_rs_identity_x509::{CertificateChain, DerCertificate, X509CredentialValidator};

    use crate::{
        x509::{
            test_utils::{
                load_test_ca, load_test_cert_chain, load_test_invalid_ca_chain,
                load_test_invalid_chain,
            },
            CertificateValidator,
        },
        AwsLcCryptoError,
    };

    pub fn load_another_ca() -> DerCertificate {
        DerCertificate::from(include_bytes!("../../test_data/x509/another_ca.der").to_vec())
    }

    #[test]
    fn can_validate_cert_chain() {
        let chain = load_test_cert_chain();

        let validator = CertificateValidator::new_der(&[load_test_ca()]).unwrap();

        validator
            .validate_chain(&chain, Some(MlsTime::now()))
            .unwrap();
    }

    #[test]
    fn will_fail_on_empty_chain() {
        let validator = CertificateValidator::new_der(&[]).unwrap();
        let empty: Vec<Vec<u8>> = Vec::new();

        let res = validator.validate_chain(&CertificateChain::from(empty), Some(MlsTime::now()));

        assert_matches!(res, Err(AwsLcCryptoError::CryptoError));
    }

    #[test]
    fn will_fail_on_invalid_chain() {
        let chain = load_test_invalid_chain();
        let validator = CertificateValidator::new_der(&[load_test_ca()]).unwrap();

        let res = validator.validate_chain(&chain, Some(MlsTime::now()));

        assert_matches!(res, Err(AwsLcCryptoError::CertValidationFailure(_)));
    }

    #[test]
    fn will_fail_on_invalid_ca() {
        let chain = load_test_invalid_ca_chain();
        let validator = CertificateValidator::new_der(&[load_another_ca()]).unwrap();
        let res = validator.validate_chain(&chain, Some(MlsTime::now()));

        assert_matches!(res, Err(AwsLcCryptoError::CertValidationFailure(_)));
    }

    #[test]
    fn can_detect_expired_certs() {
        let chain = load_test_cert_chain();

        let validator = CertificateValidator::new_der(&[load_test_ca()]).unwrap();

        let res = validator.validate_chain(
            &chain,
            Some(MlsTime::from_duration_since_epoch(Duration::from_secs(
                1798761600,
            ))),
        );

        assert_matches!(res, Err(AwsLcCryptoError::CertValidationFailure(_)));
    }
}
