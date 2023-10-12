// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// Copyright by contributors to this project.
// SPDX-License-Identifier: (Apache-2.0 OR MIT)

use std::collections::HashMap;

use aws_mls_core::{crypto::SignaturePublicKey, time::MlsTime};
use aws_mls_identity_x509::{CertificateChain, DerCertificate, X509CredentialValidator};
use spki::der::{Decode, Encode};
use x509_cert::Certificate;

use crate::{
    ec::pub_key_to_uncompressed,
    ec_for_x509::{pub_key_from_spki, signer_from_algorithm},
};

use super::X509Error;

#[derive(Debug, Clone)]
pub struct X509Validator {
    root_ca_list: HashMap<Vec<u8>, DerCertificate>,
    pinned_cert: Option<DerCertificate>,
    allow_self_signed: bool,
}

impl X509Validator {
    pub fn new(root_ca_list: Vec<DerCertificate>) -> Result<Self, X509Error> {
        let root_ca_list = root_ca_list
            .into_iter()
            .map(|cert_data| {
                // Verify the self-signture. Time is validated when CAs are used
                let cert = Certificate::from_der(&cert_data)?;
                verify_cert(&cert, &cert, None)?;
                let subject = cert.tbs_certificate.subject.to_der()?;
                Ok((subject, cert_data))
            })
            .collect::<Result<_, X509Error>>()?;

        Ok(Self {
            root_ca_list,
            pinned_cert: None,
            allow_self_signed: false,
        })
    }

    pub fn set_pinned_cert(&mut self, pinned_cert: Option<DerCertificate>) {
        self.pinned_cert = pinned_cert;
    }

    /// This MUST be used only in tests. DO NOT use in production.
    pub fn allow_self_signed(&mut self, allow: bool) {
        self.allow_self_signed = allow;
    }

    fn validate_chain(
        &self,
        chain: &CertificateChain,
        timestamp: Option<MlsTime>,
    ) -> Result<SignaturePublicKey, X509Error> {
        (!chain.is_empty())
            .then_some(())
            .ok_or(X509Error::EmptyCertificateChain)?;

        if let Some(pinned_cert) = self.pinned_cert.as_ref() {
            chain
                .contains(pinned_cert)
                .then_some(())
                .ok_or(X509Error::PinnedCertNotFound)?;
        }

        let chain = chain
            .iter()
            .map(|cert_data| Certificate::from_der(cert_data))
            .collect::<Result<Vec<_>, _>>()?;

        for (cert1, cert2) in chain
            .iter()
            .zip(chain.iter().skip(1).chain(chain.iter().rev().take(1)))
        {
            let maybe_ca = self
                .root_ca_list
                .get(&cert1.tbs_certificate.issuer.to_der()?);

            let verifier = maybe_ca
                .map(|ca| {
                    let ca = Certificate::from_der(ca)?;

                    if let Some(time) = timestamp {
                        verify_time(&ca, time)?;
                    }

                    Ok::<_, X509Error>(ca)
                })
                .transpose()?;

            let verifier = verifier.as_ref().unwrap_or(cert2);
            verify_cert(verifier, cert1, timestamp)?;

            // If we found a CA, we're done with the chain.
            if maybe_ca.is_some() {
                let leaf_cert = chain.first().ok_or(X509Error::EmptyCertificateChain)?;

                let pub_key =
                    pub_key_from_spki(&leaf_cert.tbs_certificate.subject_public_key_info)?;

                let pub_signing_key = pub_key_to_uncompressed(&pub_key).map(Into::into)?;

                return Ok(pub_signing_key);
            }
        }

        Err(X509Error::CaNotFound)
    }
}

fn verify_time(cert: &Certificate, time: MlsTime) -> Result<(), X509Error> {
    let validity = cert.tbs_certificate.validity;
    let now = time.seconds_since_epoch();
    let not_before = validity.not_before.to_unix_duration().as_secs();
    let not_after = validity.not_after.to_unix_duration().as_secs();

    (not_before <= now && now <= not_after)
        .then_some(())
        .ok_or_else(|| X509Error::ValidityError(now, format!("{cert:?}")))
}

fn verify_cert(
    verifier: &Certificate,
    verified: &Certificate,
    timestamp: Option<MlsTime>,
) -> Result<(), X509Error> {
    // Re-encode the verified TBS struct to get the signed bytes
    let mut tbs = Vec::new();
    verified.tbs_certificate.encode_to_vec(&mut tbs)?;

    // Create a signer for the verifier
    let signer =
        signer_from_algorithm(&verifier.tbs_certificate.subject_public_key_info.algorithm)?;

    let pub_key = pub_key_from_spki(&verifier.tbs_certificate.subject_public_key_info)?;

    // Verify the signature
    signer.verify(
        &pub_key_to_uncompressed(&pub_key).map(Into::into)?,
        verified.signature.raw_bytes(),
        &tbs,
    )?;

    // Verify properties
    if let Some(time) = timestamp {
        verify_time(verified, time)?;
    }

    Ok(())
}

fn validate_self_signed(
    chain: &CertificateChain,
    timestamp: Option<MlsTime>,
) -> Result<SignaturePublicKey, X509Error> {
    if chain.len() != 1 {
        return Err(X509Error::SelfSignedWrongLength(chain.len()));
    }

    let cert = Certificate::from_der(&chain[0])?;

    verify_cert(&cert, &cert, timestamp)?;

    let pub_key = pub_key_from_spki(&cert.tbs_certificate.subject_public_key_info)?;

    let pub_signing_key = pub_key_to_uncompressed(&pub_key).map(Into::into)?;

    Ok(pub_signing_key)
}

impl X509CredentialValidator for X509Validator {
    type Error = X509Error;

    fn validate_chain(
        &self,
        chain: &aws_mls_identity_x509::CertificateChain,
        timestamp: Option<aws_mls_core::time::MlsTime>,
    ) -> Result<SignaturePublicKey, Self::Error> {
        if !self.allow_self_signed {
            self.validate_chain(chain, timestamp)
        } else {
            validate_self_signed(chain, timestamp)
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use assert_matches::assert_matches;
    use aws_mls_core::time::MlsTime;
    use aws_mls_identity_x509::{CertificateChain, X509CredentialValidator};
    use spki::der::Decode;
    use x509_cert::Certificate;

    use crate::{
        ec_signer::EcSignerError,
        x509::{
            util::test_utils::{
                load_another_ca, load_test_ca, load_test_cert_chain, load_test_invalid_ca_chain,
                load_test_invalid_chain,
            },
            X509Error,
        },
    };

    use super::X509Validator;

    #[test]
    fn can_validate_cert_chain() {
        let chain = load_test_cert_chain();

        let validator = X509Validator::new(vec![load_test_ca()]).unwrap();

        validator
            .validate_chain(&chain, Some(MlsTime::now()))
            .unwrap();
    }

    #[test]
    fn can_validate_cert_chain_without_ca() {
        let chain = load_test_cert_chain();
        let chain = chain[0..chain.len() - 1].to_vec().into();

        let validator = X509Validator::new(vec![load_test_ca()]).unwrap();

        validator
            .validate_chain(&chain, Some(MlsTime::now()))
            .unwrap();
    }

    #[test]
    fn can_validate_cert_chain_with_pinned() {
        let chain = load_test_cert_chain();

        let mut validator = X509Validator::new(vec![load_test_ca()]).unwrap();
        validator.set_pinned_cert(Some(chain.get(1).unwrap().clone()));

        validator
            .validate_chain(&chain, Some(MlsTime::now()))
            .unwrap();
    }

    #[test]
    fn can_validate_self_signed() {
        let mut validator = X509Validator::new(vec![]).unwrap();
        validator.allow_self_signed(true);

        let chain = vec![load_test_ca()].into();

        X509CredentialValidator::validate_chain(&validator, &chain, Some(MlsTime::now())).unwrap();
    }

    #[test]
    fn fails_on_too_long_self_signed() {
        let mut validator = X509Validator::new(vec![]).unwrap();
        validator.allow_self_signed(true);

        let chain = vec![load_test_ca(), load_another_ca()].into();

        let res = X509CredentialValidator::validate_chain(&validator, &chain, Some(MlsTime::now()));

        assert_matches!(res, Err(X509Error::SelfSignedWrongLength(2)))
    }

    #[test]
    fn fails_if_pinned_missing() {
        let chain = load_test_cert_chain();

        let mut validator = X509Validator::new(vec![load_test_ca()]).unwrap();
        validator.set_pinned_cert(Some(load_another_ca()));

        let res = validator.validate_chain(&chain, Some(MlsTime::now()));

        assert_matches!(res, Err(X509Error::PinnedCertNotFound));
    }

    #[test]
    fn can_detect_invalid_ca_certificates() {
        assert_matches!(
            X509Validator::new(vec![vec![0u8; 32].into()]),
            Err(X509Error::X509DerError(_))
        )
    }

    #[test]
    fn can_detect_ca_cert_with_invalid_self_signed_signature() {
        let test_cert = load_test_cert_chain()[0].clone();

        assert_matches!(
            X509Validator::new(vec![test_cert]),
            Err(X509Error::EcSignerError(EcSignerError::InvalidSignature))
        )
    }

    #[test]
    fn will_fail_on_empty_chain() {
        let validator = X509Validator::new(vec![]).unwrap();
        let empty: Vec<Vec<u8>> = Vec::new();

        let res = validator.validate_chain(&CertificateChain::from(empty), Some(MlsTime::now()));

        assert_matches!(res, Err(X509Error::EmptyCertificateChain));
    }

    #[test]
    fn will_fail_on_invalid_chain() {
        let chain = load_test_invalid_chain();
        let validator = X509Validator::new(vec![load_test_ca()]).unwrap();

        let res = validator.validate_chain(&chain, Some(MlsTime::now()));

        assert_matches!(
            res,
            Err(X509Error::EcSignerError(EcSignerError::InvalidSignature))
        );
    }

    #[test]
    fn will_fail_on_invalid_ca() {
        let chain = load_test_invalid_ca_chain();
        let validator = X509Validator::new(vec![load_another_ca()]).unwrap();
        let res = validator.validate_chain(&chain, Some(MlsTime::now()));

        assert_matches!(
            res,
            Err(X509Error::EcSignerError(EcSignerError::InvalidSignature))
        );
    }

    #[test]
    fn can_detect_expired_certs() {
        let chain = load_test_cert_chain();

        let validator = X509Validator::new(vec![load_test_ca()]).unwrap();

        let res = validator.validate_chain(
            &chain,
            Some(MlsTime::from_duration_since_epoch(Duration::from_secs(
                1798761600,
            ))),
        );

        assert_matches!(res, Err(X509Error::ValidityError(_, _)));
    }

    #[test]
    fn will_return_public_key_of_leaf() {
        let chain = load_test_cert_chain();

        let expected = Certificate::from_der(chain.leaf().unwrap())
            .unwrap()
            .tbs_certificate
            .subject_public_key_info
            .subject_public_key
            .raw_bytes()
            .to_vec()
            .into();

        let validator = X509Validator::new(vec![load_test_ca()]).unwrap();

        assert_eq!(validator.validate_chain(&chain, None).unwrap(), expected)
    }
}
