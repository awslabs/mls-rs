// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// Copyright by contributors to this project.
// SPDX-License-Identifier: (Apache-2.0 OR MIT)

use mls_rs_core::{crypto::SignaturePublicKey, time::MlsTime};
use mls_rs_identity_x509::{CertificateChain, DerCertificate, X509CredentialValidator};
use spki::der::{Decode, Encode};
use std::{
    collections::HashMap,
    fmt::{self, Debug},
};
use x509_cert::Certificate;

use crate::{
    ec::pub_key_to_uncompressed,
    ec_for_x509::{pub_key_from_spki, signer_from_algorithm},
};

use super::{util::verify_ca_extensions, X509Error};

#[derive(Clone)]
pub struct X509Validator {
    root_ca_list: HashMap<Vec<u8>, DerCertificate>,
    pinned_cert: Option<DerCertificate>,
    allow_self_signed: bool,
}

impl Debug for X509Validator {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("X509Validator")
            .field(
                "root_ca_list",
                &mls_rs_core::debug::pretty_with(|f| {
                    f.debug_map()
                        .entries(
                            self.root_ca_list
                                .iter()
                                .map(|(k, v)| (mls_rs_core::debug::pretty_bytes(k), v)),
                        )
                        .finish()
                }),
            )
            .field("pinned_cert", &self.pinned_cert)
            .field("allow_self_signed", &self.allow_self_signed)
            .finish()
    }
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

        for (j, (cert1, cert2)) in chain
            .iter()
            .zip(chain.iter().skip(1).chain(chain.iter().rev().take(1)))
            .enumerate()
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

            verify_ca_extensions(verifier, j)?;
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

fn verify_time(cert: &Certificate, timestamp: MlsTime) -> Result<(), X509Error> {
    let validity = cert.tbs_certificate.validity;
    let not_before = MlsTime::from(validity.not_before.to_unix_duration());
    let not_after = MlsTime::from(validity.not_after.to_unix_duration());

    if timestamp < not_before || timestamp > not_after {
        return Err(X509Error::ValidityError {
            timestamp,
            not_before,
            not_after,
        });
    }

    Ok(())
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
        chain: &mls_rs_identity_x509::CertificateChain,
        timestamp: Option<mls_rs_core::time::MlsTime>,
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
    use mls_rs_core::{
        crypto::{SignaturePublicKey, SignatureSecretKey},
        time::MlsTime,
    };
    use mls_rs_crypto_traits::Curve;
    use mls_rs_identity_x509::{CertificateChain, DerCertificate, X509CredentialValidator};
    use spki::{
        der::{
            asn1::{BitString, OctetString},
            oid::AssociatedOid,
            Decode, Encode,
        },
        AlgorithmIdentifier, SubjectPublicKeyInfo,
    };
    use x509_cert::ext::{
        pkix::{BasicConstraints, KeyUsage, KeyUsages},
        Extension,
    };
    use x509_cert::{name::Name, serial_number::SerialNumber, time::Validity, TbsCertificate};
    use x509_cert::{Certificate, Version};

    use crate::{
        ec::pub_key_from_uncompressed,
        ec_for_x509::{pub_key_to_spki, ED25519_OID},
        ec_signer::{EcSigner, EcSignerError},
        x509::{
            util::{
                basic_constraints, ca_key_usage,
                test_utils::{
                    load_another_ca, load_ca_missing_basic_constraints,
                    load_chain_violating_path_len_0, load_chain_with_ca_missing_basic_constraints,
                    load_chain_with_intermediate_missing_key_usage, load_root_ca_path_len_0,
                    load_test_ca, load_test_cert_chain, load_test_invalid_ca_chain,
                    load_test_invalid_chain, load_test_p384_ca,
                },
            },
            X509Error,
        },
    };

    use super::X509Validator;

    #[test]
    fn can_validate_cert_chain() {
        let chain = load_test_cert_chain();

        let validator = X509Validator::new(vec![load_test_ca()]).unwrap();

        // June 8, 2026 09:19:21 UTC
        let time = MlsTime::from_duration_since_epoch(Duration::from_secs(1780910361));

        validator.validate_chain(&chain, Some(time)).unwrap();
    }

    #[test]
    fn can_validate_cert_chain_without_ca() {
        let chain = load_test_cert_chain();
        let chain = chain[0..chain.len() - 1].to_vec().into();

        // June 8, 2026 09:19:21 UTC
        let time = MlsTime::from_duration_since_epoch(Duration::from_secs(1780910361));

        let validator = X509Validator::new(vec![load_test_ca()]).unwrap();
        validator.validate_chain(&chain, Some(time)).unwrap();
    }

    #[test]
    fn can_validate_cert_chain_with_pinned() {
        let chain = load_test_cert_chain();

        let mut validator = X509Validator::new(vec![load_test_ca()]).unwrap();
        validator.set_pinned_cert(Some(chain.get(1).unwrap().clone()));

        // June 8, 2026 09:19:21 UTC
        let time = MlsTime::from_duration_since_epoch(Duration::from_secs(1780910361));

        validator.validate_chain(&chain, Some(time)).unwrap();
    }

    #[test]
    fn can_validate_self_signed() {
        let mut validator = X509Validator::new(vec![]).unwrap();
        validator.allow_self_signed(true);

        let chain = vec![load_test_ca()].into();

        // June 8, 2026 09:19:21 UTC
        let time = MlsTime::from_duration_since_epoch(Duration::from_secs(1780910361));

        X509CredentialValidator::validate_chain(&validator, &chain, Some(time)).unwrap();
    }

    #[test]
    fn can_validate_p384_cert() {
        let mut validator = X509Validator::new(vec![]).unwrap();
        validator.allow_self_signed(true);

        let chain = vec![load_test_p384_ca()].into();

        // February 4, 2025 00:00:00 UTC
        let time = MlsTime::from_duration_since_epoch(Duration::from_secs(1738627200));

        X509CredentialValidator::validate_chain(&validator, &chain, Some(time)).unwrap();
    }

    #[test]
    fn fails_on_too_long_self_signed() {
        let mut validator = X509Validator::new(vec![]).unwrap();
        validator.allow_self_signed(true);

        let chain = vec![load_test_ca(), load_another_ca()].into();

        // June 8, 2026 09:19:21 UTC
        let time = MlsTime::from_duration_since_epoch(Duration::from_secs(1780910361));

        let res = X509CredentialValidator::validate_chain(&validator, &chain, Some(time));

        assert_matches!(res, Err(X509Error::SelfSignedWrongLength(2)))
    }

    #[test]
    fn fails_if_pinned_missing() {
        let chain = load_test_cert_chain();

        let mut validator = X509Validator::new(vec![load_test_ca()]).unwrap();
        validator.set_pinned_cert(Some(load_another_ca()));

        // June 8, 2026 09:19:21 UTC
        let time = MlsTime::from_duration_since_epoch(Duration::from_secs(1780910361));

        let res = validator.validate_chain(&chain, Some(time));

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

        // June 8, 2026 09:19:21 UTC
        let time = MlsTime::from_duration_since_epoch(Duration::from_secs(1780910361));

        let res = validator.validate_chain(&CertificateChain::from(empty), Some(time));

        assert_matches!(res, Err(X509Error::EmptyCertificateChain));
    }

    #[test]
    fn will_fail_on_invalid_chain() {
        let chain = load_test_invalid_chain();
        let validator = X509Validator::new(vec![load_another_ca()]).unwrap();

        // June 8, 2026 09:19:21 UTC
        let time = MlsTime::from_duration_since_epoch(Duration::from_secs(1780910361));

        let res = validator.validate_chain(&chain, Some(time));

        assert_matches!(
            res,
            Err(X509Error::EcSignerError(EcSignerError::EcError(_)))
        );
    }

    #[test]
    fn will_fail_on_invalid_ca() {
        let chain = load_test_invalid_ca_chain();
        let validator = X509Validator::new(vec![load_another_ca()]).unwrap();

        // June 8, 2026 09:19:21 UTC
        let time = MlsTime::from_duration_since_epoch(Duration::from_secs(1780910361));

        let res = validator.validate_chain(&chain, Some(time));

        assert_matches!(
            res,
            Err(X509Error::EcSignerError(EcSignerError::EcError(_)))
        );
    }

    #[test]
    fn can_detect_expired_certs() {
        let chain = load_test_cert_chain();

        let validator = X509Validator::new(vec![load_test_ca()]).unwrap();

        let res = validator.validate_chain(&chain, Some(MlsTime::from(7258118400)));

        let Err(X509Error::ValidityError {
            timestamp,
            not_before,
            not_after,
        }) = res
        else {
            panic!("Expected validity error, got: {res:?}");
        };
        assert_eq!(timestamp, MlsTime::from(7258118400));
        assert_eq!(not_before, MlsTime::from(1674656456));
        assert_eq!(not_after, MlsTime::from(4828256456));
    }

    /// A leaf issued directly by a root CA whose `BasicConstraints` has `cA=false` is rejected.
    #[test]
    fn leaf_issued_by_ca_missing_basic_constraints_is_rejected() {
        let chain = load_chain_with_ca_missing_basic_constraints();
        let validator = X509Validator::new(vec![load_ca_missing_basic_constraints()]).unwrap();

        let result = validator.validate_chain(&chain, None);

        assert_matches!(result, Err(X509Error::InvalidCaExtensions));
    }

    /// An intermediate CA with `cA=true` and a `KeyUsage` extension present but without
    /// `keyCertSign` set is rejected when used to verify the certificate below it. (A CA with
    /// no `KeyUsage` extension at all would NOT be rejected, per RFC 5280 §6.1.4(n).)
    #[test]
    fn intermediate_missing_key_usage_is_rejected() {
        let chain = load_chain_with_intermediate_missing_key_usage();
        let validator = X509Validator::new(vec![load_test_ca()]).unwrap();

        let result = validator.validate_chain(&chain, None);

        assert_matches!(result, Err(X509Error::InvalidCaExtensions));
    }

    /// An intermediate CA with `cA=true` and no `KeyUsage` extension at all (as opposed to one
    /// present without `keyCertSign`) is NOT rejected, per RFC 5280 §6.1.4(n) ("if a key usage
    /// extension is present, verify..."), matching OpenSSL's `X509_check_purpose` behavior.
    #[test]
    fn intermediate_with_no_key_usage_extension_at_all_succeeds() {
        let signer = EcSigner::new_from_curve(Curve::Ed25519);
        let algorithm = AlgorithmIdentifier {
            oid: ED25519_OID,
            parameters: None,
        };

        fn ca_name(label: &str) -> Name {
            crate::x509::util::build_x509_name(&[
                mls_rs_identity_x509::SubjectComponent::CommonName(label.to_string()),
            ])
            .unwrap()
        }

        struct SignerContext<'a> {
            signer: &'a EcSigner,
            algorithm: &'a AlgorithmIdentifier<x509_cert::der::Any>,
        }

        fn build_signed_cert(
            ctx: &SignerContext,
            serial: u64,
            issuer: &Name,
            issuer_secret: &SignatureSecretKey,
            subject: Name,
            subject_public: &SignaturePublicKey,
            extensions: Option<Vec<Extension>>,
        ) -> Certificate {
            let ec_pub = pub_key_from_uncompressed(subject_public, **ctx.signer).unwrap();
            let der_pub = pub_key_to_spki(&ec_pub).unwrap();
            let spki = SubjectPublicKeyInfo::from_der(&der_pub).unwrap();

            let tbs = TbsCertificate {
                version: Version::V3,
                serial_number: SerialNumber::from(serial),
                signature: ctx.algorithm.clone(),
                issuer: issuer.clone(),
                validity: Validity::from_now(Duration::from_secs(3600)).unwrap(),
                subject,
                subject_public_key_info: spki,
                issuer_unique_id: None,
                subject_unique_id: None,
                extensions,
            };

            let tbs_der = tbs.to_der().unwrap();
            let signature_bytes = ctx.signer.sign(issuer_secret, &tbs_der).unwrap();
            let signature = BitString::from_bytes(&signature_bytes).unwrap();

            Certificate {
                tbs_certificate: tbs,
                signature_algorithm: ctx.algorithm.clone(),
                signature,
            }
        }

        let ctx = SignerContext {
            signer: &signer,
            algorithm: &algorithm,
        };

        // Root: self-signed CA, correctly extended (cA=true, keyCertSign set).
        let (root_secret, root_public) = signer.signature_key_generate().unwrap();
        let root_name = ca_name("NoKeyUsage Root");
        let root_cert = build_signed_cert(
            &ctx,
            0,
            &root_name,
            &root_secret,
            root_name.clone(),
            &root_public,
            Some(vec![
                basic_constraints(true).unwrap(),
                ca_key_usage().unwrap(),
            ]),
        );

        // Intermediate: cA=true, but NO KeyUsage extension at all.
        let (intermediate_secret, intermediate_public) = signer.signature_key_generate().unwrap();
        let intermediate_name = ca_name("NoKeyUsage Intermediate");
        let intermediate_cert = build_signed_cert(
            &ctx,
            1,
            &root_name,
            &root_secret,
            intermediate_name.clone(),
            &intermediate_public,
            Some(vec![basic_constraints(true).unwrap()]),
        );

        // Leaf: never acts as a verifier, so it carries no extensions.
        let (_leaf_secret, leaf_public) = signer.signature_key_generate().unwrap();
        let leaf_name = ca_name("NoKeyUsage Leaf");
        let leaf_cert = build_signed_cert(
            &ctx,
            2,
            &intermediate_name,
            &intermediate_secret,
            leaf_name,
            &leaf_public,
            None,
        );

        let root_der = DerCertificate::from(root_cert.to_der().unwrap());
        let chain = CertificateChain::from_iter(
            [leaf_cert, intermediate_cert]
                .into_iter()
                .map(|cert| DerCertificate::from(cert.to_der().unwrap())),
        );

        let validator = X509Validator::new(vec![root_der]).unwrap();

        let result = validator.validate_chain(&chain, None);

        assert_matches!(
            result,
            Ok(_),
            "expected an intermediate CA with cA=true and no KeyUsage extension at all to \
             succeed, got {result:?}"
        );
    }

    /// A root CA with `path_len_constraint = Some(0)` is rejected when the presented chain has
    /// an intermediate CA between the root and the leaf, violating the constraint.
    #[test]
    fn path_len_constraint_violation_is_rejected() {
        let chain = load_chain_violating_path_len_0();
        let validator = X509Validator::new(vec![load_root_ca_path_len_0()]).unwrap();

        let result = validator.validate_chain(&chain, None);

        assert_matches!(
            result,
            Err(X509Error::PathLenConstraintExceeded {
                path_len_constraint: 0,
                subordinate_ca_count: 1,
            })
        );
    }

    /// Builds a well-formed, leaf-first chain of `depth` CA certificates (root plus
    /// `depth - 1` intermediates), all correctly extended, with an unextended leaf on top.
    /// Returns `(chain, root_certificate)`.
    fn build_well_formed_chain(depth: usize) -> (CertificateChain, DerCertificate) {
        assert!((1..=5).contains(&depth), "depth must be in 1..=5");

        let signer = EcSigner::new_from_curve(Curve::Ed25519);
        let algorithm = AlgorithmIdentifier {
            oid: ED25519_OID,
            parameters: None,
        };

        fn ca_name(label: &str) -> Name {
            crate::x509::util::build_x509_name(&[
                mls_rs_identity_x509::SubjectComponent::CommonName(label.to_string()),
            ])
            .unwrap()
        }

        struct SignerContext<'a> {
            signer: &'a EcSigner,
            algorithm: &'a AlgorithmIdentifier<x509_cert::der::Any>,
        }

        fn build_signed_cert(
            ctx: &SignerContext,
            serial: u64,
            issuer: &Name,
            issuer_secret: &SignatureSecretKey,
            subject: Name,
            subject_public: &SignaturePublicKey,
            extensions: Option<Vec<Extension>>,
        ) -> Certificate {
            let ec_pub = pub_key_from_uncompressed(subject_public, **ctx.signer).unwrap();
            let der_pub = pub_key_to_spki(&ec_pub).unwrap();
            let spki = SubjectPublicKeyInfo::from_der(&der_pub).unwrap();

            let tbs = TbsCertificate {
                version: Version::V3,
                serial_number: SerialNumber::from(serial),
                signature: ctx.algorithm.clone(),
                issuer: issuer.clone(),
                validity: Validity::from_now(Duration::from_secs(3600)).unwrap(),
                subject,
                subject_public_key_info: spki,
                issuer_unique_id: None,
                subject_unique_id: None,
                extensions,
            };

            let tbs_der = tbs.to_der().unwrap();
            let signature_bytes = ctx.signer.sign(issuer_secret, &tbs_der).unwrap();
            let signature = BitString::from_bytes(&signature_bytes).unwrap();

            Certificate {
                tbs_certificate: tbs,
                signature_algorithm: ctx.algorithm.clone(),
                signature,
            }
        }

        let ctx = SignerContext {
            signer: &signer,
            algorithm: &algorithm,
        };

        let ca_extensions = || vec![basic_constraints(true).unwrap(), ca_key_usage().unwrap()];

        // Root: self-signed CA.
        let (root_secret, root_public) = signer.signature_key_generate().unwrap();
        let root_name = ca_name("PBT Root");
        let root_cert = build_signed_cert(
            &ctx,
            0,
            &root_name,
            &root_secret,
            root_name.clone(),
            &root_public,
            Some(ca_extensions()),
        );

        // Chain built root-to-leaf, then reversed to the leaf-first order `validate_chain`
        // expects.
        let mut certs_root_to_leaf = vec![root_cert.clone()];
        let mut issuer_name = root_name;
        let mut issuer_secret = root_secret;

        for i in 1..depth {
            let (secret, public) = signer.signature_key_generate().unwrap();
            let subject_name = ca_name(&format!("PBT Intermediate {i}"));

            let cert = build_signed_cert(
                &ctx,
                i as u64,
                &issuer_name,
                &issuer_secret,
                subject_name.clone(),
                &public,
                Some(ca_extensions()),
            );

            certs_root_to_leaf.push(cert);
            issuer_name = subject_name;
            issuer_secret = secret;
        }

        // Leaf: never acts as a verifier, so it carries no CA extensions at all.
        let (_leaf_secret, leaf_public) = signer.signature_key_generate().unwrap();
        let leaf_name = ca_name("PBT Leaf");
        let leaf_cert = build_signed_cert(
            &ctx,
            depth as u64,
            &issuer_name,
            &issuer_secret,
            leaf_name,
            &leaf_public,
            None,
        );
        certs_root_to_leaf.push(leaf_cert);

        certs_root_to_leaf.reverse();

        let root_der = DerCertificate::from(root_cert.to_der().unwrap());
        let chain = CertificateChain::from_iter(
            certs_root_to_leaf
                .into_iter()
                .map(|cert| DerCertificate::from(cert.to_der().unwrap())),
        );

        (chain, root_der)
    }

    /// Like [`build_well_formed_chain`], but the root's `path_len_constraint` is set explicitly.
    fn build_chain_with_root_path_len_constraint(
        depth: usize,
        root_path_len_constraint: Option<u8>,
    ) -> (CertificateChain, DerCertificate) {
        assert!((1..=5).contains(&depth), "depth must be in 1..=5");

        let signer = EcSigner::new_from_curve(Curve::Ed25519);
        let algorithm = AlgorithmIdentifier {
            oid: ED25519_OID,
            parameters: None,
        };

        fn ca_name(label: &str) -> Name {
            crate::x509::util::build_x509_name(&[
                mls_rs_identity_x509::SubjectComponent::CommonName(label.to_string()),
            ])
            .unwrap()
        }

        struct SignerContext<'a> {
            signer: &'a EcSigner,
            algorithm: &'a AlgorithmIdentifier<x509_cert::der::Any>,
        }

        fn build_signed_cert(
            ctx: &SignerContext,
            serial: u64,
            issuer: &Name,
            issuer_secret: &SignatureSecretKey,
            subject: Name,
            subject_public: &SignaturePublicKey,
            extensions: Option<Vec<Extension>>,
        ) -> Certificate {
            let ec_pub = pub_key_from_uncompressed(subject_public, **ctx.signer).unwrap();
            let der_pub = pub_key_to_spki(&ec_pub).unwrap();
            let spki = SubjectPublicKeyInfo::from_der(&der_pub).unwrap();

            let tbs = TbsCertificate {
                version: Version::V3,
                serial_number: SerialNumber::from(serial),
                signature: ctx.algorithm.clone(),
                issuer: issuer.clone(),
                validity: Validity::from_now(Duration::from_secs(3600)).unwrap(),
                subject,
                subject_public_key_info: spki,
                issuer_unique_id: None,
                subject_unique_id: None,
                extensions,
            };

            let tbs_der = tbs.to_der().unwrap();
            let signature_bytes = ctx.signer.sign(issuer_secret, &tbs_der).unwrap();
            let signature = BitString::from_bytes(&signature_bytes).unwrap();

            Certificate {
                tbs_certificate: tbs,
                signature_algorithm: ctx.algorithm.clone(),
                signature,
            }
        }

        fn basic_constraints_with_path_len(path_len_constraint: Option<u8>) -> Extension {
            let basic_constraints = BasicConstraints {
                ca: true,
                path_len_constraint,
            };

            Extension {
                extn_id: BasicConstraints::OID,
                critical: true,
                extn_value: OctetString::new(basic_constraints.to_der().unwrap()).unwrap(),
            }
        }

        fn root_key_usage() -> Extension {
            Extension {
                extn_id: KeyUsage::OID,
                critical: true,
                extn_value: OctetString::new(
                    KeyUsage(KeyUsages::KeyCertSign | KeyUsages::CRLSign)
                        .to_der()
                        .unwrap(),
                )
                .unwrap(),
            }
        }

        let ctx = SignerContext {
            signer: &signer,
            algorithm: &algorithm,
        };

        let root_extensions = vec![
            basic_constraints_with_path_len(root_path_len_constraint),
            root_key_usage(),
        ];
        let intermediate_extensions =
            || vec![basic_constraints(true).unwrap(), ca_key_usage().unwrap()];

        // Root: self-signed CA with the requested path_len_constraint.
        let (root_secret, root_public) = signer.signature_key_generate().unwrap();
        let root_name = ca_name("PathLen Root");
        let root_cert = build_signed_cert(
            &ctx,
            0,
            &root_name,
            &root_secret,
            root_name.clone(),
            &root_public,
            Some(root_extensions),
        );

        let mut certs_root_to_leaf = vec![root_cert.clone()];
        let mut issuer_name = root_name;
        let mut issuer_secret = root_secret;

        for i in 1..depth {
            let (secret, public) = signer.signature_key_generate().unwrap();
            let subject_name = ca_name(&format!("PathLen Intermediate {i}"));

            let cert = build_signed_cert(
                &ctx,
                i as u64,
                &issuer_name,
                &issuer_secret,
                subject_name.clone(),
                &public,
                Some(intermediate_extensions()),
            );

            certs_root_to_leaf.push(cert);
            issuer_name = subject_name;
            issuer_secret = secret;
        }

        // Leaf: never acts as a verifier, so it carries no CA extensions at all.
        let (_leaf_secret, leaf_public) = signer.signature_key_generate().unwrap();
        let leaf_name = ca_name("PathLen Leaf");
        let leaf_cert = build_signed_cert(
            &ctx,
            depth as u64,
            &issuer_name,
            &issuer_secret,
            leaf_name,
            &leaf_public,
            None,
        );
        certs_root_to_leaf.push(leaf_cert);

        certs_root_to_leaf.reverse();

        let root_der = DerCertificate::from(root_cert.to_der().unwrap());
        let chain = CertificateChain::from_iter(
            certs_root_to_leaf
                .into_iter()
                .map(|cert| DerCertificate::from(cert.to_der().unwrap())),
        );

        (chain, root_der)
    }

    /// The well-formed-chain generator itself produces a chain that validates successfully
    /// (two intermediate CAs between the leaf and the self-signed root).
    #[test]
    fn well_formed_generated_chain_validates_successfully() {
        let (chain, root) = build_well_formed_chain(3);
        let validator = X509Validator::new(vec![root]).unwrap();

        assert_matches!(validator.validate_chain(&chain, None), Ok(_));
    }

    /// Boundary case: `path_len_constraint = Some(1)` with exactly one subordinate CA succeeds.
    #[test]
    fn path_len_constraint_one_with_exactly_one_subordinate_ca_succeeds() {
        let (chain, root) = build_chain_with_root_path_len_constraint(2, Some(1));
        let validator = X509Validator::new(vec![root]).unwrap();

        validator.validate_chain(&chain, None).unwrap();
    }

    /// Unbounded case: `path_len_constraint = None` with several subordinate CAs succeeds.
    #[test]
    fn path_len_constraint_none_with_many_subordinate_cas_succeeds() {
        // depth 5 => root + 3 intermediates + leaf => 4 subordinate CAs below the root.
        let (chain, root) = build_chain_with_root_path_len_constraint(5, None);
        let validator = X509Validator::new(vec![root]).unwrap();

        validator.validate_chain(&chain, None).unwrap();
    }

    /// A leaf certificate with no CA extensions at all, never acting as a verifier, is exempt
    /// from the CA extension checks and validates successfully.
    #[test]
    fn leaf_with_no_ca_extensions_never_acting_as_verifier_succeeds() {
        // depth 1 => leaf is issued directly by the self-signed root, with no intermediates, so
        // the leaf never certifies another certificate and is never itself checked for CA
        // extensions.
        let (chain, root) = build_well_formed_chain(1);
        assert_eq!(chain.len(), 2, "expected [leaf, root]");

        let leaf = Certificate::from_der(chain.leaf().unwrap()).unwrap();
        assert!(
            leaf.tbs_certificate.extensions.is_none()
                || leaf.tbs_certificate.extensions.as_ref().unwrap().is_empty(),
        );

        let validator = X509Validator::new(vec![root]).unwrap();

        validator.validate_chain(&chain, None).unwrap();
    }

    /// Any well-formed chain (every CA correctly extended, no path_len_constraint to violate)
    /// of depth 1..=5 validates successfully.
    #[test]
    fn well_formed_chains_of_varying_depth_validate_successfully() {
        for depth in 1..=5usize {
            let (chain, root) = build_well_formed_chain(depth);
            let validator = X509Validator::new(vec![root]).unwrap();

            validator.validate_chain(&chain, None).unwrap();
        }
    }

    // The tests below call `X509CredentialValidator::validate_chain(&validator, ..)` explicitly
    // to guarantee dispatch through the trait method (the private inherent method of the same
    // name would otherwise take priority under normal method resolution).

    /// A chain with a malformed intermediate CA is rejected through the public trait method.
    #[test]
    fn public_trait_rejects_malformed_intermediate_ca() {
        let chain = load_chain_with_intermediate_missing_key_usage();
        let validator = X509Validator::new(vec![load_test_ca()]).unwrap();

        let result = X509CredentialValidator::validate_chain(&validator, &chain, None);

        assert_matches!(result, Err(X509Error::InvalidCaExtensions));
    }

    /// A well-formed multi-level chain validates successfully through the public trait method.
    #[test]
    fn public_trait_accepts_well_formed_multilevel_chain() {
        let (chain, root) = build_well_formed_chain(3);
        let validator = X509Validator::new(vec![root]).unwrap();

        X509CredentialValidator::validate_chain(&validator, &chain, None).unwrap();
    }

    /// The `allow_self_signed` branch never calls `verify_ca_extensions`, so a self-signed
    /// certificate with no CA extensions at all still validates successfully.
    #[test]
    fn public_trait_self_signed_ignores_missing_ca_extensions() {
        let signer = EcSigner::new_from_curve(Curve::Ed25519);
        let algorithm = AlgorithmIdentifier {
            oid: ED25519_OID,
            parameters: None,
        };

        let (secret, public) = signer.signature_key_generate().unwrap();
        let name = crate::x509::util::build_x509_name(&[
            mls_rs_identity_x509::SubjectComponent::CommonName(
                "Self-Signed No CA Extensions".to_string(),
            ),
        ])
        .unwrap();

        let ec_pub = pub_key_from_uncompressed(&public, *signer).unwrap();
        let der_pub = pub_key_to_spki(&ec_pub).unwrap();
        let spki = SubjectPublicKeyInfo::from_der(&der_pub).unwrap();

        let tbs = TbsCertificate {
            version: Version::V3,
            serial_number: SerialNumber::from(1u64),
            signature: algorithm.clone(),
            issuer: name.clone(),
            validity: Validity::from_now(Duration::from_secs(3600)).unwrap(),
            subject: name,
            subject_public_key_info: spki,
            issuer_unique_id: None,
            subject_unique_id: None,
            extensions: None,
        };

        let tbs_der = tbs.to_der().unwrap();
        let signature_bytes = signer.sign(&secret, &tbs_der).unwrap();
        let signature = BitString::from_bytes(&signature_bytes).unwrap();

        let cert = Certificate {
            tbs_certificate: tbs,
            signature_algorithm: algorithm,
            signature,
        };

        let chain: CertificateChain = vec![DerCertificate::from(cert.to_der().unwrap())].into();

        let mut validator = X509Validator::new(vec![]).unwrap();
        validator.allow_self_signed(true);

        X509CredentialValidator::validate_chain(&validator, &chain, None).unwrap();
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

        // June 8, 2026 09:19:21 UTC
        let time = MlsTime::from_duration_since_epoch(Duration::from_secs(1780910361));

        assert_eq!(
            validator.validate_chain(&chain, Some(time)).unwrap(),
            expected
        )
    }
}
