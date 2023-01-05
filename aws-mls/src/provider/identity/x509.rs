use aws_mls_crypto_ferriscrypt::ferriscrypt::asym::ec_key::{self, Curve, EcKeyError};
use aws_mls_crypto_ferriscrypt::ferriscrypt::digest::digest;
use aws_mls_crypto_ferriscrypt::ferriscrypt::digest::HashFunction::Sha256;
use der::{Decode, Encode};
use std::collections::HashSet;
use thiserror::Error;
use x509_cert::certificate::Certificate;

use crate::cipher_suite::CipherSuite;
use crate::group::{Member, RosterUpdate};
use crate::identity::SigningIdentity;
use crate::identity::{
    CertificateData, CredentialError, MlsCredential, X509Credential, CREDENTIAL_TYPE_X509,
};
use crate::provider::identity::IdentityProvider;
use crate::time::{MlsTime, SystemTimeError};

#[derive(Debug, Error)]
pub enum X509Error {
    #[error("error parsing DER certificate: {0}")]
    CertificateParseError(der::Error),
    #[error("empty certificate chain (it must contain the CA)")]
    EmptyCertificateChain,
    #[error(transparent)]
    EcKeyError(#[from] EcKeyError),
    #[error(transparent)]
    DerError(#[from] x509_cert::der::Error),
    #[error("validating a certificate type that is not X.509")]
    NotX509Certificate,
    #[error("signature invalid for parent certificate {0} and child certificate {1}")]
    InvalidSignature(String, String),
    #[error("no trusted CA certificate found in the chain")]
    CaNotFound,
    #[error("unsupported algorithm with OID {0} for curve {1:?}; the following hash algorithms are supported:
        SHA256 for curve P256, SHA384 for curve P384, SHA512 for curve P521")]
    UnsupportedHash(String, Curve),
    #[error("unsupported algorithm with OID {0}; only EC algorithms are supported")]
    UnsupportedAlgorithm(String),
    #[error("leaf public key does not match signing identity public key")]
    LeafPublicKeyMismatch,
    #[error("leaf public key curve {0:?} does not match the curve MLS ciphersuite {1:?}")]
    CurveMismatch(Curve, Curve),
    #[error(transparent)]
    CredentialError(#[from] CredentialError),
    #[error("identity extractor error: {0:?}")]
    IdentityError(#[source] Box<dyn std::error::Error + Send + Sync>),
    #[error("self-signed certificate provided as chain of length {0} but it must have length 1")]
    SelfSignedWrongLength(usize),
    #[error("pinned certificate not found in the chain")]
    PinnedCertNotFound,
    #[error(transparent)]
    SystemTimeError(#[from] SystemTimeError),
    #[error("Current (commit) timestamp {0} outside of the validity period of certificate {1}")]
    ValidityError(u64, String),
}

#[derive(Clone, Debug, Default)]
pub struct BasicX509Provider<I: X509IdentityExtractor> {
    ca_certs: HashSet<Vec<u8>>,
    id_extractor: I,
    allow_self_signed: bool,
    pinned_cert: Option<CertificateData>,
}

pub trait X509IdentityExtractor {
    type Error: std::error::Error + Send + Sync + 'static;
    type IdentityEvent;

    fn identity(&self, cert_chain: &[Certificate]) -> Result<Vec<u8>, Self::Error>;

    fn valid_successor(
        &self,
        predecessor: &[Certificate],
        successor: &[Certificate],
    ) -> Result<bool, Self::Error>;

    fn identity_events(
        &self,
        update: &RosterUpdate,
        prior_roster: Vec<Member>,
    ) -> Result<Vec<Self::IdentityEvent>, Self::Error>;
}

impl<I: X509IdentityExtractor> BasicX509Provider<I> {
    pub fn new(ca_certs: Vec<&[u8]>, id_generator: I) -> Result<Self, X509Error> {
        let ca_certs = ca_certs
            .into_iter()
            .map(|cert_data| {
                // Verify the self-signture
                let cert =
                    Certificate::from_der(cert_data).map_err(X509Error::CertificateParseError)?;

                // Time is validated when CAs are used
                verify_cert(&cert, &cert, None)?;

                Ok(hash_cert(cert_data))
            })
            .collect::<Result<_, X509Error>>()?;

        Ok(Self {
            ca_certs,
            id_extractor: id_generator,
            allow_self_signed: false,
            pinned_cert: None,
        })
    }

    pub fn set_pinned_cert(&mut self, pinned_cert: Option<CertificateData>) {
        self.pinned_cert = pinned_cert;
    }

    /// This MUST be used only in tests. DO NOT use in production.
    pub fn allow_self_signed(&mut self, allow: bool) {
        self.allow_self_signed = allow;
    }

    fn validate_chain(
        &self,
        signing_identity: &SigningIdentity,
        cipher_suite: CipherSuite,
        timestamp: Option<MlsTime>,
    ) -> Result<(), X509Error> {
        let x509_cred = X509Credential::from_credential(&signing_identity.credential)?;
        let chain = x509_cred.credential;

        if !self.ca_certs.contains(&hash_cert(
            chain.ca().ok_or(X509Error::EmptyCertificateChain)?,
        )) {
            return Err(X509Error::CaNotFound);
        }

        if let Some(pinned_cert) = self.pinned_cert.as_ref() {
            chain
                .contains(pinned_cert)
                .then_some(())
                .ok_or(X509Error::PinnedCertNotFound)?;
        }

        let chain = chain
            .iter()
            .map(|cert_data| Certificate::from_der(cert_data))
            .collect::<Result<Vec<_>, _>>()
            .map_err(X509Error::CertificateParseError)?;

        if let Some(time) = timestamp {
            let ca = chain.last().ok_or(X509Error::EmptyCertificateChain)?;
            verify_time(ca, time)?;
        }

        let leaf_pk = get_public_key(&chain[0])?;

        if leaf_pk.to_uncompressed_bytes()? != *signing_identity.signature_key {
            return Err(X509Error::LeafPublicKeyMismatch);
        }

        if leaf_pk.curve() != signature_key_curve(cipher_suite) {
            return Err(X509Error::CurveMismatch(
                leaf_pk.curve(),
                signature_key_curve(cipher_suite),
            ));
        }

        chain
            .iter()
            .zip(chain.iter().skip(1))
            .try_for_each(|(cert1, cert2)| verify_cert(cert2, cert1, timestamp))
    }
}

fn signature_key_curve(cipher_suite: CipherSuite) -> Curve {
    match cipher_suite {
        CipherSuite::Curve25519Aes128 => Curve::Ed25519,
        CipherSuite::P256Aes128 => Curve::P256,
        CipherSuite::Curve25519ChaCha20 => Curve::Ed25519,
        #[cfg(feature = "openssl_engine")]
        CipherSuite::Curve448Aes256 => Curve::Ed448,
        #[cfg(feature = "openssl_engine")]
        CipherSuite::P521Aes256 => Curve::P521,
        #[cfg(feature = "openssl_engine")]
        CipherSuite::Curve448ChaCha20 => Curve::Ed448,
        #[cfg(feature = "openssl_engine")]
        CipherSuite::P384Aes256 => Curve::P384,
    }
}

impl<IE: X509IdentityExtractor> IdentityProvider for BasicX509Provider<IE> {
    type Error = X509Error;
    type IdentityEvent = IE::IdentityEvent;

    fn validate(
        &self,
        signing_identity: &SigningIdentity,
        cipher_suite: CipherSuite,
        timestamp: Option<MlsTime>,
    ) -> Result<(), Self::Error> {
        if !self.allow_self_signed {
            self.validate_chain(signing_identity, cipher_suite, timestamp)
        } else {
            validate_self_signed(signing_identity, cipher_suite, timestamp)
        }
    }

    fn identity(&self, signing_id: &SigningIdentity) -> Result<Vec<u8>, Self::Error> {
        let x509_cred = X509Credential::from_credential(&signing_id.credential)?;

        self.id_extractor
            .identity(&x509_cred.credential.parse()?)
            .map_err(|e| X509Error::IdentityError(e.into()))
    }

    fn valid_successor(
        &self,
        predecessor: &SigningIdentity,
        successor: &SigningIdentity,
    ) -> Result<bool, Self::Error> {
        let predecessor_cred = X509Credential::from_credential(&predecessor.credential)?;
        let predecessor_certs = predecessor_cred.credential.parse()?;

        let successor_cred = X509Credential::from_credential(&successor.credential)?;
        let successor_certs = successor_cred.credential.parse()?;

        self.id_extractor
            .valid_successor(&predecessor_certs, &successor_certs)
            .map_err(|e| X509Error::IdentityError(e.into()))
    }

    fn supported_types(&self) -> Vec<crate::identity::CredentialType> {
        vec![CREDENTIAL_TYPE_X509]
    }

    fn identity_events(
        &self,
        update: &RosterUpdate,
        prior_roster: Vec<Member>,
    ) -> Result<Vec<Self::IdentityEvent>, Self::Error> {
        self.id_extractor
            .identity_events(update, prior_roster)
            .map_err(|e| X509Error::IdentityError(e.into()))
    }
}

fn verify_cert(
    verifier: &Certificate,
    verified: &Certificate,
    current_time: Option<MlsTime>,
) -> Result<(), X509Error> {
    // Check that we support the signing algorithm
    check_algorithm_supported(verified)?;

    let public_key = get_public_key(verifier)?;

    // Check that we support the combination of the public key curve and hash algorithm used to signed `verified`
    check_hash_supported(verified, &public_key)?;

    // Re-encode the verified TBS struct to get the signed bytes
    let mut tbs = Vec::new();

    verified
        .tbs_certificate
        .encode_to_vec(&mut tbs)
        .map_err(X509Error::CertificateParseError)?;

    // Verify the signature
    public_key
        .verify(verified.signature.raw_bytes(), &tbs)?
        .then_some(())
        .ok_or_else(|| {
            X509Error::InvalidSignature(format!("{:?}", verifier), format!("{:?}", verified))
        })?;

    // Verify properties
    if let Some(time) = current_time {
        verify_time(verified, time)?;
    }

    Ok(())
}

fn verify_time(cert: &Certificate, time: MlsTime) -> Result<(), X509Error> {
    let validity = cert.tbs_certificate.validity;
    let now = time.seconds_since_epoch()?;
    let not_before = validity.not_before.to_unix_duration().as_secs();
    let not_after = validity.not_after.to_unix_duration().as_secs();

    (not_before <= now && now <= not_after)
        .then_some(())
        .ok_or_else(|| X509Error::ValidityError(now, format!("{:?}", cert)))
}

fn hash_cert(cert_data: &[u8]) -> Vec<u8> {
    digest(Sha256, cert_data)
}

pub(crate) fn get_public_key(cert: &Certificate) -> Result<ec_key::PublicKey, X509Error> {
    // Re-encode the `subject_public_key_info` (containing the key bytes and the algorithm) to get the public key.
    let key_der = cert
        .tbs_certificate
        .subject_public_key_info
        .to_vec()
        .map_err(X509Error::CertificateParseError)?;

    ec_key::PublicKey::from_der(&key_der).map_err(Into::into)
}

// OID codes from https://www.rfc-editor.org/rfc/rfc5758#section-3.2 and https://www.rfc-editor.org/rfc/rfc8410.html#section-3
fn check_algorithm_supported(cert: &Certificate) -> Result<(), X509Error> {
    let algorithm = cert.signature_algorithm.oid.to_string();

    [
        "1.2.840.10045.4.3.2",
        "1.2.840.10045.4.3.3",
        "1.2.840.10045.4.3.4",
        "1.3.101.112",
        "1.3.101.113",
    ]
    .contains(&algorithm.as_str())
    .then_some(())
    .ok_or(X509Error::UnsupportedAlgorithm(algorithm))
}

// OID codes from https://www.rfc-editor.org/rfc/rfc5758#section-3.2
fn check_hash_supported(
    cert: &Certificate,
    public_key: &ec_key::PublicKey,
) -> Result<(), X509Error> {
    let algorithm = cert.signature_algorithm.oid.to_string();

    let valid = match public_key.curve() {
        ec_key::Curve::P256 => algorithm == "1.2.840.10045.4.3.2",
        #[cfg(feature = "openssl_engine")]
        ec_key::Curve::P384 => algorithm == "1.2.840.10045.4.3.3",
        #[cfg(feature = "openssl_engine")]
        ec_key::Curve::P521 => algorithm == "1.2.840.10045.4.3.4",
        _ => true,
    };

    valid
        .then_some(())
        .ok_or_else(|| X509Error::UnsupportedHash(algorithm, public_key.curve()))
}

fn validate_self_signed(
    signing_identity: &SigningIdentity,
    cipher_suite: CipherSuite,
    timestamp: Option<MlsTime>,
) -> Result<(), X509Error> {
    let chain = X509Credential::from_credential(&signing_identity.credential)?.credential;

    if chain.len() != 1 {
        return Err(X509Error::SelfSignedWrongLength(chain.len()));
    }

    let leaf_cert = Certificate::from_der(&chain[0]).map_err(X509Error::CertificateParseError)?;
    let leaf_pk = get_public_key(&leaf_cert)?;

    if leaf_pk.to_uncompressed_bytes()? != *signing_identity.signature_key {
        return Err(X509Error::LeafPublicKeyMismatch);
    }

    if leaf_pk.curve() != signature_key_curve(cipher_suite) {
        return Err(X509Error::CurveMismatch(
            leaf_pk.curve(),
            signature_key_curve(cipher_suite),
        ));
    }

    verify_cert(&leaf_cert, &leaf_cert, timestamp)
}

#[cfg(any(test, feature = "benchmark"))]
pub(crate) mod test_utils {
    use crate::group::{Member, RosterUpdate};

    use super::{Certificate, X509Error, X509IdentityExtractor};

    #[derive(Clone, Debug)]
    pub struct TestIdGenerator {}

    impl X509IdentityExtractor for TestIdGenerator {
        type Error = X509Error;
        type IdentityEvent = ();

        fn identity(&self, chain: &[Certificate]) -> Result<Vec<u8>, X509Error> {
            Ok(chain
                .get(0)
                .ok_or(X509Error::EmptyCertificateChain)?
                .tbs_certificate
                .subject_public_key_info
                .subject_public_key
                .to_vec())
        }

        fn valid_successor(
            &self,
            predecessor: &[Certificate],
            successor: &[Certificate],
        ) -> Result<bool, Self::Error> {
            use der::Encode;

            let id1 = predecessor
                .get(0)
                .ok_or(X509Error::EmptyCertificateChain)?
                .tbs_certificate
                .to_vec()
                .map_err(X509Error::CertificateParseError)?;

            let id2 = successor
                .get(0)
                .ok_or(X509Error::EmptyCertificateChain)?
                .tbs_certificate
                .to_vec()
                .map_err(X509Error::CertificateParseError)?;

            Ok(id1 == id2)
        }

        fn identity_events(
            &self,
            _update: &RosterUpdate,
            _prior_roster: Vec<Member>,
        ) -> Result<Vec<Self::IdentityEvent>, Self::Error> {
            Ok(vec![])
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use crate::{
        identity::{
            test_utils::{get_test_x509_credential, test_cert, test_chain},
            CertificateChain, CertificateData, MlsCredential, X509Credential,
        },
        time::MlsTime,
    };

    use super::{
        get_public_key, test_utils::TestIdGenerator, BasicX509Provider, IdentityProvider,
        SigningIdentity, X509Error,
    };
    use crate::cipher_suite::CipherSuite;
    use assert_matches::assert_matches;
    use aws_mls_core::crypto::SignaturePublicKey;
    use aws_mls_crypto_ferriscrypt::ferriscrypt::asym::ec_key::{self, Curve};
    use der::{asn1::UIntRef, Decode};

    #[cfg(target_arch = "wasm32")]
    use wasm_bindgen_test::wasm_bindgen_test as test;
    use x509_cert::Certificate;

    pub fn get_validation_result(
        chain: CertificateChain,
        leaf_pk: ec_key::PublicKey,
        timestamp: Option<MlsTime>,
    ) -> Result<(), X509Error> {
        let ca: Vec<&[u8]> = vec![chain.ca().unwrap()];
        let validator = BasicX509Provider::new(ca, TestIdGenerator {}).unwrap();
        let credential = get_test_x509_credential(chain);

        let signing_id = SigningIdentity {
            signature_key: leaf_pk.to_uncompressed_bytes().unwrap().into(),
            credential,
        };

        validator.validate(&signing_id, CipherSuite::P256Aes128, timestamp)
    }

    #[test]
    fn verifying_valid_chain_succeeds() {
        let (chain, leaf_pk) = test_chain();
        get_validation_result(chain, leaf_pk, None).unwrap();
    }

    #[test]
    fn verifying_invalid_chain_fails() {
        let (mut chain, leaf_pk) = test_chain();

        // Make the chain invalid by swapping two certificates
        chain.swap(1, 2);

        assert_matches!(
            get_validation_result(chain, leaf_pk, None),
            Err(X509Error::InvalidSignature(..))
        );
    }

    #[test]
    fn verifying_mismatching_identity_pk_fails() {
        let (chain, leaf_pk) = test_chain();

        let curve = leaf_pk.curve();
        let sk_len = curve.secret_key_size();
        let mismatching_sk = ec_key::SecretKey::from_bytes(&vec![1u8; sk_len], curve).unwrap();
        let mismatching_pk = mismatching_sk.to_public().unwrap();

        assert_matches!(
            get_validation_result(chain, mismatching_pk, None),
            Err(X509Error::LeafPublicKeyMismatch)
        );
    }

    #[test]
    fn verifying_unknown_ca_fails() {
        let (chain, leaf_pk) = test_chain();
        let validator = BasicX509Provider::new(vec![], TestIdGenerator {}).unwrap();
        let credential = get_test_x509_credential(chain);

        let signing_id = SigningIdentity {
            signature_key: SignaturePublicKey::from(leaf_pk.to_uncompressed_bytes().unwrap()),
            credential,
        };

        assert_matches!(
            validator.validate(&signing_id, CipherSuite::P256Aes128, None),
            Err(X509Error::CaNotFound)
        );
    }

    #[test]
    fn verifying_with_unsupported_hash_fails_gracefully() {
        let (mut chain, leaf_pk) = test_chain();

        // This certificate the same key as id0.der except id1 signed it using sha256
        chain[0] = CertificateData::from(
            include_bytes!("../../../test_data/cert_chain/id0_sha512.der").to_vec(),
        );

        assert_matches!(
            get_validation_result(chain, leaf_pk, None),
            Err(X509Error::UnsupportedHash(..))
        );
    }

    #[test]
    fn verifying_rsa_fails_gracefully() {
        let rsa_cert_bytes = include_bytes!("../../../test_data/rsa_cert.der").to_vec();
        let validator = BasicX509Provider::new(vec![&rsa_cert_bytes], TestIdGenerator {});
        assert_matches!(validator, Err(X509Error::UnsupportedAlgorithm(_)));
    }

    #[test]
    fn creating_validator_with_invalid_ca_cert_fails() {
        let valid_ca_bytes = include_bytes!("../../../test_data/cert_chain/id3-ca.der").to_vec();
        let valid_ca_cert = Certificate::from_der(&valid_ca_bytes).unwrap();

        let mut invalid_ca = valid_ca_cert.clone();
        invalid_ca.tbs_certificate.serial_number = UIntRef::new(&[1, 2, 3]).unwrap();
        let mut invalid_ca_bytes = Vec::new();
        der::Encode::encode_to_vec(&invalid_ca, &mut invalid_ca_bytes).unwrap();

        assert_matches!(
            BasicX509Provider::new(vec![&valid_ca_bytes, &invalid_ca_bytes], TestIdGenerator {}),
            Err(X509Error::InvalidSignature(..))
        );
    }

    #[test]
    fn all_curves_are_supported() {
        let curves = [
            Curve::P256,
            #[cfg(feature = "openssl_engine")]
            Curve::P384,
            #[cfg(feature = "openssl_engine")]
            Curve::P521,
            Curve::Ed25519,
            #[cfg(feature = "openssl_engine")]
            Curve::Ed448,
        ];

        let cert_data = curves.into_iter().map(test_cert).collect::<Vec<_>>();
        let certs = cert_data.iter().map(|cert| &cert[..]).collect();
        BasicX509Provider::new(certs, TestIdGenerator {}).unwrap();
    }

    #[test]
    fn empty_chain_is_rejected() {
        let (_, leaf_pk) = test_chain();
        let validator = BasicX509Provider::new(Vec::new(), TestIdGenerator {}).unwrap();

        let credential = X509Credential {
            credential: Vec::new().into(),
        }
        .to_credential()
        .unwrap();

        let signing_id = SigningIdentity {
            signature_key: SignaturePublicKey::from(leaf_pk.to_uncompressed_bytes().unwrap()),
            credential,
        };

        // The certificate is rejected because empty chain contains no CA.
        assert_matches!(
            validator.validate(&signing_id, CipherSuite::P256Aes128, None),
            Err(X509Error::EmptyCertificateChain)
        );
    }

    #[test]
    fn verifying_invalid_ciphersuite_fails() {
        let (chain, leaf_pk) = test_chain();
        let validator =
            BasicX509Provider::new(vec![chain.ca().unwrap()], TestIdGenerator {}).unwrap();

        let credential = X509Credential { credential: chain }
            .to_credential()
            .unwrap();

        let signing_id = SigningIdentity {
            signature_key: leaf_pk.to_uncompressed_bytes().unwrap().into(),
            credential,
        };

        assert_matches!(
            validator.validate(&signing_id, CipherSuite::Curve25519Aes128, None),
            Err(X509Error::CurveMismatch(..))
        );
    }

    #[test]
    fn verifying_self_signed_works() {
        let mut validator = BasicX509Provider::new(vec![], TestIdGenerator {}).unwrap();
        validator.allow_self_signed(true);

        let bytes = include_bytes!("../../../test_data/cert_chain/id3-ca.der").to_vec();
        let cert = Certificate::from_der(&bytes).unwrap();

        let credential = X509Credential {
            credential: vec![bytes.clone().into()].into(),
        }
        .to_credential()
        .unwrap();

        let signature_key = get_public_key(&cert)
            .unwrap()
            .to_uncompressed_bytes()
            .unwrap()
            .into();

        let signing_id = SigningIdentity {
            credential,
            signature_key,
        };

        validator
            .validate(&signing_id, CipherSuite::P256Aes128, None)
            .unwrap();
    }

    #[test]
    fn too_long_self_signed_is_rejected() {
        let mut validator = BasicX509Provider::new(vec![], TestIdGenerator {}).unwrap();
        validator.allow_self_signed(true);

        let bytes = include_bytes!("../../../test_data/cert_chain/id3-ca.der").to_vec();
        let cert = Certificate::from_der(&bytes).unwrap();

        let credential = X509Credential {
            credential: vec![bytes.clone().into(), bytes.clone().into()].into(),
        }
        .to_credential()
        .unwrap();

        let signature_key = get_public_key(&cert)
            .unwrap()
            .to_uncompressed_bytes()
            .unwrap()
            .into();

        let signing_id = SigningIdentity {
            credential,
            signature_key,
        };

        assert_matches!(
            validator.validate(&signing_id, CipherSuite::P256Aes128, None),
            Err(X509Error::SelfSignedWrongLength(2))
        );
    }

    #[test]
    fn too_short_self_signed_is_rejected() {
        let mut validator = BasicX509Provider::new(vec![], TestIdGenerator {}).unwrap();
        validator.allow_self_signed(true);

        let credential = X509Credential {
            credential: vec![].into(),
        }
        .to_credential()
        .unwrap();

        let signature_key = vec![3u8].into();

        let signing_id = SigningIdentity {
            credential,
            signature_key,
        };

        assert_matches!(
            validator.validate(&signing_id, CipherSuite::P256Aes128, None),
            Err(X509Error::SelfSignedWrongLength(0))
        );
    }

    #[test]
    fn pinned_cert() {
        let (chain, leaf_pk) = test_chain();

        let ca: Vec<&[u8]> = vec![chain.ca().unwrap()];
        let mut validator = BasicX509Provider::new(ca, TestIdGenerator {}).unwrap();
        validator.set_pinned_cert(Some(chain[1].clone()));

        // Validation with pinned cert succeeds : validate chain[0..4]
        let signing_id = SigningIdentity {
            signature_key: leaf_pk.to_uncompressed_bytes().unwrap().into(),
            credential: get_test_x509_credential(chain.clone()),
        };

        validator
            .validate(&signing_id, CipherSuite::P256Aes128, None)
            .unwrap();

        // Validation without pinned cert fails : validate chain[2..4]
        let leaf_cert = Certificate::from_der(&chain[2]).unwrap();
        let leaf_pk = get_public_key(&leaf_cert).unwrap();

        let signing_id = SigningIdentity {
            signature_key: leaf_pk.to_uncompressed_bytes().unwrap().into(),
            credential: get_test_x509_credential(chain[2..4].to_vec().into()),
        };

        assert_matches!(
            validator.validate(&signing_id, CipherSuite::P256Aes128, None),
            Err(X509Error::PinnedCertNotFound)
        );
    }

    #[test]
    fn using_valid_timestamp_is_accepted() {
        let (chain, leaf_pk) = test_chain();

        // August 16, 2022
        let valid_time = MlsTime::from_duration_since_epoch(Duration::from_secs(1660642238));

        get_validation_result(chain, leaf_pk, valid_time).unwrap();
    }

    #[test]
    fn using_invalid_timestamp_is_rejected() {
        let (chain, leaf_pk) = test_chain();

        // August 16, 2023
        let future_time = MlsTime::from_duration_since_epoch(Duration::from_secs(1692178238));
        // August 16, 2021
        let past_time = MlsTime::from_duration_since_epoch(Duration::from_secs(1629106238));

        assert_matches!(
            get_validation_result(chain.clone(), leaf_pk.clone(), future_time),
            Err(X509Error::ValidityError(_, _))
        );
        assert_matches!(
            get_validation_result(chain, leaf_pk, past_time),
            Err(X509Error::ValidityError(_, _))
        );
    }
}
