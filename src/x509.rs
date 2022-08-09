use std::{collections::HashSet, ops::Deref};

use der::{Decode, Encode};
use ferriscrypt::asym::ec_key::{self, Curve, EcKeyError};
use ferriscrypt::digest::digest;
use ferriscrypt::digest::HashFunction::Sha256;
use thiserror::Error;
use tls_codec_derive::{TlsDeserialize, TlsSerialize, TlsSize};
use x509_cert::certificate::Certificate;

use crate::cipher_suite::CipherSuite;
use crate::signing_identity::SigningIdentity;
use crate::{client_config::CredentialValidator, credential::Credential};

#[derive(Debug, Error)]
pub enum X509Error {
    #[error("error parsing DER certificate: {0}")]
    CertificateParseError(der::Error),
    #[error("empty certificate chain (it must contain the CA)")]
    EmptyCertificateChain,
    #[error(transparent)]
    EcKeyError(#[from] EcKeyError),
    #[error("validating a certificate type that is not X.509")]
    NotX509Certificate,
    #[error("signature invalid for parent certificate {0} and child certificate {1}")]
    InvalidSignature(String, String),
    #[error("CA certificate not in the set of trusted CA's: not found certificate {0}")]
    CaNotFound(String),
    #[error("unsupported algorithm with OID {0} for curve {1:?}; the following hash algorithms are supported: 
        SHA256 for curve P256, SHA384 for curve P384, SHA512 for curve P521")]
    UnsupportedHash(String, Curve),
    #[error("unsupported algorithm with OID {0}; only EC algorithms are supported")]
    UnsupportedAlgorithm(String),
    #[error("leaf public key does not match signing identity public key")]
    LeafPublicKeyMismatch,
    #[error("leaf public key curve {0:?} does not match the curve MLS ciphersuite {1:?}")]
    CurveMismatch(Curve, Curve),
}

#[derive(
    Clone,
    Debug,
    PartialEq,
    TlsSize,
    TlsSerialize,
    TlsDeserialize,
    Eq,
    Hash,
    serde::Deserialize,
    serde::Serialize,
)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct CertificateData(#[tls_codec(with = "crate::tls::ByteVec")] Vec<u8>);

impl From<Vec<u8>> for CertificateData {
    fn from(data: Vec<u8>) -> Self {
        CertificateData(data)
    }
}

impl Deref for CertificateData {
    type Target = Vec<u8>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[derive(Clone, Debug, Default)]
pub struct BasicX509Validator {
    ca_certs: HashSet<Vec<u8>>,
}

impl BasicX509Validator {
    pub fn new(ca_certs: Vec<&[u8]>) -> Result<Self, X509Error> {
        let ca_certs = ca_certs
            .into_iter()
            .map(|cert_data| {
                // Verify the self-signture
                let cert =
                    Certificate::from_der(cert_data).map_err(X509Error::CertificateParseError)?;
                verify_cert(&cert, &cert)?;
                Ok(hash_cert(cert_data))
            })
            .collect::<Result<_, X509Error>>()?;

        Ok(Self { ca_certs })
    }
}

impl CredentialValidator for BasicX509Validator {
    type Error = X509Error;

    fn validate(
        &self,
        signing_identity: &SigningIdentity,
        cipher_suite: CipherSuite,
    ) -> Result<(), Self::Error> {
        let chain = match &signing_identity.credential {
            Credential::X509(chain) => Ok(chain),
            _ => Err(X509Error::NotX509Certificate),
        }?;

        let ca_cert = chain.last().ok_or(X509Error::EmptyCertificateChain)?;
        let ca_hash = hash_cert(ca_cert);

        if !self.ca_certs.contains(&ca_hash) {
            return Err(X509Error::CaNotFound(format!("{:?}", ca_cert)));
        }

        let chain = chain
            .iter()
            .map(|cert_data| Certificate::from_der(cert_data))
            .collect::<Result<Vec<_>, _>>()
            .map_err(X509Error::CertificateParseError)?;

        let leaf_pk = get_public_key(&chain[0])?;

        if leaf_pk.to_uncompressed_bytes()? != *signing_identity.signature_key {
            return Err(X509Error::LeafPublicKeyMismatch);
        }

        if leaf_pk.curve() != cipher_suite.signature_key_curve() {
            return Err(X509Error::CurveMismatch(
                leaf_pk.curve(),
                cipher_suite.signature_key_curve(),
            ));
        }

        chain
            .iter()
            .zip(chain.iter().skip(1))
            .try_for_each(|(cert1, cert2)| verify_cert(cert2, cert1))
    }

    fn is_equal_identity(&self, _left: &Credential, _right: &Credential) -> bool {
        true
    }
}

fn verify_cert(verifier: &Certificate, verified: &Certificate) -> Result<(), X509Error> {
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
        })
}

fn hash_cert(cert_data: &[u8]) -> Vec<u8> {
    digest(Sha256, cert_data)
}

fn get_public_key(cert: &Certificate) -> Result<ec_key::PublicKey, X509Error> {
    // Re-encode the `subject_public_key_info` (containing the key bytes and the algorithm) to get the public key.
    let mut public_key = Vec::new();

    cert.tbs_certificate
        .subject_public_key_info
        .encode_to_vec(&mut public_key)
        .map_err(X509Error::CertificateParseError)?;

    ec_key::PublicKey::from_der(&public_key).map_err(Into::into)
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

#[derive(
    Clone,
    Debug,
    PartialEq,
    TlsSize,
    TlsSerialize,
    TlsDeserialize,
    Eq,
    Hash,
    serde::Deserialize,
    serde::Serialize,
)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct CertificateChain(#[tls_codec(with = "crate::tls::DefVec")] Vec<CertificateData>);

impl From<Vec<CertificateData>> for CertificateChain {
    fn from(cert_data: Vec<CertificateData>) -> Self {
        CertificateChain(cert_data)
    }
}

impl Deref for CertificateChain {
    type Target = Vec<CertificateData>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl CertificateChain {
    pub fn empty() -> Self {
        Self(vec![])
    }

    pub fn leaf(&self) -> Result<&CertificateData, X509Error> {
        self.0.first().ok_or(X509Error::EmptyCertificateChain)
    }
}

#[cfg(any(test, feature = "benchmark"))]
pub(crate) mod test_utils {
    #[cfg(test)]
    use super::{get_public_key, Certificate, CertificateChain};
    use crate::x509::CertificateData;
    use ferriscrypt::asym::ec_key;

    pub fn test_cert(curve: ec_key::Curve) -> CertificateData {
        let data = match curve {
            ec_key::Curve::P256 => include_bytes!("../test_data/p256_cert.der").to_vec(),
            #[cfg(feature = "openssl_engine")]
            ec_key::Curve::P384 => include_bytes!("../test_data/p384_cert.der").to_vec(),
            #[cfg(feature = "openssl_engine")]
            ec_key::Curve::P521 => include_bytes!("../test_data/p521_cert.der").to_vec(),
            ec_key::Curve::Ed25519 => include_bytes!("../test_data/ed25519_cert.der").to_vec(),
            #[cfg(feature = "openssl_engine")]
            ec_key::Curve::Ed448 => include_bytes!("../test_data/ed448_cert.der").to_vec(),
            _ => panic!("invalid test curve"),
        };

        CertificateData::from(data)
    }

    #[cfg(test)]
    pub fn test_chain() -> (CertificateChain, ec_key::PublicKey) {
        use der::Decode;

        let ca_data = include_bytes!("../test_data/cert_chain/id3-ca.der").to_vec();
        let id2_data = include_bytes!("../test_data/cert_chain/id2.der").to_vec();
        let id1_data = include_bytes!("../test_data/cert_chain/id1.der").to_vec();
        let id0_data = include_bytes!("../test_data/cert_chain/id0-leaf.der").to_vec();

        let leaf_cert = Certificate::from_der(&id0_data).unwrap();
        let leaf_pk = get_public_key(&leaf_cert).unwrap();

        let chain = [id0_data, id1_data, id2_data, ca_data]
            .into_iter()
            .map(CertificateData::from)
            .collect::<Vec<_>>()
            .into();

        (chain, leaf_pk)
    }
}

#[cfg(test)]
mod tests {
    use crate::x509::{test_utils::test_cert, CertificateData};

    use super::{
        test_utils::test_chain, BasicX509Validator, Credential, CredentialValidator,
        SigningIdentity, X509Error,
    };
    use crate::cipher_suite::CipherSuite;
    use assert_matches::assert_matches;
    use der::{asn1::UIntRef, Decode};
    use ferriscrypt::asym::ec_key::{self, Curve};

    #[cfg(target_arch = "wasm32")]
    use wasm_bindgen_test::wasm_bindgen_test as test;
    use x509_cert::Certificate;

    #[test]
    fn verifying_valid_chain_succeeds() {
        let (chain, leaf_pk) = test_chain();
        let validator = BasicX509Validator::new(vec![chain.last().unwrap()]).unwrap();
        let credential = Credential::X509(chain);

        let signing_id = SigningIdentity {
            signature_key: leaf_pk.to_uncompressed_bytes().unwrap().into(),
            credential,
        };

        validator
            .validate(&signing_id, CipherSuite::P256Aes128)
            .unwrap();
    }

    #[test]
    fn verifying_invalid_chain_fails() {
        let (mut chain, leaf_pk) = test_chain();

        // Make the chain invalid by swapping two certificates
        chain.0.swap(1, 2);

        let validator = BasicX509Validator::new(vec![chain.last().unwrap()]).unwrap();
        let credential = Credential::X509(chain);

        let signing_id = SigningIdentity {
            signature_key: leaf_pk.to_uncompressed_bytes().unwrap().into(),
            credential,
        };

        assert_matches!(
            validator.validate(&signing_id, CipherSuite::P256Aes128),
            Err(X509Error::InvalidSignature(..))
        );
    }

    #[test]
    fn verifying_mismatching_identity_pk_fails() {
        let (chain, leaf_pk) = test_chain();
        let validator = BasicX509Validator::new(vec![chain.last().unwrap()]).unwrap();
        let credential = Credential::X509(chain);

        let curve = leaf_pk.curve();
        let sk_len = curve.secret_key_size();
        let mismatching_sk = ec_key::SecretKey::from_bytes(&vec![1u8; sk_len], curve).unwrap();
        let mismatching_pk = mismatching_sk.to_public().unwrap();

        let signing_id = SigningIdentity {
            signature_key: mismatching_pk.try_into().unwrap(),
            credential,
        };

        assert_matches!(
            validator.validate(&signing_id, CipherSuite::P256Aes128),
            Err(X509Error::LeafPublicKeyMismatch)
        );
    }

    #[test]
    fn verifying_unknown_ca_fails() {
        let (chain, leaf_pk) = test_chain();
        let validator = BasicX509Validator::new(vec![]).unwrap();
        let credential = Credential::X509(chain);

        let signing_id = SigningIdentity {
            signature_key: leaf_pk.try_into().unwrap(),
            credential,
        };

        assert_matches!(
            validator.validate(&signing_id, CipherSuite::P256Aes128),
            Err(X509Error::CaNotFound(_))
        );
    }

    #[test]
    fn verifying_with_unsupported_hash_fails_gracefully() {
        let (mut chain, leaf_pk) = test_chain();

        // This certificate the same key as id0.der except id1 signed it using sha256
        chain.0[0] =
            CertificateData(include_bytes!("../test_data/cert_chain/id0_sha512.der").to_vec());

        let validator = BasicX509Validator::new(vec![chain.last().unwrap()]).unwrap();
        let credential = Credential::X509(chain);

        let signing_id = SigningIdentity {
            signature_key: leaf_pk.try_into().unwrap(),
            credential,
        };

        assert_matches!(
            validator.validate(&signing_id, CipherSuite::P256Aes128),
            Err(X509Error::UnsupportedHash(..))
        );
    }

    #[test]
    fn verifying_rsa_fails_gracefully() {
        let rsa_cert_bytes = include_bytes!("../test_data/rsa_cert.der").to_vec();
        let validator = BasicX509Validator::new(vec![&rsa_cert_bytes]);
        assert_matches!(validator, Err(X509Error::UnsupportedAlgorithm(_)));
    }

    #[test]
    fn creating_validator_with_invalid_ca_cert_fails() {
        let valid_ca_bytes = include_bytes!("../test_data/cert_chain/id3-ca.der").to_vec();

        let valid_ca_cert = Certificate::from_der(&valid_ca_bytes).unwrap();
        let mut invalid_ca = valid_ca_cert.clone();
        invalid_ca.tbs_certificate.serial_number = UIntRef::new(&[1, 2, 3]).unwrap();
        let mut invalid_ca_bytes = Vec::new();
        der::Encode::encode_to_vec(&invalid_ca, &mut invalid_ca_bytes).unwrap();

        assert_matches!(
            BasicX509Validator::new(vec![&valid_ca_bytes, &invalid_ca_bytes]),
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
        BasicX509Validator::new(certs).unwrap();
    }

    #[test]
    fn empty_chain_is_rejected() {
        let (_, leaf_pk) = test_chain();
        let validator = BasicX509Validator::new(Vec::new()).unwrap();
        let credential = Credential::X509(Vec::new().into());

        let signing_id = SigningIdentity {
            signature_key: leaf_pk.try_into().unwrap(),
            credential,
        };

        assert_matches!(
            validator.validate(&signing_id, CipherSuite::P256Aes128),
            Err(X509Error::EmptyCertificateChain)
        );
    }

    #[test]
    fn verifying_invalid_ciphersuite_fails() {
        let (chain, leaf_pk) = test_chain();
        let validator = BasicX509Validator::new(vec![chain.last().unwrap()]).unwrap();
        let credential = Credential::X509(chain);

        let signing_id = SigningIdentity {
            signature_key: leaf_pk.to_uncompressed_bytes().unwrap().into(),
            credential,
        };

        assert_matches!(
            validator.validate(&signing_id, CipherSuite::Curve25519Aes128),
            Err(X509Error::CurveMismatch(..))
        );
    }
}
