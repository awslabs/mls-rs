use std::fmt::Debug;

use p256::pkcs8::EncodePublicKey;
use spki::{AlgorithmIdentifier, ObjectIdentifier, SubjectPublicKeyInfo};

use crate::{
    ec::{pub_key_from_uncompressed, Curve, EcError, EcPublicKey},
    ec_signer::EcSigner,
};
pub const X25519_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.101.110");
pub const ED25519_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.101.112");
pub const P256_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.3.1.7");

#[derive(Debug)]
#[cfg_attr(feature = "std", derive(thiserror::Error))]
pub enum EcX509Error {
    #[cfg_attr(feature = "std", error(transparent))]
    DerError(x509_cert::der::Error),
    #[cfg_attr(feature = "std", error(transparent))]
    EcError(EcError),
    #[cfg_attr(feature = "std", error(transparent))]
    SpkiError(spki::Error),
    #[cfg_attr(feature = "std", error("error parsing P256 key"))]
    NistSpkiError,
    #[cfg_attr(feature = "std", error("unsupported public key algorithm: {0:?}"))]
    UnsupportedPublicKeyAlgorithm(String),
}

impl From<x509_cert::der::Error> for EcX509Error {
    fn from(e: x509_cert::der::Error) -> Self {
        EcX509Error::DerError(e)
    }
}

impl From<EcError> for EcX509Error {
    fn from(e: EcError) -> Self {
        EcX509Error::EcError(e)
    }
}

impl From<spki::Error> for EcX509Error {
    fn from(e: spki::Error) -> Self {
        EcX509Error::SpkiError(e)
    }
}

pub fn curve_from_algorithm(algorithm: &AlgorithmIdentifier) -> Result<Curve, EcX509Error> {
    if algorithm.oid == ED25519_OID {
        Ok(Curve::Ed25519)
    } else if algorithm.oid == X25519_OID {
        Ok(Curve::X25519)
    } else if algorithm.parameters_oid() == Ok(P256_OID) {
        Ok(Curve::P256)
    } else {
        Err(EcX509Error::UnsupportedPublicKeyAlgorithm(format!(
            "{algorithm:?}"
        )))
    }
}

pub fn signer_from_algorithm(algorithm: &AlgorithmIdentifier) -> Result<EcSigner, EcX509Error> {
    let curve = curve_from_algorithm(algorithm)?;

    match curve {
        Curve::Ed25519 | Curve::P256 => Ok(EcSigner::new_from_curve(curve)),
        _ => Err(EcX509Error::UnsupportedPublicKeyAlgorithm(format!(
            "{algorithm:?}"
        ))),
    }
}

pub fn pub_key_to_spki(key: &EcPublicKey) -> Result<Vec<u8>, EcX509Error> {
    match key {
        EcPublicKey::X25519(key) => to_spki(X25519_OID, key.as_bytes()),
        EcPublicKey::Ed25519(key) => to_spki(ED25519_OID, key.as_bytes()),
        EcPublicKey::P256(key) => Ok(key
            .to_public_key_der()
            .map_err(|_| EcX509Error::NistSpkiError)?
            .to_vec()),
    }
}

pub fn pub_key_from_spki(spki: &SubjectPublicKeyInfo) -> Result<EcPublicKey, EcX509Error> {
    match curve_from_algorithm(&spki.algorithm)? {
        Curve::X25519 => {
            pub_key_from_uncompressed(spki.subject_public_key, Curve::X25519).map_err(Into::into)
        }
        Curve::Ed25519 => {
            pub_key_from_uncompressed(spki.subject_public_key, Curve::Ed25519).map_err(Into::into)
        }
        Curve::P256 => p256::PublicKey::from_sec1_bytes(spki.subject_public_key)
            .map_err(|e| EcX509Error::from(EcError::P256Error(e)))
            .map(EcPublicKey::P256),
    }
}

fn to_spki(oid: ObjectIdentifier, key_data: &[u8]) -> Result<Vec<u8>, EcX509Error> {
    let key_info = SubjectPublicKeyInfo {
        algorithm: spki::AlgorithmIdentifier {
            oid,
            parameters: None,
        },
        subject_public_key: key_data,
    };

    spki::der::Encode::to_vec(&key_info).map_err(Into::into)
}
