use std::fmt::Debug;

use p256::pkcs8::EncodePublicKey;
use sec1::der::Document;
use spki::{ObjectIdentifier, SubjectPublicKeyInfo};
use thiserror::Error;

use crate::ec::EcPublicKey;
pub const X25519_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.101.110");
pub const ED25519_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.101.112");
pub const P256_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.3.1.7");

#[derive(Debug, Error)]
pub enum EcX509Error {
    #[error(transparent)]
    DerError(#[from] x509_cert::der::Error),
    #[error("error parsing P256 key")]
    NistSpkiError,
}

pub fn pub_key_to_der(key: &EcPublicKey) -> Result<Vec<u8>, EcX509Error> {
    match key {
        EcPublicKey::X25519(key) => to_spki(X25519_OID, key.as_bytes()),
        EcPublicKey::Ed25519(key) => to_spki(ED25519_OID, key.as_bytes()),
        EcPublicKey::P256(key) => Ok(key
            .to_public_key_der()
            .map_err(|_| EcX509Error::NistSpkiError)?
            .as_der()
            .to_vec()),
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
