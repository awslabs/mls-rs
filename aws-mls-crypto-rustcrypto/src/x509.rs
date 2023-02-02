use std::net::AddrParseError;

use aws_mls_core::{crypto::CipherSuite, time::SystemTimeError};
use aws_mls_identity_x509::SubjectAltName;
use spki::{der::Tag, ObjectIdentifier};
use thiserror::Error;

use crate::{ec::EcError, ec_for_x509::EcX509Error, ec_signer::EcSignerError};

mod reader;
mod util;
mod validator;
mod writer;

pub use reader::X509Reader;
pub use validator::X509Validator;
pub use writer::X509Writer;

#[allow(clippy::large_enum_variant)]
#[derive(Debug, Error)]
pub enum X509Error {
    #[error(transparent)]
    X509DerError(#[from] x509_cert::der::Error),
    #[error(transparent)]
    EcError(#[from] EcError),
    #[error(transparent)]
    RandError(#[from] rand_core::Error),
    #[error(transparent)]
    EcX509Error(#[from] EcX509Error),
    #[error(transparent)]
    ConstOidError(#[from] const_oid::Error),
    #[error(transparent)]
    EcSignerError(#[from] EcSignerError),
    #[error(transparent)]
    AddrParseError(#[from] AddrParseError),
    #[error("cipher suite {0:?} is not a valid signing key")]
    InvalidSigningKey(CipherSuite),
    #[error("subject alt name type of {0:?} is not supported")]
    UnsupportedSubjectAltName(SubjectAltName),
    #[error("unexpected empty certificate chain")]
    EmptyCertificateChain,
    #[error("a CA cert must have the basic constraint extension set to ca without the path length constraint, and the
        key usage extension set to keyCertSign")]
    InvalidCaExtensions,
    #[error("invalid certificate lifetime")]
    InvalidCertificateLifetime,
    #[error(transparent)]
    SystemTimeError(#[from] SystemTimeError),
    #[error("no trusted CA certificate found in the chain")]
    CaNotFound,
    #[error("pinned certificate not found in the chain")]
    PinnedCertNotFound,
    #[error("Current (commit) timestamp {0} outside of the validity period of certificate {1}")]
    ValidityError(u64, String),
    #[error("unsupported signing algorithm with OID {0}")]
    UnsupportedAlgorithm(ObjectIdentifier),
    #[error(transparent)]
    SpkiError(#[from] spki::Error),
    #[error("unsupported OID {0} for subject component")]
    UnsupportedSubjectComponentOid(ObjectIdentifier),
    #[error("cannot parse component type {0} in X509 name")]
    UnexpectedComponentType(Tag),
    #[error("cannot parse ip address with incorrect number of octets {0}")]
    IncorrectIpOctets(usize),
    #[error("cannot parse subject alt name with type {0}")]
    CannotParseAltName(String),
    #[error("self-signed certificate provided as chain of length {0} but it must have length 1")]
    SelfSignedWrongLength(usize),
}
