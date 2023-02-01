use std::net::AddrParseError;

use aws_mls_core::{crypto::CipherSuite, time::SystemTimeError};
use aws_mls_identity_x509::SubjectAltName;
use thiserror::Error;

use crate::{ec::EcError, ec_for_x509::EcX509Error, ec_signer::EcSignerError};

mod util;
mod writer;

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
}
