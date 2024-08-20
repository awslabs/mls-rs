// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// Copyright by contributors to this project.
// SPDX-License-Identifier: (Apache-2.0 OR MIT)

use std::net::AddrParseError;

use mls_rs_core::crypto::CipherSuite;
use mls_rs_core::error::IntoAnyError;
use mls_rs_identity_x509::SubjectAltName;
use spki::der::Tag;
use spki::ObjectIdentifier;

use crate::ec::EcError;
use crate::ec_for_x509::EcX509Error;
use crate::ec_signer::EcSignerError;

mod reader;
mod util;
mod validator;
mod writer;

pub use reader::X509Reader;
pub use validator::X509Validator;
pub use writer::CertificateRequestWriter;

#[allow(clippy::large_enum_variant)]
#[derive(Debug)]
#[cfg_attr(feature = "std", derive(thiserror::Error))]
pub enum X509Error {
    #[cfg_attr(feature = "std", error(transparent))]
    X509DerError(x509_cert::der::Error),
    #[cfg_attr(feature = "std", error(transparent))]
    EcError(EcError),
    #[cfg_attr(feature = "std", error(transparent))]
    RandError(rand_core::Error),
    #[cfg_attr(feature = "std", error(transparent))]
    EcX509Error(EcX509Error),
    #[cfg_attr(feature = "std", error(transparent))]
    ConstOidError(const_oid::Error),
    #[cfg_attr(feature = "std", error(transparent))]
    EcSignerError(EcSignerError),
    #[cfg_attr(feature = "std", error(transparent))]
    AddrParseError(AddrParseError),
    #[cfg_attr(
        feature = "std",
        error("cipher suite {0:?} is not a valid signing key")
    )]
    InvalidSigningKey(CipherSuite),
    #[cfg_attr(feature = "std", error("unsupported cipher suite"))]
    UnsupportedCipherSuite,
    #[cfg_attr(
        feature = "std",
        error("subject alt name type of {0:?} is not supported")
    )]
    UnsupportedSubjectAltName(SubjectAltName),
    #[cfg_attr(feature = "std", error("unexpected empty certificate chain"))]
    EmptyCertificateChain,
    #[cfg_attr(feature = "std", error("a CA cert must have the basic constraint extension set to ca without the path length constraint, and the
        key usage extension set to keyCertSign"))]
    InvalidCaExtensions,
    #[cfg_attr(feature = "std", error("invalid certificate lifetime"))]
    InvalidCertificateLifetime,
    #[cfg_attr(feature = "std", error("no trusted CA certificate found in the chain"))]
    CaNotFound,
    #[cfg_attr(feature = "std", error("pinned certificate not found in the chain"))]
    PinnedCertNotFound,
    #[cfg_attr(
        feature = "std",
        error("Current (commit) timestamp {0} outside of the validity period of certificate {1}")
    )]
    ValidityError(u64, String),
    #[cfg_attr(feature = "std", error("unsupported signing algorithm with OID {0}"))]
    UnsupportedAlgorithm(ObjectIdentifier),
    #[cfg_attr(feature = "std", error(transparent))]
    SpkiError(spki::Error),
    #[cfg_attr(feature = "std", error("unsupported OID {0} for subject component"))]
    UnsupportedSubjectComponentOid(ObjectIdentifier),
    #[cfg_attr(feature = "std", error("cannot parse component type {0} in X509 name"))]
    UnexpectedComponentType(Tag),
    #[cfg_attr(
        feature = "std",
        error("cannot parse ip address with incorrect number of octets {0}")
    )]
    IncorrectIpOctets(usize),
    #[cfg_attr(feature = "std", error("cannot parse subject alt name with type {0}"))]
    CannotParseAltName(String),
    #[cfg_attr(
        feature = "std",
        error("self-signed certificate provided as chain of length {0} but it must have length 1")
    )]
    SelfSignedWrongLength(usize),
}

impl From<x509_cert::der::Error> for X509Error {
    fn from(e: x509_cert::der::Error) -> Self {
        X509Error::X509DerError(e)
    }
}

impl From<EcError> for X509Error {
    fn from(e: EcError) -> Self {
        X509Error::EcError(e)
    }
}

impl From<rand_core::Error> for X509Error {
    fn from(e: rand_core::Error) -> Self {
        X509Error::RandError(e)
    }
}

impl From<EcX509Error> for X509Error {
    fn from(e: EcX509Error) -> Self {
        X509Error::EcX509Error(e)
    }
}

impl From<const_oid::Error> for X509Error {
    fn from(e: const_oid::Error) -> Self {
        X509Error::ConstOidError(e)
    }
}

impl From<EcSignerError> for X509Error {
    fn from(e: EcSignerError) -> Self {
        X509Error::EcSignerError(e)
    }
}

impl From<AddrParseError> for X509Error {
    fn from(e: AddrParseError) -> X509Error {
        X509Error::AddrParseError(e)
    }
}

impl From<spki::Error> for X509Error {
    fn from(e: spki::Error) -> Self {
        X509Error::SpkiError(e)
    }
}

impl IntoAnyError for X509Error {
    #[cfg(feature = "std")]
    fn into_dyn_error(self) -> Result<Box<dyn std::error::Error + Send + Sync>, Self> {
        Ok(self.into())
    }
}
