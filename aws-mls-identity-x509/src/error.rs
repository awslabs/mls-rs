use alloc::boxed::Box;
use aws_mls_core::identity::CredentialType;

#[cfg(feature = "std")]
use std::error::Error;

#[cfg(not(feature = "std"))]
use core::error::Error;

#[derive(Debug, thiserror::Error)]
pub enum X509IdentityError {
    #[error("unsupported credential type {0:?}")]
    UnsupportedCredentialType(CredentialType),
    #[error("signing identity public key does not match the leaf certificate")]
    SignatureKeyMismatch,
    #[error("unable to parse certificate chain data")]
    InvalidCertificateChain,
    #[error("invalid offset within certificate chain")]
    InvalidOffset,
    #[error("empty certificate chain")]
    EmptyCertificateChain,
    #[error(transparent)]
    CredentialEncodingError(Box<dyn Error + Send + Sync + 'static>),
    #[error(transparent)]
    X509ReaderError(Box<dyn Error + Send + Sync + 'static>),
    #[error(transparent)]
    IdentityExtractorError(Box<dyn Error + Send + Sync + 'static>),
    #[error(transparent)]
    X509ValidationError(Box<dyn Error + Send + Sync + 'static>),
    #[error(transparent)]
    IdentityWarningProviderError(Box<dyn Error + Send + Sync + 'static>),
}
