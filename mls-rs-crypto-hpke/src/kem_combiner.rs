use mls_rs_core::error::{AnyError, IntoAnyError};
use mls_rs_crypto_traits::KemType;

#[cfg(not(mls_build_async))]
pub mod byte_vec_codecs;
#[cfg(not(mls_build_async))]
pub mod ghp;
#[cfg(not(mls_build_async))]
pub mod prgs;
pub mod xwing;

#[derive(Debug)]
#[cfg_attr(feature = "std", derive(thiserror::Error))]
pub enum Error {
    #[cfg_attr(feature = "std", error(transparent))]
    KemError(AnyError),
    #[cfg_attr(feature = "std", error(transparent))]
    KdfError(AnyError),
    #[cfg_attr(feature = "std", error(transparent))]
    PrgError(AnyError),
    #[cfg_attr(feature = "std", error(transparent))]
    ByteVecCodecError(AnyError),
    #[cfg_attr(feature = "std", error(transparent))]
    RandomOracleError(AnyError),
    #[cfg_attr(feature = "std", error("invalid key data"))]
    InvalidKeyData,
    #[cfg_attr(feature = "std", error(transparent))]
    MlsCodecError(mls_rs_core::mls_rs_codec::Error),
    #[cfg_attr(feature = "std", error("invalid prg output length"))]
    InvalidPrgOutputLength,
    #[cfg_attr(feature = "std", error("invalid prg output length {0}"))]
    InvalidInputLength(usize),
}

impl IntoAnyError for Error {}

fn kem_error<E: IntoAnyError>(e: E) -> Error {
    Error::KemError(e.into_any_error())
}

fn prg_error<E: IntoAnyError>(e: E) -> Error {
    Error::PrgError(e.into_any_error())
}

fn codec_error<E: IntoAnyError>(e: E) -> Error {
    Error::ByteVecCodecError(e.into_any_error())
}

fn ro_error<E: IntoAnyError>(e: E) -> Error {
    Error::RandomOracleError(e.into_any_error())
}

impl From<mls_rs_core::mls_rs_codec::Error> for Error {
    #[inline]
    fn from(e: mls_rs_core::mls_rs_codec::Error) -> Self {
        Error::MlsCodecError(e)
    }
}

pub trait FixedLengthKemType: KemType {
    fn public_key_size(&self) -> usize;
    fn secret_key_size(&self) -> usize;

    fn enc_size(&self) -> usize {
        self.public_key_size()
    }
}
