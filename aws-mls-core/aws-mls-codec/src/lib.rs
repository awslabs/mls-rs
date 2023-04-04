#![cfg_attr(not(feature = "std"), no_std)]
#![cfg_attr(not(feature = "std"), feature(error_in_core))]
extern crate alloc;

use alloc::{string::String, vec::Vec};

extern crate thiserror_core as thiserror;

use thiserror_core::Error;

mod array;

/// Optimized encoding and decoding for types that can be represented by `Vec<u8>`.
///
/// Compatible with derive macros by using `mls_codec(with = "aws_mls_codec::byte_vec")`
pub mod byte_vec;

mod option;
mod reader;
mod stdint;
mod varint;
mod vec;
mod writer;

pub use array::*;
pub use option::*;
pub use reader::*;
pub use stdint::*;
pub use varint::*;
pub use vec::*;
pub use writer::*;

pub use aws_mls_codec_derive::*;

#[derive(Debug, Error)]
pub enum Error {
    #[error("Integer out of range for VarInt")]
    VarIntOutOfRange,
    #[error("Invalid varint prefix {0}")]
    InvalidVarIntPrefix(u8),
    #[error("VarInt does not use the min-length encoding")]
    VarIntMinimumLengthEncoding,
    #[error("UnexpectedEOF")]
    UnexpectedEOF,
    #[error("Option marker out of range: {0}")]
    OptionOutOfRange(u8),
    #[error("Unsupported enum discriminant")]
    UnsupportedEnumDiscriminant,
    #[error("mls codec error: {0}")]
    Custom(String),
}

/// Trait that determines the encoded length in MLS encoding.
pub trait MlsSize {
    fn mls_encoded_len(&self) -> usize;
}

/// Trait to support serializing a type with MLS encoding.
pub trait MlsEncode: MlsSize {
    fn mls_encode<W: Writer>(&self, writer: W) -> Result<(), Error>;

    #[inline]
    fn mls_encode_to_vec(&self) -> Result<Vec<u8>, Error> {
        let mut vec = Vec::with_capacity(self.mls_encoded_len());
        self.mls_encode(&mut vec)?;

        Ok(vec)
    }
}

/// Trait to support deserialzing to a type using MLS encoding.
pub trait MlsDecode: Sized {
    fn mls_decode<R: Reader>(reader: R) -> Result<Self, Error>;
}
