#![cfg_attr(not(feature = "std"), no_std)]
extern crate alloc;

pub use alloc::vec::Vec;

mod array;

/// Optimized encoding and decoding for types that can be represented by `Vec<u8>`.
///
/// Compatible with derive macros by using `mls_codec(with = "aws_mls_codec::byte_vec")`
pub mod byte_vec;

pub mod iter;

mod map;
mod option;
mod stdint;
mod tuple;
mod varint;
mod vec;

pub use array::*;
pub use option::*;
pub use stdint::*;
pub use tuple::*;
pub use varint::*;
pub use vec::*;

pub use aws_mls_codec_derive::*;

#[derive(Debug)]
#[cfg_attr(feature = "std", derive(thiserror::Error))]
pub enum Error {
    #[cfg_attr(feature = "std", error("Integer out of range for VarInt"))]
    VarIntOutOfRange,
    #[cfg_attr(feature = "std", error("Invalid varint prefix {0}"))]
    InvalidVarIntPrefix(u8),
    #[cfg_attr(feature = "std", error("VarInt does not use the min-length encoding"))]
    VarIntMinimumLengthEncoding,
    #[cfg_attr(feature = "std", error("UnexpectedEOF"))]
    UnexpectedEOF,
    #[cfg_attr(feature = "std", error("Option marker out of range: {0}"))]
    OptionOutOfRange(u8),
    #[cfg_attr(feature = "std", error("Unsupported enum discriminant"))]
    UnsupportedEnumDiscriminant,
    #[cfg_attr(feature = "std", error("mls codec error: {0}"))]
    #[cfg(feature = "std")]
    Custom(String),
    #[cfg(not(feature = "std"))]
    Custom(u8),
}

/// Trait that determines the encoded length in MLS encoding.
pub trait MlsSize {
    fn mls_encoded_len(&self) -> usize;
}

impl<T> MlsSize for &T
where
    T: MlsSize + ?Sized,
{
    #[inline]
    fn mls_encoded_len(&self) -> usize {
        (*self).mls_encoded_len()
    }
}

/// Trait to support serializing a type with MLS encoding.
pub trait MlsEncode: MlsSize {
    fn mls_encode(&self, writer: &mut Vec<u8>) -> Result<(), Error>;

    #[inline]
    fn mls_encode_to_vec(&self) -> Result<Vec<u8>, Error> {
        let mut vec = Vec::with_capacity(self.mls_encoded_len());
        self.mls_encode(&mut vec)?;

        Ok(vec)
    }
}

impl<T> MlsEncode for &T
where
    T: MlsEncode + ?Sized,
{
    #[inline]
    fn mls_encode(&self, writer: &mut Vec<u8>) -> Result<(), Error> {
        (*self).mls_encode(writer)
    }
}

/// Trait to support deserialzing to a type using MLS encoding.
pub trait MlsDecode: Sized {
    fn mls_decode(reader: &mut &[u8]) -> Result<Self, Error>;
}
