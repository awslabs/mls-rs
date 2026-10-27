// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// Copyright by contributors to this project.
// SPDX-License-Identifier: (Apache-2.0 OR MIT)

#![cfg_attr(not(feature = "std"), no_std)]
extern crate alloc;

use alloc::boxed::Box;

pub use alloc::vec::Vec;

mod array;

/// Optimized encoding and decoding for types that can be represented by `Vec<u8>`.
///
/// Compatible with derive macros by using `mls_codec(with = "mls_rs_codec::byte_vec")`
pub mod byte_vec;

pub mod iter;

mod bool;
mod cow;
mod map;
mod option;
mod stdint;
mod string;
mod tuple;
mod varint;
mod vec;

pub use varint::*;

pub use mls_rs_codec_derive::*;

#[derive(Debug)]
#[cfg_attr(feature = "std", derive(thiserror::Error))]
#[non_exhaustive]
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
    #[cfg_attr(feature = "std", error("Expected UTF-8 string"))]
    Utf8,
    #[cfg_attr(feature = "std", error("Invalid content"))]
    InvalidContent,
    #[cfg_attr(feature = "std", error("Unexpected trailing data"))]
    UnexpectedTrailingData,
    #[cfg_attr(feature = "std", error("mls codec error: {0}"))]
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

impl<T> MlsSize for Box<T>
where
    T: MlsSize + ?Sized,
{
    #[inline]
    fn mls_encoded_len(&self) -> usize {
        self.as_ref().mls_encoded_len()
    }
}

/// Trait to support serializing a type with MLS encoding.
pub trait MlsEncode: MlsSize {
    fn mls_encode(&self, writer: &mut Vec<u8>) -> Result<(), Error>;

    #[inline]
    fn mls_encode_to_vec(&self) -> Result<Vec<u8>, Error> {
        #[cfg(feature = "preallocate")]
        let mut vec = Vec::with_capacity(self.mls_encoded_len());

        #[cfg(not(feature = "preallocate"))]
        let mut vec = Vec::new();

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

impl<T> MlsEncode for Box<T>
where
    T: MlsEncode + ?Sized,
{
    #[inline]
    fn mls_encode(&self, writer: &mut Vec<u8>) -> Result<(), Error> {
        self.as_ref().mls_encode(writer)
    }
}

/// Trait to support deserialzing to a type using MLS encoding.
pub trait MlsDecode: Sized {
    fn mls_decode(reader: &mut &[u8]) -> Result<Self, Error>;

    /// Decode a value spanning all of `bytes`, rejecting any trailing data.
    ///
    /// [`mls_decode`](MlsDecode::mls_decode) only reads a prefix, which is what a field of a
    /// larger structure needs but lets distinct inputs decode to the same top level value.
    #[inline]
    fn mls_decode_exhaustive(mut bytes: &[u8]) -> Result<Self, Error> {
        let value = Self::mls_decode(&mut bytes)?;

        bytes
            .is_empty()
            .then_some(value)
            .ok_or(Error::UnexpectedTrailingData)
    }
}

impl<T: MlsDecode> MlsDecode for Box<T> {
    #[inline]
    fn mls_decode(reader: &mut &[u8]) -> Result<Self, Error> {
        T::mls_decode(reader).map(Box::new)
    }
}

#[cfg(test)]
mod tests {
    use crate::{Error, MlsDecode, MlsEncode};
    use alloc::{vec, vec::Vec};
    use assert_matches::assert_matches;

    #[cfg(target_arch = "wasm32")]
    use wasm_bindgen_test::wasm_bindgen_test as test;

    #[test]
    fn exhaustive_decode_accepts_exact_input() {
        let serialized = vec![1u8, 2, 3].mls_encode_to_vec().unwrap();

        assert_eq!(
            Vec::<u8>::mls_decode_exhaustive(&serialized).unwrap(),
            vec![1u8, 2, 3]
        );
    }

    #[test]
    fn exhaustive_decode_rejects_trailing_data() {
        let mut serialized = vec![1u8, 2, 3].mls_encode_to_vec().unwrap();
        serialized.push(0);

        assert_matches!(
            Vec::<u8>::mls_decode_exhaustive(&serialized),
            Err(Error::UnexpectedTrailingData)
        );
    }

    #[test]
    fn exhaustive_decode_rejects_truncated_input() {
        assert_matches!(
            Vec::<u8>::mls_decode_exhaustive(&[2, 3]),
            Err(Error::UnexpectedEOF)
        );
    }
}
