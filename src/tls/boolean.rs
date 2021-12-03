use crate::tls::{Deserializer, Serializer, Sizer};
use std::io::{Read, Write};
use tls_codec::{Deserialize, Serialize};

/// Adapter for TLS serialization of boolean values
///
/// `false` is serialized as `0u8` and `true` is serialized as `1u8`.
pub struct Boolean;

impl Boolean {
    pub fn tls_serialized_len(_: &bool) -> usize {
        1
    }

    pub fn tls_serialize<W: Write>(b: &bool, writer: &mut W) -> Result<usize, tls_codec::Error> {
        (*b as u8).tls_serialize(writer)
    }

    pub fn tls_deserialize<R: Read>(reader: &mut R) -> Result<bool, tls_codec::Error> {
        Ok(u8::tls_deserialize(reader)? != 0)
    }
}

impl Sizer<bool> for Boolean {
    fn serialized_len(x: &bool) -> usize {
        Self::tls_serialized_len(x)
    }
}

impl Serializer<bool> for Boolean {
    fn serialize<W: Write>(x: &bool, writer: &mut W) -> Result<usize, tls_codec::Error> {
        Self::tls_serialize(x, writer)
    }
}

impl Deserializer<bool> for Boolean {
    fn deserialize<R: Read>(reader: &mut R) -> Result<bool, tls_codec::Error> {
        Self::tls_deserialize(reader)
    }
}
