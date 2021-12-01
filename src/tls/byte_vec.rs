use crate::tls::{Deserializer, Serializer, Sizer};
use std::io::{Read, Write};
use tls_codec::{Deserialize, Serialize, Size, TlsByteSliceU32, TlsByteVecU32};

pub struct ByteVec;

impl ByteVec {
    pub fn tls_serialized_len(v: &[u8]) -> usize {
        TlsByteSliceU32(v).tls_serialized_len()
    }

    pub fn tls_serialize<W: Write>(v: &[u8], writer: &mut W) -> Result<usize, tls_codec::Error> {
        TlsByteSliceU32(v).tls_serialize(writer)
    }

    pub fn tls_deserialize<T, R>(reader: &mut R) -> Result<T, tls_codec::Error>
    where
        T: From<Vec<u8>>,
        R: Read,
    {
        Ok(TlsByteVecU32::tls_deserialize(reader)?.into_vec().into())
    }
}

impl<T: AsRef<[u8]> + ?Sized> Sizer<T> for ByteVec {
    fn serialized_len(x: &T) -> usize {
        Self::tls_serialized_len(x.as_ref())
    }
}

impl<T: AsRef<[u8]> + ?Sized> Serializer<T> for ByteVec {
    fn serialize<W: Write>(x: &T, writer: &mut W) -> Result<usize, tls_codec::Error> {
        Self::tls_serialize(x.as_ref(), writer)
    }
}

impl<T: From<Vec<u8>>> Deserializer<T> for ByteVec {
    fn deserialize<R: Read>(reader: &mut R) -> Result<T, tls_codec::Error> {
        Self::tls_deserialize(reader)
    }
}
