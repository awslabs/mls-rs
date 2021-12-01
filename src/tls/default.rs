use crate::tls::{Deserializer, Serializer, Sizer};
use std::io::{Read, Write};
use tls_codec::{Deserialize, Serialize, Size};

pub struct DefaultSer;

impl DefaultSer {
    pub fn tls_serialized_len<T: Size + ?Sized>(x: &T) -> usize {
        x.tls_serialized_len()
    }

    pub fn tls_serialize<T, W>(x: &T, writer: &mut W) -> Result<usize, tls_codec::Error>
    where
        T: Serialize + ?Sized,
        W: Write,
    {
        x.tls_serialize(writer)
    }

    pub fn tls_deserialize<T, R>(reader: &mut R) -> Result<T, tls_codec::Error>
    where
        T: Deserialize,
        R: Read,
    {
        T::tls_deserialize(reader)
    }
}

impl<T: Size + ?Sized> Sizer<T> for DefaultSer {
    fn serialized_len(x: &T) -> usize {
        Self::tls_serialized_len(x)
    }
}

impl<T: Serialize + ?Sized> Serializer<T> for DefaultSer {
    fn serialize<W: Write>(x: &T, writer: &mut W) -> Result<usize, tls_codec::Error> {
        Self::tls_serialize(x, writer)
    }
}

impl<T: Deserialize> Deserializer<T> for DefaultSer {
    fn deserialize<R: Read>(reader: &mut R) -> Result<T, tls_codec::Error> {
        Self::tls_deserialize(reader)
    }
}
