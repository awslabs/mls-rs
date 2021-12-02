use crate::tls::{Deserializer, Serializer, Sizer};
use std::convert::{TryFrom, TryInto};
use std::{
    io::{Read, Write},
    mem::size_of,
};
use tls_codec::{Deserialize, Serialize};

pub struct ByteVec<I = u32>(I);

impl<I> ByteVec<I>
where
    I: TryFrom<usize> + TryInto<usize> + Serialize + Deserialize,
{
    pub fn tls_serialized_len(v: &[u8]) -> usize {
        size_of::<I>() + v.len()
    }

    pub fn tls_serialize<W: Write>(v: &[u8], writer: &mut W) -> Result<usize, tls_codec::Error> {
        let len = I::try_from(v.len()).map_err(|_| tls_codec::Error::InvalidVectorLength)?;
        let written = len.tls_serialize(writer)?;
        writer.write_all(v)?;
        Ok(written + v.len())
    }

    pub fn tls_deserialize<T, R>(reader: &mut R) -> Result<T, tls_codec::Error>
    where
        T: From<Vec<u8>>,
        R: Read,
    {
        let len = I::tls_deserialize(reader)?;
        let len: usize = len
            .try_into()
            .map_err(|_| tls_codec::Error::InvalidVectorLength)?;
        let mut buffer = vec![0; len];
        reader.read_exact(&mut buffer)?;
        Ok(buffer.into())
    }
}

impl<I, T> Sizer<T> for ByteVec<I>
where
    I: TryFrom<usize> + TryInto<usize> + Serialize + Deserialize,
    T: AsRef<[u8]> + ?Sized,
{
    fn serialized_len(x: &T) -> usize {
        Self::tls_serialized_len(x.as_ref())
    }
}

impl<I, T> Serializer<T> for ByteVec<I>
where
    I: TryFrom<usize> + TryInto<usize> + Serialize + Deserialize,
    T: AsRef<[u8]> + ?Sized,
{
    fn serialize<W: Write>(x: &T, writer: &mut W) -> Result<usize, tls_codec::Error> {
        Self::tls_serialize(x.as_ref(), writer)
    }
}

impl<I, T> Deserializer<T> for ByteVec<I>
where
    I: TryFrom<usize> + TryInto<usize> + Serialize + Deserialize,
    T: From<Vec<u8>>,
{
    fn deserialize<R: Read>(reader: &mut R) -> Result<T, tls_codec::Error> {
        Self::tls_deserialize(reader)
    }
}
