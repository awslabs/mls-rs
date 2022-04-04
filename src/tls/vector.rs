use crate::tls::{DefaultSer, Deserializer, ReadWithCount, Serializer, Sizer, VarInt};
use std::{
    convert::{TryFrom, TryInto},
    io::{Read, Write},
};
use tls_codec::{Deserialize, Serialize, Size};

/// Adapter for TLS serialization of vectors
pub struct Vector<S = DefaultSer>(S);

pub type DefVec = Vector;

impl<S> Vector<S> {
    pub fn tls_serialized_len<T>(v: &[T]) -> usize
    where
        S: Sizer<T>,
    {
        let len = v.iter().map(|x| S::serialized_len(x)).sum::<usize>();
        let header_length = VarInt::try_from(len)
            .expect("The size of the slice in bytes is too large to serialize it")
            .tls_serialized_len();
        header_length + len
    }

    pub fn tls_serialize<W, T>(v: &[T], writer: &mut W) -> Result<usize, tls_codec::Error>
    where
        S: Sizer<T> + Serializer<T>,
        W: Write,
    {
        let mut buffer = Vec::new();
        let len = v.iter().try_fold(0, |acc, x| {
            Ok::<_, tls_codec::Error>(acc + S::serialize(x, &mut buffer)?)
        })?;
        let len = VarInt::try_from(len).map_err(|_| tls_codec::Error::InvalidVectorLength)?;
        let written = len.tls_serialize(writer)?;
        writer.write_all(&buffer)?;
        Ok(written + buffer.len())
    }

    pub fn tls_deserialize<T, R>(reader: &mut R) -> Result<Vec<T>, tls_codec::Error>
    where
        S: Sizer<T> + Deserializer<T>,
        R: Read,
    {
        let len = VarInt::tls_deserialize(reader)?;
        let len: usize = len
            .try_into()
            .map_err(|_| tls_codec::Error::InvalidVectorLength)?;
        let reader = &mut ReadWithCount::new(reader);
        let mut items = Vec::new();
        while reader.bytes_read() < len {
            items.push(S::deserialize(reader)?);
        }
        Ok(items)
    }
}

impl<S, T> Sizer<[T]> for Vector<S>
where
    S: Sizer<T>,
{
    fn serialized_len(x: &[T]) -> usize {
        Self::tls_serialized_len(x)
    }
}

impl<S, T> Sizer<Vec<T>> for Vector<S>
where
    S: Sizer<T>,
{
    fn serialized_len(x: &Vec<T>) -> usize {
        Self::tls_serialized_len(x)
    }
}

impl<S, T> Serializer<[T]> for Vector<S>
where
    S: Sizer<T> + Serializer<T>,
{
    fn serialize<W: Write>(x: &[T], writer: &mut W) -> Result<usize, tls_codec::Error> {
        Self::tls_serialize(x, writer)
    }
}

impl<S, T> Serializer<Vec<T>> for Vector<S>
where
    S: Sizer<T> + Serializer<T>,
{
    fn serialize<W: Write>(x: &Vec<T>, writer: &mut W) -> Result<usize, tls_codec::Error> {
        Self::tls_serialize(x, writer)
    }
}

impl<S, T> Deserializer<Vec<T>> for Vector<S>
where
    S: Sizer<T> + Deserializer<T>,
{
    fn deserialize<R: Read>(reader: &mut R) -> Result<Vec<T>, tls_codec::Error> {
        Self::tls_deserialize(reader)
    }
}

#[cfg(test)]
mod tests {
    use crate::tls::test_utils::ser_deser;
    use assert_matches::assert_matches;
    use tls_codec::{Deserialize, Serialize};
    use tls_codec_derive::{TlsDeserialize, TlsSerialize, TlsSize};

    #[cfg(target_arch = "wasm32")]
    use wasm_bindgen_test::wasm_bindgen_test as test;

    #[derive(Clone, Copy, Debug, PartialEq, TlsDeserialize, TlsSerialize, TlsSize)]
    struct Item(u8);

    #[derive(Debug, PartialEq, TlsDeserialize, TlsSerialize, TlsSize)]
    struct Data(#[tls_codec(with = "crate::tls::DefVec")] Vec<Item>);

    #[test]
    fn serialization_works() {
        assert_eq!(
            vec![3, 1, 2, 3],
            Data(vec![Item(1), Item(2), Item(3)])
                .tls_serialize_detached()
                .unwrap()
        );
    }

    #[test]
    fn data_round_trips() {
        let x = Data(vec![Item(1), Item(2), Item(3)]);
        assert_eq!(x, ser_deser(&x).unwrap());
    }

    #[test]
    fn empty_vec_can_be_deserialized() {
        assert_eq!(
            Data(Vec::new()),
            Data::tls_deserialize(&mut &[0u8][..]).unwrap()
        );
    }

    #[test]
    fn too_few_items_to_deserialize_gives_an_error() {
        assert_matches!(
            Data::tls_deserialize(&mut &[2, 3][..]),
            Err(tls_codec::Error::EndOfStream)
        );
    }
}
