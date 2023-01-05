use crate::tls::{Deserializer, Serializer, Sizer, VarInt};
use std::convert::{TryFrom, TryInto};
use std::io::{Read, Write};
use tls_codec::{Deserialize, Serialize, Size};

/// Adapter for TLS serialization of arrays of bytes
pub struct ByteVec;

impl ByteVec {
    pub fn tls_serialized_len<T>(v: &T) -> usize
    where
        T: AsRef<[u8]> + ?Sized,
    {
        let len = v.as_ref().len();
        let header_length = VarInt::try_from(len)
            .expect("Slice has too many bytes to be serialized")
            .tls_serialized_len();
        header_length + len
    }

    pub fn tls_serialize<T, W>(v: &T, writer: &mut W) -> Result<usize, tls_codec::Error>
    where
        T: AsRef<[u8]> + ?Sized,
        W: Write,
    {
        let v = v.as_ref();
        let len = VarInt::try_from(v.len()).map_err(|_| tls_codec::Error::InvalidVectorLength)?;
        let written = len.tls_serialize(writer)?;
        writer.write_all(v)?;
        Ok(written + v.len())
    }

    pub fn tls_deserialize<T, R>(reader: &mut R) -> Result<T, tls_codec::Error>
    where
        T: From<Vec<u8>>,
        R: Read,
    {
        let len = VarInt::tls_deserialize(reader)?;
        let len: usize = len
            .try_into()
            .map_err(|_| tls_codec::Error::InvalidVectorLength)?;
        let mut buffer = vec![0; len];
        reader.read_exact(&mut buffer)?;
        Ok(buffer.into())
    }
}

impl<T> Sizer<T> for ByteVec
where
    T: AsRef<[u8]> + ?Sized,
{
    fn serialized_len(x: &T) -> usize {
        Self::tls_serialized_len(x.as_ref())
    }
}

impl<T> Serializer<T> for ByteVec
where
    T: AsRef<[u8]> + ?Sized,
{
    fn serialize<W: Write>(x: &T, writer: &mut W) -> Result<usize, tls_codec::Error> {
        Self::tls_serialize(x.as_ref(), writer)
    }
}

impl<T> Deserializer<T> for ByteVec
where
    T: From<Vec<u8>>,
{
    fn deserialize<R: Read>(reader: &mut R) -> Result<T, tls_codec::Error> {
        Self::tls_deserialize(reader)
    }
}

#[cfg(test)]
mod tests {
    use crate::tls::test_utils::ser_deser;
    use assert_matches::assert_matches;
    use std::iter::repeat;
    use tls_codec::{Deserialize, Serialize};
    use tls_codec_derive::{TlsDeserialize, TlsSerialize, TlsSize};

    #[cfg(target_arch = "wasm32")]
    use wasm_bindgen_test::wasm_bindgen_test as test;

    #[derive(Debug, PartialEq, TlsDeserialize, TlsSerialize, TlsSize)]
    struct Data(#[tls_codec(with = "crate::tls::ByteVec")] Vec<u8>);

    #[test]
    fn serialization_works() {
        assert_eq!(
            vec![3, 1, 2, 3],
            Data(vec![1, 2, 3]).tls_serialize_detached().unwrap()
        );
    }

    #[test]
    fn serialization_of_more_than_63_bytes_works() {
        let input = Data(repeat(5u8).take(257).collect());
        let expected = [0x41, 0x01]
            .into_iter()
            .chain(input.0.iter().copied())
            .collect::<Vec<_>>();
        assert_eq!(expected, input.tls_serialize_detached().unwrap());
    }

    #[test]
    fn serialization_of_more_than_16383_bytes_works() {
        let input = Data(repeat(5u8).take(65538).collect());
        let expected = [0x80, 0x01, 0x00, 0x02]
            .into_iter()
            .chain(input.0.iter().copied())
            .collect::<Vec<_>>();
        assert_eq!(expected, input.tls_serialize_detached().unwrap());
    }

    #[test]
    fn data_round_trips() {
        let x = Data(vec![1, 2, 3]);
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
            Data::tls_deserialize(&mut &[2u8, 3][..]),
            Err(tls_codec::Error::EndOfStream)
        );
    }
}
