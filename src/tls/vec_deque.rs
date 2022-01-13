use crate::tls::{DefaultSer, Deserializer, Serializer, Sizer};
use std::{
    collections::VecDeque,
    convert::{TryFrom, TryInto},
    io::{Read, Write},
    mem::size_of,
};
use tls_codec::{Deserialize, Serialize};

use super::Vector;

/// Adapter for TLS serialization of VecDeque
///
/// `I` is the index type specifying how many bytes to use for the length in bytes of the VecDeque.
pub struct VectorDeque<I = u32, S = DefaultSer>(I, S);

pub type DefVecDeque<I> = VectorDeque<I>;

impl<I, S> VectorDeque<I, S>
where
    I: TryFrom<usize> + TryInto<usize> + Serialize + Deserialize,
{
    pub fn tls_serialized_len<T>(v: &VecDeque<T>) -> usize
    where
        S: Sizer<T>,
    {
        size_of::<I>() + v.iter().map(|x| S::serialized_len(x)).sum::<usize>()
    }

    pub fn tls_serialize<W, T>(v: &VecDeque<T>, writer: &mut W) -> Result<usize, tls_codec::Error>
    where
        S: Sizer<T> + Serializer<T>,
        W: Write,
    {
        let len = Self::tls_serialized_len(v) - size_of::<I>();
        let len = I::try_from(len).map_err(|_| tls_codec::Error::InvalidVectorLength)?;
        v.iter().try_fold(len.tls_serialize(writer)?, |acc, x| {
            Ok(acc + S::serialize(x, writer)?)
        })
    }

    pub fn tls_deserialize<T, R>(reader: &mut R) -> Result<VecDeque<T>, tls_codec::Error>
    where
        S: Sizer<T> + Deserializer<T>,
        R: Read,
    {
        let v = Vector::<I, S>::tls_deserialize(reader)?;
        Ok(VecDeque::from(v))
    }
}

impl<I, S, T> Sizer<VecDeque<T>> for VectorDeque<I, S>
where
    I: TryFrom<usize> + TryInto<usize> + Serialize + Deserialize,
    S: Sizer<T>,
{
    fn serialized_len(x: &VecDeque<T>) -> usize {
        Self::tls_serialized_len(x)
    }
}

impl<I, S, T> Serializer<VecDeque<T>> for VectorDeque<I, S>
where
    I: TryFrom<usize> + TryInto<usize> + Serialize + Deserialize,
    S: Sizer<T> + Serializer<T>,
{
    fn serialize<W: Write>(x: &VecDeque<T>, writer: &mut W) -> Result<usize, tls_codec::Error> {
        Self::tls_serialize(x, writer)
    }
}

impl<I, S, T> Deserializer<VecDeque<T>> for VectorDeque<I, S>
where
    I: TryFrom<usize> + TryInto<usize> + Serialize + Deserialize,
    S: Sizer<T> + Deserializer<T>,
{
    fn deserialize<R: Read>(reader: &mut R) -> Result<VecDeque<T>, tls_codec::Error> {
        Self::tls_deserialize(reader)
    }
}

#[cfg(test)]
mod tests {
    use crate::tls::test_util::ser_deser;
    use assert_matches::assert_matches;
    use std::collections::VecDeque;
    use tls_codec::{Deserialize, Serialize};
    use tls_codec_derive::{TlsDeserialize, TlsSerialize, TlsSize};

    #[derive(Clone, Copy, Debug, PartialEq, TlsDeserialize, TlsSerialize, TlsSize)]
    struct Item(u8);

    #[derive(Debug, PartialEq, TlsDeserialize, TlsSerialize, TlsSize)]
    struct Data(#[tls_codec(with = "crate::tls::DefVecDeque::<u16>")] VecDeque<Item>);

    #[test]
    fn serialization_works() {
        assert_eq!(
            VecDeque::from([0, 3, 1, 2, 3]),
            Data(VecDeque::from([Item(1), Item(2), Item(3)]))
                .tls_serialize_detached()
                .unwrap()
        );
    }

    #[test]
    fn data_round_trips() {
        let x = Data(VecDeque::from([Item(1), Item(2), Item(3)]));
        assert_eq!(x, ser_deser(&x).unwrap());
    }

    #[test]
    fn empty_vec_deque_can_be_deserialized() {
        assert_eq!(
            Data(VecDeque::new()),
            Data::tls_deserialize(&mut &[0u8, 0][..]).unwrap()
        );
    }

    #[test]
    fn too_few_items_to_deserialize_gives_an_error() {
        assert_matches!(
            Data::tls_deserialize(&mut &[0u8, 2, 3][..]),
            Err(tls_codec::Error::EndOfStream)
        );
    }

    #[test]
    fn serializing_oversized_vec_deque_fails() {
        assert_matches!(
            Data(vec![Item(1); usize::from(u16::MAX) + 1].into()).tls_serialize_detached(),
            Err(tls_codec::Error::InvalidVectorLength)
        );
    }
}
