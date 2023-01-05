use crate::tls::{DefaultSer, Deserializer, Serializer, Sizer, VarInt};
use std::{
    collections::HashMap,
    convert::TryFrom,
    hash::Hash,
    io::{Read, Write},
};
use tls_codec::{Deserialize, Serialize, Size};

/// Adapter for TLS serialization of maps
///
/// A map is serialized as a sequence of value-key pairs.
pub struct Map<KeySer = DefaultSer, ValueSer = DefaultSer>(KeySer, ValueSer);

pub type DefMap = Map;

impl<KeySer, ValueSer> Map<KeySer, ValueSer> {
    fn serialized_len_without_header<K, V>(m: &HashMap<K, V>) -> usize
    where
        KeySer: Sizer<K>,
        ValueSer: Sizer<V>,
    {
        m.iter()
            .map(|(k, v)| KeySer::serialized_len(k) + ValueSer::serialized_len(v))
            .sum::<usize>()
    }

    pub fn tls_serialized_len<K, V>(m: &HashMap<K, V>) -> usize
    where
        KeySer: Sizer<K>,
        ValueSer: Sizer<V>,
    {
        let len = Self::serialized_len_without_header(m);
        let header_length = VarInt::try_from(len)
            .expect("The size of the map in bytes is too large to serialize it")
            .tls_serialized_len();
        header_length + len
    }

    pub fn tls_serialize<K, V, W>(
        m: &HashMap<K, V>,
        writer: &mut W,
    ) -> Result<usize, tls_codec::Error>
    where
        KeySer: Sizer<K> + Serializer<K>,
        ValueSer: Sizer<V> + Serializer<V>,
        W: Write,
        K: Ord,
    {
        let len = Self::serialized_len_without_header(m);
        let len = VarInt::try_from(len).map_err(|_| tls_codec::Error::InvalidVectorLength)?;
        // HashMap item order is not deterministic so sort by key to regain determinism when
        // serializing.
        let mut items = m.iter().collect::<Vec<_>>();
        items.sort_by_key(|&(k, _)| k);
        items
            .iter()
            .try_fold(len.tls_serialize(writer)?, |acc, (k, v)| {
                Ok(acc + KeySer::serialize(k, writer)? + ValueSer::serialize(v, writer)?)
            })
    }

    pub fn tls_deserialize<K, V, R>(reader: &mut R) -> Result<HashMap<K, V>, tls_codec::Error>
    where
        K: Eq + Hash,
        KeySer: Sizer<K> + Deserializer<K>,
        ValueSer: Sizer<V> + Deserializer<V>,
        R: Read,
    {
        let len = VarInt::tls_deserialize(reader)?;
        let len = usize::try_from(len).map_err(|_| tls_codec::Error::InvalidVectorLength)?;
        let mut read_len = 0;
        let mut m = HashMap::new();
        while read_len < len {
            let k = KeySer::deserialize(reader)?;
            read_len += KeySer::serialized_len(&k);
            let v = ValueSer::deserialize(reader)?;
            read_len += ValueSer::serialized_len(&v);
            m.insert(k, v);
        }
        Ok(m)
    }
}

impl<KeySer, ValueSer, K, V> Sizer<HashMap<K, V>> for Map<KeySer, ValueSer>
where
    KeySer: Sizer<K>,
    ValueSer: Sizer<V>,
{
    fn serialized_len(m: &HashMap<K, V>) -> usize {
        Self::tls_serialized_len(m)
    }
}

impl<KeySer, ValueSer, K, V> Serializer<HashMap<K, V>> for Map<KeySer, ValueSer>
where
    KeySer: Sizer<K> + Serializer<K>,
    ValueSer: Sizer<V> + Serializer<V>,
    K: Ord,
{
    fn serialize<W: Write>(m: &HashMap<K, V>, writer: &mut W) -> Result<usize, tls_codec::Error> {
        Self::tls_serialize(m, writer)
    }
}

impl<KeySer, ValueSer, K, V> Deserializer<HashMap<K, V>> for Map<KeySer, ValueSer>
where
    KeySer: Sizer<K> + Deserializer<K>,
    ValueSer: Sizer<V> + Deserializer<V>,
    K: Eq + Hash,
{
    fn deserialize<R: Read>(reader: &mut R) -> Result<HashMap<K, V>, tls_codec::Error> {
        Self::tls_deserialize(reader)
    }
}

#[cfg(test)]
mod tests {
    use crate::tls::test_utils::ser_deser;
    use assert_matches::assert_matches;
    use std::collections::HashMap;
    use tls_codec::{Deserialize, Serialize};
    use tls_codec_derive::{TlsDeserialize, TlsSerialize, TlsSize};

    #[cfg(target_arch = "wasm32")]
    use wasm_bindgen_test::wasm_bindgen_test as test;

    #[derive(Debug, PartialEq, TlsDeserialize, TlsSerialize, TlsSize)]
    struct Data(#[tls_codec(with = "crate::tls::DefMap")] HashMap<u8, u16>);

    #[test]
    fn serialization_works() {
        assert_eq!(
            vec![6, 1, 0, 10, 2, 0, 20],
            Data([(1, 10), (2, 20)].into_iter().collect())
                .tls_serialize_detached()
                .unwrap()
        );
    }

    #[test]
    fn data_round_trips() {
        let x = Data([(1, 10), (2, 20)].into_iter().collect());
        assert_eq!(x, ser_deser(&x).unwrap());
    }

    #[test]
    fn empty_map_can_be_deserialized() {
        assert_eq!(
            Data(Default::default()),
            Data::tls_deserialize(&mut &[0][..]).unwrap()
        );
    }

    #[test]
    fn missing_value_gives_an_error() {
        assert_matches!(
            Data::tls_deserialize(&mut &[6, 1, 0, 10, 2][..]),
            Err(tls_codec::Error::EndOfStream)
        );
    }
}
