use crate::tls::{DefaultSer, Deserializer, Serializer, Sizer};
use std::{
    collections::HashMap,
    convert::TryFrom,
    hash::Hash,
    io::{Read, Write},
    mem::size_of,
};
use tls_codec::{Deserialize, Serialize};

/// Adapter for TLS serialization of maps
///
/// A map is serialized as a sequence of value-key pairs.
pub struct Map<KeySer = DefaultSer, ValueSer = DefaultSer>(KeySer, ValueSer);

pub type DefMap = Map;

impl<KeySer, ValueSer> Map<KeySer, ValueSer> {
    pub fn tls_serialized_len<K, V>(m: &HashMap<K, V>) -> usize
    where
        KeySer: Sizer<K>,
        ValueSer: Sizer<V>,
    {
        size_of::<u32>()
            + m.iter()
                .map(|(k, v)| KeySer::serialized_len(k) + ValueSer::serialized_len(v))
                .sum::<usize>()
    }

    pub fn tls_serialize<K, V, W>(
        m: &HashMap<K, V>,
        writer: &mut W,
    ) -> Result<usize, tls_codec::Error>
    where
        KeySer: Sizer<K> + Serializer<K>,
        ValueSer: Sizer<V> + Serializer<V>,
        W: Write,
    {
        let len = Self::tls_serialized_len(m) - size_of::<u32>();
        let len = u32::try_from(len).map_err(|_| tls_codec::Error::InvalidVectorLength)?;
        m.iter()
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
        let len = u32::tls_deserialize(reader)?;
        let len = usize::try_from(len).map_err(|_| tls_codec::Error::InvalidVectorLength)?;
        let mut read_len = 0;
        let mut m = HashMap::with_capacity(len);
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
