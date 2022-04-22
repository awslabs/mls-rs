use serde::{
    de::{SeqAccess, Visitor},
    ser::SerializeSeq,
    Deserialize, Deserializer, Serialize, Serializer,
};
use std::{collections::HashMap, fmt, hash::Hash, marker::PhantomData};

pub fn serialize<K, V, S>(map: &HashMap<K, V>, serializer: S) -> Result<S::Ok, S::Error>
where
    K: Eq + Hash + Serialize,
    V: Serialize,
    S: Serializer,
{
    let mut seq = serializer.serialize_seq(Some(map.len()))?;
    map.iter()
        .try_for_each(|(k, v)| seq.serialize_element(&(k, v)))?;
    seq.end()
}

pub fn deserialize<'de, K, V, D>(deserializer: D) -> Result<HashMap<K, V>, D::Error>
where
    K: Eq + Hash + Deserialize<'de>,
    V: Deserialize<'de>,
    D: Deserializer<'de>,
{
    deserializer.deserialize_seq(MapVisitor(PhantomData))
}

struct MapVisitor<K, V>(PhantomData<(K, V)>);

impl<'de, K, V> Visitor<'de> for MapVisitor<K, V>
where
    K: Eq + Hash + Deserialize<'de>,
    V: Deserialize<'de>,
{
    type Value = HashMap<K, V>;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        write!(formatter, "a sequence of pairs")
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
        std::iter::from_fn(|| seq.next_element().transpose()).collect()
    }
}
