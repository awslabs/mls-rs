use base64::display::Base64Display;
use serde::de::{self, Visitor};
use serde::Deserialize;
use serde::{Deserializer, Serializer};
use serde_with::{DeserializeAs, SerializeAs};

pub struct VecAsBase64;

impl<T> SerializeAs<T> for VecAsBase64
where
    T: AsRef<[u8]>,
{
    fn serialize_as<S>(source: &T, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if !serializer.is_human_readable() {
            return serializer.serialize_bytes(source.as_ref());
        }

        serializer.collect_str(&Base64Display::with_config(
            source.as_ref(),
            base64::STANDARD,
        ))
    }
}

impl<'de, T> DeserializeAs<'de, T> for VecAsBase64
where
    T: From<Vec<u8>>,
{
    fn deserialize_as<D>(deserializer: D) -> Result<T, D::Error>
    where
        D: Deserializer<'de>,
    {
        if !deserializer.is_human_readable() {
            let vec_u8 = Vec::deserialize(deserializer)?;
            return Ok(T::from(vec_u8));
        }

        struct Base64Visitor;

        impl Visitor<'_> for Base64Visitor {
            type Value = Vec<u8>;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("a base64 string")
            }

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                base64::decode(v).map_err(de::Error::custom)
            }
        }

        let vec_u8 = deserializer.deserialize_str(Base64Visitor)?;

        Ok(T::from(vec_u8))
    }
}
