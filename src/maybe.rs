use num_enum::TryFromPrimitive;
use std::io::{Read, Write};

#[derive(Clone, Debug, Copy, PartialEq)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub enum MaybeEnum<T, V>
where
    T: TryFromPrimitive<Primitive = V>,
{
    Enum(T),
    Other(V),
}

impl<T, V> From<T> for MaybeEnum<T, V>
where
    T: TryFromPrimitive<Primitive = V>,
{
    fn from(value: T) -> Self {
        MaybeEnum::Enum(value)
    }
}

impl<T, V> MaybeEnum<T, V>
where
    T: Copy + Into<V> + TryFromPrimitive<Primitive = V>,
    V: Copy,
{
    pub fn from_raw_value(value: V) -> Self {
        T::try_from_primitive(value)
            .map(MaybeEnum::Enum)
            .unwrap_or_else(|_| MaybeEnum::Other(value))
    }

    pub fn raw_value(&self) -> V {
        match self {
            MaybeEnum::Enum(item) => (*item).into(),
            MaybeEnum::Other(value) => *value,
        }
    }

    pub fn into_enum(self) -> Option<T> {
        match self {
            MaybeEnum::Enum(e) => Some(e),
            MaybeEnum::Other(_) => None,
        }
    }
}

impl<T, V> serde::Serialize for MaybeEnum<T, V>
where
    T: Copy + Into<V> + TryFromPrimitive<Primitive = V>,
    V: Copy + serde::Serialize,
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.raw_value().serialize(serializer)
    }
}

impl<'de, T, V> serde::Deserialize<'de> for MaybeEnum<T, V>
where
    T: Copy + Into<V> + TryFromPrimitive<Primitive = V>,
    V: Copy + serde::Deserialize<'de>,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let raw_value = V::deserialize(deserializer)?;
        Ok(MaybeEnum::from_raw_value(raw_value))
    }
}

impl<T, V> tls_codec::Size for MaybeEnum<T, V>
where
    T: Copy + Into<V> + TryFromPrimitive<Primitive = V>,
    V: Copy + tls_codec::Size,
{
    fn tls_serialized_len(&self) -> usize {
        self.raw_value().tls_serialized_len()
    }
}

impl<T, V> tls_codec::Serialize for MaybeEnum<T, V>
where
    T: Copy + Into<V> + TryFromPrimitive<Primitive = V>,
    V: Copy + tls_codec::Serialize,
{
    fn tls_serialize<W: Write>(&self, writer: &mut W) -> Result<usize, tls_codec::Error> {
        self.raw_value().tls_serialize(writer)
    }
}

impl<T, V> tls_codec::Deserialize for MaybeEnum<T, V>
where
    T: Copy + Into<V> + TryFromPrimitive<Primitive = V>,
    V: Copy + tls_codec::Deserialize,
{
    fn tls_deserialize<R: Read>(bytes: &mut R) -> Result<Self, tls_codec::Error>
    where
        Self: Sized,
    {
        let raw_value = V::tls_deserialize(bytes)?;
        Ok(Self::from_raw_value(raw_value))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use assert_matches::assert_matches;
    use enum_iterator::IntoEnumIterator;
    use num_enum::IntoPrimitive;
    use tls_codec::Serialize;

    use tls_codec_derive::{TlsDeserialize, TlsSerialize, TlsSize};
    #[cfg(target_arch = "wasm32")]
    use wasm_bindgen_test::wasm_bindgen_test as test;

    #[derive(
        Debug,
        PartialEq,
        IntoPrimitive,
        TryFromPrimitive,
        IntoEnumIterator,
        Clone,
        Copy,
        TlsSize,
        TlsSerialize,
        TlsDeserialize,
    )]
    #[repr(u8)]
    enum TestEnum {
        One = 1,
        Two,
        Three,
    }

    #[test]
    fn test_maybe_enum() {
        for enum_value in TestEnum::into_enum_iter() {
            let maybe: MaybeEnum<TestEnum, _> = MaybeEnum::from_raw_value(enum_value as u8);
            assert_matches!(maybe, MaybeEnum::Enum(v) if v == enum_value);
        }

        let test_val = 4u8;
        let other: MaybeEnum<TestEnum, _> = MaybeEnum::from_raw_value(test_val);
        assert_eq!(other, MaybeEnum::Other(test_val));
    }

    #[test]
    fn test_maybe_enum_serialize() {
        let supported = MaybeEnum::Enum(TestEnum::One);

        assert_eq!(
            TestEnum::One.tls_serialize_detached().unwrap(),
            supported.tls_serialize_detached().unwrap()
        );

        let not_supported: MaybeEnum<TestEnum, _> = MaybeEnum::Other(32);

        assert_eq!(
            32u8.tls_serialize_detached().unwrap(),
            not_supported.tls_serialize_detached().unwrap()
        );
    }

    #[test]
    fn test_maybe_enum_from() {
        let supported = MaybeEnum::Enum(TestEnum::One);

        assert_eq!(MaybeEnum::from(TestEnum::One), supported);

        let unsupported: MaybeEnum<TestEnum, _> = MaybeEnum::Other(32);
        assert_eq!(MaybeEnum::from_raw_value(32u8), unsupported);
    }
}
