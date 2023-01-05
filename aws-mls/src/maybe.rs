use num_enum::TryFromPrimitive;
use std::io::{Read, Write};

#[derive(Clone, Debug, Copy, PartialEq, Eq)]
enum MaybeEnumInner<T>
where
    T: TryFromPrimitive,
{
    Enum(T),
    Other(T::Primitive),
}

#[derive(Clone, Debug, Copy, PartialEq, Eq)]
pub struct MaybeEnum<T: TryFromPrimitive>(MaybeEnumInner<T>);

impl<T> From<T> for MaybeEnum<T>
where
    T: TryFromPrimitive,
{
    fn from(value: T) -> Self {
        Self(MaybeEnumInner::Enum(value))
    }
}

#[cfg(feature = "arbitrary")]
impl<'a, T> arbitrary::Arbitrary<'a> for MaybeEnum<T>
where
    T: TryFromPrimitive,
    T::Primitive: arbitrary::Arbitrary<'a>,
{
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        Ok(Self::from_raw_value(arbitrary::Arbitrary::arbitrary(u)?))
    }
}

impl<T> MaybeEnum<T>
where
    T: TryFromPrimitive,
{
    pub fn from_raw_value(value: T::Primitive) -> Self {
        Self(
            T::try_from_primitive(value)
                .map_or_else(|_| MaybeEnumInner::Other(value), MaybeEnumInner::Enum),
        )
    }

    pub fn into_enum(self) -> Option<T> {
        match self.0 {
            MaybeEnumInner::Enum(e) => Some(e),
            MaybeEnumInner::Other(_) => None,
        }
    }
}

impl<T> MaybeEnum<T>
where
    T: Copy + TryFromPrimitive + Into<T::Primitive>,
{
    pub fn raw_value(&self) -> T::Primitive {
        match self.0 {
            MaybeEnumInner::Enum(item) => item.into(),
            MaybeEnumInner::Other(value) => value,
        }
    }
}

impl<T> serde::Serialize for MaybeEnum<T>
where
    T: Copy + TryFromPrimitive + Into<T::Primitive>,
    T::Primitive: serde::Serialize,
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.raw_value().serialize(serializer)
    }
}

impl<'de, T> serde::Deserialize<'de> for MaybeEnum<T>
where
    T: TryFromPrimitive,
    T::Primitive: serde::Deserialize<'de>,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let raw_value = serde::Deserialize::deserialize(deserializer)?;
        Ok(MaybeEnum::from_raw_value(raw_value))
    }
}

impl<T> tls_codec::Size for MaybeEnum<T>
where
    T: Copy + Into<T::Primitive> + TryFromPrimitive,
    T::Primitive: tls_codec::Size,
{
    fn tls_serialized_len(&self) -> usize {
        self.raw_value().tls_serialized_len()
    }
}

impl<T> tls_codec::Serialize for MaybeEnum<T>
where
    T: Copy + Into<T::Primitive> + TryFromPrimitive,
    T::Primitive: tls_codec::Serialize,
{
    fn tls_serialize<W: Write>(&self, writer: &mut W) -> Result<usize, tls_codec::Error> {
        self.raw_value().tls_serialize(writer)
    }
}

impl<T> tls_codec::Deserialize for MaybeEnum<T>
where
    T: Copy + Into<T::Primitive> + TryFromPrimitive,
    T::Primitive: tls_codec::Deserialize,
{
    fn tls_deserialize<R: Read>(bytes: &mut R) -> Result<Self, tls_codec::Error> {
        let raw_value = tls_codec::Deserialize::tls_deserialize(bytes)?;
        Ok(Self::from_raw_value(raw_value))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
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
        enum_iterator::Sequence,
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
        for enum_value in enum_iterator::all::<TestEnum>() {
            let maybe: MaybeEnum<TestEnum> = MaybeEnum::from_raw_value(enum_value as u8);
            assert_eq!(maybe, MaybeEnum::from(enum_value));
        }

        let test_val = 4u8;
        let other: MaybeEnum<TestEnum> = MaybeEnum::from_raw_value(test_val);
        assert_eq!(other.into_enum(), None);
        assert_eq!(other.raw_value(), test_val);
    }

    #[test]
    fn test_maybe_enum_serialize() {
        let supported = MaybeEnum::from(TestEnum::One);

        assert_eq!(
            TestEnum::One.tls_serialize_detached().unwrap(),
            supported.tls_serialize_detached().unwrap()
        );

        let not_supported: MaybeEnum<TestEnum> = MaybeEnum::from_raw_value(32);

        assert_eq!(
            32u8.tls_serialize_detached().unwrap(),
            not_supported.tls_serialize_detached().unwrap()
        );
    }

    #[test]
    fn test_maybe_enum_from() {
        let supported = MaybeEnum::from(TestEnum::One);

        assert_eq!(supported.into_enum(), Some(TestEnum::One));

        let unsupported: MaybeEnum<TestEnum> = MaybeEnum::from_raw_value(32);
        assert_eq!(unsupported.into_enum(), None);
        assert_eq!(unsupported.raw_value(), 32);
    }

    #[test]
    fn from_raw_value_and_raw_value_are_inverse() {
        for x in enum_iterator::all::<TestEnum>()
            .map(MaybeEnum::from)
            .chain(Some(MaybeEnum::from_raw_value(4)))
        {
            assert_eq!(x, MaybeEnum::from_raw_value(x.raw_value()));
        }
    }
}
