use crate::tls::{DefaultSer, Deserializer, Serializer, Sizer};
use std::io::{Read, Write};
use tls_codec::{Deserialize, Serialize};

/// Adapter for TLS serialization of optional values
///
/// `None` is serialized as `0u8` and `Some(x)` is serialized as `1u8` followed by the serialization
/// of `x` using the `S` adapter.
pub struct Optional<S = DefaultSer>(S);

impl<S> Optional<S> {
    pub fn tls_serialized_len<T>(x: &Option<T>) -> usize
    where
        S: Sizer<T>,
    {
        1 + x.as_ref().map_or(0, |x| S::serialized_len(x))
    }

    pub fn tls_serialize<W, T>(x: &Option<T>, writer: &mut W) -> Result<usize, tls_codec::Error>
    where
        S: Serializer<T>,
        W: Write,
    {
        match x {
            Some(x) => Ok(1u8.tls_serialize(writer)? + S::serialize(x, writer)?),
            None => 0u8.tls_serialize(writer),
        }
    }

    pub fn tls_deserialize<T, R>(reader: &mut R) -> Result<Option<T>, tls_codec::Error>
    where
        S: Deserializer<T>,
        R: Read,
    {
        match u8::tls_deserialize(reader)? {
            0 => Ok(None),
            1 => Ok(Some(S::deserialize(reader)?)),
            _ => Err(tls_codec::Error::DecodingError(
                "Invalid Option discriminant".into(),
            )),
        }
    }
}

impl<S, T> Sizer<Option<T>> for Optional<S>
where
    S: Sizer<T>,
{
    fn serialized_len(x: &Option<T>) -> usize {
        Self::tls_serialized_len(x)
    }
}

impl<S, T> Serializer<Option<T>> for Optional<S>
where
    S: Serializer<T>,
{
    fn serialize<W: Write>(x: &Option<T>, writer: &mut W) -> Result<usize, tls_codec::Error> {
        Self::tls_serialize(x, writer)
    }
}

impl<S, T> Deserializer<Option<T>> for Optional<S>
where
    S: Deserializer<T>,
{
    fn deserialize<R: Read>(reader: &mut R) -> Result<Option<T>, tls_codec::Error> {
        Self::tls_deserialize(reader)
    }
}

#[cfg(test)]
mod tests {
    use crate::tls::ser_deser;
    use tls_codec::{Deserialize, Serialize};
    use tls_codec_derive::{TlsDeserialize, TlsSerialize, TlsSize};

    #[derive(Debug, PartialEq, TlsDeserialize, TlsSerialize, TlsSize)]
    struct Data(#[tls_codec(with = "crate::tls::Optional::<crate::tls::DefaultSer>")] Option<u8>);

    #[test]
    fn none_is_serialized_correctly() {
        assert_eq!(vec![0u8], Data(None).tls_serialize_detached().unwrap());
    }

    #[test]
    fn some_is_serialized_correctly() {
        assert_eq!(
            vec![1u8, 2],
            Data(Some(2)).tls_serialize_detached().unwrap()
        );
    }

    #[test]
    fn none_round_trips() {
        let x = Data(None);
        assert_eq!(x, ser_deser(&x).unwrap());
    }

    #[test]
    fn some_round_trips() {
        let x = Data(Some(2));
        assert_eq!(x, ser_deser(&x).unwrap());
    }

    #[test]
    fn deserializing_invalid_discriminant_fails() {
        assert!(matches!(
            Data::tls_deserialize(&mut &[2u8][..]),
            Err(tls_codec::Error::DecodingError(_))
        ));
    }
}
