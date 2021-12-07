use crate::tls::{Deserializer, Serializer, Sizer};
use std::io::{Read, Write};
use tls_codec::{Deserialize, Serialize};

/// Adapter for TLS serialization of boolean values
///
/// `false` is serialized as `0u8` and `true` is serialized as `1u8`.
pub struct Boolean;

impl Boolean {
    pub fn tls_serialized_len(_: &bool) -> usize {
        1
    }

    pub fn tls_serialize<W: Write>(b: &bool, writer: &mut W) -> Result<usize, tls_codec::Error> {
        (*b as u8).tls_serialize(writer)
    }

    pub fn tls_deserialize<R: Read>(reader: &mut R) -> Result<bool, tls_codec::Error> {
        Ok(u8::tls_deserialize(reader)? != 0)
    }
}

impl Sizer<bool> for Boolean {
    fn serialized_len(x: &bool) -> usize {
        Self::tls_serialized_len(x)
    }
}

impl Serializer<bool> for Boolean {
    fn serialize<W: Write>(x: &bool, writer: &mut W) -> Result<usize, tls_codec::Error> {
        Self::tls_serialize(x, writer)
    }
}

impl Deserializer<bool> for Boolean {
    fn deserialize<R: Read>(reader: &mut R) -> Result<bool, tls_codec::Error> {
        Self::tls_deserialize(reader)
    }
}

#[cfg(test)]
mod tests {
    use crate::tls::test_util::ser_deser;
    use tls_codec::Serialize;
    use tls_codec_derive::{TlsDeserialize, TlsSerialize, TlsSize};

    #[derive(Debug, PartialEq, TlsDeserialize, TlsSerialize, TlsSize)]
    struct Data(#[tls_codec(with = "crate::tls::Boolean")] bool);

    #[test]
    fn false_is_serialized_correctly() {
        assert_eq!(vec![0u8], Data(false).tls_serialize_detached().unwrap());
    }

    #[test]
    fn true_is_serialized_correctly() {
        assert_eq!(vec![1u8], Data(true).tls_serialize_detached().unwrap());
    }

    #[test]
    fn false_round_trips() {
        let x = Data(false);
        assert_eq!(x, ser_deser(&x).unwrap());
    }

    #[test]
    fn true_round_trips() {
        let x = Data(true);
        assert_eq!(x, ser_deser(&x).unwrap());
    }
}
