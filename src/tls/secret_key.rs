use crate::tls::{Deserializer, Serializer, Sizer};
use ferriscrypt::asym::ec_key::SecretKey;
use std::io::{Read, Write};
use tls_codec::{Deserialize, Serialize, Size, TlsByteVecU32};

/// Adapter for TLS serialization of secret keys
pub struct SecretKeySer;

impl SecretKeySer {
    pub fn tls_serialized_len(key: &SecretKey) -> usize {
        // TODO: Unwrapping may be inappropriate here. Also, converting to DER just for the sake of
        // getting the length seems inefficient.
        TlsByteVecU32::new(key.to_der().unwrap()).tls_serialized_len()
    }

    pub fn tls_serialize<W: Write>(
        key: &SecretKey,
        writer: &mut W,
    ) -> Result<usize, tls_codec::Error> {
        let bytes = key
            .to_der()
            .map_err(|e| tls_codec::Error::EncodingError(e.to_string()))?;
        TlsByteVecU32::new(bytes).tls_serialize(writer)
    }

    pub fn tls_deserialize<R: Read>(reader: &mut R) -> Result<SecretKey, tls_codec::Error> {
        let bytes = TlsByteVecU32::tls_deserialize(reader)?.into_vec();
        SecretKey::from_der(&bytes).map_err(|e| tls_codec::Error::DecodingError(e.to_string()))
    }
}

impl Sizer<SecretKey> for SecretKeySer {
    fn serialized_len(key: &SecretKey) -> usize {
        Self::tls_serialized_len(key)
    }
}

impl Serializer<SecretKey> for SecretKeySer {
    fn serialize<W: Write>(key: &SecretKey, writer: &mut W) -> Result<usize, tls_codec::Error> {
        Self::tls_serialize(key, writer)
    }
}

impl Deserializer<SecretKey> for SecretKeySer {
    fn deserialize<R: Read>(reader: &mut R) -> Result<SecretKey, tls_codec::Error> {
        Self::tls_deserialize(reader)
    }
}

#[cfg(test)]
mod tests {
    use crate::tls::ser_deser;
    use ferriscrypt::asym::ec_key::{Curve, SecretKey};
    use tls_codec_derive::{TlsDeserialize, TlsSerialize, TlsSize};

    #[derive(Debug, PartialEq, TlsDeserialize, TlsSerialize, TlsSize)]
    struct Data(#[tls_codec(with = "crate::tls::SecretKeySer")] SecretKey);

    #[test]
    fn data_round_trips() {
        let key = Data(SecretKey::generate(Curve::Ed25519).unwrap());
        assert_eq!(key, ser_deser(&key).unwrap());
    }
}
