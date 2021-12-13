use crate::tls::{Deserializer, Serializer, Sizer};
use ferriscrypt::x509::CertificateChain;
use std::io::{Read, Write};
use tls_codec::{Deserialize, Serialize, Size};
use tls_codec_derive::{TlsDeserialize, TlsSerialize, TlsSize};

#[derive(TlsSerialize, TlsDeserialize, TlsSize)]
struct CertificateChainAdapter(
    #[tls_codec(with = "crate::tls::Vector::<u32, crate::tls::ByteVec::<u16>>")] Vec<Vec<u8>>,
);

/// Adapter for TLS serialization of secret keys
pub struct CertificateChainSer;

impl CertificateChainSer {
    pub fn tls_serialized_len(chain: &CertificateChain) -> usize {
        // TODO: Unwrapping may be inappropriate here. Also, converting to DER just for the sake of
        // getting the length seems inefficient.
        CertificateChainAdapter(chain.to_der().unwrap()).tls_serialized_len()
    }

    pub fn tls_serialize<W: Write>(
        key: &CertificateChain,
        writer: &mut W,
    ) -> Result<usize, tls_codec::Error> {
        let adapter = key
            .to_der()
            .map(CertificateChainAdapter)
            .map_err(|e| tls_codec::Error::EncodingError(e.to_string()))?;
        adapter.tls_serialize(writer)
    }

    pub fn tls_deserialize<R: Read>(reader: &mut R) -> Result<CertificateChain, tls_codec::Error> {
        let adapter = CertificateChainAdapter::tls_deserialize(reader)?;

        CertificateChain::from_der(&adapter.0)
            .map_err(|e| tls_codec::Error::DecodingError(e.to_string()))
    }
}

impl Sizer<CertificateChain> for CertificateChainSer {
    fn serialized_len(chain: &CertificateChain) -> usize {
        Self::tls_serialized_len(chain)
    }
}

impl Serializer<CertificateChain> for CertificateChainSer {
    fn serialize<W: Write>(
        chain: &CertificateChain,
        writer: &mut W,
    ) -> Result<usize, tls_codec::Error> {
        Self::tls_serialize(chain, writer)
    }
}

impl Deserializer<CertificateChain> for CertificateChainSer {
    fn deserialize<R: Read>(reader: &mut R) -> Result<CertificateChain, tls_codec::Error> {
        Self::tls_deserialize(reader)
    }
}

#[cfg(test)]
mod tests {
    use crate::tls::test_util::ser_deser;
    use ferriscrypt::x509::CertificateChain;
    use tls_codec_derive::{TlsDeserialize, TlsSerialize, TlsSize};

    #[derive(Debug, TlsDeserialize, TlsSerialize, TlsSize)]
    struct Data(#[tls_codec(with = "crate::tls::CertificateChainSer")] CertificateChain);

    #[test]
    fn data_round_trips() {
        let cert_pem_data = include_bytes!("../../test_data/certs.pem");
        let certificate_chain = Data(CertificateChain::from_pem(cert_pem_data).unwrap());

        // Serialize / Deserialize the Data type, and then convert it back into its original
        // PEM format to verify correctness
        let res = ser_deser::<Data>(&certificate_chain)
            .unwrap()
            .0
            .to_pem()
            .unwrap();

        assert_eq!(res, cert_pem_data);
    }
}
