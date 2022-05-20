use std::ops::Deref;

use der::{Decoder, Encodable};
use ferriscrypt::asym::ec_key::{EcKeyError, PublicKey};
use spki::SubjectPublicKeyInfo;
use thiserror::Error;
use tls_codec_derive::{TlsDeserialize, TlsSerialize, TlsSize};

#[derive(Debug, Error)]
pub enum X509Error {
    #[error("Certificate parsing error: {0}")]
    CertificateParseError(der::Error),
    #[error("empty certificate chain found")]
    EmptyCertificateChain,
    #[error("unsupported public key type: {0}")]
    UnsupportedPublicKeyType(String),
    #[error(transparent)]
    EcKeyError(#[from] EcKeyError),
}

#[derive(
    Clone,
    Debug,
    PartialEq,
    TlsSize,
    TlsSerialize,
    TlsDeserialize,
    Eq,
    Hash,
    serde::Deserialize,
    serde::Serialize,
)]
pub struct CertificateData(#[tls_codec(with = "crate::tls::ByteVec")] Vec<u8>);

impl From<Vec<u8>> for CertificateData {
    fn from(data: Vec<u8>) -> Self {
        CertificateData(data)
    }
}

impl Deref for CertificateData {
    type Target = Vec<u8>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl CertificateData {
    pub fn public_key_data(&self) -> Result<Vec<u8>, X509Error> {
        // Current state of this function is as follows:
        // x509-parser crate has an unpatched sec vuln https://github.com/rusticata/x509-parser/issues/111
        // X509 crate in RustCrypto is experimental and does not expose certificate parsing yet
        // We only need to extract the public key, so we are directly using the RustCrypto der
        // crate, which is stable and will work well for this purpose. Applications using MLS still
        // need to write their own X509 validation code, so application developers can
        // choose whatever they like.
        let mut decoder = Decoder::new(&self.0).map_err(X509Error::CertificateParseError)?;

        decoder
            .sequence(|x509_decoder| {
                let pub_key_data = x509_decoder.sequence(|tbs_decoder| {
                    let _version = ::der::asn1::ContextSpecific::decode_explicit(
                        tbs_decoder,
                        ::der::TagNumber::N0,
                    )?
                    .map(|cs| cs.value)
                    .unwrap_or(0u8);

                    let _serial_number = tbs_decoder.any()?;
                    let _signature = tbs_decoder.any()?;
                    let _issuer = tbs_decoder.any()?;
                    let _validity = tbs_decoder.any()?;
                    let _subject = tbs_decoder.any()?;

                    let subject_public_key_info: SubjectPublicKeyInfo = tbs_decoder.decode()?;

                    while !tbs_decoder.is_finished() {
                        tbs_decoder.any()?;
                    }

                    subject_public_key_info.to_vec()
                })?;

                while !x509_decoder.is_finished() {
                    x509_decoder.any()?;
                }

                Ok(pub_key_data)
            })
            .map_err(X509Error::CertificateParseError)
    }

    pub fn public_key(&self) -> Result<PublicKey, X509Error> {
        PublicKey::from_der(&self.public_key_data()?).map_err(Into::into)
    }
}

#[derive(
    Clone,
    Debug,
    PartialEq,
    TlsSize,
    TlsSerialize,
    TlsDeserialize,
    Eq,
    Hash,
    serde::Deserialize,
    serde::Serialize,
)]
pub struct CertificateChain(#[tls_codec(with = "crate::tls::DefVec")] Vec<CertificateData>);

impl From<Vec<CertificateData>> for CertificateChain {
    fn from(cert_data: Vec<CertificateData>) -> Self {
        CertificateChain(cert_data)
    }
}

impl Deref for CertificateChain {
    type Target = Vec<CertificateData>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl CertificateChain {
    pub fn empty() -> Self {
        Self(vec![])
    }

    pub fn leaf(&self) -> Result<&CertificateData, X509Error> {
        self.0.first().ok_or(X509Error::EmptyCertificateChain)
    }
}

#[cfg(test)]
pub(crate) mod test_utils {
    use super::CertificateData;
    use ferriscrypt::asym::ec_key::{Curve, SecretKey};

    pub fn test_cert(curve: Curve) -> CertificateData {
        let data = match curve {
            Curve::P256 => include_bytes!("../test_data/p256_cert.der").to_vec(),
            #[cfg(feature = "openssl_engine")]
            Curve::P384 => include_bytes!("../test_data/p384_cert.der").to_vec(),
            #[cfg(feature = "openssl_engine")]
            Curve::P521 => include_bytes!("../test_data/p521_cert.der").to_vec(),
            Curve::Ed25519 => include_bytes!("../test_data/ed25519_cert.der").to_vec(),
            #[cfg(feature = "openssl_engine")]
            Curve::Ed448 => include_bytes!("../test_data/ed448_cert.der").to_vec(),
            _ => panic!("invalid test curve"),
        };

        CertificateData::from(data)
    }

    pub fn test_key(curve: Curve) -> SecretKey {
        let data = match curve {
            Curve::P256 => include_bytes!("../test_data/p256_key.der").to_vec(),
            #[cfg(feature = "openssl_engine")]
            Curve::P384 => include_bytes!("../test_data/p384_key.der").to_vec(),
            #[cfg(feature = "openssl_engine")]
            Curve::P521 => include_bytes!("../test_data/p521_key.der").to_vec(),
            Curve::Ed25519 => include_bytes!("../test_data/ed25519_key.der").to_vec(),
            #[cfg(feature = "openssl_engine")]
            Curve::Ed448 => include_bytes!("../test_data/ed448_key.der").to_vec(),
            _ => panic!("invalid test curve"),
        };

        SecretKey::from_der(&data).unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::x509::test_utils::{test_cert, test_key};
    use assert_matches::assert_matches;
    use ferriscrypt::asym::ec_key::Curve;

    #[cfg(target_arch = "wasm32")]
    use wasm_bindgen_test::wasm_bindgen_test as test;

    #[test]
    fn test_certificate_public_key() {
        let signing_curves = [
            Curve::P256,
            #[cfg(feature = "openssl_engine")]
            Curve::P384,
            #[cfg(feature = "openssl_engine")]
            Curve::P521,
            Curve::Ed25519,
            #[cfg(feature = "openssl_engine")]
            Curve::Ed448,
        ];

        for curve in signing_curves {
            println!("Running certificate parsing test for curve {:?}", curve);

            let cert_data = test_cert(curve);
            let cert_key = cert_data.public_key().unwrap();
            let expected_key = test_key(curve).to_public().unwrap();

            assert_eq!(cert_key, expected_key)
        }
    }

    #[test]
    fn test_empty_certificate_chain() {
        let empty_chain = CertificateChain::from(vec![]);
        assert_matches!(empty_chain.leaf(), Err(X509Error::EmptyCertificateChain));
    }

    #[test]
    fn test_leaf_certificate() {
        let test_chain =
            CertificateChain::from(vec![test_cert(Curve::P256), test_cert(Curve::Ed25519)]);

        assert_eq!(test_chain.leaf().unwrap(), &test_cert(Curve::P256));
    }
}
