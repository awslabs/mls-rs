use aws_mls_core::crypto::{CipherSuiteProvider, HpkeCiphertext, HpkePublicKey, HpkeSecretKey};
use thiserror::Error;
use tls_codec::{Deserialize, Serialize};
use tls_codec_derive::{TlsSerialize, TlsSize};

#[derive(Debug, Clone, TlsSize, TlsSerialize)]
struct EncryptContext<'a> {
    #[tls_codec(with = "crate::tls::ByteVec")]
    label: Vec<u8>,
    #[tls_codec(with = "crate::tls::ByteVec")]
    context: &'a [u8],
}

impl<'a> EncryptContext<'a> {
    pub fn new(label: &str, context: &'a [u8]) -> Self {
        Self {
            label: format!("MLS 1.0 {label}").into_bytes(),
            context,
        }
    }
}

#[derive(Debug, Error)]
pub enum HpkeEncryptionError {
    #[error(transparent)]
    TlsSerializationError(#[from] tls_codec::Error),
    #[error("internal hpke error: {0:?}")]
    InternalHpkeError(#[source] Box<dyn std::error::Error + Send + Sync>),
}

pub(crate) trait HpkeEncryptable: Serialize + Deserialize + Sized {
    const ENCRYPT_LABEL: &'static str;

    fn encrypt<P: CipherSuiteProvider>(
        &self,
        cipher_suite_provider: &P,
        public_key: &HpkePublicKey,
        context: &[u8],
    ) -> Result<HpkeCiphertext, HpkeEncryptionError> {
        let context = EncryptContext::new(Self::ENCRYPT_LABEL, context).tls_serialize_detached()?;
        let content = self.tls_serialize_detached()?;

        cipher_suite_provider
            .hpke_seal(public_key, &context, None, &content)
            .map_err(|e| HpkeEncryptionError::InternalHpkeError(e.into()))
    }

    fn decrypt<P: CipherSuiteProvider>(
        cipher_suite_provider: &P,
        secret_key: &HpkeSecretKey,
        context: &[u8],
        ciphertext: &HpkeCiphertext,
    ) -> Result<Self, HpkeEncryptionError> {
        let context = EncryptContext::new(Self::ENCRYPT_LABEL, context).tls_serialize_detached()?;

        let plaintext = cipher_suite_provider
            .hpke_open(ciphertext, secret_key, &context, None)
            .map_err(|e| HpkeEncryptionError::InternalHpkeError(e.into()))?;

        Ok(Self::tls_deserialize(&mut &*plaintext)?)
    }
}

#[cfg(test)]
pub(crate) mod test_utils {
    use std::io::{Read, Write};

    use aws_mls_core::crypto::{CipherSuiteProvider, HpkeCiphertext};
    use tls_codec::{Deserialize, Serialize, Size};

    use crate::crypto::test_utils::try_test_cipher_suite_provider;

    use super::HpkeEncryptable;

    #[derive(Debug, serde::Serialize, serde::Deserialize)]
    pub struct HpkeInteropTestCase {
        #[serde(with = "hex::serde", rename = "priv")]
        secret: Vec<u8>,
        #[serde(with = "hex::serde", rename = "pub")]
        public: Vec<u8>,
        label: String,
        #[serde(with = "hex::serde")]
        context: Vec<u8>,
        #[serde(with = "hex::serde")]
        plaintext: Vec<u8>,
        #[serde(with = "hex::serde")]
        kem_output: Vec<u8>,
        #[serde(with = "hex::serde")]
        ciphertext: Vec<u8>,
    }

    #[derive(Debug, serde::Serialize, serde::Deserialize)]
    pub struct InteropTestCase {
        cipher_suite: u16,
        encrypt_with_label: HpkeInteropTestCase,
    }

    #[test]
    fn test_basic_crypto_test_vectors() {
        // The test vector can be found here https://github.com/mlswg/mls-implementations/blob/main/test-vectors/crypto-basics.json
        let test_cases: Vec<InteropTestCase> =
            load_test_cases!(basic_crypto, Vec::<InteropTestCase>::new());

        test_cases.into_iter().for_each(|test_case| {
            if let Some(cs) = try_test_cipher_suite_provider(test_case.cipher_suite) {
                test_case.encrypt_with_label.verify(&cs)
            }
        })
    }

    #[derive(Clone, Debug)]
    struct TestEncryptable(Vec<u8>);

    impl HpkeEncryptable for TestEncryptable {
        const ENCRYPT_LABEL: &'static str = "EncryptWithLabel";
    }

    impl Size for TestEncryptable {
        fn tls_serialized_len(&self) -> usize {
            self.0.len()
        }
    }

    impl Serialize for TestEncryptable {
        fn tls_serialize<W: Write>(&self, writer: &mut W) -> Result<usize, tls_codec::Error> {
            writer.write_all(&self.0)?;
            Ok(self.0.len())
        }
    }

    impl Deserialize for TestEncryptable {
        fn tls_deserialize<R: Read>(reader: &mut R) -> Result<Self, tls_codec::Error> {
            let mut buf = vec![];
            reader.read_to_end(&mut buf)?;
            Ok(Self(buf))
        }
    }

    impl HpkeInteropTestCase {
        pub fn verify<P: CipherSuiteProvider>(&self, cs: &P) {
            let secret = self.secret.clone().into();

            let ciphertext = HpkeCiphertext {
                kem_output: self.kem_output.clone(),
                ciphertext: self.ciphertext.clone(),
            };

            let computed_plaintext =
                TestEncryptable::decrypt(cs, &secret, &self.context, &ciphertext).unwrap();

            assert_eq!(&computed_plaintext.0, &self.plaintext)
        }
    }
}
