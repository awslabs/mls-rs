use std::ops::Deref;

use crate::cipher_suite::CipherSuite;
use ferriscrypt::kdf::{hkdf::Hkdf, KdfError};
use tls_codec_derive::{TlsDeserialize, TlsSerialize, TlsSize};

#[derive(
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Clone,
    TlsDeserialize,
    TlsSerialize,
    TlsSize,
    serde::Deserialize,
    serde::Serialize,
)]
pub struct HashReference([u8; 16]);

impl Deref for HashReference {
    type Target = [u8; 16];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl AsRef<[u8]> for HashReference {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl From<[u8; 16]> for HashReference {
    fn from(val: [u8; 16]) -> Self {
        Self(val)
    }
}

impl HashReference {
    pub fn from_value(
        value: &[u8],
        label: &[u8],
        cipher_suite: CipherSuite,
    ) -> Result<HashReference, KdfError> {
        let kdf = Hkdf::new(cipher_suite.hash_function());

        let extracted = kdf.extract(value, &[])?;

        let mut res = [0u8; 16];
        kdf.expand(&extracted, label, &mut res)?;

        Ok(HashReference(res))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;
    use thiserror::Error;

    #[cfg(target_arch = "wasm32")]
    use wasm_bindgen_test::wasm_bindgen_test as test;

    #[derive(Debug, Deserialize)]
    struct TestCase {
        cipher_suite: u16,
        #[serde(deserialize_with = "hex::serde::deserialize")]
        input: Vec<u8>,
        #[serde(deserialize_with = "hex::serde::deserialize")]
        output: Vec<u8>,
    }

    #[derive(Debug, Error)]
    enum TestError {
        #[error(transparent)]
        KdfError(#[from] KdfError),
        #[error(transparent)]
        TlsCodecError(#[from] tls_codec::Error),
    }

    #[test]
    fn test_hash_reference_construction() {
        let test_cases: Vec<TestCase> =
            serde_json::from_slice(include_bytes!("../test_data/hash_reference.json")).unwrap();

        for test_case in test_cases {
            let cipher_suite = CipherSuite::from_raw(test_case.cipher_suite);

            if let Some(cipher_suite) = cipher_suite {
                let output =
                    HashReference::from_value(&test_case.input, b"MLS 1.0 ref", cipher_suite)
                        .unwrap();

                assert_eq!(output.as_ref(), &test_case.output);
            } else {
                println!("Skipping test case for unsupported cipher suite");
            }
        }
    }
}
