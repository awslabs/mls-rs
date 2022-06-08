use std::{
    fmt::{self, Debug},
    ops::Deref,
};

use crate::cipher_suite::CipherSuite;
use tls_codec::Serialize;
use tls_codec_derive::{TlsDeserialize, TlsSerialize, TlsSize};

#[derive(Debug, TlsSerialize, TlsSize)]
struct RefHashInput<'a> {
    #[tls_codec(with = "crate::tls::ByteVec")]
    pub label: &'a [u8],
    #[tls_codec(with = "crate::tls::ByteVec")]
    pub value: &'a [u8],
}

#[derive(
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
pub struct HashReference(#[tls_codec(with = "crate::tls::ByteVec")] Vec<u8>);

impl Debug for HashReference {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("HashReference")
            .field(&hex::encode(&self.0))
            .finish()
    }
}

impl Deref for HashReference {
    type Target = Vec<u8>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl AsRef<[u8]> for HashReference {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl From<Vec<u8>> for HashReference {
    fn from(val: Vec<u8>) -> Self {
        Self(val)
    }
}

impl HashReference {
    pub fn compute(
        value: &[u8],
        label: &[u8],
        cipher_suite: CipherSuite,
    ) -> Result<HashReference, tls_codec::Error> {
        let input = RefHashInput { label, value };

        input
            .tls_serialize_detached()
            .map(|bytes| HashReference(cipher_suite.hash_function().digest(&bytes)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::{Deserialize, Serialize};

    #[cfg(target_arch = "wasm32")]
    use wasm_bindgen_test::wasm_bindgen_test as test;

    #[derive(Debug, Deserialize, Serialize)]
    struct TestCase {
        cipher_suite: u16,
        #[serde(with = "hex::serde")]
        input: Vec<u8>,
        #[serde(with = "hex::serde")]
        output: Vec<u8>,
    }

    const TEST_LABEL: &[u8] = b"test label";

    fn generate_hash_reference_test_cases() -> Vec<TestCase> {
        CipherSuite::all()
            .map(|cipher_suite| {
                let input = b"test input";
                let output = HashReference::compute(input, TEST_LABEL, cipher_suite).unwrap();

                TestCase {
                    cipher_suite: cipher_suite as u16,
                    input: input.to_vec(),
                    output: output.to_vec(),
                }
            })
            .collect()
    }

    fn load_test_cases() -> Vec<TestCase> {
        load_test_cases!(hash_reference, generate_hash_reference_test_cases)
    }

    #[test]
    fn test_hash_reference_construction() {
        let test_cases = load_test_cases();

        for test_case in test_cases {
            let cipher_suite = CipherSuite::from_raw(test_case.cipher_suite);

            if let Some(cipher_suite) = cipher_suite {
                let output =
                    HashReference::compute(&test_case.input, TEST_LABEL, cipher_suite).unwrap();

                assert_eq!(output.len(), cipher_suite.hash_function().digest_size());
                assert_eq!(output.as_ref(), &test_case.output);
            } else {
                println!("Skipping test case for unsupported cipher suite");
            }
        }
    }
}
