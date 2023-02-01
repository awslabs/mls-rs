use std::{
    fmt::{self, Debug},
    ops::Deref,
};

use crate::serde_utils::vec_u8_as_base64::VecAsBase64;
use crate::{cipher_suite::CipherSuite, provider::crypto::CipherSuiteProvider};
use serde_with::serde_as;
use thiserror::Error;
use tls_codec::Serialize;
use tls_codec_derive::{TlsDeserialize, TlsSerialize, TlsSize};

#[derive(Debug, Error)]
pub enum HashReferenceError {
    #[error(transparent)]
    TlsCodecError(#[from] tls_codec::Error),
    #[error(transparent)]
    CipherSuiteProviderError(Box<dyn std::error::Error + Send + Sync + 'static>),
    #[error("cipher suite {0:?} is invalid for calculating hash references of this object")]
    InvalidCipherSuite(CipherSuite),
}

#[derive(Debug, TlsSerialize, TlsSize)]
struct RefHashInput<'a> {
    #[tls_codec(with = "crate::tls::ByteVec")]
    pub label: &'a [u8],
    #[tls_codec(with = "crate::tls::ByteVec")]
    pub value: &'a [u8],
}

#[serde_as]
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
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct HashReference(
    #[tls_codec(with = "crate::tls::ByteVec")]
    #[serde_as(as = "VecAsBase64")]
    Vec<u8>,
);

impl Debug for HashReference {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("HashReference")
            .field(&hex::encode(&self.0))
            .finish()
    }
}

impl Deref for HashReference {
    type Target = [u8];

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
    pub fn compute<P: CipherSuiteProvider>(
        value: &[u8],
        label: &[u8],
        cipher_suite: &P,
    ) -> Result<HashReference, HashReferenceError> {
        let input = RefHashInput { label, value };

        input
            .tls_serialize_detached()
            .map_err(Into::into)
            .and_then(|bytes| {
                Ok(HashReference(cipher_suite.hash(&bytes).map_err(|e| {
                    HashReferenceError::CipherSuiteProviderError(e.into())
                })?))
            })
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        cipher_suite::CipherSuite,
        provider::crypto::test_utils::{
            test_cipher_suite_provider, try_test_cipher_suite_provider,
        },
    };

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
                let provider = test_cipher_suite_provider(cipher_suite);

                let input = b"test input";
                let output = HashReference::compute(input, TEST_LABEL, &provider).unwrap();

                TestCase {
                    cipher_suite: cipher_suite.into(),
                    input: input.to_vec(),
                    output: output.to_vec(),
                }
            })
            .collect()
    }

    fn load_test_cases() -> Vec<TestCase> {
        load_test_cases!(hash_reference, generate_hash_reference_test_cases())
    }

    #[test]
    fn test_hash_reference_construction() {
        let test_cases = load_test_cases();

        for test_case in test_cases {
            let Some(provider) = try_test_cipher_suite_provider(test_case.cipher_suite) else {
                continue;
            };

            let output = HashReference::compute(&test_case.input, TEST_LABEL, &provider).unwrap();

            assert_eq!(output.len(), provider.kdf_extract_size());
            assert_eq!(output.as_ref(), &test_case.output);
        }
    }
}
