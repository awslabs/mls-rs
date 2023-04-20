use core::ops::Deref;

use crate::client::MlsError;
use crate::serde_utils::vec_u8_as_base64::VecAsBase64;
use crate::CipherSuiteProvider;
use alloc::vec::Vec;
use aws_mls_codec::{MlsDecode, MlsEncode, MlsSize};
use serde_with::serde_as;

#[derive(Debug, MlsSize, MlsEncode)]
struct RefHashInput<'a> {
    #[mls_codec(with = "aws_mls_codec::byte_vec")]
    pub label: &'a [u8],
    #[mls_codec(with = "aws_mls_codec::byte_vec")]
    pub value: &'a [u8],
}

#[serde_as]
#[derive(
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Clone,
    MlsSize,
    MlsEncode,
    MlsDecode,
    serde::Deserialize,
    serde::Serialize,
)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct HashReference(
    #[mls_codec(with = "aws_mls_codec::byte_vec")]
    #[serde_as(as = "VecAsBase64")]
    Vec<u8>,
);

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
    ) -> Result<HashReference, MlsError> {
        let input = RefHashInput { label, value };

        input
            .mls_encode_to_vec()
            .map_err(Into::into)
            .and_then(|bytes| {
                Ok(HashReference(
                    cipher_suite
                        .hash(&bytes)
                        .map_err(|e| MlsError::CryptoProviderError(e.into()))?,
                ))
            })
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        cipher_suite::CipherSuite,
        crypto::test_utils::{test_cipher_suite_provider, try_test_cipher_suite_provider},
    };

    use super::*;
    use alloc::string::{String, ToString};
    use serde::{Deserialize, Serialize};

    #[cfg(target_arch = "wasm32")]
    use wasm_bindgen_test::wasm_bindgen_test as test;

    #[derive(Debug, Deserialize, Serialize)]
    struct HashRefTestCase {
        label: String,
        #[serde(with = "hex::serde")]
        value: Vec<u8>,
        #[serde(with = "hex::serde")]
        out: Vec<u8>,
    }

    #[derive(Debug, serde::Serialize, serde::Deserialize)]
    pub struct InteropTestCase {
        cipher_suite: u16,
        ref_hash: HashRefTestCase,
    }

    fn generate_hash_reference_test_cases() -> Vec<InteropTestCase> {
        CipherSuite::all()
            .map(|cipher_suite| {
                let provider = test_cipher_suite_provider(cipher_suite);

                let input = b"test input";
                let label = "test label";

                let output = HashReference::compute(input, label.as_bytes(), &provider).unwrap();

                let ref_hash = HashRefTestCase {
                    label: label.to_string(),
                    value: input.to_vec(),
                    out: output.to_vec(),
                };

                InteropTestCase {
                    cipher_suite: cipher_suite.into(),
                    ref_hash,
                }
            })
            .collect()
    }

    #[test]
    fn test_basic_crypto_test_vectors() {
        // The test vector can be found here https://github.com/mlswg/mls-implementations/blob/main/test-vectors/crypto-basics.json
        let test_cases: Vec<InteropTestCase> =
            load_test_cases!(basic_crypto, generate_hash_reference_test_cases());

        test_cases.into_iter().for_each(|test_case| {
            if let Some(cs) = try_test_cipher_suite_provider(test_case.cipher_suite) {
                let label = test_case.ref_hash.label.as_bytes();
                let value = &test_case.ref_hash.value;
                let computed = HashReference::compute(value, label, &cs).unwrap();
                assert_eq!(&*computed, &test_case.ref_hash.out);
            }
        })
    }
}
