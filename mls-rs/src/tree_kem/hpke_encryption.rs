// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// Copyright by contributors to this project.
// SPDX-License-Identifier: (Apache-2.0 OR MIT)

use alloc::vec::Vec;
use mls_rs_codec::{MlsEncode, MlsSize};

use crate::client::MlsError;

#[derive(Debug, Clone, MlsSize, MlsEncode)]
struct EncryptContext<'a> {
    #[mls_codec(with = "mls_rs_codec::byte_vec")]
    label: Vec<u8>,
    #[mls_codec(with = "mls_rs_codec::byte_vec")]
    context: &'a [u8],
}

impl<'a> EncryptContext<'a> {
    pub fn new(label: &str, context: &'a [u8]) -> Self {
        Self {
            label: [b"MLS 1.0 ", label.as_bytes()].concat(),
            context,
        }
    }
}

pub(crate) trait HpkeInfo {
    const ENCRYPT_LABEL: &'static str;

    fn hpke_info(context: &[u8]) -> Result<Vec<u8>, MlsError> {
        Ok(EncryptContext::new(Self::ENCRYPT_LABEL, context).mls_encode_to_vec()?)
    }
}

#[cfg(test)]
pub(crate) mod test_utils {
    use alloc::{string::String, vec::Vec};
    use mls_rs_codec::{MlsDecode, MlsEncode, MlsSize};
    use mls_rs_core::crypto::{CipherSuiteProvider, HpkeCiphertext};

    use crate::crypto::test_utils::try_test_cipher_suite_provider;

    use super::HpkeInfo;

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

    #[maybe_async::test(not(mls_build_async), async(mls_build_async, crate::futures_test))]
    async fn test_basic_crypto_test_vectors() {
        // The test vector can be found here https://github.com/mlswg/mls-implementations/blob/main/test-vectors/crypto-basics.json
        let test_cases: Vec<InteropTestCase> =
            load_test_case_json!(basic_crypto, Vec::<InteropTestCase>::new());

        for test_case in test_cases {
            if let Some(cs) = try_test_cipher_suite_provider(test_case.cipher_suite) {
                test_case.encrypt_with_label.verify(&cs).await
            }
        }
    }

    #[derive(Clone, Debug, MlsSize, MlsEncode, MlsDecode)]
    struct TestInfo;

    impl HpkeInfo for TestInfo {
        const ENCRYPT_LABEL: &'static str = "EncryptWithLabel";
    }

    impl HpkeInteropTestCase {
        #[cfg_attr(not(mls_build_async), maybe_async::must_be_sync)]
        pub async fn verify<P: CipherSuiteProvider>(&self, cs: &P) {
            let secret = self.secret.clone().into();
            let public = self.public.clone().into();

            let ciphertext = HpkeCiphertext {
                kem_output: self.kem_output.clone(),
                ciphertext: self.ciphertext.clone(),
            };

            let info = TestInfo::hpke_info(&self.context).unwrap();

            let computed_plaintext = cs
                .hpke_open(&ciphertext, &secret, &public, &info, None)
                .await
                .unwrap();

            assert_eq!(&computed_plaintext, &self.plaintext)
        }
    }
}
