use aws_mls_codec::{MlsDecode, MlsEncode, MlsSize};
use zeroize::Zeroizing;

use crate::{
    crypto::CipherSuiteProvider,
    group::{epoch::SenderDataSecret, framing::ContentType, key_schedule::kdf_expand_with_label},
    tree_kem::node::LeafIndex,
};

use super::{CiphertextProcessorError, ReuseGuard};

#[derive(Clone, Debug, PartialEq, Eq, MlsSize, MlsEncode, MlsDecode)]
pub(crate) struct SenderData {
    pub sender: LeafIndex,
    pub generation: u32,
    pub reuse_guard: ReuseGuard,
}

#[derive(Clone, Debug, PartialEq, Eq, MlsSize, MlsEncode, MlsDecode)]
pub(crate) struct SenderDataAAD {
    #[mls_codec(with = "aws_mls_codec::byte_vec")]
    pub group_id: Vec<u8>,
    pub epoch: u64,
    pub content_type: ContentType,
}

#[derive(Debug)]
pub(crate) struct SenderDataKey<'a, CP: CipherSuiteProvider> {
    pub(crate) key: Zeroizing<Vec<u8>>,
    pub(crate) nonce: Zeroizing<Vec<u8>>,
    cipher_suite_provider: &'a CP,
}

impl<'a, CP: CipherSuiteProvider> SenderDataKey<'a, CP> {
    pub(super) fn new(
        sender_data_secret: &SenderDataSecret,
        ciphertext: &[u8],
        cipher_suite_provider: &'a CP,
    ) -> Result<Self, CiphertextProcessorError> {
        // Sample the first extract_size bytes of the ciphertext, and if it is shorter, just use
        // the ciphertext itself
        let extract_size = cipher_suite_provider.kdf_extract_size();
        let ciphertext_sample = ciphertext.get(0..extract_size).unwrap_or(ciphertext);

        // Generate a sender data key and nonce using the sender_data_secret from the current
        // epoch's key schedule
        let key = kdf_expand_with_label(
            cipher_suite_provider,
            sender_data_secret,
            "key",
            ciphertext_sample,
            Some(cipher_suite_provider.aead_key_size()),
        )?;

        let nonce = kdf_expand_with_label(
            cipher_suite_provider,
            sender_data_secret,
            "nonce",
            ciphertext_sample,
            Some(cipher_suite_provider.aead_nonce_size()),
        )?;

        Ok(Self {
            key,
            nonce,
            cipher_suite_provider,
        })
    }

    pub(crate) fn seal(
        &self,
        sender_data: &SenderData,
        aad: &SenderDataAAD,
    ) -> Result<Vec<u8>, CiphertextProcessorError> {
        self.cipher_suite_provider
            .aead_seal(
                &self.key,
                &sender_data.mls_encode_to_vec()?,
                Some(&aad.mls_encode_to_vec()?),
                &self.nonce,
            )
            .map_err(|e| CiphertextProcessorError::CipherSuiteProviderError(e.into()))
    }

    pub(crate) fn open(
        &self,
        sender_data: &[u8],
        aad: &SenderDataAAD,
    ) -> Result<SenderData, CiphertextProcessorError> {
        self.cipher_suite_provider
            .aead_open(
                &self.key,
                sender_data,
                Some(&aad.mls_encode_to_vec()?),
                &self.nonce,
            )
            .map_err(|e| CiphertextProcessorError::CipherSuiteProviderError(e.into()))
            .and_then(|data| SenderData::mls_decode(&**data).map_err(From::from))
    }
}

#[cfg(test)]
pub(crate) mod test_utils {
    use aws_mls_core::crypto::CipherSuiteProvider;

    use super::SenderDataKey;

    #[derive(Debug, serde::Serialize, serde::Deserialize)]
    pub struct InteropSenderData {
        #[serde(with = "hex::serde")]
        pub sender_data_secret: Vec<u8>,
        #[serde(with = "hex::serde")]
        pub ciphertext: Vec<u8>,
        #[serde(with = "hex::serde")]
        pub key: Vec<u8>,
        #[serde(with = "hex::serde")]
        pub nonce: Vec<u8>,
    }

    impl InteropSenderData {
        pub(crate) fn new<P: CipherSuiteProvider>(cs: &P) -> Self {
            let secret = cs.random_bytes_vec(cs.kdf_extract_size()).unwrap().into();
            let ciphertext = cs.random_bytes_vec(77).unwrap();
            let key = SenderDataKey::new(&secret, &ciphertext, cs).unwrap();
            let secret = (*secret).clone();

            Self {
                ciphertext,
                key: key.key.to_vec(),
                nonce: key.nonce.to_vec(),
                sender_data_secret: secret,
            }
        }

        pub fn verify<P: CipherSuiteProvider>(&self, cs: &P) {
            let secret = self.sender_data_secret.clone().into();
            let key = SenderDataKey::new(&secret, &self.ciphertext, cs).unwrap();
            assert_eq!(key.key.to_vec(), self.key, "sender data key mismatch");
            assert_eq!(key.nonce.to_vec(), self.nonce, "sender data nonce mismatch");
        }
    }
}

#[cfg(test)]
mod tests {

    #[cfg(target_arch = "wasm32")]
    use wasm_bindgen_test::wasm_bindgen_test as test;

    use crate::{
        cipher_suite::CipherSuite,
        crypto::test_utils::{test_cipher_suite_provider, try_test_cipher_suite_provider},
        group::{
            ciphertext_processor::reuse_guard::ReuseGuard, framing::ContentType,
            test_utils::random_bytes,
        },
        tree_kem::node::LeafIndex,
        CipherSuiteProvider,
    };

    use super::{SenderData, SenderDataAAD, SenderDataKey};

    #[derive(serde::Deserialize, serde::Serialize)]
    struct TestCase {
        cipher_suite: u16,
        #[serde(with = "hex::serde")]
        secret: Vec<u8>,
        #[serde(with = "hex::serde")]
        ciphertext_bytes: Vec<u8>,
        #[serde(with = "hex::serde")]
        expected_key: Vec<u8>,
        #[serde(with = "hex::serde")]
        expected_nonce: Vec<u8>,
        sender_data: TestSenderData,
        sender_data_aad: TestSenderDataAAD,
        #[serde(with = "hex::serde")]
        expected_ciphertext: Vec<u8>,
    }

    #[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
    struct TestSenderData {
        sender: u32,
        generation: u32,
        #[serde(with = "hex::serde")]
        reuse_guard: Vec<u8>,
    }

    impl From<TestSenderData> for SenderData {
        fn from(value: TestSenderData) -> Self {
            let reuse_guard = ReuseGuard::new(value.reuse_guard);

            Self {
                sender: LeafIndex(value.sender),
                generation: value.generation,
                reuse_guard,
            }
        }
    }

    #[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
    struct TestSenderDataAAD {
        epoch: u64,
        #[serde(with = "hex::serde")]
        group_id: Vec<u8>,
    }

    impl From<TestSenderDataAAD> for SenderDataAAD {
        fn from(value: TestSenderDataAAD) -> Self {
            Self {
                epoch: value.epoch,
                group_id: value.group_id,
                content_type: ContentType::Application,
            }
        }
    }

    fn generate_sender_data_key_test_vector() -> Vec<TestCase> {
        let test_cases = CipherSuite::all()
            .map(test_cipher_suite_provider)
            .map(|provider| {
                let ext_size = provider.kdf_extract_size();
                let secret = random_bytes(ext_size).into();
                let ciphertext_sizes = [ext_size - 5, ext_size, ext_size + 5];

                let sender_data = TestSenderData {
                    sender: 0,
                    generation: 13,
                    reuse_guard: random_bytes(4),
                };

                let sender_data_aad = TestSenderDataAAD {
                    group_id: b"group".to_vec(),
                    epoch: 42,
                };

                ciphertext_sizes.into_iter().map(move |ciphertext_size| {
                    let ciphertext_bytes = random_bytes(ciphertext_size);

                    let sender_data_key =
                        SenderDataKey::new(&secret, &ciphertext_bytes, &provider).unwrap();

                    let expected_ciphertext = sender_data_key
                        .seal(&sender_data.clone().into(), &sender_data_aad.clone().into())
                        .unwrap();

                    TestCase {
                        cipher_suite: provider.cipher_suite().into(),
                        secret: secret.to_vec(),
                        ciphertext_bytes,
                        expected_key: sender_data_key.key.to_vec(),
                        expected_nonce: sender_data_key.nonce.to_vec(),
                        sender_data: sender_data.clone(),
                        sender_data_aad: sender_data_aad.clone(),
                        expected_ciphertext,
                    }
                })
            });

        test_cases.flatten().collect()
    }

    fn load_test_cases() -> Vec<TestCase> {
        load_test_cases!(
            sender_data_key_test_vector,
            generate_sender_data_key_test_vector()
        )
    }

    #[test]
    fn sender_data_key_test_vector() {
        for test_case in load_test_cases() {
            let Some(provider) = try_test_cipher_suite_provider(test_case.cipher_suite) else {
                continue;
            };

            let sender_data_key = SenderDataKey::new(
                &test_case.secret.into(),
                &test_case.ciphertext_bytes,
                &provider,
            )
            .unwrap();

            assert_eq!(sender_data_key.key.to_vec(), test_case.expected_key);
            assert_eq!(sender_data_key.nonce.to_vec(), test_case.expected_nonce);

            let sender_data = test_case.sender_data.into();
            let sender_data_aad = test_case.sender_data_aad.into();

            let ciphertext = sender_data_key
                .seal(&sender_data, &sender_data_aad)
                .unwrap();

            assert_eq!(ciphertext, test_case.expected_ciphertext);

            let plaintext = sender_data_key.open(&ciphertext, &sender_data_aad).unwrap();

            assert_eq!(plaintext, sender_data);
        }
    }
}
