// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// Copyright by contributors to this project.
// SPDX-License-Identifier: (Apache-2.0 OR MIT)

use mls_rs_core::crypto::CipherSuite;
use mls_rs_crypto_traits::{KdfId, KdfType};

use js_sys::Uint8Array;
use wasm_bindgen_futures::JsFuture;
use web_sys::SubtleCrypto;

use crate::{get_crypto, key_type::KeyType, CryptoError};

#[derive(Clone)]
pub struct Hkdf {
    key_type: KeyType,
    kdf_id: KdfId,
    hash: &'static str,
    blocksize: usize,
}

impl Hkdf {
    pub fn new(cipher_suite: CipherSuite) -> Option<Self> {
        let kdf_id = KdfId::new(cipher_suite)?;

        let (hash, blocksize) = match kdf_id {
            KdfId::HkdfSha256 => ("SHA-256", 64),
            KdfId::HkdfSha384 => ("SHA-384", 128),
            KdfId::HkdfSha512 => ("SHA-512", 128),
            _ => return None,
        };

        Some(Self {
            key_type: KeyType::Hmac(hash),
            kdf_id,
            hash,
            blocksize,
        })
    }
}

#[maybe_async::must_be_async(?Send)]
impl KdfType for Hkdf {
    type Error = CryptoError;

    fn kdf_id(&self) -> u16 {
        self.kdf_id as u16
    }

    async fn expand(&self, prk: &[u8], info: &[u8], len: usize) -> Result<Vec<u8>, Self::Error> {
        if len == 0 {
            return Ok(Vec::new());
        }

        let mut out = vec![0u8; len];
        let (mut i, mut t) = (1u8, Vec::new());

        for chunk in out.chunks_mut(self.extract_size()) {
            let input = [&t, info, &i.to_be_bytes()].concat();
            t = self.hmac(prk, &input).await?;
            chunk.copy_from_slice(&t[0..chunk.len()]);
            i += 1;
        }

        Ok(out)
    }

    async fn extract(&self, salt: &[u8], ikm: &[u8]) -> Result<Vec<u8>, Self::Error> {
        self.hmac(salt, ikm).await
    }

    fn extract_size(&self) -> usize {
        self.kdf_id.extract_size()
    }
}

impl Hkdf {
    const IPAD: u8 = 0x36;
    const OPAD: u8 = 0x5c;

    pub(crate) async fn hmac(&self, key: &[u8], data: &[u8]) -> Result<Vec<u8>, CryptoError> {
        if key.is_empty() {
            return self.hmac_empty_key(data).await;
        }

        let crypto = get_crypto()?;

        let key = self.key_type.import(&crypto, key).await?;
        let algo = self.key_type.algorithm();

        let out = crypto.sign_with_str_and_u8_array(algo, &key, &mut data.to_vec())?;
        let out = JsFuture::from(out).await?;

        Ok(Uint8Array::new(&out).to_vec())
    }

    async fn hmac_empty_key(&self, data: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let crypto = get_crypto()?;

        let mut inner = vec![Self::IPAD; self.blocksize];
        inner.extend_from_slice(data);

        let mut outer = vec![Self::OPAD; self.blocksize];
        outer.append(&mut self.hash_with_crypto(&inner, &crypto).await?);

        self.hash_with_crypto(&outer, &crypto).await
    }

    pub(crate) async fn hash(&self, data: &[u8]) -> Result<Vec<u8>, CryptoError> {
        self.hash_with_crypto(data, &get_crypto()?).await
    }

    async fn hash_with_crypto(
        &self,
        data: &[u8],
        crypto: &SubtleCrypto,
    ) -> Result<Vec<u8>, CryptoError> {
        let data = Uint8Array::from(data);
        let data = crypto.digest_with_str_and_buffer_source(self.hash, &data)?;
        let data = JsFuture::from(data).await?;
        let data = Uint8Array::new(&data).to_vec();

        Ok(data)
    }
}

#[cfg(test)]
mod tests {
    use mls_rs_crypto_traits::KdfType;

    use super::Hkdf;

    #[derive(serde::Deserialize)]
    struct TestVector {
        #[serde(with = "hex::serde")]
        ikm: Vec<u8>,
        #[serde(with = "hex::serde")]
        info: Vec<u8>,
        test_cases: Vec<TestCase>,
    }

    #[derive(serde::Deserialize)]
    struct TestCase {
        ciphersuite: u16,
        #[serde(with = "hex::serde")]
        salt: Vec<u8>,
        #[serde(with = "hex::serde")]
        prk: Vec<u8>,
        #[serde(with = "hex::serde")]
        okm: Vec<u8>,
    }

    #[wasm_bindgen_test::wasm_bindgen_test]
    async fn hkdf() {
        let test_vector: TestVector =
            serde_json::from_str(include_str!("../test_data/hkdf.json")).unwrap();

        let info = test_vector.info;
        let ikm = test_vector.ikm;

        for tc in test_vector.test_cases {
            let kdf = Hkdf::new(tc.ciphersuite.into()).unwrap();

            let prk = kdf.extract(&tc.salt, &ikm).await.unwrap();
            assert_eq!(&prk, &tc.prk);

            let okm = kdf.expand(&tc.prk, &info, tc.okm.len()).await.unwrap();
            assert_eq!(&okm, &tc.okm);
        }
    }
}
