// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// Copyright by contributors to this project.
// SPDX-License-Identifier: (Apache-2.0 OR MIT)

use mls_rs_core::crypto::{CipherSuite, HpkePublicKey, HpkeSecretKey};
use mls_rs_crypto_traits::{Curve, DhType, SamplingMethod};

use der::Any;
use js_sys::Uint8Array;
use wasm_bindgen_futures::JsFuture;
use web_sys::{CryptoKey, EcdhKeyDeriveParams, SubtleCrypto};

use super::der_private_key::{generate, DerPrivateKey};
use crate::{get_crypto, key_type::KeyType, CryptoError};

use const_oid::db::rfc5912::{SECP_256_R_1, SECP_384_R_1, SECP_521_R_1};

#[derive(Clone)]
pub(crate) struct Ecdh {
    curve_name: &'static str,
    curve: Curve,
    named_curve: Any,
}

impl Ecdh {
    pub fn new(cipher_suite: CipherSuite) -> Option<Self> {
        let curve = Curve::from_ciphersuite(cipher_suite, false)?;

        match curve {
            Curve::P256 => Some(Self {
                curve_name: "P-256",
                curve,
                named_curve: SECP_256_R_1.into(),
            }),
            Curve::P384 => Some(Self {
                curve_name: "P-384",
                curve,
                named_curve: SECP_384_R_1.into(),
            }),
            Curve::P521 => Some(Self {
                curve_name: "P-521",
                curve,
                named_curve: SECP_521_R_1.into(),
            }),
            _ => None,
        }
    }
}

impl Ecdh {
    async fn dh(
        &self,
        secret_key: &HpkeSecretKey,
        public_key: &HpkePublicKey,
    ) -> Result<Vec<u8>, CryptoError> {
        let crypto = get_crypto()?;
        let public_key_type = KeyType::EcdhPublic(self.curve_name);

        let private_key = self.import_private_key_for_dh(&crypto, secret_key).await?;
        let public_key = public_key_type.import(&crypto, public_key).await?;
        let params = EcdhKeyDeriveParams::new(public_key_type.algorithm(), &public_key);

        // Size of shared secret in bits, equal to the secret key size.
        let bitlength = self.secret_key_size() as u32 * 8;
        let shared_secret = crypto.derive_bits_with_object(&params, &private_key, bitlength)?;
        let shared_secret = JsFuture::from(shared_secret).await?;
        let shared_secret = Uint8Array::new(&shared_secret);

        Ok(shared_secret.to_vec())
    }

    async fn import_private_key_for_dh(
        &self,
        crypto: &SubtleCrypto,
        private_key: &[u8],
    ) -> Result<CryptoKey, CryptoError> {
        let private_key_type = KeyType::EcdhSecret(self.curve_name);

        // Try importing the secret key as DER (this happens when DH is called by HPKE for
        // encap with secret key from `Self::generate`).
        if DerPrivateKey::is_der(private_key) {
            return private_key_type
                .import(crypto, private_key)
                .await
                .map_err(Into::into);
        }

        // Try importing the secret key as raw (coming from path secret derivation for decap).
        // Try without the public key first.
        let der_private_key = DerPrivateKey::from_raw(private_key)
            .map_err(|e| CryptoError::DerError(e.to_string()))?;

        let private_key = der_private_key
            .to_bytes(self.named_curve.clone())
            .map_err(|e| CryptoError::DerError(e.to_string()))?;

        Ok(private_key_type.import(crypto, &private_key).await?)
    }

    async fn generate(&self) -> Result<(HpkeSecretKey, HpkePublicKey), CryptoError> {
        let (private, public) = generate(self.curve_name).await?;
        Ok((private.into(), public.into()))
    }

    async fn to_public(&self, secret_key: &HpkeSecretKey) -> Result<HpkePublicKey, CryptoError> {
        let crypto = get_crypto()?;
        let private_key_type = KeyType::EcdhSecret(self.curve_name);

        let der_secret_key = DerPrivateKey::from_raw(secret_key)
            .map_err(|e| CryptoError::DerError(e.to_string()))?;

        // Try providing a key without the public key
        let bytes = der_secret_key
            .to_bytes(self.named_curve.clone())
            .map_err(|e| CryptoError::DerError(e.to_string()))?;

        let private_key = private_key_type.import(&crypto, &bytes).await;

        // If it worked, check if the public key has been computed
        if let Ok(private_key) = &private_key {
            let exported = crypto.export_key(private_key_type.format(), private_key)?;
            let exported = JsFuture::from(exported).await?;
            let exported = Uint8Array::new(&exported).to_vec();

            let exported = DerPrivateKey::from_bytes(&exported)
                .map_err(|e| CryptoError::DerError(e.to_string()))?;

            if let Some(public_key) = exported.public_key {
                return Ok(public_key.value.raw_bytes().to_vec().into());
            }
        }

        Err(CryptoError::CouldNotComputePublicKey)
    }
}

#[maybe_async::must_be_async(?Send)]
impl DhType for Ecdh {
    type Error = CryptoError;

    async fn dh(
        &self,
        secret_key: &HpkeSecretKey,
        public_key: &HpkePublicKey,
    ) -> Result<Vec<u8>, Self::Error> {
        self.dh(secret_key, public_key).await
    }

    async fn generate(&self) -> Result<(HpkeSecretKey, HpkePublicKey), Self::Error> {
        self.generate().await
    }

    async fn to_public(&self, secret_key: &HpkeSecretKey) -> Result<HpkePublicKey, Self::Error> {
        self.to_public(secret_key).await
    }

    fn bitmask_for_rejection_sampling(&self) -> SamplingMethod {
        self.curve.hpke_sampling_method()
    }

    fn secret_key_size(&self) -> usize {
        self.curve.secret_key_size()
    }

    fn public_key_validate(&self, _key: &HpkePublicKey) -> Result<(), Self::Error> {
        Ok(())
    }

    fn public_key_size(&self) -> usize {
        self.curve.secret_key_size()
    }
}

#[cfg(test)]
mod tests {
    use mls_rs_core::crypto::CipherSuite;

    use super::Ecdh;

    #[derive(serde::Deserialize)]
    struct TestCase {
        ciphersuite: u16,
        #[serde(with = "hex::serde")]
        alice_pub: Vec<u8>,
        #[serde(with = "hex::serde")]
        alice_pri: Vec<u8>,
        #[serde(with = "hex::serde")]
        bob_pub: Vec<u8>,
        #[serde(with = "hex::serde")]
        bob_pri: Vec<u8>,
        #[serde(with = "hex::serde")]
        shared_secret: Vec<u8>,
    }

    #[wasm_bindgen_test::wasm_bindgen_test]
    async fn ecdh() {
        let test_vector: Vec<TestCase> =
            serde_json::from_str(include_str!("../../test_data/ecdh.json")).unwrap();

        for tc in test_vector {
            if !supported(tc.ciphersuite.into()) {
                continue;
            }

            let ecdh = Ecdh::new(tc.ciphersuite.into()).unwrap();

            let alice_pri = tc.alice_pri.into();
            let bob_pri = tc.bob_pri.into();
            let alice_pub = tc.alice_pub.into();
            let bob_pub = tc.bob_pub.into();

            let shared_secret = ecdh.dh(&alice_pri, &bob_pub).await.unwrap();
            assert_eq!(&shared_secret, &tc.shared_secret);

            let shared_secret = ecdh.dh(&bob_pri, &alice_pub).await.unwrap();
            assert_eq!(&shared_secret, &tc.shared_secret);

            assert_eq!(&alice_pub, &ecdh.to_public(&alice_pri).await.unwrap());
            assert_eq!(&bob_pub, &ecdh.to_public(&bob_pri).await.unwrap());
        }
    }

    fn supported(cipher_suite: CipherSuite) -> bool {
        [
            CipherSuite::P256_AES128,
            CipherSuite::P384_AES256,
            CipherSuite::P521_AES256,
        ]
        .contains(&cipher_suite)
    }
}
