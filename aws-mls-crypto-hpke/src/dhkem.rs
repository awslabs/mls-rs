use aws_mls_crypto_traits::{DhType, KdfType, KemResult, KemType};

use aws_mls_core::{
    crypto::{HpkePublicKey, HpkeSecretKey},
    error::{AnyError, IntoAnyError},
};
use zeroize::Zeroizing;

use crate::kdf::HpkeKdf;

#[cfg(test)]
use alloc::vec;
use alloc::vec::Vec;

#[derive(Debug)]
#[cfg_attr(feature = "std", derive(thiserror::Error))]
pub enum DhKemError {
    #[cfg_attr(feature = "std", error(transparent))]
    KdfError(AnyError),
    #[cfg_attr(feature = "std", error(transparent))]
    DhError(AnyError),
    /// NIST key derivation from bytes failure. This is statistically unlikely
    #[cfg_attr(
        feature = "std",
        error("Failed to derive nist keypair from raw bytes after 255 attempts")
    )]
    KeyDerivationError,
}

impl IntoAnyError for DhKemError {
    #[cfg(feature = "std")]
    fn into_dyn_error(self) -> Result<Box<dyn std::error::Error + Send + Sync>, Self> {
        Ok(self.into())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DhKem<DH: DhType, KDF: KdfType> {
    dh: DH,
    kdf: HpkeKdf<KDF>,
    kem_id: u16,
    n_secret: usize,
    #[cfg(test)]
    test_key_data: Vec<u8>,
}

impl<DH: DhType, KDF: KdfType> DhKem<DH, KDF> {
    pub fn new(dh: DH, kdf: KDF, kem_id: u16, n_secret: usize) -> Self {
        let suite_id = [b"KEM", &kem_id.to_be_bytes() as &[u8]].concat();
        let kdf = HpkeKdf::new(suite_id, kdf);

        Self {
            dh,
            kdf,
            kem_id,
            n_secret,
            #[cfg(test)]
            test_key_data: vec![],
        }
    }
}

impl<DH: DhType, KDF: KdfType> KemType for DhKem<DH, KDF> {
    type Error = DhKemError;

    fn kem_id(&self) -> u16 {
        self.kem_id
    }

    fn derive(&self, ikm: &[u8]) -> Result<(HpkeSecretKey, HpkePublicKey), Self::Error> {
        let dkp_prk = self
            .kdf
            .labeled_extract(&[], b"dkp_prk", ikm)
            .map_err(|e| DhKemError::KdfError(e.into_any_error()))?;

        if let Some(bitmask) = self.dh.bitmask_for_rejection_sampling() {
            self.derive_with_rejection_sampling(&dkp_prk, bitmask)
        } else {
            self.derive_without_rejection_sampling(&dkp_prk)
        }
    }

    fn generate(&self) -> Result<(HpkeSecretKey, HpkePublicKey), Self::Error> {
        #[cfg(test)]
        if !self.test_key_data.is_empty() {
            return self.derive(&self.test_key_data);
        }

        self.dh
            .generate()
            .map_err(|e| DhKemError::DhError(e.into_any_error()))
    }

    fn encap(&self, remote_pk: &HpkePublicKey) -> Result<KemResult, Self::Error> {
        let (ephemeral_sk, ephemeral_pk) = self.generate()?;

        let ecdh_ss = self
            .dh
            .dh(&ephemeral_sk, remote_pk)
            .map(Zeroizing::new)
            .map_err(|e| DhKemError::DhError(e.into_any_error()))?;

        let kem_context = [ephemeral_pk.as_ref(), remote_pk.as_ref()].concat();

        let shared_secret = self
            .kdf
            .labeled_extract_then_expand(&ecdh_ss, &kem_context, self.n_secret)
            .map_err(|e| DhKemError::KdfError(e.into_any_error()))?;

        Ok(KemResult::new(shared_secret, ephemeral_pk.into()))
    }

    fn decap(
        &self,
        enc: &[u8],
        secret_key: &HpkeSecretKey,
        public_key: &HpkePublicKey,
    ) -> Result<Vec<u8>, Self::Error> {
        let remote_pk = enc.to_vec().into();

        let ecdh_ss = self
            .dh
            .dh(secret_key, &remote_pk)
            .map(Zeroizing::new)
            .map_err(|e| DhKemError::DhError(e.into_any_error()))?;

        let kem_context = [enc, public_key].concat();

        self.kdf
            .labeled_extract_then_expand(&ecdh_ss, &kem_context, self.n_secret)
            .map_err(|e| DhKemError::KdfError(e.into_any_error()))
    }

    fn public_key_validate(&self, key: &HpkePublicKey) -> Result<(), Self::Error> {
        self.dh
            .public_key_validate(key)
            .map_err(|e| DhKemError::DhError(e.into_any_error()))
    }
}

impl<DH: DhType, KDF: KdfType> DhKem<DH, KDF> {
    fn derive_with_rejection_sampling(
        &self,
        dkp_prk: &[u8],
        bitmask: u8,
    ) -> Result<(HpkeSecretKey, HpkePublicKey), DhKemError> {
        // The RFC specifies we get 255 chances to generate bytes that will be within range of the order for the curve
        for i in 0u8..255 {
            let mut secret_key = self
                .kdf
                .labeled_expand(dkp_prk, b"candidate", &[i], self.dh.secret_key_size())
                .map_err(|e| DhKemError::KdfError(e.into_any_error()))?;

            secret_key[0] &= bitmask;
            let secret_key = secret_key.into();

            // Compute the public key and if it succeeds, return the key pair
            if let Ok(pair) = self.dh.to_public(&secret_key).map(|pk| (secret_key, pk)) {
                return Ok(pair);
            }
        }

        // If we never generate bytes that work, throw an error
        Err(DhKemError::KeyDerivationError)
    }

    fn derive_without_rejection_sampling(
        &self,
        dkp_prk: &[u8],
    ) -> Result<(HpkeSecretKey, HpkePublicKey), DhKemError> {
        let sk = self
            .kdf
            .labeled_expand(dkp_prk, b"sk", &[], self.dh.secret_key_size())
            .map_err(|e| DhKemError::KdfError(e.into_any_error()))?
            .into();

        let pk = self
            .dh
            .to_public(&sk)
            .map_err(|e| DhKemError::DhError(e.into_any_error()))?;

        Ok((sk, pk))
    }

    #[cfg(test)]
    pub fn set_test_data(&mut self, test_data: Vec<u8>) {
        self.test_key_data = test_data
    }
}

#[cfg(test)]
mod test {
    use aws_mls_core::crypto::CipherSuite;
    use aws_mls_crypto_traits::KemType;
    use serde::Deserialize;

    use crate::test_utils::{filter_test_case, test_dhkem, TestCaseAlgo};

    use alloc::vec::Vec;

    #[cfg(target_arch = "wasm32")]
    use wasm_bindgen_test::wasm_bindgen_test as test;

    #[test]
    fn test_derive_no_sampling() {
        // Curve 25519 does not need sampling.
        let dhkem = test_dhkem(CipherSuite::CURVE25519_AES128);

        // Test case from RFC 9180, Section A.1.1, ikmE
        let ikm = "7268600d403fce431561aef583ee1613527cff655c1343f29812e66706df3234";
        let expected_pk = "37fda3567bdbd628e88668c3c8d7e97d1d1253b6d4ea6d44c150f741f1bf4431";
        let expected_sk = "52c4a758a802cd8b936eceea314432798d5baf2d7e9235dc084ab1b9cfa2f736";

        let (sk, pk) = dhkem.derive(&hex::decode(ikm).unwrap()).unwrap();

        assert_eq!(sk.to_vec(), hex::decode(expected_sk).unwrap());
        assert_eq!(pk.to_vec(), hex::decode(expected_pk).unwrap());
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn test_derive_with_sampling() {
        // Curve P521 and P256 do need sampling.
        let dhkem = test_dhkem(CipherSuite::P521_AES256);

        // Test case from RFC 9180, Section A.6.1, ikmE
        let ikm = "7f06ab8215105fc46aceeb2e3dc5028b44364f960426eb0d8e4026c2f8b5d7e7a986688f1591abf5ab753c357a5d6f0440414b4ed4ede71317772ac98d9239f70904";
        let expected_pk = "040138b385ca16bb0d5fa0c0665fbbd7e69e3ee29f63991d3e9b5fa740aab8900aaeed46ed73a49055758425a0ce36507c54b29cc5b85a5cee6bae0cf1c21f2731ece2013dc3fb7c8d21654bb161b463962ca19e8c654ff24c94dd2898de12051f1ed0692237fb02b2f8d1dc1c73e9b366b529eb436e98a996ee522aef863dd5739d2f29b0";
        let expected_sk = "014784c692da35df6ecde98ee43ac425dbdd0969c0c72b42f2e708ab9d535415a8569bdacfcc0a114c85b8e3f26acf4d68115f8c91a66178cdbd03b7bcc5291e374b";

        let (sk, pk) = dhkem.derive(&hex::decode(ikm).unwrap()).unwrap();

        assert_eq!(sk.to_vec(), hex::decode(expected_sk).unwrap());
        assert_eq!(pk.to_vec(), hex::decode(expected_pk).unwrap());
    }

    #[cfg(target_arch = "wasm32")]
    #[test]
    fn test_derive_with_sampling() {
        // Curve P521 and P256 do need sampling.
        let dhkem = test_dhkem(CipherSuite::P256_AES128);

        // Test case from RFC 9180, Section A.3.1, ikmE
        let ikm = "4270e54ffd08d79d5928020af4686d8f6b7d35dbe470265f1f5aa22816ce860e";
        let expected_pk = "04a92719c6195d5085104f469a8b9814d5838ff72b60501e2c4466e5e67b325ac98536d7b61a1af4b78e5b7f951c0900be863c403ce65c9bfcb9382657222d18c4";
        let expected_sk = "4995788ef4b9d6132b249ce59a77281493eb39af373d236a1fe415cb0c2d7beb";

        let (sk, pk) = dhkem.derive(&hex::decode(ikm).unwrap()).unwrap();

        assert_eq!(sk.to_vec(), hex::decode(expected_sk).unwrap());
        assert_eq!(pk.to_vec(), hex::decode(expected_pk).unwrap());
    }

    #[test]
    fn encap_decap() {
        let file = include_str!("../test_data/test_hpke.json");
        let test_vectors: Vec<EncapDecapTestCase> = serde_json::from_str(file).unwrap();
        test_vectors.into_iter().for_each(encap_decap_test_case);
    }

    #[derive(Deserialize, Debug)]
    struct EncapDecapTestCase {
        #[serde(flatten)]
        algo: TestCaseAlgo,
        #[serde(with = "hex::serde", rename(deserialize = "pkRm"))]
        pk_rm: Vec<u8>,
        #[serde(with = "hex::serde", rename(deserialize = "skRm"))]
        sk_rm: Vec<u8>,
        #[serde(with = "hex::serde", rename(deserialize = "ikmE"))]
        ikm_e: Vec<u8>,
        #[serde(with = "hex::serde")]
        shared_secret: Vec<u8>,
        #[serde(with = "hex::serde")]
        enc: Vec<u8>,
    }

    fn encap_decap_test_case(test_case: EncapDecapTestCase) {
        let Some(cipher_suite) = filter_test_case(&test_case.algo) else {
            return;
        };

        let pk_rm = test_case.pk_rm.into();

        let mut dhkem = test_dhkem(cipher_suite);
        dhkem.set_test_data(test_case.ikm_e);

        let res = dhkem.encap(&pk_rm).unwrap();
        assert_eq!(res.enc(), &test_case.enc);
        assert_eq!(res.shared_secret(), &test_case.shared_secret);

        let shared_secret = dhkem
            .decap(res.enc(), &test_case.sk_rm.into(), &pk_rm)
            .unwrap();

        assert_eq!(shared_secret, test_case.shared_secret);
    }
}
