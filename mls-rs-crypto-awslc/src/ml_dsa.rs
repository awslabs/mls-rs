// Copyright by contributors to this project.
// SPDX-License-Identifier: (Apache-2.0 OR MIT)

//! ML-DSA-44 and ML-DSA-65 (FIPS 204) as used by draft-ietf-mls-pq-ciphersuites-07 §2.
//! Secret keys are the 32-byte seed ξ (RFC 9881 §6 "seed" format).

use aws_lc_rs::signature::{
    KeyPair, PqdsaKeyPair, PqdsaSigningAlgorithm, PqdsaVerificationAlgorithm, UnparsedPublicKey,
    ML_DSA_44, ML_DSA_44_SIGNING, ML_DSA_65, ML_DSA_65_SIGNING,
};
use mls_rs_crypto_traits::Curve;
use zeroize::Zeroizing;

use crate::AwsLcCryptoError;

/// The seed ξ (FIPS 204 Alg. 1).
const SEED_LEN: usize = 32;

/// Length of the seed-only PKCS#8 prefix (RFC 9881 §6).
const SEED_PKCS8_PREFIX_LEN: usize = 22;

pub(crate) struct MlDsa {
    signing: &'static PqdsaSigningAlgorithm,
    verification: &'static PqdsaVerificationAlgorithm,
    public_key_len: usize,
    seed_pkcs8_prefix: [u8; SEED_PKCS8_PREFIX_LEN],
}

/// The seed-only PKCS#8 prefix for OID 2.16.840.1.101.3.4.3.`arc` (RFC 9881 §2, §6).
const fn seed_pkcs8_prefix(arc: u8) -> [u8; SEED_PKCS8_PREFIX_LEN] {
    [
        0x30, 0x34, 0x02, 0x01, 0x00, 0x30, 0x0b, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03,
        0x04, 0x03, arc, 0x04, 0x22, 0x80, 0x20,
    ]
}

impl MlDsa {
    pub(crate) fn new(curve: Curve) -> Option<Self> {
        match curve {
            Curve::MlDsa44 => Some(Self {
                signing: &ML_DSA_44_SIGNING,
                verification: &ML_DSA_44,
                public_key_len: 1312,
                seed_pkcs8_prefix: seed_pkcs8_prefix(0x11),
            }),
            Curve::MlDsa65 => Some(Self {
                signing: &ML_DSA_65_SIGNING,
                verification: &ML_DSA_65,
                public_key_len: 1952,
                seed_pkcs8_prefix: seed_pkcs8_prefix(0x12),
            }),
            _ => None,
        }
    }

    /// Generate (ξ, pk) with the FIPS-approved `PqdsaKeyPair::generate`.
    pub(crate) fn generate(&self) -> Result<(Zeroizing<Vec<u8>>, Vec<u8>), AwsLcCryptoError> {
        let key_pair = PqdsaKeyPair::generate(self.signing)?;
        let pkcs8 = key_pair.to_pkcs8v1()?;

        let seed = pkcs8
            .as_ref()
            .strip_prefix(&self.seed_pkcs8_prefix)
            .filter(|seed| seed.len() == SEED_LEN)
            .ok_or(AwsLcCryptoError::CryptoError)?;

        Ok((
            Zeroizing::new(seed.to_vec()),
            key_pair.public_key().as_ref().to_vec(),
        ))
    }

    /// ML-DSA.KeyGen_internal(ξ) (FIPS 204 Alg. 6).
    fn key_pair(&self, seed: &[u8]) -> Result<PqdsaKeyPair, AwsLcCryptoError> {
        if seed.len() != SEED_LEN {
            return Err(AwsLcCryptoError::InvalidKeyData);
        }

        Ok(PqdsaKeyPair::from_seed(self.signing, seed)?)
    }

    pub(crate) fn public_key(&self, seed: &[u8]) -> Result<Vec<u8>, AwsLcCryptoError> {
        Ok(self.key_pair(seed)?.public_key().as_ref().to_vec())
    }

    /// ML-DSA.Sign(sk, M, ctx = "") (FIPS 204 Alg. 2), hedged.
    pub(crate) fn sign(&self, seed: &[u8], data: &[u8]) -> Result<Vec<u8>, AwsLcCryptoError> {
        let key_pair = self.key_pair(seed)?;
        let mut signature = vec![0u8; self.signing.signature_len()];
        let len = key_pair.sign(data, &mut signature)?;
        signature.truncate(len);

        Ok(signature)
    }

    /// ML-DSA.Verify(pk, M, σ, ctx = "") (FIPS 204 Alg. 3); raw `pkEncode` keys only.
    pub(crate) fn verify(
        &self,
        public_key: &[u8],
        signature: &[u8],
        data: &[u8],
    ) -> Result<(), AwsLcCryptoError> {
        if public_key.len() != self.public_key_len {
            return Err(AwsLcCryptoError::InvalidSignature);
        }

        UnparsedPublicKey::new(self.verification, public_key)
            .verify(data, signature)
            .map_err(|_| AwsLcCryptoError::InvalidSignature)
    }
}
