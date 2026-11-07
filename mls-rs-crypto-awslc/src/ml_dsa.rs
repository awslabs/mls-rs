// Copyright by contributors to this project.
// SPDX-License-Identifier: (Apache-2.0 OR MIT)

//! ML-DSA-44 (FIPS 204) as used by draft-ietf-mls-pq-ciphersuites-07 §2.
//! Secret keys are the 32-byte seed ξ (RFC 9881 §6 "seed" format).

use aws_lc_rs::signature::{
    KeyPair, PqdsaKeyPair, UnparsedPublicKey, ML_DSA_44, ML_DSA_44_SIGNING,
};
use zeroize::Zeroizing;

use crate::AwsLcCryptoError;

const PUBLIC_KEY_LEN: usize = 1312;

/// The seed ξ (FIPS 204 Alg. 1).
const SEED_LEN: usize = 32;

/// The seed-only PKCS#8 prefix for ML-DSA-44 (RFC 9881 §2, §6).
const SEED_PKCS8_PREFIX: [u8; 22] = [
    0x30, 0x34, 0x02, 0x01, 0x00, 0x30, 0x0b, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04,
    0x03, 0x11, 0x04, 0x22, 0x80, 0x20,
];

/// Generate (ξ, pk) with the FIPS-approved `PqdsaKeyPair::generate`.
pub(crate) fn generate() -> Result<(Zeroizing<Vec<u8>>, Vec<u8>), AwsLcCryptoError> {
    let key_pair = PqdsaKeyPair::generate(&ML_DSA_44_SIGNING)?;
    let pkcs8 = key_pair.to_pkcs8v1()?;

    let seed = pkcs8
        .as_ref()
        .strip_prefix(&SEED_PKCS8_PREFIX)
        .filter(|seed| seed.len() == SEED_LEN)
        .ok_or(AwsLcCryptoError::CryptoError)?;

    Ok((
        Zeroizing::new(seed.to_vec()),
        key_pair.public_key().as_ref().to_vec(),
    ))
}

/// ML-DSA.KeyGen_internal(ξ) (FIPS 204 Alg. 6).
fn key_pair(seed: &[u8]) -> Result<PqdsaKeyPair, AwsLcCryptoError> {
    if seed.len() != SEED_LEN {
        return Err(AwsLcCryptoError::InvalidKeyData);
    }

    Ok(PqdsaKeyPair::from_seed(&ML_DSA_44_SIGNING, seed)?)
}

pub(crate) fn public_key(seed: &[u8]) -> Result<Vec<u8>, AwsLcCryptoError> {
    Ok(key_pair(seed)?.public_key().as_ref().to_vec())
}

/// ML-DSA.Sign(sk, M, ctx = "") (FIPS 204 Alg. 2), hedged.
pub(crate) fn sign(seed: &[u8], data: &[u8]) -> Result<Vec<u8>, AwsLcCryptoError> {
    let key_pair = key_pair(seed)?;
    let mut signature = vec![0u8; ML_DSA_44_SIGNING.signature_len()];
    let len = key_pair.sign(data, &mut signature)?;
    signature.truncate(len);

    Ok(signature)
}

/// ML-DSA.Verify(pk, M, σ, ctx = "") (FIPS 204 Alg. 3); raw `pkEncode` keys only.
pub(crate) fn verify(
    public_key: &[u8],
    signature: &[u8],
    data: &[u8],
) -> Result<(), AwsLcCryptoError> {
    if public_key.len() != PUBLIC_KEY_LEN {
        return Err(AwsLcCryptoError::InvalidSignature);
    }

    UnparsedPublicKey::new(&ML_DSA_44, public_key)
        .verify(data, signature)
        .map_err(|_| AwsLcCryptoError::InvalidSignature)
}
