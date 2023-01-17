// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::array::TryFromSliceError;

use aws_mls_core::crypto::CipherSuite;
use p256::ecdsa::signature::{Signer, Verifier};
use p256::elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint};
use rand_core::{OsRng, RngCore};
use thiserror::Error;
use zeroize::Zeroize;

#[derive(Debug, Eq, PartialEq, Clone)]
pub enum EcPublicKey {
    X25519(x25519_dalek::PublicKey),
    Ed25519(ed25519_dalek::PublicKey),
    P256(p256::PublicKey),
}

pub enum EcPrivateKey {
    X25519(x25519_dalek::StaticSecret),
    Ed25519(ed25519_dalek::SecretKey),
    P256(p256::SecretKey),
}

#[derive(Debug, Error)]
pub enum EcError {
    #[error(transparent)]
    Sec1ParsingError(#[from] sec1::der::Error),
    /// Attempted to import a secret key that does not contain valid bytes for its curve
    #[error("invalid secret key bytes")]
    InvalidSecretKeyBytes,
    #[error("unsupported curve type")]
    UnsupportedCurve,
    #[error("invalid public key data")]
    EcKeyInvalidKeyData,
    #[error("ec key is not a signature key")]
    EcKeyNotSignature,
    #[error(transparent)]
    TryFromSliceError(#[from] TryFromSliceError),
    #[error(transparent)]
    P256EcdsaError(#[from] p256::ecdsa::Error),
    #[error(transparent)]
    RandCoreError(#[from] rand_core::Error),
    #[error("ecdh key type mismatch")]
    EcdhKeyTypeMismatch,
    #[error("ec key is not an ecdh key")]
    EcKeyNotEcdh,
}

/// Elliptic curve types
#[derive(Clone, Copy, Debug, Eq, enum_iterator::Sequence, PartialEq)]
#[repr(u8)]
#[cfg_attr(test, derive(serde::Deserialize))]
pub enum Curve {
    /// NIST Curve-P256
    P256,
    /// Elliptic-curve Diffie-Hellman key exchange Curve25519
    X25519,
    /// Edwards-curve Digital Signature Algorithm Curve25519
    Ed25519,
}

impl Curve {
    /// Returns the amount of bytes of a secret key using this curve
    #[inline(always)]
    pub fn secret_key_size(&self) -> usize {
        match self {
            Curve::P256 => 32,
            Curve::X25519 => 32,
            Curve::Ed25519 => 32,
        }
    }

    pub fn from_ciphersuite(cipher_suite: CipherSuite, for_sig: bool) -> Result<Self, EcError> {
        match cipher_suite {
            CipherSuite::P256Aes128 => Ok(Curve::P256),
            CipherSuite::Curve25519Aes128 | CipherSuite::Curve25519ChaCha20 if for_sig => {
                Ok(Curve::Ed25519)
            }
            CipherSuite::Curve25519Aes128 | CipherSuite::Curve25519ChaCha20 => Ok(Curve::X25519),
            _ => Err(EcError::UnsupportedCurve),
        }
    }

    #[inline(always)]
    pub(crate) fn curve_bitmask(&self) -> Option<u8> {
        match self {
            Curve::P256 => Some(0xFF),
            Curve::X25519 => None,
            Curve::Ed25519 => None,
        }
    }

    /// Returns an iterator over all curves
    #[inline(always)]
    pub fn all() -> impl Iterator<Item = Curve> {
        enum_iterator::all()
    }
}

impl Clone for EcPrivateKey {
    fn clone(&self) -> Self {
        match self {
            Self::X25519(key) => Self::X25519(key.clone()),
            Self::Ed25519(key) => Self::Ed25519(
                ed25519_dalek::SecretKey::from_bytes(key.as_bytes())
                    .expect("The bytes represent a secret key"),
            ),
            Self::P256(key) => Self::P256(key.clone()),
        }
    }
}

impl std::fmt::Debug for EcPrivateKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::X25519(_) => f.write_str("X25519 Secret Key"),
            Self::Ed25519(_) => f.write_str("Ed25519 Secret Key"),
            Self::P256(_) => f.write_str("P256 Secret Key"),
        }
    }
}

pub fn pub_key_from_uncompressed(bytes: &[u8], curve: Curve) -> Result<EcPublicKey, EcError> {
    match curve {
        Curve::P256 => {
            let encoded_point =
                p256::EncodedPoint::from_bytes(bytes).map_err(|_| EcError::EcKeyInvalidKeyData)?;

            let key_option: Option<p256::PublicKey> =
                p256::PublicKey::from_encoded_point(&encoded_point).into();
            let key = key_option.ok_or(EcError::EcKeyInvalidKeyData)?;

            Ok(EcPublicKey::P256(key))
        }
        Curve::X25519 => {
            let array: [u8; 32] = bytes.try_into()?;
            Ok(EcPublicKey::X25519(x25519_dalek::PublicKey::from(array)))
        }
        Curve::Ed25519 => Ok(EcPublicKey::Ed25519(ed25519_dalek::PublicKey::from_bytes(
            bytes,
        )?)),
    }
}

pub fn pub_key_to_uncompressed(key: &EcPublicKey) -> Result<Vec<u8>, EcError> {
    match key {
        EcPublicKey::X25519(key) => Ok(key.to_bytes().to_vec()),
        EcPublicKey::Ed25519(key) => Ok(key.to_bytes().to_vec()),
        EcPublicKey::P256(key) => Ok(key.as_affine().to_encoded_point(false).as_bytes().to_vec()),
    }
}

pub fn generate_private_key(curve: Curve) -> Result<EcPrivateKey, EcError> {
    match curve {
        Curve::P256 => Ok(EcPrivateKey::P256(p256::SecretKey::random(OsRng))),
        Curve::X25519 => {
            // x25519_dalek uses an outdated rand_core, this is functionally equal to
            // StaticSecret::new passing an Rng from rand_core
            let mut array = [0u8; 32];
            OsRng.try_fill_bytes(&mut array)?;
            Ok(EcPrivateKey::X25519(x25519_dalek::StaticSecret::from(
                array,
            )))
        }
        Curve::Ed25519 => {
            // ed25519_dalek uses an outdated rand_core, this is functionally equal to
            // SecretKey::generate passing an Rng from rand_core
            let mut array = [0u8; 32];
            OsRng.try_fill_bytes(&mut array)?;
            let key = ed25519_dalek::SecretKey::from_bytes(&array)?;
            array.zeroize();

            Ok(EcPrivateKey::Ed25519(key))
        }
    }
}

pub fn private_key_from_bytes(bytes: &[u8], curve: Curve) -> Result<EcPrivateKey, EcError> {
    // TODO why option was used gere?
    let key = match curve {
        Curve::P256 => p256::SecretKey::from_be_bytes(bytes)
            .ok()
            .map(EcPrivateKey::P256),
        Curve::X25519 => bytes
            .try_into()
            .ok()
            .map(|bytes: &[u8; 32]| EcPrivateKey::X25519(x25519_dalek::StaticSecret::from(*bytes))),
        Curve::Ed25519 => ed25519_dalek::SecretKey::from_bytes(bytes)
            .ok()
            .map(EcPrivateKey::Ed25519),
    };

    key.ok_or(EcError::EcKeyInvalidKeyData)
}

pub fn private_key_to_bytes(key: &EcPrivateKey) -> Result<Vec<u8>, EcError> {
    match key {
        EcPrivateKey::X25519(key) => Ok(key.to_bytes().to_vec()),
        EcPrivateKey::Ed25519(key) => Ok(key.to_bytes().to_vec()),
        EcPrivateKey::P256(key) => Ok(key.to_be_bytes().to_vec()),
    }
}

pub fn private_key_to_public(private_key: &EcPrivateKey) -> Result<EcPublicKey, EcError> {
    match private_key {
        EcPrivateKey::X25519(key) => Ok(EcPublicKey::X25519(x25519_dalek::PublicKey::from(key))),
        EcPrivateKey::Ed25519(key) => Ok(EcPublicKey::Ed25519(ed25519_dalek::PublicKey::from(key))),
        EcPrivateKey::P256(key) => Ok(EcPublicKey::P256(key.public_key())),
    }
}

fn ecdh_p256(
    private_key: &p256::SecretKey,
    public_key: &p256::PublicKey,
) -> Result<Vec<u8>, EcError> {
    let shared_secret = p256::elliptic_curve::ecdh::diffie_hellman(
        private_key.to_nonzero_scalar(),
        public_key.as_affine(),
    );

    Ok(shared_secret.as_bytes().to_vec())
}

fn ecdh_x25519(
    private_key: &x25519_dalek::StaticSecret,
    public_key: &x25519_dalek::PublicKey,
) -> Result<Vec<u8>, EcError> {
    Ok(private_key.diffie_hellman(public_key).to_bytes().to_vec())
}

pub fn private_key_ecdh(
    private_key: &EcPrivateKey,
    remote_public: &EcPublicKey,
) -> Result<Vec<u8>, EcError> {
    let shared_secret = match private_key {
        EcPrivateKey::X25519(private_key) => {
            if let EcPublicKey::X25519(remote_public) = remote_public {
                ecdh_x25519(private_key, remote_public)
            } else {
                Err(EcError::EcdhKeyTypeMismatch)
            }
        }
        EcPrivateKey::Ed25519(_) => Err(EcError::EcKeyNotEcdh),
        EcPrivateKey::P256(private_key) => {
            if let EcPublicKey::P256(remote_public) = remote_public {
                ecdh_p256(private_key, remote_public)
            } else {
                Err(EcError::EcdhKeyTypeMismatch)
            }
        }
    }?;

    Ok(shared_secret)
}

pub fn sign_p256(private_key: &p256::SecretKey, data: &[u8]) -> Result<Vec<u8>, EcError> {
    let signing_key = p256::ecdsa::SigningKey::from(private_key);
    let signature = signing_key.sign(data);
    Ok(signature.to_der().as_bytes().to_vec())
}

pub fn sign_ed25519(
    private_key: &ed25519_dalek::SecretKey,
    data: &[u8],
) -> Result<Vec<u8>, EcError> {
    let expanded = ed25519_dalek::ExpandedSecretKey::from(private_key);
    Ok(expanded
        .sign(data, &ed25519_dalek::PublicKey::from(private_key))
        .to_bytes()
        .to_vec())
}

pub fn verify_p256(
    public_key: &p256::PublicKey,
    signature: &[u8],
    data: &[u8],
) -> Result<bool, EcError> {
    let verifying_key = p256::ecdsa::VerifyingKey::from(public_key);
    let signature = p256::ecdsa::Signature::from_der(signature)?;
    let is_valid = verifying_key.verify(data, &signature).is_ok();

    Ok(is_valid)
}

pub fn verify_ed25519(
    public_key: &ed25519_dalek::PublicKey,
    signature: &[u8],
    data: &[u8],
) -> Result<bool, EcError> {
    let signature = ed25519_dalek::Signature::try_from(signature)?;
    Ok(public_key.verify(data, &signature).is_ok())
}

pub fn generate_keypair(curve: Curve) -> Result<KeyPair, EcError> {
    let secret = generate_private_key(curve)?;
    let public = private_key_to_public(&secret)?;
    let secret = private_key_to_bytes(&secret)?;
    let public = pub_key_to_uncompressed(&public)?;
    Ok(KeyPair { public, secret })
}

pub struct KeyPair {
    pub public: Vec<u8>,
    pub secret: Vec<u8>,
}

pub fn private_key_bytes_to_public(secret_key: &[u8], curve: Curve) -> Result<Vec<u8>, EcError> {
    let secret_key = private_key_from_bytes(secret_key, curve)?;
    let public_key = private_key_to_public(&secret_key)?;
    pub_key_to_uncompressed(&public_key)
}

#[cfg(test)]
pub mod test_utils {
    use aws_mls_core::crypto::CipherSuite;
    use serde::Deserialize;

    use super::Curve;

    #[derive(Deserialize)]
    pub(crate) struct TestKeys {
        #[serde(with = "hex::serde")]
        p256: Vec<u8>,
        #[serde(with = "hex::serde")]
        x25519: Vec<u8>,
        #[serde(with = "hex::serde")]
        ed25519: Vec<u8>,
    }

    impl TestKeys {
        pub(crate) fn get_key(&self, cipher_suite: CipherSuite, for_sig: bool) -> Vec<u8> {
            let curve = Curve::from_ciphersuite(cipher_suite, for_sig).unwrap();

            match curve {
                Curve::P256 => self.p256.clone(),
                Curve::X25519 => self.x25519.clone(),
                Curve::Ed25519 => self.ed25519.clone(),
            }
        }
    }

    pub(crate) fn get_test_public_keys() -> TestKeys {
        let test_case_file = include_str!("../test_data/test_public_keys.json");
        serde_json::from_str(test_case_file).unwrap()
    }

    pub(crate) fn get_test_secret_keys() -> TestKeys {
        let test_case_file = include_str!("../test_data/test_private_keys.json");
        serde_json::from_str(test_case_file).unwrap()
    }
}

#[cfg(test)]
mod tests {
    use assert_matches::assert_matches;

    use crate::ec::generate_private_key;

    use super::Curve;

    #[test]
    fn private_key_can_be_generated_for_all_curves() {
        Curve::all().for_each(|curve| {
            assert_matches!(
                generate_private_key(curve),
                Ok(_),
                "Failed to generate private key for {curve:?}"
            );
        });
    }
}
