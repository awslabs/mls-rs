// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use alloc::vec::Vec;

#[cfg(feature = "std")]
use std::array::TryFromSliceError;

#[cfg(not(feature = "std"))]
use core::array::TryFromSliceError;

use aws_mls_core::crypto::CipherSuite;
use p256::elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint};
use rand_core::{OsRng, RngCore};
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

#[derive(Debug)]
#[cfg_attr(feature = "std", derive(thiserror::Error))]
pub enum EcError {
    #[cfg_attr(feature = "std", error("p256 error: {0:?}"))]
    P256Error(p256::elliptic_curve::Error),
    #[cfg_attr(feature = "std", error("ed25519 error: {0:?}"))]
    Ed25519Error(ed25519_dalek::SignatureError),
    #[cfg_attr(feature = "std", error("unsupported curve type"))]
    UnsupportedCurve,
    #[cfg_attr(feature = "std", error("invalid public key data"))]
    EcKeyInvalidKeyData,
    #[cfg_attr(feature = "std", error("ec key is not a signature key"))]
    EcKeyNotSignature,
    #[cfg_attr(feature = "std", error(transparent))]
    TryFromSliceError(TryFromSliceError),
    #[cfg_attr(feature = "std", error("p256 signature error: {0:?}"))]
    SignatureError(p256::ecdsa::Error),
    #[cfg_attr(feature = "std", error("rand error: {0:?}"))]
    RandCoreError(rand_core::Error),
    #[cfg_attr(feature = "std", error("ecdh key type mismatch"))]
    EcdhKeyTypeMismatch,
    #[cfg_attr(feature = "std", error("ec key is not an ecdh key"))]
    EcKeyNotEcdh,
}

impl From<p256::elliptic_curve::Error> for EcError {
    fn from(value: p256::elliptic_curve::Error) -> Self {
        EcError::P256Error(value)
    }
}

impl From<ed25519_dalek::SignatureError> for EcError {
    fn from(value: ed25519_dalek::SignatureError) -> Self {
        EcError::Ed25519Error(value)
    }
}

impl From<p256::ecdsa::Error> for EcError {
    fn from(value: p256::ecdsa::Error) -> Self {
        EcError::SignatureError(value)
    }
}

impl From<rand_core::Error> for EcError {
    fn from(value: rand_core::Error) -> Self {
        EcError::RandCoreError(value)
    }
}

impl From<TryFromSliceError> for EcError {
    fn from(e: TryFromSliceError) -> Self {
        EcError::TryFromSliceError(e)
    }
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
            CipherSuite::P256_AES128 => Ok(Curve::P256),
            CipherSuite::CURVE25519_AES128 | CipherSuite::CURVE25519_CHACHA if for_sig => {
                Ok(Curve::Ed25519)
            }
            CipherSuite::CURVE25519_AES128 | CipherSuite::CURVE25519_CHACHA => Ok(Curve::X25519),
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

impl core::fmt::Debug for EcPrivateKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
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

            let key = key_option.ok_or_else(|| EcError::EcKeyInvalidKeyData)?;

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

            let key = EcPrivateKey::X25519(x25519_dalek::StaticSecret::from(array));

            array.zeroize();

            Ok(key)
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
    match curve {
        Curve::P256 => p256::SecretKey::from_be_bytes(bytes)
            .map_err(|_| EcError::EcKeyInvalidKeyData)
            .map(EcPrivateKey::P256),
        Curve::X25519 => bytes
            .try_into()
            .map_err(|_| EcError::EcKeyInvalidKeyData)
            .map(|bytes: &[u8; 32]| EcPrivateKey::X25519(x25519_dalek::StaticSecret::from(*bytes))),
        Curve::Ed25519 => ed25519_dalek::SecretKey::from_bytes(bytes)
            .map_err(|_| EcError::EcKeyInvalidKeyData)
            .map(EcPrivateKey::Ed25519),
    }
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

    Ok(shared_secret.raw_secret_bytes().to_vec())
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

    let signature: p256::ecdsa::Signature =
        p256::ecdsa::signature::Signer::sign(&signing_key, data);

    Ok(signature.to_der().to_bytes().to_vec())
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

    let is_valid =
        p256::ecdsa::signature::Verifier::verify(&verifying_key, data, &signature).is_ok();

    Ok(is_valid)
}

pub fn verify_ed25519(
    public_key: &ed25519_dalek::PublicKey,
    signature: &[u8],
    data: &[u8],
) -> Result<bool, EcError> {
    let signature = ed25519_dalek::Signature::try_from(signature)?;
    Ok(ed25519_dalek::Verifier::verify(public_key, data, &signature).is_ok())
}

pub fn generate_keypair(curve: Curve) -> Result<KeyPair, EcError> {
    let secret = generate_private_key(curve)?;
    let public = private_key_to_public(&secret)?;
    let secret = private_key_to_bytes(&secret)?;
    let public = pub_key_to_uncompressed(&public)?;
    Ok(KeyPair { public, secret })
}

#[derive(Clone, Default, Debug)]
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
pub(crate) mod test_utils {
    use serde::Deserialize;

    use super::Curve;

    use alloc::vec::Vec;

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
        pub(crate) fn get_key_from_curve(&self, curve: Curve) -> Vec<u8> {
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

    impl Curve {
        pub fn is_curve_25519(&self) -> bool {
            self == &Curve::X25519 || self == &Curve::Ed25519
        }

        pub fn byte_equal(self, other: Curve) -> bool {
            if self == other {
                return true;
            }

            if self.is_curve_25519() && other.is_curve_25519() {
                return true;
            }

            false
        }
    }
}

#[cfg(test)]
mod tests {
    use assert_matches::assert_matches;

    use super::{
        generate_keypair, generate_private_key, private_key_bytes_to_public,
        private_key_from_bytes, private_key_to_bytes, pub_key_from_uncompressed,
        pub_key_to_uncompressed,
        test_utils::{get_test_public_keys, get_test_secret_keys},
        Curve, EcError,
    };

    use alloc::vec;

    #[test]
    fn private_key_can_be_generated() {
        Curve::all().for_each(|curve| {
            let one_key = generate_private_key(curve)
                .unwrap_or_else(|e| panic!("Failed to generate private key for {curve:?} : {e}"));

            let another_key = generate_private_key(curve)
                .unwrap_or_else(|e| panic!("Failed to generate private key for {curve:?} : {e}"));

            assert_ne!(
                private_key_to_bytes(&one_key).unwrap(),
                private_key_to_bytes(&another_key).unwrap(),
                "Same key generated twice for {curve:?}"
            );
        });
    }

    #[test]
    fn key_pair_can_be_generated() {
        Curve::all().for_each(|curve| {
            assert_matches!(
                generate_keypair(curve),
                Ok(_),
                "Failed to generate key pair for {curve:?}"
            );
        });
    }

    #[test]
    fn private_key_can_be_imported_and_exported() {
        Curve::all().for_each(|curve| {
            let key_bytes = get_test_secret_keys().get_key_from_curve(curve);

            let imported_key = private_key_from_bytes(&key_bytes, curve)
                .unwrap_or_else(|e| panic!("Failed to import private key for {curve:?} : {e}"));

            let exported_bytes = private_key_to_bytes(&imported_key)
                .unwrap_or_else(|e| panic!("Failed to export private key for {curve:?} : {e}"));

            assert_eq!(exported_bytes, key_bytes);
        });
    }

    #[test]
    fn public_key_can_be_imported_and_exported() {
        Curve::all().for_each(|curve| {
            let key_bytes = get_test_public_keys().get_key_from_curve(curve);

            let imported_key = pub_key_from_uncompressed(&key_bytes, curve)
                .unwrap_or_else(|e| panic!("Failed to import public key for {curve:?} : {e}"));

            let exported_bytes = pub_key_to_uncompressed(&imported_key)
                .unwrap_or_else(|e| panic!("Failed to export public key for {curve:?} : {e}"));

            assert_eq!(exported_bytes, key_bytes);
        });
    }

    #[test]
    fn secret_to_public() {
        let test_public_keys = get_test_public_keys();
        let test_secret_keys = get_test_secret_keys();

        for curve in Curve::all() {
            let secret_key = test_secret_keys.get_key_from_curve(curve);
            let public_key = private_key_bytes_to_public(&secret_key, curve).unwrap();
            assert_eq!(public_key, test_public_keys.get_key_from_curve(curve));
        }
    }

    #[test]
    fn mismatched_curve_import() {
        for curve in Curve::all() {
            for other_curve in Curve::all().filter(|c| !c.byte_equal(curve)) {
                let public_key = get_test_public_keys().get_key_from_curve(curve);
                let res = pub_key_from_uncompressed(&public_key, other_curve);

                assert!(res.is_err());
            }
        }
    }

    #[test]
    fn test_order_range_enforcement() {
        let p256_order =
            hex::decode("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551")
                .unwrap();

        // Keys must be <= to order
        let p256_res = private_key_from_bytes(&p256_order, Curve::P256);
        assert_matches!(p256_res, Err(EcError::EcKeyInvalidKeyData));

        let nist_curves = [Curve::P256];

        // Keys must not be 0
        for curve in nist_curves {
            assert_matches!(
                private_key_from_bytes(&vec![0u8; curve.secret_key_size()], curve),
                Err(EcError::EcKeyInvalidKeyData)
            );
        }
    }
}
