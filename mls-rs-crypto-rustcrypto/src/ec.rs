// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// Copyright by contributors to this project.
// SPDX-License-Identifier: (Apache-2.0 OR MIT)

// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use alloc::vec::Vec;
use mls_rs_crypto_traits::Curve;

#[cfg(feature = "std")]
use std::array::TryFromSliceError;

#[cfg(not(feature = "std"))]
use core::array::TryFromSliceError;

use core::fmt::{self, Debug};
use ed25519_dalek::Signer;
use p256::elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint};
use rand_core::OsRng;

#[derive(Debug, Eq, PartialEq, Clone)]
pub enum EcPublicKey {
    X25519(x25519_dalek::PublicKey),
    Ed25519(ed25519_dalek::VerifyingKey),
    P256(p256::PublicKey),
    P384(p384::PublicKey),
}

pub enum EcPrivateKey {
    X25519(x25519_dalek::StaticSecret),
    Ed25519(ed25519_dalek::SigningKey),
    P256(p256::SecretKey),
    P384(p384::SecretKey),
}

#[derive(Debug)]
#[cfg_attr(feature = "std", derive(thiserror::Error))]
pub enum EcError {
    #[cfg_attr(feature = "std", error("p256 error: {0:?}"))]
    P256Error(p256::elliptic_curve::Error),
    #[cfg_attr(feature = "std", error("p384 error: {0:?}"))]
    P384Error(p384::elliptic_curve::Error),
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

impl core::fmt::Debug for EcPrivateKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::X25519(_) => f.write_str("X25519 Secret Key"),
            Self::Ed25519(_) => f.write_str("Ed25519 Secret Key"),
            Self::P256(_) => f.write_str("P256 Secret Key"),
            Self::P384(_) => f.write_str("P384 Secret Key"),
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
        Curve::Ed25519 => Ok(EcPublicKey::Ed25519(
            ed25519_dalek::VerifyingKey::from_bytes(bytes.try_into()?)?,
        )),
        Curve::P384 => {
            let encoded_point =
                p384::EncodedPoint::from_bytes(bytes).map_err(|_| EcError::EcKeyInvalidKeyData)?;

            let key_option: Option<p384::PublicKey> =
                p384::PublicKey::from_encoded_point(&encoded_point).into();

            let key = key_option.ok_or_else(|| EcError::EcKeyInvalidKeyData)?;

            Ok(EcPublicKey::P384(key))
        }
        _ => Err(EcError::UnsupportedCurve),
    }
}

pub fn pub_key_to_uncompressed(key: &EcPublicKey) -> Result<Vec<u8>, EcError> {
    match key {
        EcPublicKey::X25519(key) => Ok(key.to_bytes().to_vec()),
        EcPublicKey::Ed25519(key) => Ok(key.to_bytes().to_vec()),
        EcPublicKey::P256(key) => Ok(key.as_affine().to_encoded_point(false).as_bytes().to_vec()),
        EcPublicKey::P384(key) => Ok(key.as_affine().to_encoded_point(false).as_bytes().to_vec()),
    }
}

pub fn generate_private_key(curve: Curve) -> Result<EcPrivateKey, EcError> {
    match curve {
        Curve::P256 => Ok(EcPrivateKey::P256(p256::SecretKey::random(&mut OsRng))),
        Curve::X25519 => Ok(EcPrivateKey::X25519(
            x25519_dalek::StaticSecret::random_from_rng(OsRng),
        )),
        Curve::Ed25519 => Ok(EcPrivateKey::Ed25519(ed25519_dalek::SigningKey::generate(
            &mut OsRng,
        ))),
        Curve::P384 => Ok(EcPrivateKey::P384(p384::SecretKey::random(&mut OsRng))),
        _ => Err(EcError::UnsupportedCurve),
    }
}

pub fn private_key_from_bytes(bytes: &[u8], curve: Curve) -> Result<EcPrivateKey, EcError> {
    match curve {
        Curve::P256 => p256::SecretKey::from_slice(bytes)
            .map_err(|_| EcError::EcKeyInvalidKeyData)
            .map(EcPrivateKey::P256),
        Curve::X25519 => bytes
            .try_into()
            .map_err(|_| EcError::EcKeyInvalidKeyData)
            .map(|bytes: &[u8; 32]| EcPrivateKey::X25519(x25519_dalek::StaticSecret::from(*bytes))),
        Curve::Ed25519 => ed25519_private_from_bytes(bytes),
        Curve::P384 => p384::SecretKey::from_slice(bytes)
            .map_err(|_| EcError::EcKeyInvalidKeyData)
            .map(EcPrivateKey::P384),
        _ => Err(EcError::UnsupportedCurve),
    }
}

fn ed25519_private_from_bytes(bytes: &[u8]) -> Result<EcPrivateKey, EcError> {
    let signing_key = ed25519_dalek::SigningKey::from_keypair_bytes(bytes.try_into()?)?;
    Ok(EcPrivateKey::Ed25519(signing_key))
}

pub fn private_key_to_bytes(key: &EcPrivateKey) -> Result<Vec<u8>, EcError> {
    match key {
        EcPrivateKey::X25519(key) => Ok(key.to_bytes().to_vec()),
        EcPrivateKey::Ed25519(key) => Ok(key.to_keypair_bytes().to_vec()),
        EcPrivateKey::P256(key) => Ok(key.to_bytes().to_vec()),
        EcPrivateKey::P384(key) => Ok(key.to_bytes().to_vec()),
    }
}

pub fn private_key_to_public(private_key: &EcPrivateKey) -> Result<EcPublicKey, EcError> {
    match private_key {
        EcPrivateKey::X25519(key) => Ok(EcPublicKey::X25519(x25519_dalek::PublicKey::from(key))),
        EcPrivateKey::Ed25519(key) => Ok(EcPublicKey::Ed25519(key.verifying_key())),
        EcPrivateKey::P256(key) => Ok(EcPublicKey::P256(key.public_key())),
        EcPrivateKey::P384(key) => Ok(EcPublicKey::P384(key.public_key())),
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

fn ecdh_p384(
    private_key: &p384::SecretKey,
    public_key: &p384::PublicKey,
) -> Result<Vec<u8>, EcError> {
    let shared_secret = p384::elliptic_curve::ecdh::diffie_hellman(
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
        EcPrivateKey::P384(private_key) => {
            if let EcPublicKey::P384(remote_public) = remote_public {
                ecdh_p384(private_key, remote_public)
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

pub fn sign_p384(private_key: &p384::SecretKey, data: &[u8]) -> Result<Vec<u8>, EcError> {
    let signing_key = p384::ecdsa::SigningKey::from(private_key);

    let signature: p384::ecdsa::Signature =
        p384::ecdsa::signature::Signer::sign(&signing_key, data);

    Ok(signature.to_der().to_bytes().to_vec())
}

pub fn sign_ed25519(key: &ed25519_dalek::SigningKey, data: &[u8]) -> Result<Vec<u8>, EcError> {
    Ok(key.sign(data).to_bytes().to_vec())
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

pub fn verify_p384(
    public_key: &p384::PublicKey,
    signature: &[u8],
    data: &[u8],
) -> Result<bool, EcError> {
    let verifying_key = p384::ecdsa::VerifyingKey::from(public_key);
    let signature = p384::ecdsa::Signature::from_der(signature)?;

    let is_valid =
        p384::ecdsa::signature::Verifier::verify(&verifying_key, data, &signature).is_ok();

    Ok(is_valid)
}

pub fn verify_ed25519(
    public_key: &ed25519_dalek::VerifyingKey,
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

#[derive(Clone, Default)]
pub struct KeyPair {
    pub public: Vec<u8>,
    pub secret: Vec<u8>,
}

impl Debug for KeyPair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KeyPair")
            .field("public", &mls_rs_core::debug::pretty_bytes(&self.public))
            .field("secret", &mls_rs_core::debug::pretty_bytes(&self.secret))
            .finish()
    }
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
                _ => Vec::new(),
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

    pub fn is_curve_25519(curve: Curve) -> bool {
        curve == Curve::X25519 || curve == Curve::Ed25519
    }

    pub fn byte_equal(curve: Curve, other: Curve) -> bool {
        if curve == other {
            return true;
        }

        if is_curve_25519(curve) && is_curve_25519(other) {
            return true;
        }

        false
    }

    #[cfg(feature = "x509")]
    pub fn ed25519_seed_to_private_key(seed: &[u8]) -> Vec<u8> {
        let secret = ed25519_dalek::SecretKey::try_from(seed).unwrap();
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&secret);
        signing_key.to_keypair_bytes().to_vec()
    }
}

#[cfg(test)]
mod tests {
    use assert_matches::assert_matches;

    use super::{
        generate_keypair, generate_private_key, private_key_bytes_to_public,
        private_key_from_bytes, private_key_to_bytes, pub_key_from_uncompressed,
        pub_key_to_uncompressed,
        test_utils::{byte_equal, get_test_public_keys, get_test_secret_keys},
        Curve, EcError,
    };

    use alloc::vec;

    const SUPPORTED_CURVES: [Curve; 3] = [Curve::Ed25519, Curve::P256, Curve::X25519];

    #[test]
    fn private_key_can_be_generated() {
        SUPPORTED_CURVES.iter().copied().for_each(|curve| {
            let one_key = generate_private_key(curve)
                .unwrap_or_else(|e| panic!("Failed to generate private key for {curve:?} : {e:?}"));

            let another_key = generate_private_key(curve)
                .unwrap_or_else(|e| panic!("Failed to generate private key for {curve:?} : {e:?}"));

            assert_ne!(
                private_key_to_bytes(&one_key).unwrap(),
                private_key_to_bytes(&another_key).unwrap(),
                "Same key generated twice for {curve:?}"
            );
        });
    }

    #[test]
    fn key_pair_can_be_generated() {
        SUPPORTED_CURVES.iter().copied().for_each(|curve| {
            assert_matches!(
                generate_keypair(curve),
                Ok(_),
                "Failed to generate key pair for {curve:?}"
            );
        });
    }

    #[test]
    fn private_key_can_be_imported_and_exported() {
        SUPPORTED_CURVES.iter().copied().for_each(|curve| {
            let key_bytes = get_test_secret_keys().get_key_from_curve(curve);

            let imported_key = private_key_from_bytes(&key_bytes, curve)
                .unwrap_or_else(|e| panic!("Failed to import private key for {curve:?} : {e:?}"));

            let exported_bytes = private_key_to_bytes(&imported_key)
                .unwrap_or_else(|e| panic!("Failed to export private key for {curve:?} : {e:?}"));

            assert_eq!(exported_bytes, key_bytes);
        });
    }

    #[test]
    fn public_key_can_be_imported_and_exported() {
        SUPPORTED_CURVES.iter().copied().for_each(|curve| {
            let key_bytes = get_test_public_keys().get_key_from_curve(curve);

            let imported_key = pub_key_from_uncompressed(&key_bytes, curve)
                .unwrap_or_else(|e| panic!("Failed to import public key for {curve:?} : {e:?}"));

            let exported_bytes = pub_key_to_uncompressed(&imported_key)
                .unwrap_or_else(|e| panic!("Failed to export public key for {curve:?} : {e:?}"));

            assert_eq!(exported_bytes, key_bytes);
        });
    }

    #[test]
    fn secret_to_public() {
        let test_public_keys = get_test_public_keys();
        let test_secret_keys = get_test_secret_keys();

        for curve in SUPPORTED_CURVES.iter().copied() {
            let secret_key = test_secret_keys.get_key_from_curve(curve);
            let public_key = private_key_bytes_to_public(&secret_key, curve).unwrap();
            assert_eq!(public_key, test_public_keys.get_key_from_curve(curve));
        }
    }

    #[test]
    fn mismatched_curve_import() {
        for curve in SUPPORTED_CURVES.iter().copied() {
            for other_curve in SUPPORTED_CURVES
                .iter()
                .copied()
                .filter(|c| !byte_equal(*c, curve))
            {
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
