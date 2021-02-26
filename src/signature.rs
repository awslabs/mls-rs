use crate::asym::{PublicKey, SecretKey, AsymmetricKeyError};
use crate::hash::{HashFunction};
use openssl::error::ErrorStack;
use thiserror::Error;
use rand_core::{CryptoRng, RngCore};
use serde::ser::Error;
use serde::{Deserialize, Serialize};
use num_enum::{IntoPrimitive, TryFromPrimitive};

#[derive(Error, Debug)]
pub enum SignatureError {
    #[error("Openssl error: {0}")]
    OpenSSLError(#[from] ErrorStack),
    #[error("Asymmetric key error: {0}")]
    AsymmetricKeyError(#[from] AsymmetricKeyError),
    #[error("Invalid signature data")]
    InvalidSignatureData,
    #[error("Invalid key data")]
    InvalidKeyData
}

#[derive(IntoPrimitive, TryFromPrimitive, Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(into = "u16", try_from = "u16")]
#[repr(u16)]
pub enum SignatureSchemeId {
    EcdsaSecp256r1Sha256 = 0x0403,
    EcdsaSecp521r1Sha512 = 0x0603,
    Ed25519 = 0x0703,
    #[cfg(test)]
    Test = 0x0042,
}

pub trait SignatureScheme {
    type PK: PublicKey;
    type SK: SecretKey;

    const IDENTIFIER: SignatureSchemeId;

    fn random_key_pair<RNG: CryptoRng + RngCore>(rng: RNG) -> Result<(Self::PK, Self::SK), SignatureError>;
    fn sign(sig_key: &Self::SK, data: &[u8]) -> Result<Vec<u8>, SignatureError>;
    fn verify(pub_key: &Self::PK, signature: &[u8], data: &[u8]) -> Result<bool, SignatureError>;
}

#[macro_use]
mod ossl {
    use openssl::hash::MessageDigest;
    use openssl::pkey::{PKey, Private, Public};
    use openssl::error::ErrorStack;
    use openssl::sign::{Signer, Verifier};
    use openssl::ec::EcKey;

    pub fn sign(digest: MessageDigest, sig_key: EcKey<Private>, data: &[u8]) -> Result<Vec<u8>, ErrorStack> {
        let pkey = PKey::from_ec_key(sig_key)?;
        let mut signer = Signer::new(digest, &pkey)?;
        signer.sign_oneshot_to_vec(data).map_err(|e| e.into())
    }

    pub fn verify(digest: MessageDigest, pub_key: EcKey<Public>, signature: &[u8], data: &[u8]) -> Result<bool, ErrorStack> {
        let pkey = PKey::from_ec_key(pub_key)?;
        let mut verifier = Verifier::new(digest, &pkey)?;
        verifier.verify_oneshot(signature, data).map_err(|e| e.into())
    }

    macro_rules! impl_openssl_signature {
        ($name:ident, $pk_ty:ty, $sk_ty:ty, $eng_ty:ty, $digest:expr, $scheme_id:expr) => {
            pub struct $name;

            impl SignatureScheme for $name {
                type PK = $pk_ty;
                type SK = $sk_ty;

                const IDENTIFIER: SignatureSchemeId = $scheme_id;

                fn random_key_pair<RNG: CryptoRng + RngCore>(rng: RNG)
                    -> Result<(Self::PK, Self::SK), SignatureError> {
                    <$eng_ty>::random_key_pair(rng).map_err(|e| e.into())
                }

                fn sign(sig_key: &Self::SK, data: &[u8]) -> Result<Vec<u8>, SignatureError> {
                    super::ossl::sign($digest, sig_key.key.clone(), data)
                        .map_err(|e| e.into())
                }

                fn verify(pub_key: &Self::PK,
                    signature: &[u8], data: &[u8]) -> Result<bool, SignatureError> {
                    super::ossl::verify($digest, pub_key.key.clone(), signature, data)
                        .map_err(|e| e.into())
                }
            }
        };
    }
}

pub mod p256 {
    use crate::asym::p256;
    use super::{ SignatureScheme, SignatureError};
    use rand_core::{CryptoRng, RngCore};
    use crate::asym::AsymmetricKeyEngine;
    use openssl::hash::MessageDigest;
    use crate::signature::SignatureSchemeId;

    impl_openssl_signature!(EcDsaP256, p256::PublicKey, p256::SecretKey,
        p256::Engine, MessageDigest::sha256(), SignatureSchemeId::EcdsaSecp256r1Sha256);

    #[cfg(test)]
    mod test {
        use crate::asym::{p256, AsymmetricKey};
        use crate::signature::SignatureScheme;
        use crate::rand::OpenSslRng;

        #[test]
        //RFC 6979 Deterministic DSA and ECDSA
        fn test_p256_signatures() {
            let test_msg = b"sample".to_vec();
            let test_secret = p256::SecretKey
            ::from_bytes(&hex!("C9AFA9D845BA75166B5C215767B1D\
                                      6934E50C3DB36E89B127B8A622B120F6721"))
                .expect("invalid key");

            let test_public = p256::PublicKey
            ::from_bytes(&hex!("0460FED4BA255A9D31C961EB74C6356D68C049B8\
                                      923B61FA6CE669622E60F29FB67903FE1008B8BC\
                                      99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C2\
                                      94D4462299"))
                .expect("invalid key");

            let signaure = super::EcDsaP256::sign(&test_secret,
                                                  &test_msg).expect("failed to sign");

            let verification = super::EcDsaP256::verify(&test_public,
                                                        &signaure,
                                                        &test_msg)
                .expect("failed to verify");

            assert_eq!(verification, true);
        }

        #[test]
        fn test_p256_signature_fail() {
            let test_keypair_a = super::EcDsaP256::random_key_pair(OpenSslRng)
                .expect("keypair gen failed");

            let test_keypair_b = super::EcDsaP256::random_key_pair(OpenSslRng)
                .expect("keypair gen failed");

            let test_data = b"hello world".to_vec();

            let signature = super::EcDsaP256::sign(&test_keypair_a.1, &test_data)
                .expect("signature failed");

            let verification = super::EcDsaP256::verify(&test_keypair_b.0,
                                                        &signature,
                                                        &test_data)
                .expect("validation failed");

            assert_eq!(verification, false);
        }
    }
}

pub mod p512 {
    use crate::asym::p521;
    use super::{ SignatureScheme, SignatureError, SignatureSchemeId};
    use rand_core::{CryptoRng, RngCore};
    use crate::asym::AsymmetricKeyEngine;
    use openssl::hash::MessageDigest;
    impl_openssl_signature!(EcDsaP521, p521::PublicKey,
        p521::SecretKey, p521::Engine, MessageDigest::sha512(), SignatureSchemeId::EcdsaSecp521r1Sha512);

    #[cfg(test)]
    mod test {
        use crate::asym::{p521, AsymmetricKey};
        use crate::signature::SignatureScheme;
        use crate::rand::OpenSslRng;

        #[test]
        //RFC 6979 Deterministic DSA and ECDSA
        fn test_p521_signatures() {
            let test_msg = b"sample".to_vec();
            let test_secret = p521::SecretKey
            ::from_bytes(&hex!("00FAD06DAA62BA3B25D2FB40133DA757205DE67F5BB0018FEE8C86E1B6\
                                      8C7E75CAA896EB32F1F47C70855836A6D16FCC1466F6D8FBEC67DB89EC\
                                      0C08B0E996B83538"))
                .expect("invalid key");

            let test_public = p521::PublicKey
            ::from_bytes(&hex!("0401894550D0785932E00EAA23B694F213F8C3121F86DC97A04E5A716\
            7DB4E5BCD371123D46E45DB6B5D5370A7F20FB633155D38FFA16D2BD761DCAC474B9A2F5023A4004931\
            01C962CD4D2FDDF782285E64584139C2F91B47F87FF82354D6630F746A28A0DB25741B5B34A828008B2\
            2ACC23F924FAAFBD4D33F81EA66956DFEAA2BFDFCF5"))
                .expect("invalid key");

            let signaure = super::EcDsaP521::sign(&test_secret,
                                                  &test_msg).expect("failed to sign");

            let verification = super::EcDsaP521::verify(&test_public,
                                                        &signaure,
                                                        &test_msg)
                .expect("failed to verify");

            assert_eq!(verification, true);
        }

        #[test]
        fn test_p521_signature_fail() {
            let test_keypair_a = super::EcDsaP521::random_key_pair(OpenSslRng)
                .expect("keypair gen failed");

            let test_keypair_b = super::EcDsaP521::random_key_pair(OpenSslRng)
                .expect("keypair gen failed");

            let test_data = b"hello world".to_vec();

            let signature = super::EcDsaP521::sign(&test_keypair_a.1, &test_data)
                .expect("signature failed");

            let verification = super::EcDsaP521::verify(&test_keypair_b.0,
                                                        &signature,
                                                        &test_data)
                .expect("validation failed");

            assert_eq!(verification, false);
        }
    }
}

pub mod ed25519 {
    use crate::asym::{AsymmetricKey, AsymmetricKeyError};
    use crate::signature::{SignatureScheme, SignatureError, SignatureSchemeId};
    use ed25519_dalek::{Signature, Signer, Keypair, Verifier};
    use std::convert::TryFrom;
    use rand_core::{CryptoRng, RngCore};

    #[derive(Clone)]
    pub struct PublicKey {
        key: ed25519_dalek::PublicKey
    }

    impl AsymmetricKey for PublicKey {
        fn from_bytes(bytes: &[u8]) -> Result<Self, AsymmetricKeyError> {
            let key = ed25519_dalek::PublicKey::from_bytes(bytes)
                .map_err(|_| AsymmetricKeyError::InvalidKeyType())?;
            Ok(Self { key })
        }

        fn to_bytes(&self) -> Result<Vec<u8>, AsymmetricKeyError> {
            Ok(self.key.to_bytes().to_vec())
        }
    }

    impl crate::asym::PublicKey for PublicKey {}

    pub struct SecretKey {
        key: ed25519_dalek::SecretKey
    }

    impl AsymmetricKey for SecretKey {
        fn from_bytes(bytes: &[u8]) -> Result<Self, AsymmetricKeyError> {
            let key = ed25519_dalek::SecretKey::from_bytes(bytes)
                .map_err(|_| AsymmetricKeyError::InvalidKeyType())?;
            Ok(Self { key })
        }

        fn to_bytes(&self) -> Result<Vec<u8>, AsymmetricKeyError> {
            Ok(self.key.to_bytes().to_vec())
        }
    }

    impl crate::asym::SecretKey for SecretKey {}

    pub struct EdDsa25519();

    impl SignatureScheme for EdDsa25519 {
        type PK = PublicKey;
        type SK = SecretKey;

        const IDENTIFIER: SignatureSchemeId = SignatureSchemeId::Ed25519;

        fn random_key_pair<RNG: CryptoRng + RngCore>(mut rng: RNG) -> Result<(Self::PK, Self::SK), SignatureError> {
            let keypair = Keypair::generate(&mut rng);
            Ok((PublicKey { key: keypair.public }, SecretKey { key: keypair.secret }))
        }

        fn sign(sig_key: &Self::SK, data: &[u8]) -> Result<Vec<u8>, SignatureError> {
            let pk = ed25519_dalek::PublicKey::from(&sig_key.key);

            // Weird hack but ed25519_dalek::SecretKey does not implement clone
            let sk = ed25519_dalek::SecretKey::from_bytes(&*sig_key.to_bytes()?)
                .map_err(|_| SignatureError::InvalidKeyData)?;

            let keypair = Keypair { secret: sk, public: pk };

            Ok(keypair.sign(data).to_bytes().to_vec())
        }

        fn verify(pub_key: &Self::PK, signature: &[u8], data: &[u8]) -> Result<bool, SignatureError> {
            let sig = Signature::try_from(signature)
                .map_err(|_| SignatureError::InvalidSignatureData)?;
            Ok(pub_key.key.verify(data, &sig).is_ok())
        }
    }

    #[cfg(test)]
    mod test {
        use crate::signature::SignatureScheme;
        use crate::rand::OpenSslRng;
        use crate::asym::AsymmetricKey;

        #[test]
        fn test_ed25519_signature() {
            let test_msg = b"".to_vec();
            let test_secret = super::SecretKey
            ::from_bytes(&hex!("9d61b19deffd5a60ba844af492ec2cc4\
                                      4449c5697b326919703bac031cae7f60"))
                .expect("invalid key");

            let test_public = super::PublicKey
            ::from_bytes(&hex!("d75a980182b10ab7d54bfed3c964073a\
                                      0ee172f3daa62325af021a68f707511a"))
                .expect("invalid key");

            let signaure = super::EdDsa25519::sign(&test_secret,
                                                   &test_msg).expect("failed to sign");

            let verification = super::EdDsa25519::verify(&test_public,
                                                         &signaure,
                                                         &test_msg)
                .expect("failed to verify");

            assert_eq!(verification, true);
        }

        #[test]
        fn test_ed25519_signature_fail() {
            let test_keypair_a = super::EdDsa25519::random_key_pair(OpenSslRng)
                .expect("keypair gen failed");

            let test_keypair_b = super::EdDsa25519::random_key_pair(OpenSslRng)
                .expect("keypair gen failed");

            let test_data = b"hello world".to_vec();

            let signature = super::EdDsa25519::sign(&test_keypair_a.1, &test_data)
                .expect("signature failed");

            let verification = super::EdDsa25519::verify(&test_keypair_b.0,
                                                         &signature,
                                                         &test_data)
                .expect("validation failed");

            assert_eq!(verification, false);
        }
    }
}