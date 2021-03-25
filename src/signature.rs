use crate::asym::{AsymmetricKeyError, AsymmetricKey};
use openssl::error::ErrorStack;
use rand_core::{CryptoRng, RngCore};
use serde::ser::Error;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use num_enum::{IntoPrimitive, TryFromPrimitive};

#[derive(Error, Debug)]
pub enum SignatureError {
    #[error("Openssl error: {0}")]
    OpenSSLError(#[from] ErrorStack),
    #[error("Asymmetric key error: {0}")]
    AsymmetricKeyError(#[from] AsymmetricKeyError),
    #[error("Invalid signature data")]
    InvalidSignatureData,
    #[error("serialization error")]
    SerializationFailure,
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



pub trait Signable {
    type E: Error;
    fn to_signable_vec(&self) -> Result<Vec<u8>, Self::E>;
}

impl Signable for Vec<u8> {
    type E = bincode::Error;
    fn to_signable_vec(&self) -> Result<Vec<u8>, Self::E> {
        Ok(self.clone()) //TODO: Remove clone
    }
}

pub trait Signer {
    fn sign<T: Signable + 'static>(&self, data: &T) -> Result<Vec<u8>, SignatureError>;
}

pub trait Verifier {
    fn verify<T: Signable + 'static>(&self, signature: &[u8], data: &T) -> Result<bool, SignatureError>;
}

pub trait SignatureScheme: Sized {
    type PK: Verifier + AsymmetricKey;
    type SK: Signer + AsymmetricKey;

    const IDENTIFIER: SignatureSchemeId;

    fn new_random<RNG: CryptoRng + RngCore + 'static>(rng: RNG) -> Result<Self, SignatureError>;

    fn get_signer(&self) -> &Self::SK;
    fn get_verifier(&self) -> &Self::PK;

    fn as_public_signature_key(&self) -> Result<PublicSignatureKey, SignatureError> {
        Ok(PublicSignatureKey {
            signature_scheme: Self::IDENTIFIER,
            signature_key: self.get_verifier().to_bytes()?
        })
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct PublicSignatureKey {
    pub signature_scheme: SignatureSchemeId,
    pub signature_key: Vec<u8>
}

impl Verifier for PublicSignatureKey {
    fn verify<T: Signable + 'static>(&self, signature: &[u8], data: &T) -> Result<bool, SignatureError> {
        match self.signature_scheme {
            SignatureSchemeId::EcdsaSecp256r1Sha256 => {
                let key = crate::asym::p256::PublicKey::from_bytes(&self.signature_key)?;
                key.verify(signature, data)
            }
            SignatureSchemeId::EcdsaSecp521r1Sha512 => {
                let key = crate::asym::p521::PublicKey::from_bytes(&self.signature_key)?;
                key.verify(signature, data)
            }
            SignatureSchemeId::Ed25519 => {
                let key = ed25519::PublicKey::from_bytes(&self.signature_key)?;
                key.verify(signature, data)
            },
            #[cfg(test)]
            SignatureSchemeId::Test => {
                Ok(signature.len() == 0 && data.to_signable_vec().unwrap().len() == 0)
            }
        }
    }
}

#[macro_use]
mod ossl {
    use openssl::ec::EcKey;
    use openssl::error::ErrorStack;
    use openssl::hash::MessageDigest;
    use openssl::pkey::{PKey, Private, Public};
    use openssl::sign::{Signer, Verifier};

    pub fn sign(
        digest: MessageDigest,
        sig_key: EcKey<Private>,
        data: &[u8],
    ) -> Result<Vec<u8>, ErrorStack> {
        let pkey = PKey::from_ec_key(sig_key)?;
        let mut signer = Signer::new(digest, &pkey)?;
        signer.sign_oneshot_to_vec(data)
    }

    pub fn verify(
        digest: MessageDigest,
        pub_key: EcKey<Public>,
        signature: &[u8],
        data: &[u8],
    ) -> Result<bool, ErrorStack> {
        let pkey = PKey::from_ec_key(pub_key)?;
        let mut verifier = Verifier::new(digest, &pkey)?;
        verifier.verify_oneshot(signature, data)
    }

    macro_rules! impl_openssl_signature {
        ($name:ident, $pk_ty:ty, $sk_ty:ty, $eng_ty:ty, $digest:expr, $scheme_id:expr) => {
            #[derive(Clone, Debug, Serialize, Deserialize)]
            pub struct $name {
                signer: $sk_ty,
                verifier: $pk_ty
            }

            impl Signer for $sk_ty {
                fn sign<T: Signable>(&self, data: &T) -> Result<Vec<u8>, SignatureError> {
                    let vec_to_sign = data
                        .to_signable_vec()
                        .map_err(|_| SignatureError::SerializationFailure)?;
                    super::ossl::sign($digest, self.key.clone(), &vec_to_sign)
                        .map_err(|e| e.into())
                }
            }

            impl Verifier for $pk_ty {
                fn verify<T: Signable>(
                    &self, signature: &[u8], data: &T
                ) -> Result<bool, SignatureError> {
                     let vec_to_verify = data
                        .to_signable_vec()
                        .map_err(|_| SignatureError::SerializationFailure)?;
                    super::ossl::verify($digest, self.key.clone(), signature, &vec_to_verify)
                        .map_err(|e| e.into())
                }
            }

            impl SignatureScheme for $name {
                type PK = $pk_ty;
                type SK = $sk_ty;

                const IDENTIFIER: SignatureSchemeId = $scheme_id;

                fn new_random<RNG: CryptoRng + RngCore + 'static>(
                    rng: RNG,
                ) -> Result<Self, SignatureError> {
                    let (pk, sk) = <$eng_ty>::random_key_pair(rng)?;
                    Ok(Self {
                        signer: sk,
                        verifier: pk
                    })
                }

                fn get_signer(&self) -> &Self::SK {
                    &self.signer
                }

                fn get_verifier(&self) -> &Self::PK {
                    &self.verifier
                }
            }
        };
    }
}

pub mod p256 {
    use super::{Signable, SignatureError, SignatureScheme, Signer, Verifier};
    use crate::asym::p256;
    use crate::asym::AsymmetricKeyEngine;
    use crate::signature::SignatureSchemeId;
    use openssl::hash::MessageDigest;
    use rand_core::{CryptoRng, RngCore};
    use serde::{Deserialize, Serialize};

    impl_openssl_signature!(
        EcDsaP256,
        p256::PublicKey,
        p256::SecretKey,
        p256::Engine,
        MessageDigest::sha256(),
        SignatureSchemeId::EcdsaSecp256r1Sha256
    );

    #[cfg(test)]
    mod test {
        use crate::asym::{p256, AsymmetricKey};
        use crate::rand::OpenSslRng;
        use crate::signature::{SignatureScheme, Signer, Verifier};

        #[test]
        //RFC 6979 Deterministic DSA and ECDSA
        fn test_p256_signatures() {
            let test_msg = b"sample".to_vec();
            let test_secret = p256::SecretKey::from_bytes(&hex!(
                "C9AFA9D845BA75166B5C215767B1D\
                                      6934E50C3DB36E89B127B8A622B120F6721"
            ))
            .expect("invalid key");

            let test_public = p256::PublicKey::from_bytes(&hex!(
                "0460FED4BA255A9D31C961EB74C6356D68C049B8\
                                      923B61FA6CE669622E60F29FB67903FE1008B8BC\
                                      99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C2\
                                      94D4462299"
            ))
            .expect("invalid key");

            let signaure = test_secret.sign(&test_msg).expect("failed to sign");

            let verification = test_public.verify(&signaure, &test_msg)
                .expect("failed to verify");

            assert_eq!(verification, true);
        }

        #[test]
        fn test_p256_signature_fail() {
            let p256_a =
                super::EcDsaP256::new_random(OpenSslRng).expect("keypair gen failed");

            let p256_b =
                super::EcDsaP256::new_random(OpenSslRng).expect("keypair gen failed");

            let test_data = b"hello world".to_vec();

            let signature =
                p256_a.signer.sign(&test_data).expect("signature failed");

            let verification = p256_b.verifier.verify(&signature, &test_data)
                .expect("validation failed");

            assert_eq!(verification, false);
        }

        #[test]
        fn test_p256_public_signature_key() {
            let sig_key = super::EcDsaP256::new_random(OpenSslRng)
                .expect("key error");

            let bad_key = super::EcDsaP256::new_random(OpenSslRng)
                .expect("key error");

            let test_data = b"test".to_vec();
            let signature = sig_key.get_signer().sign(&test_data).expect("sig error");

            assert_eq!(sig_key.as_public_signature_key()
                           .expect("pub key error")
                           .verify(&signature, &test_data)
                           .expect("sig error")
                       ,true);

            assert_eq!(bad_key.as_public_signature_key()
                           .expect("pub key error")
                           .verify(&signature, &test_data)
                           .expect("sig error")
                       ,false);
        }
    }
}

pub mod p521 {
    use super::{Signable, SignatureError, SignatureScheme, SignatureSchemeId, Signer, Verifier};
    use crate::asym::p521;
    use crate::asym::AsymmetricKeyEngine;
    use openssl::hash::MessageDigest;
    use rand_core::{CryptoRng, RngCore};
    use serde::{Deserialize, Serialize};

    impl_openssl_signature!(
        EcDsaP521,
        p521::PublicKey,
        p521::SecretKey,
        p521::Engine,
        MessageDigest::sha512(),
        SignatureSchemeId::EcdsaSecp521r1Sha512
    );

    #[cfg(test)]
    mod test {
        use crate::asym::{p521, AsymmetricKey};
        use crate::rand::OpenSslRng;
        use crate::signature::{SignatureScheme, Signer, Verifier};

        #[test]
        //RFC 6979 Deterministic DSA and ECDSA
        fn test_p521_signatures() {
            let test_msg = b"sample".to_vec();
            let test_secret = p521::SecretKey::from_bytes(&hex!(
                "00FAD06DAA62BA3B25D2FB40133DA757205DE67F5BB0018FEE8C86E1B6\
                                      8C7E75CAA896EB32F1F47C70855836A6D16FCC1466F6D8FBEC67DB89EC\
                                      0C08B0E996B83538"
            ))
            .expect("invalid key");

            let test_public = p521::PublicKey::from_bytes(&hex!(
                "0401894550D0785932E00EAA23B694F213F8C3121F86DC97A04E5A716\
            7DB4E5BCD371123D46E45DB6B5D5370A7F20FB633155D38FFA16D2BD761DCAC474B9A2F5023A4004931\
            01C962CD4D2FDDF782285E64584139C2F91B47F87FF82354D6630F746A28A0DB25741B5B34A828008B2\
            2ACC23F924FAAFBD4D33F81EA66956DFEAA2BFDFCF5"
            ))
            .expect("invalid key");

            let signature =
                test_secret.sign(&test_msg).expect("signature failed");

            let verification = test_public.verify(&signature, &test_msg)
                .expect("validation failed");

            assert_eq!(verification, true);
        }

        #[test]
        fn test_p521_signature_fail() {
            let p521_a =
                super::EcDsaP521::new_random(OpenSslRng).expect("keypair gen failed");

            let p521_b =
                super::EcDsaP521::new_random(OpenSslRng).expect("keypair gen failed");

            let test_data = b"hello world".to_vec();

            let signature =
                p521_a.signer.sign(&test_data).expect("signature failed");

            let verification = p521_b.verifier.verify(&signature, &test_data)
                .expect("validation failed");

            assert_eq!(verification, false);
        }

        #[test]
        fn test_p521_public_signature_key() {
            let sig_key = super::EcDsaP521::new_random(OpenSslRng)
                .expect("key error");

            let bad_key = super::EcDsaP521::new_random(OpenSslRng)
                .expect("key error");

            let test_data = b"test".to_vec();
            let signature = sig_key.get_signer().sign(&test_data).expect("sig error");

            assert_eq!(sig_key.as_public_signature_key()
                           .expect("pub key error")
                           .verify(&signature, &test_data)
                           .expect("sig error")
                       ,true);

            assert_eq!(bad_key.as_public_signature_key()
                           .expect("pub key error")
                           .verify(&signature, &test_data)
                           .expect("sig error")
                       ,false);
        }
    }
}

pub mod ed25519 {
    use crate::asym::{AsymmetricKey, AsymmetricKeyError};
    use crate::signature::{Signable, SignatureError, SignatureScheme, SignatureSchemeId};
    use ed25519_dalek::{Keypair, Signature, Signer, Verifier};
    use rand_core::{CryptoRng, RngCore};
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    use std::convert::TryFrom;

    #[derive(Clone, Debug)]
    pub struct PublicKey {
        key: ed25519_dalek::PublicKey,
    }

    impl_serialization!(PublicKey);

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

    impl super::Verifier for PublicKey {
        fn verify<T: Signable>(&self, signature: &[u8], data: &T) -> Result<bool, SignatureError> {
            let sig =
                Signature::try_from(signature).map_err(|_| SignatureError::InvalidSignatureData)?;

            let vec_to_verify = data
                .to_signable_vec()
                .map_err(|_| SignatureError::SerializationFailure)?;

            Ok(self.key.verify(&vec_to_verify, &sig).is_ok())
        }
    }

    #[derive(Debug)]
    pub struct SecretKey {
        key: ed25519_dalek::SecretKey,
    }

    impl Clone for SecretKey {
        fn clone(&self) -> Self {
            SecretKey {
                key: ed25519_dalek::SecretKey::from_bytes(&self.key.to_bytes()).unwrap(),
            }
        }
    }

    impl_serialization!(SecretKey);

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

    impl super::Signer for SecretKey {
        fn sign<T: Signable>(&self, data: &T) -> Result<Vec<u8>, SignatureError> {
            let pk = ed25519_dalek::PublicKey::from(&self.key);
            let keypair = Keypair {
                secret: self.clone().key,
                public: pk,
            };

            let vec_to_sign = data
                .to_signable_vec()
                .map_err(|_| SignatureError::SerializationFailure)?;

            Ok(keypair.sign(&vec_to_sign).to_bytes().to_vec())
        }
    }

    impl crate::asym::SecretKey for SecretKey {}

    #[derive(Clone, Debug)]
    pub struct EdDsa25519 {
        signer: SecretKey,
        verifier: PublicKey
    }

    impl SignatureScheme for EdDsa25519 {
        type PK = PublicKey;
        type SK = SecretKey;

        const IDENTIFIER: SignatureSchemeId = SignatureSchemeId::Ed25519;

        fn new_random<RNG: CryptoRng + RngCore + 'static>(
            mut rng: RNG,
        ) -> Result<Self, SignatureError> {
            let keypair = Keypair::generate(&mut rng);
            Ok(Self {
                signer: SecretKey { key: keypair.secret },
                verifier: PublicKey { key: keypair.public }
            })
        }

        fn get_signer(&self) -> &Self::SK {
            &self.signer
        }

        fn get_verifier(&self) -> &Self::PK {
            &self.verifier
        }
    }

    #[cfg(test)]
    mod test {
        use crate::asym::AsymmetricKey;
        use crate::rand::OpenSslRng;
        use crate::signature::{SignatureScheme, Signer, Verifier};
        use crate::signature::ed25519::EdDsa25519;

        #[test]
        fn test_ed25519_signature() {
            let test_msg = b"".to_vec();
            let test_secret = super::SecretKey::from_bytes(&hex!(
                "9d61b19deffd5a60ba844af492ec2cc4\
                                      4449c5697b326919703bac031cae7f60"
            ))
            .expect("invalid key");

            let test_public = super::PublicKey::from_bytes(&hex!(
                "d75a980182b10ab7d54bfed3c964073a\
                                      0ee172f3daa62325af021a68f707511a"
            ))
            .expect("invalid key");

            let signaure =
                test_secret.sign(&test_msg).expect("failed to sign");

            let verification = test_public.verify(&signaure, &test_msg)
                .expect("failed to verify");

            assert_eq!(verification, true);
        }

        #[test]
        fn test_ed25519_signature_fail() {
            let ed25519_a =
                EdDsa25519::new_random(OpenSslRng)
                    .expect("keypair gen failed");

            let ed25519_b =
                EdDsa25519::new_random(OpenSslRng)
                    .expect("keypair gen failed");

            let test_data = b"hello world".to_vec();

            let signature = ed25519_a.signer.sign(&test_data).expect("signature failed");

            let verification = ed25519_b.verifier
                .verify(&signature, &test_data)
                .expect("validation failed");

            assert_eq!(verification, false);
        }

        #[test]
        fn test_ed25519_public_signature_key() {
            let sig_key = EdDsa25519::new_random(OpenSslRng)
                .expect("key error");

            let bad_key = EdDsa25519::new_random(OpenSslRng)
                .expect("key error");

            let test_data = b"test".to_vec();
            let signature = sig_key.get_signer().sign(&test_data).expect("sig error");

            assert_eq!(sig_key.as_public_signature_key()
                           .expect("pub key error")
                           .verify(&signature, &test_data)
                           .expect("sig error")
                       ,true);

            assert_eq!(bad_key.as_public_signature_key()
                           .expect("pub key error")
                           .verify(&signature, &test_data)
                           .expect("sig error")
                       ,false);
        }
    }
}

#[cfg(test)]
pub (crate) mod test_utils {
    use crate::signature::{Signer, SignatureError, Signable, Verifier, SignatureScheme, SignatureSchemeId};
    use rand_core::{CryptoRng, RngCore};
    use crate::asym::{AsymmetricKey, AsymmetricKeyError};
    use mockall::mock;

    mock! {
        pub Signer {}

        impl Clone for Signer {
            fn clone(&self) -> Self;
        }

        impl AsymmetricKey for Signer {
            fn from_bytes(bytes: &[u8]) -> Result<Self, AsymmetricKeyError>;
            fn to_bytes(&self) -> Result<Vec<u8>, AsymmetricKeyError>;
        }

        impl Signer for Signer {
            fn sign<T: Signable + 'static>(&self, data: &T) -> Result<Vec<u8>, SignatureError>;
        }
    }

    mock! {
        pub Verifier {}

        impl Clone for Verifier {
            fn clone(&self) -> Self;
        }

        impl AsymmetricKey for Verifier {
            fn from_bytes(bytes: &[u8]) -> Result<Self, AsymmetricKeyError>;
            fn to_bytes(&self) -> Result<Vec<u8>, AsymmetricKeyError>;
        }

        impl Verifier for Verifier {
            fn verify<T: Signable + 'static>(&self, signature: &[u8], data: &T) -> Result<bool, SignatureError>;
        }
    }

    mock! {
        pub TestSignatureScheme {}

        impl SignatureScheme for TestSignatureScheme {
            type PK = MockVerifier;
            type SK = MockSigner;
            const IDENTIFIER: SignatureSchemeId = SignatureSchemeId::Test;

            fn new_random<RNG: CryptoRng + RngCore + 'static>(rng: RNG) -> Result<Self, SignatureError>;
            fn get_signer(&self) -> &<MockTestSignatureScheme as SignatureScheme>::SK;
            fn get_verifier(&self) -> &<MockTestSignatureScheme as SignatureScheme>::PK;
        }
    }

    pub fn get_test_verifier(test_bytes: &[u8]) -> MockVerifier {
        let mut verifier = MockVerifier::new();
        let copy_test_bytes = test_bytes.clone().to_vec();
        verifier.expect_to_bytes().returning(move || Ok(copy_test_bytes.clone()));
        verifier
    }

    pub fn get_test_signer(test_bytes: &[u8]) -> MockSigner {
        let mut signer = MockSigner::new();
        let copy_test_bytes = test_bytes.clone().to_vec();
        signer.expect_to_bytes().returning(move || Ok(copy_test_bytes.clone()));
        signer
    }
}

#[cfg(test)]
mod test {
    use super::test_utils::MockTestSignatureScheme;
    use super::SignatureSchemeId;
    use crate::signature::{SignatureScheme};
    use super::test_utils::get_test_verifier;

    #[test]
    fn test_signature_scheme() {
        let test_bytes = b"test".to_vec();

        let mut scheme = MockTestSignatureScheme::new();
        scheme.expect_get_verifier().return_const(get_test_verifier(&test_bytes));

        let res = scheme.as_public_signature_key().expect("failed public key");
        assert_eq!(res.signature_scheme, SignatureSchemeId::Test);
        assert_eq!(res.signature_key, test_bytes)
    }
}
