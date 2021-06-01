use crate::crypto::kdf::KdfError;
use crate::crypto::rand::SecureRng;
use openssl::error::ErrorStack;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum AsymmetricKeyError {
    #[error("Openssl error: {0}")]
    OpenSSLError(#[from] ErrorStack),
    #[error("Invalid key type for action")]
    InvalidKeyType(),
    #[error("Key derive failure")]
    KeyDerivationError(),
    #[error("KDF error")]
    KdfError(#[from] KdfError),
    #[error("RNG error: {0}")]
    RngFailure(#[from] rand_core::Error),
}

pub trait AsymmetricKey: Sized + Clone {
    fn from_bytes(bytes: &[u8]) -> Result<Self, AsymmetricKeyError>;
    fn to_bytes(&self) -> Result<Vec<u8>, AsymmetricKeyError>;
}

pub trait SecretKey: AsymmetricKey {}
pub trait PublicKey: AsymmetricKey {}

pub trait AsymmetricKeyEngine {
    type PK: PublicKey;
    type SK: SecretKey;
    const SK_LEN: u16;
    fn random_key_pair<RNG: SecureRng + 'static>(
        rng: RNG,
    ) -> Result<(Self::PK, Self::SK), AsymmetricKeyError>;
    fn get_pub_key(sk: &Self::SK) -> Result<Self::PK, AsymmetricKeyError>;
}

pub trait EcdhEngine: AsymmetricKeyEngine {
    fn shared_secret(
        local_sk: &Self::SK,
        remote_pk: &Self::PK,
    ) -> Result<Vec<u8>, AsymmetricKeyError>;
}

/* OpenSSL Functions */
#[macro_use]
mod ossl {
    use openssl::bn::{BigNum, BigNumContext};
    use openssl::ec::{EcGroup, EcKey, EcPoint, PointConversionForm};
    use openssl::error::ErrorStack;
    use openssl::nid::Nid;
    use openssl::pkey::{PKey, Private, Public};

    pub fn shared_secret(
        local_sk: &EcKey<Private>,
        remote_pk: &EcKey<Public>,
    ) -> Result<Vec<u8>, ErrorStack> {
        let local_sec_key = PKey::from_ec_key(local_sk.clone())?;
        let remote_pub_key = PKey::from_ec_key(remote_pk.clone())?;

        let mut ecdh_derive = openssl::derive::Deriver::new(&local_sec_key)?;
        ecdh_derive.set_peer(&remote_pub_key)?;
        ecdh_derive.derive_to_vec()
    }

    pub fn get_public(private: &EcKey<Private>) -> Result<EcKey<Public>, ErrorStack> {
        EcKey::from_public_key(private.group(), private.public_key())
    }

    pub fn pub_key_from_bytes(nid: Nid, bytes: &[u8]) -> Result<EcKey<Public>, ErrorStack> {
        let group = EcGroup::from_curve_name(nid)?;
        let mut ctx = BigNumContext::new()?;
        let point = EcPoint::from_bytes(&group, bytes, &mut ctx)?;
        EcKey::from_public_key(&group, &point)
    }

    pub fn pub_key_to_bytes(public: &EcKey<Public>) -> Result<Vec<u8>, ErrorStack> {
        let mut ctx = BigNumContext::new()?;

        public
            .public_key()
            .to_bytes(public.group(), PointConversionForm::UNCOMPRESSED, &mut ctx)
    }

    pub fn pri_key_from_bytes(nid: Nid, bytes: &[u8]) -> Result<EcKey<Private>, ErrorStack> {
        // Get the order and verify that the bytes are in range
        let mut ctx = BigNumContext::new()?;
        let group = EcGroup::from_curve_name(nid)?;
        let mut order = BigNum::new()?;
        group.order(&mut order, &mut ctx)?;

        // Create a big num from our sk_val
        let sk_val = BigNum::from_slice(bytes)?;

        // The secret can't be greater than or equal to the order of the curve
        if sk_val.ge(&order) || sk_val.eq(&BigNum::from_u32(0)?) {
            return Err(ErrorStack::get());
        }

        // Derive the public key from the private key since this is the only way we can get
        // what we need from the openssl crate
        let mut pk_val = EcPoint::new(&group)?;
        let mul_ctx = BigNumContext::new()?;
        pk_val.mul_generator(&group, &sk_val, &mul_ctx)?;
        EcKey::from_private_components(&group, &sk_val, &pk_val)
    }

    pub fn pri_key_to_bytes(key: &EcKey<Private>) -> Result<Vec<u8>, ErrorStack> {
        Ok(key.private_key().to_vec())
    }

    macro_rules! openssl_asym_key {
        ($nid:expr, $n_sk:expr, $n_pk:expr, $bitmask:expr) => {
            #[derive(Debug, Clone)]
            pub struct PublicKey {
                pub(crate) key: EcKey<Public>,
            }

            impl From<EcKey<Public>> for PublicKey {
                fn from(key: EcKey<Public>) -> Self {
                    PublicKey { key }
                }
            }

            impl AsymmetricKey for PublicKey {
                fn from_bytes(bytes: &[u8]) -> Result<Self, AsymmetricKeyError> {
                    if (bytes.len() != $n_pk) {
                        return Err(AsymmetricKeyError::InvalidKeyType());
                    }
                    Ok(Self {
                        key: super::ossl::pub_key_from_bytes($nid, bytes)?,
                    })
                }

                fn to_bytes(&self) -> Result<Vec<u8>, AsymmetricKeyError> {
                    super::ossl::pub_key_to_bytes(&self.key).map_err(|e| e.into())
                }
            }

            impl super::PublicKey for PublicKey {}

            #[derive(Debug, Clone)]
            pub struct SecretKey {
                pub(crate) key: EcKey<Private>,
            }

            impl From<EcKey<Private>> for SecretKey {
                fn from(key: EcKey<Private>) -> Self {
                    SecretKey { key }
                }
            }

            impl AsymmetricKey for SecretKey {
                fn from_bytes(bytes: &[u8]) -> Result<Self, AsymmetricKeyError> {
                    Ok(Self {
                        key: super::ossl::pri_key_from_bytes($nid, bytes)?,
                    })
                }

                fn to_bytes(&self) -> Result<Vec<u8>, AsymmetricKeyError> {
                    super::ossl::pri_key_to_bytes(&self.key).map_err(|e| e.into())
                }
            }

            impl super::SecretKey for SecretKey {}

            pub struct Engine();

            impl AsymmetricKeyEngine for Engine {
                type PK = PublicKey;
                type SK = SecretKey;
                const SK_LEN: u16 = $n_sk;

                // Heavily based on the derive_key_pair function which ensures the random value
                // is in range for the curve
                fn random_key_pair<RNG: SecureRng>(
                    mut rng: RNG,
                ) -> Result<(Self::PK, Self::SK), AsymmetricKeyError> {
                    for _ in 0u8..255 {
                        let mut bytes = vec![0u8; Self::SK_LEN.into()];
                        rng.try_fill_bytes(&mut bytes)?;

                        bytes[0] &= $bitmask;

                        if let Ok(secret_key) = Self::SK::from_bytes(&bytes) {
                            if let Ok(pub_key) = Self::get_pub_key(&secret_key) {
                                return Ok((pub_key, secret_key));
                            }
                        }
                    }
                    Err(AsymmetricKeyError::KeyDerivationError())
                }

                fn get_pub_key(sk: &Self::SK) -> Result<Self::PK, AsymmetricKeyError> {
                    super::ossl::get_public(&sk.key)
                        .map(|k| k.into())
                        .map_err(|e| e.into())
                }
            }

            impl EcdhEngine for Engine {
                fn shared_secret(
                    local_sk: &Self::SK,
                    remote_pk: &Self::PK,
                ) -> Result<Vec<u8>, AsymmetricKeyError> {
                    super::ossl::shared_secret(&local_sk.key, &remote_pk.key).map_err(|e| e.into())
                }
            }
        };
    }
}

macro_rules! impl_serialization {
    ($key_type:ty) => {
        impl Serialize for $key_type {
            fn serialize<S>(
                &self,
                serializer: S,
            ) -> Result<<S as Serializer>::Ok, <S as Serializer>::Error>
            where
                S: Serializer,
            {
                use serde::ser::Error;
                serializer.serialize_bytes(
                    &self
                        .to_bytes()
                        .map_err(|_| S::Error::custom("failed key serialization"))?,
                )
            }
        }

        impl<'de> Deserialize<'de> for $key_type {
            fn deserialize<D>(deserializer: D) -> Result<Self, <D as Deserializer<'de>>::Error>
            where
                D: Deserializer<'de>,
            {
                use serde::de::Error;
                let bytes: Vec<u8> = Vec::deserialize(deserializer)?;
                <$key_type>::from_bytes(&bytes)
                    .map_err(|_| D::Error::custom("failed key deserialization"))
            }
        }
    };
}

#[cfg(test)]
macro_rules! asym_key_tests {
    () => {
        #[test]
        fn test_key_serialization() {
            run_serialization_test::<PublicKey, SecretKey, Engine>(get_test_case());
        }

        #[test]
        fn test_pri_key_to_pub_key() {
            run_pri_to_pub_test::<PublicKey, SecretKey, Engine>(get_test_case());
        }

        #[test]
        fn test_random_keys() {
            run_random_key_test::<PublicKey, SecretKey, Engine>(get_test_case());
        }

        #[test]
        fn test_shared_secret() {
            run_ecdh_test_case::<PublicKey, SecretKey, Engine>(get_test_case());
        }
    };
}

pub mod p521 {
    use super::{AsymmetricKey, AsymmetricKeyEngine, AsymmetricKeyError, EcdhEngine};
    use crate::crypto::rand::SecureRng;
    use openssl::ec::EcKey;
    use openssl::nid::Nid;
    use openssl::pkey::{Private, Public};
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    openssl_asym_key!(Nid::SECP521R1, 66, 133, 0x01);
    impl_serialization!(PublicKey);
    impl_serialization!(SecretKey);

    #[cfg(test)]
    mod test {
        use super::Engine;
        use super::PublicKey;
        use super::SecretKey;

        use crate::crypto::asym::test::{
            run_ecdh_test_case, run_pri_to_pub_test, run_random_key_test, run_serialization_test,
            TestCase,
        };

        fn get_test_case() -> TestCase {
            TestCase {
                alice_pub: hex!(
                    "0401ebb34dd75721abf8adc9dbed178\
                                 89cbb9765d90a7c60f2cef007bb0f2b\
                                 26e14881fd4442e689d61cb2dd046ee\
                                 30e3ffd20f9a45bbdf6413d583a2dbf\
                                 59924fd35c00f6b632d194c0388e22d\
                                 8437e558c552ae195adfd153f92d749\
                                 08351b2f8c4eda94edb0916d1b53c02\
                                 0b5eecaed1a5fc38a233e4830587bb2\
                                 ee3489b3b42a5a86a4"
                ),
                alice_pri: hex!(
                    "0113f82da825735e3d97276683b2b74\
                                 277bad27335ea71664af2430cc4f334\
                                 59b9669ee78b3ffb9b8683015d344dc\
                                 bfef6fb9af4c6c470be254516cd3c1a\
                                 1fb47362"
                ),
                bob_pub: hex!(
                    "04010ebfafc6e85e08d24bfffcc1a4511\
                               db0e634beeb1b6dec8c5939ae44766201\
                               af6200430ba97c8ac6a0e9f08b33ce7e9\
                               feeb5ba4ee5e0d81510c24295b8a08d02\
                               3500a4a6ec300df9e257b0372b5e7abfe\
                               f093436719a77887ebb0b18cf8099b9f4\
                               212b6e30a1419c18e029d36863cc9d448\
                               f4dba4d2a0e60711be572915fbd4fef26\
                               95"
                ),
                bob_pri: hex!(
                    "00cee3480d8645a17d249f2776d28bae6\
                               16952d1791fdb4b70f7c3378732aa1b22\
                               928448bcd1dc2496d435b01048066ebe4\
                               f72903c361b1a9dc1193dc2c9d0891b96"
                ),
                shared_secret: hex!(
                    "00cdea89621cfa46b132f9e4cfe\
                                     2261cde2d4368eb5656634c7cc9\
                                     8c7a00cde54ed1866a0dd3e6126\
                                     c9d2f845daff82ceb1da08f5d87\
                                     521bb0ebeca77911169c20cc"
                ),
            }
        }

        asym_key_tests!();
    }
}

pub mod p256 {
    use super::{AsymmetricKey, AsymmetricKeyEngine, AsymmetricKeyError, EcdhEngine};
    use crate::crypto::rand::SecureRng;
    use openssl::ec::EcKey;
    use openssl::nid::Nid;
    use openssl::pkey::{Private, Public};
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    openssl_asym_key!(Nid::X9_62_PRIME256V1, 32, 65, 0xFF);
    impl_serialization!(PublicKey);
    impl_serialization!(SecretKey);

    #[cfg(test)]
    mod test {
        use super::Engine;
        use super::PublicKey;
        use super::SecretKey;

        use crate::crypto::asym::test::{
            run_ecdh_test_case, run_pri_to_pub_test, run_random_key_test, run_serialization_test,
            TestCase,
        };

        fn get_test_case() -> TestCase {
            TestCase {
                alice_pub: hex!(
                    "042af502f3be8952f2c9b5a8d4160d09e97165be50bc4\
                                 2ae4a5e8d3b4ba83aeb15eb0faf4ca986c4d38681a0f9\
                                 872d79d56795bd4bff6e6de3c0f5015ece5efd85"
                ),
                alice_pri: hex!(
                    "814264145f2f56f2e96a8e337a1284993faf432a5abce\
                                 59e867b7291d507a3af"
                ),
                bob_pub: hex!(
                    "04b120de4aa36492795346e8de6c2c8646ae06aaea279fa77\
                               5b3ab0715f6ce51b09f1b7eece20d7b5ed8ec685fa3f071\
                               d83727027092a8411385c34dde5708b2b6"
                ),
                bob_pri: hex!(
                    "2ce1788ec197e096db95a200cc0ab26a19ce6bccad562b8\
                               eee1b593761cf7f41"
                ),
                shared_secret: hex!(
                    "dd0f5396219d1ea393310412d19a08f1f5811e9dc\
                                     8ec8eea7f80d21c820c2788"
                ),
            }
        }

        asym_key_tests!();
    }
}

pub mod x25519 {
    use crate::crypto::asym::{AsymmetricKey, AsymmetricKeyEngine, AsymmetricKeyError, EcdhEngine};
    use crate::crypto::rand::SecureRng;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    #[derive(Clone, Debug)]
    pub struct PublicKey {
        key: x25519_dalek::PublicKey,
    }

    impl From<x25519_dalek::PublicKey> for PublicKey {
        fn from(key: x25519_dalek::PublicKey) -> Self {
            PublicKey { key }
        }
    }

    impl_serialization!(PublicKey);

    impl AsymmetricKey for PublicKey {
        fn from_bytes(bytes: &[u8]) -> Result<Self, AsymmetricKeyError> {
            if bytes.len() != 32 {
                return Err(AsymmetricKeyError::InvalidKeyType());
            }

            let mut key_bytes: [u8; 32] = Default::default();
            key_bytes.copy_from_slice(bytes);
            Ok(PublicKey {
                key: x25519_dalek::PublicKey::from(key_bytes),
            })
        }

        fn to_bytes(&self) -> Result<Vec<u8>, AsymmetricKeyError> {
            Ok(Vec::from(self.key.to_bytes()))
        }
    }

    impl super::PublicKey for PublicKey {}

    #[derive(Clone)]
    pub struct SecretKey {
        key: x25519_dalek::StaticSecret,
    }

    impl From<x25519_dalek::StaticSecret> for SecretKey {
        fn from(key: x25519_dalek::StaticSecret) -> Self {
            SecretKey { key }
        }
    }

    impl_serialization!(SecretKey);

    impl AsymmetricKey for SecretKey {
        fn from_bytes(bytes: &[u8]) -> Result<Self, AsymmetricKeyError> {
            if bytes.len() != 32 {
                return Err(AsymmetricKeyError::InvalidKeyType());
            }

            let mut key_bytes: [u8; 32] = Default::default();
            key_bytes.copy_from_slice(bytes);
            Ok(SecretKey {
                key: x25519_dalek::StaticSecret::from(key_bytes),
            })
        }

        fn to_bytes(&self) -> Result<Vec<u8>, AsymmetricKeyError> {
            Ok(Vec::from(self.key.to_bytes()))
        }
    }

    impl super::SecretKey for SecretKey {}

    pub struct Engine();

    impl AsymmetricKeyEngine for Engine {
        type PK = PublicKey;
        type SK = SecretKey;
        const SK_LEN: u16 = 32;

        fn random_key_pair<RNG: SecureRng + 'static>(
            rng: RNG,
        ) -> Result<(Self::PK, Self::SK), AsymmetricKeyError> {
            let secret_key = x25519_dalek::StaticSecret::new(rng);
            let pub_key = x25519_dalek::PublicKey::from(&secret_key);
            Ok((pub_key.into(), secret_key.into()))
        }

        fn get_pub_key(sk: &Self::SK) -> Result<Self::PK, AsymmetricKeyError> {
            Ok(x25519_dalek::PublicKey::from(&sk.key).into())
        }
    }

    impl EcdhEngine for Engine {
        fn shared_secret(
            local_sk: &Self::SK,
            remote_pk: &Self::PK,
        ) -> Result<Vec<u8>, AsymmetricKeyError> {
            let shared_secret = local_sk
                .key
                .diffie_hellman(&remote_pk.key)
                .to_bytes()
                .to_vec();

            Ok(shared_secret)
        }
    }

    #[cfg(test)]
    mod test {
        use super::Engine;
        use super::PublicKey;
        use super::SecretKey;

        use crate::crypto::asym::test::{
            run_ecdh_test_case, run_pri_to_pub_test, run_random_key_test, run_serialization_test,
            TestCase,
        };

        fn get_test_case() -> TestCase {
            TestCase {
                alice_pub: hex!(
                    "8520f0098930a754748b7ddcb43ef75\
                                 a0dbf3a0d26381af4eba4a98eaa9b4e6a"
                ),
                alice_pri: hex!(
                    "70076d0a7318a57d3c16c17251b2664\
                                 5df4c2f87ebc0992ab177fba51db92c6a"
                ),
                bob_pub: hex!(
                    "de9edb7d7b7dc1b4d35b61c2ece435373\
                               f8343c85b78674dadfc7e146f882b4f"
                ),
                bob_pri: hex!(
                    "5dab087e624a8a4b79e17f8b83800ee66\
                               f3bb1292618b6fd1c2f8b27ff88e0eb"
                ),
                shared_secret: hex!(
                    "4a5d9d5ba4ce2de1728e3bf4803\
                                     50f25e07e21c947d19e3376f09b3c1e161742"
                ),
            }
        }

        asym_key_tests!();
    }
}

pub mod x448 {
    use crate::crypto::asym::{AsymmetricKey, AsymmetricKeyEngine, AsymmetricKeyError, EcdhEngine};
    use crate::crypto::rand::SecureRng;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub struct PublicKey {
        key: x448::PublicKey,
    }

    impl Clone for PublicKey {
        fn clone(&self) -> Self {
            let bytes = self.key.as_bytes();
            Self {
                key: x448::PublicKey::from_bytes(bytes).unwrap(),
            }
        }
    }

    impl From<x448::PublicKey> for PublicKey {
        fn from(key: x448::PublicKey) -> Self {
            PublicKey { key }
        }
    }

    impl_serialization!(PublicKey);

    impl AsymmetricKey for PublicKey {
        fn from_bytes(bytes: &[u8]) -> Result<Self, AsymmetricKeyError> {
            if let Some(key) = x448::PublicKey::from_bytes(bytes) {
                Ok(key.into())
            } else {
                Err(AsymmetricKeyError::InvalidKeyType())
            }
        }

        fn to_bytes(&self) -> Result<Vec<u8>, AsymmetricKeyError> {
            Ok(self.key.as_bytes().to_vec())
        }
    }

    impl super::PublicKey for PublicKey {}

    pub struct SecretKey {
        key: x448::Secret,
    }

    impl Clone for SecretKey {
        fn clone(&self) -> Self {
            let bytes = self.key.as_bytes();
            Self {
                key: x448::Secret::from_bytes(bytes).unwrap(),
            }
        }
    }

    impl_serialization!(SecretKey);

    impl From<x448::Secret> for SecretKey {
        fn from(key: x448::Secret) -> Self {
            SecretKey { key }
        }
    }

    impl AsymmetricKey for SecretKey {
        fn from_bytes(bytes: &[u8]) -> Result<Self, AsymmetricKeyError> {
            if let Some(key) = x448::Secret::from_bytes(bytes) {
                Ok(key.into())
            } else {
                Err(AsymmetricKeyError::InvalidKeyType())
            }
        }

        fn to_bytes(&self) -> Result<Vec<u8>, AsymmetricKeyError> {
            Ok(self.key.as_bytes().to_vec())
        }
    }

    impl super::SecretKey for SecretKey {}

    pub struct Engine();

    impl AsymmetricKeyEngine for Engine {
        type PK = PublicKey;
        type SK = SecretKey;
        const SK_LEN: u16 = 56;

        fn random_key_pair<RNG: SecureRng>(
            mut rng: RNG,
        ) -> Result<(Self::PK, Self::SK), AsymmetricKeyError> {
            let secret_key = x448::Secret::new(&mut rng);
            let pub_key = x448::PublicKey::from(&secret_key);
            Ok((pub_key.into(), secret_key.into()))
        }

        fn get_pub_key(sk: &Self::SK) -> Result<Self::PK, AsymmetricKeyError> {
            Ok(x448::PublicKey::from(&sk.key).into())
        }
    }

    impl EcdhEngine for Engine {
        fn shared_secret(
            local_sk: &Self::SK,
            remote_pk: &Self::PK,
        ) -> Result<Vec<u8>, AsymmetricKeyError> {
            if let Some(shared_secret) = local_sk.key.as_diffie_hellman(&remote_pk.key) {
                Ok(shared_secret.as_bytes().to_vec())
            } else {
                Err(AsymmetricKeyError::KeyDerivationError())
            }
        }
    }

    #[cfg(test)]
    mod test {
        use super::Engine;
        use super::PublicKey;
        use super::SecretKey;

        use crate::crypto::asym::test::{
            run_ecdh_test_case, run_pri_to_pub_test, run_random_key_test, run_serialization_test,
            TestCase,
        };

        fn get_test_case() -> TestCase {
            TestCase {
                alice_pub: hex!(
                    "9b08f7cc31b7e3e67d22d5aea121074a273\
                                 bd2b83de09c63faa73d2c22c5d9bbc83664\
                                 7241d953d40c5b12da88120d53177f80e53\
                                 2c41fa0"
                ),
                alice_pri: hex!(
                    "988f4925d1519f5775cf46b04b5800d4ee9\
                                 ee8bae8bc5565d498c28dd9c9baf574a941\
                                 9744897391006382a6f127ab1d9ac2d8c0a\
                                 59872eb"
                ),
                bob_pub: hex!(
                    "3eb7a829b0cd20f5bcfc0b599b6feccf6da46\
                               27107bdb0d4f345b43027d8b972fc3e34fb42\
                               32a13ca706dcb57aec3dae07bdc1c67bf33609"
                ),
                bob_pri: hex!(
                    "1c306a7ac2a0e2e0990b294470cba339e6453\
                               772b075811d8fad0d1d6927c120bb5ee8972b\
                               0d3e21374c9c921b09d1b0366f10b65173992d"
                ),
                shared_secret: hex!(
                    "07fff4181ac6cc95ec1c16a94a0f74d\
                                     12da232ce40a77552281d282bb60c0b\
                                     56fd2464c335543936521c24403085d\
                                     59a449a5037514a879d"
                ),
            }
        }

        asym_key_tests!();
    }
}

#[cfg(test)]
mod test {
    use crate::crypto::asym::{EcdhEngine, PublicKey, SecretKey};
    use crate::crypto::rand::test_rng;

    pub struct TestCase {
        pub alice_pub: Vec<u8>,
        pub alice_pri: Vec<u8>,
        pub bob_pub: Vec<u8>,
        pub bob_pri: Vec<u8>,
        pub shared_secret: Vec<u8>,
    }

    pub fn run_ecdh_test_case<PK: PublicKey, SK: SecretKey, E: EcdhEngine<PK = PK, SK = SK>>(
        case: TestCase,
    ) {
        // Import the keys into their structures
        let alice_pub = PK::from_bytes(&case.alice_pub).expect("key import failed");
        let alice_pri = SK::from_bytes(&case.alice_pri).expect("key import failed");
        let bob_pub = PK::from_bytes(&case.bob_pub).expect("key import failed");
        let bob_pri = SK::from_bytes(&case.bob_pri).expect("key import failed");

        // Use the ecdh engine to compute the shared secret (alice)
        let shared_secret_a =
            E::shared_secret(&alice_pri, &bob_pub).expect("shared secret generation failed");

        // Use the ecdh engine to compute the shared secret (bob)
        let shared_secret_b =
            E::shared_secret(&bob_pri, &alice_pub).expect("shared secret generation failed");

        // These values should be equal to each other as well as the expected case
        assert_eq!(shared_secret_a, shared_secret_b);
        assert_eq!(shared_secret_a, case.shared_secret);
    }

    pub fn run_serialization_test<PK: PublicKey, SK: SecretKey, E: EcdhEngine<PK = PK, SK = SK>>(
        case: TestCase,
    ) {
        // Make a pub key from bytes
        let pub_key = PK::from_bytes(&case.alice_pub).expect("key import failed");

        // Serialize that key and make sure it matches the original case input
        assert_eq!(
            pub_key.to_bytes().expect("key serialize failed"),
            case.alice_pub
        );

        // Make a pri key from bytes
        let secret_key = SK::from_bytes(&case.alice_pri).expect("key import failed");

        // Serialize that key to make sure it matches the original case input
        assert_eq!(
            secret_key.to_bytes().expect("key serialize failed"),
            case.alice_pri
        );

        // Verify that incorrect byte counts result in non keys
        assert_eq!(SK::from_bytes(&vec![0u8; 1]).is_err(), true);
        assert_eq!(PK::from_bytes(&vec![0u8; 1]).is_err(), true);
    }

    pub fn run_pri_to_pub_test<PK: PublicKey, SK: SecretKey, E: EcdhEngine<PK = PK, SK = SK>>(
        case: TestCase,
    ) {
        // Verify that a secret key created from the test case equals a derived key
        let secret_key = SK::from_bytes(&case.alice_pri).expect("key import failed");
        let pub_key = E::get_pub_key(&secret_key).expect("pub key generation failed");
        assert_eq!(
            pub_key.to_bytes().expect("key serialize failed"),
            case.alice_pub
        );
    }

    pub fn run_random_key_test<PK: PublicKey, SK: SecretKey, E: EcdhEngine<PK = PK, SK = SK>>(
        case: TestCase,
    ) {
        // Make an rng that returns the raw key material of our test case
        let rng = test_rng::OneValRng {
            val: case.alice_pri.clone(),
        };

        // Generate a random keypair with our fixed rng
        let (pk, sk) = E::random_key_pair(rng).expect("failed to generate key");

        // Verify that the public and secret key match our expectations
        assert_eq!(pk.to_bytes().expect("key serialize failed"), case.alice_pub);
        assert_eq!(sk.to_bytes().expect("key serialize failed"), case.alice_pri);
    }
}

#[cfg(test)]
pub mod test_util {
    use super::{AsymmetricKey, AsymmetricKeyEngine, AsymmetricKeyError, SecureRng};
    use mockall::mock;

    mock! {
        pub PublicKey {}

        impl Clone for Signer {
            fn clone(&self) -> Self;
        }

        impl AsymmetricKey for PublicKey {
            fn from_bytes(bytes: &[u8]) -> Result<Self, AsymmetricKeyError>;
            fn to_bytes(&self) -> Result<Vec<u8>, AsymmetricKeyError>;
        }

        impl super::PublicKey for PublicKey {}
    }

    mock! {
        pub SecretKey {}

        impl Clone for Verifier {
            fn clone(&self) -> Self;
        }

        impl AsymmetricKey for SecretKey {
            fn from_bytes(bytes: &[u8]) -> Result<Self, AsymmetricKeyError>;
            fn to_bytes(&self) -> Result<Vec<u8>, AsymmetricKeyError>;
        }

        impl super::SecretKey for SecretKey {}
    }

    mock! {
        pub TestKeyEngine {}

        impl AsymmetricKeyEngine for TestKeyEngine {
            type PK = MockPublicKey;
            type SK = MockSecretKey;
            const SK_LEN: u16 = 0;
            fn random_key_pair<RNG: SecureRng + 'static>(rng: RNG) -> Result<(<MockTestKeyEngine as AsymmetricKeyEngine>::PK, <MockTestKeyEngine as AsymmetricKeyEngine>::SK), AsymmetricKeyError>;
            fn get_pub_key(sk: &<MockTestKeyEngine as AsymmetricKeyEngine>::SK) -> Result<<MockTestKeyEngine as AsymmetricKeyEngine>::PK, AsymmetricKeyError>;
        }
    }
}
