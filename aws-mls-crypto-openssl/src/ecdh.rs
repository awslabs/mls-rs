use std::ops::Deref;

use aws_mls_crypto_traits::DhType;
use thiserror::Error;

use aws_mls_core::crypto::{CipherSuite, HpkePublicKey, HpkeSecretKey};

use crate::ec::{
    generate_private_key, private_key_ecdh, private_key_from_bytes, private_key_to_bytes,
    private_key_to_public, pub_key_from_uncompressed, pub_key_to_uncompressed, Curve, EcPrivateKey,
    EcPublicKey,
};

#[derive(Debug, Error)]
pub enum EcdhKemError {
    #[error(transparent)]
    OpensslError(#[from] openssl::error::ErrorStack),
    /// Attempted to import a secret key that does not contain valid bytes for its curve
    #[error("invalid secret key bytes")]
    InvalidSecretKeyBytes,
}

/// Kem identifiers for HPKE
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u16)]
pub enum KemId {
    DhKemP256Sha256 = 0x0010,
    DhKemP384Sha384 = 0x0011,
    DhKemP521Sha512 = 0x0012,
    DhKemX25519Sha256 = 0x0020,
    DhKemX448Sha512 = 0x0021,
}

impl KemId {
    pub fn new(cipher_suite: CipherSuite) -> Self {
        match cipher_suite {
            CipherSuite::Curve25519Aes128 | CipherSuite::Curve25519ChaCha20 => {
                KemId::DhKemX25519Sha256
            }
            CipherSuite::P256Aes128 => KemId::DhKemP256Sha256,
            CipherSuite::Curve448Aes256 | CipherSuite::Curve448ChaCha20 => KemId::DhKemX448Sha512,
            CipherSuite::P384Aes256 => KemId::DhKemP384Sha384,
            CipherSuite::P521Aes256 => KemId::DhKemP521Sha512,
        }
    }

    pub fn n_secret(&self) -> usize {
        match self {
            KemId::DhKemP256Sha256 => 32,
            KemId::DhKemP384Sha384 => 48,
            KemId::DhKemP521Sha512 => 64,
            KemId::DhKemX25519Sha256 => 32,
            KemId::DhKemX448Sha512 => 64,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Ecdh(Curve);

impl Deref for Ecdh {
    type Target = Curve;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Ecdh {
    pub fn new(cipher_suite: CipherSuite) -> Self {
        let curve = match cipher_suite {
            CipherSuite::Curve25519Aes128 | CipherSuite::Curve25519ChaCha20 => Curve::X25519,
            CipherSuite::P256Aes128 => Curve::P256,
            CipherSuite::Curve448Aes256 | CipherSuite::Curve448ChaCha20 => Curve::X448,
            CipherSuite::P384Aes256 => Curve::P384,
            CipherSuite::P521Aes256 => Curve::P521,
        };

        Self(curve)
    }
}

impl DhType for Ecdh {
    type Error = EcdhKemError;

    fn dh(
        &self,
        secret_key: &HpkeSecretKey,
        public_key: &HpkePublicKey,
    ) -> Result<Vec<u8>, Self::Error> {
        Ok(private_key_ecdh(
            &self.to_ec_secret_key(secret_key)?,
            &self.to_ec_public_key(public_key)?,
        )?)
    }

    fn to_public(&self, secret_key: &HpkeSecretKey) -> Result<HpkePublicKey, Self::Error> {
        let public_key = private_key_to_public(&self.to_ec_secret_key(secret_key)?)?;
        Ok(pub_key_to_uncompressed(&public_key)?.into())
    }

    fn generate(&self) -> Result<(HpkeSecretKey, HpkePublicKey), Self::Error> {
        let secret = generate_private_key(self.0)?;
        let public = private_key_to_public(&secret)?;
        let secret = private_key_to_bytes(&secret)?.into();
        let public = pub_key_to_uncompressed(&public)?.into();
        Ok((secret, public))
    }

    fn bitmask_for_rejection_sampling(&self) -> Option<u8> {
        self.curve_bitmask()
    }

    fn public_key_validate(&self, key: &HpkePublicKey) -> Result<(), Self::Error> {
        self.to_ec_public_key(key).map(|_| ())
    }

    fn secret_key_size(&self) -> usize {
        self.0.secret_key_size()
    }
}

impl Ecdh {
    fn to_ec_public_key(&self, public_key: &HpkePublicKey) -> Result<EcPublicKey, EcdhKemError> {
        Ok(pub_key_from_uncompressed(public_key, self.0)?)
    }

    fn to_ec_secret_key(&self, secret_key: &HpkeSecretKey) -> Result<EcPrivateKey, EcdhKemError> {
        private_key_from_bytes(secret_key, self.0)?.ok_or(EcdhKemError::InvalidSecretKeyBytes)
    }
}

#[cfg(test)]
mod test {
    use aws_mls_core::crypto::{CipherSuite, HpkePublicKey, HpkeSecretKey};
    use aws_mls_crypto_traits::DhType;
    use serde::Deserialize;

    use crate::ecdh::Ecdh;

    fn get_ecdhs() -> Vec<Ecdh> {
        [
            CipherSuite::P256Aes128,
            CipherSuite::P384Aes256,
            CipherSuite::P521Aes256,
            CipherSuite::Curve25519Aes128,
            CipherSuite::Curve448Aes256,
        ]
        .into_iter()
        .map(Ecdh::new)
        .collect()
    }

    #[derive(Deserialize)]
    struct TestCase {
        pub ciphersuite: CipherSuite,
        #[serde(with = "hex::serde")]
        pub alice_pub: Vec<u8>,
        #[serde(with = "hex::serde")]
        pub alice_pri: Vec<u8>,
        #[serde(with = "hex::serde")]
        pub bob_pub: Vec<u8>,
        #[serde(with = "hex::serde")]
        pub bob_pri: Vec<u8>,
        #[serde(with = "hex::serde")]
        pub shared_secret: Vec<u8>,
    }

    fn run_test_case(test_case: TestCase) {
        println!(
            "Running ECDH test for ciphersuite: {:?}",
            test_case.ciphersuite
        );

        let ecdh = Ecdh::new(test_case.ciphersuite);

        // Import the keys into their structures
        let alice_pub: HpkePublicKey = test_case.alice_pub.into();
        let bob_pub: HpkePublicKey = test_case.bob_pub.into();
        let alice_pri: HpkeSecretKey = test_case.alice_pri.into();
        let bob_pri: HpkeSecretKey = test_case.bob_pri.into();

        assert_eq!(ecdh.to_public(&alice_pri).unwrap(), alice_pub);
        assert_eq!(ecdh.to_public(&bob_pri).unwrap(), bob_pub);

        assert_eq!(
            ecdh.dh(&alice_pri, &bob_pub).unwrap(),
            test_case.shared_secret
        );

        assert_eq!(
            ecdh.dh(&bob_pri, &alice_pub).unwrap(),
            test_case.shared_secret
        );
    }

    #[test]
    fn test_algo_test_cases() {
        let test_case_file = include_str!("../test_data/test_ecdh.json");
        let test_cases: Vec<TestCase> = serde_json::from_str(test_case_file).unwrap();

        for case in test_cases {
            run_test_case(case);
        }
    }

    #[test]
    fn test_mismatched_curve() {
        for ecdh in get_ecdhs() {
            println!("Testing mismatched curve error for {:?}", *ecdh);

            let secret_key = ecdh.generate().unwrap().0;

            for other_ecdh in get_ecdhs().into_iter().filter(|c| c != &ecdh) {
                let other_public_key = other_ecdh.generate().unwrap().1;
                assert!(ecdh.dh(&secret_key, &other_public_key).is_err());
            }
        }
    }
}
