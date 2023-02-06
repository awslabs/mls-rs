use std::ops::Deref;

use aws_mls_crypto_traits::DhType;
use thiserror::Error;

use aws_mls_core::crypto::{CipherSuite, HpkePublicKey, HpkeSecretKey};

use crate::ec::{
    generate_keypair, private_key_bytes_to_public, private_key_ecdh, private_key_from_bytes,
    pub_key_from_uncompressed, Curve, EcError, EcPublicKey,
};

#[derive(Debug, Error)]
pub enum EcdhKemError {
    #[error(transparent)]
    EcError(#[from] EcError),
    #[error("unsupported cipher suite")]
    UnsupportedCipherSuite,
}

/// Kem identifiers for HPKE
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u16)]
pub enum KemId {
    DhKemP256Sha256 = 0x0010,
    DhKemX25519Sha256 = 0x0020,
}

impl KemId {
    pub fn new(cipher_suite: CipherSuite) -> Result<Self, EcdhKemError> {
        match cipher_suite {
            CipherSuite::CURVE25519_AES128 | CipherSuite::CURVE25519_CHACHA => {
                Ok(KemId::DhKemX25519Sha256)
            }
            CipherSuite::P256_AES128 => Ok(KemId::DhKemP256Sha256),
            _ => Err(EcdhKemError::UnsupportedCipherSuite),
        }
    }

    pub fn n_secret(&self) -> usize {
        32
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
    pub fn new(cipher_suite: CipherSuite) -> Result<Self, EcdhKemError> {
        Ok(Self(Curve::from_ciphersuite(cipher_suite, false)?))
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
            &private_key_from_bytes(secret_key, self.0)?,
            &self.to_ec_public_key(public_key)?,
        )?)
    }

    fn to_public(&self, secret_key: &HpkeSecretKey) -> Result<HpkePublicKey, Self::Error> {
        Ok(private_key_bytes_to_public(secret_key, self.0)?.into())
    }

    fn generate(&self) -> Result<(HpkeSecretKey, HpkePublicKey), Self::Error> {
        let key_pair = generate_keypair(self.0)?;
        Ok((key_pair.secret.into(), key_pair.public.into()))
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
}

#[cfg(test)]
mod test {
    use aws_mls_core::crypto::{CipherSuite, HpkePublicKey, HpkeSecretKey};
    use aws_mls_crypto_traits::DhType;
    use serde::Deserialize;

    use crate::ecdh::Ecdh;

    fn get_ecdhs() -> Vec<Ecdh> {
        [CipherSuite::P256_AES128, CipherSuite::CURVE25519_AES128]
            .into_iter()
            .map(Ecdh::new)
            .collect::<Result<_, _>>()
            .unwrap()
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

        let ecdh = Ecdh::new(test_case.ciphersuite).unwrap();

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
