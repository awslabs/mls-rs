use std::ptr::null_mut;

use aws_lc_rs::{
    error::Unspecified,
    kem::{Algorithm, AlgorithmIdentifier, EncapsulationKey},
    unstable::kem::{get_algorithm, AlgorithmId},
};
use aws_lc_sys::{
    EVP_PKEY_CTX_free, EVP_PKEY_CTX_kem_set_params, EVP_PKEY_CTX_new, EVP_PKEY_CTX_new_id,
    EVP_PKEY_decapsulate, EVP_PKEY_free, EVP_PKEY_get_raw_private_key, EVP_PKEY_get_raw_public_key,
    EVP_PKEY_kem_new_raw_secret_key, EVP_PKEY_keygen_deterministic, EVP_PKEY_keygen_init, EVP_PKEY,
    EVP_PKEY_KEM,
};
use mls_rs_core::crypto::{CipherSuite, HpkePublicKey, HpkeSecretKey};
use mls_rs_crypto_traits::{KdfType, KemResult, KemType};

use crate::{check_non_null, kdf::AwsLcHkdf, random_bytes, AwsLcCryptoError};

#[derive(Clone)]
pub struct KyberKem {
    kdf: AwsLcHkdf,
    kyber: Kyber,
}

impl KyberKem {
    pub fn new(cipher_suite: CipherSuite) -> Option<Self> {
        let kdf = match cipher_suite {
            CipherSuite::KYBER512 | CipherSuite::KYBER768 => {
                AwsLcHkdf::new(CipherSuite::CURVE25519_AES128)?
            }
            CipherSuite::KYBER1024 => AwsLcHkdf::new(CipherSuite::P384_AES256)?,
            _ => return None,
        };

        Some(Self {
            kdf,
            kyber: Kyber::new(cipher_suite)?,
        })
    }
}

#[derive(Debug, Clone)]
pub enum Kyber {
    KYBER512,
    KYBER768,
    KYBER1024,
}

impl Kyber {
    fn new(cipher_suite: CipherSuite) -> Option<Self> {
        match cipher_suite {
            CipherSuite::KYBER512 => Some(Self::KYBER512),
            CipherSuite::KYBER768 => Some(Self::KYBER768),
            CipherSuite::KYBER1024 => Some(Self::KYBER1024),
            _ => None,
        }
    }

    fn algorithm(&self) -> Result<&'static Algorithm<AlgorithmId>, AwsLcCryptoError> {
        let algorithm_id = match self {
            Kyber::KYBER512 => AlgorithmId::Kyber512_R3,
            Kyber::KYBER768 => AlgorithmId::Kyber768_R3,
            Kyber::KYBER1024 => AlgorithmId::Kyber1024_R3,
        };

        get_algorithm(algorithm_id).ok_or(AwsLcCryptoError::UnsupportedCipherSuite)
    }
}

impl KemType for KyberKem {
    type Error = AwsLcCryptoError;

    fn kem_id(&self) -> u16 {
        // TODO not set by any RFC
        15
    }

    fn encap(&self, remote_key: &HpkePublicKey) -> Result<KemResult, Self::Error> {
        let remote_key = EncapsulationKey::new(self.kyber.algorithm()?, remote_key)?;
        let (enc, shared_secret) = remote_key.encapsulate()?;

        Ok(KemResult {
            enc: enc.as_ref().to_vec(),
            shared_secret: shared_secret.as_ref().to_vec(),
        })
    }

    fn decap(
        &self,
        enc: &[u8],
        secret_key: &HpkeSecretKey,
        _local_public: &HpkePublicKey,
    ) -> Result<Vec<u8>, Self::Error> {
        let nid = self.kyber.algorithm()?.id().nid();
        let len = self.secret_key_size();
        let mut shared_secret = vec![0u8; 32];

        let res = unsafe {
            let pkey = check_non_null(EVP_PKEY_kem_new_raw_secret_key(
                nid,
                secret_key.as_ptr(),
                len,
            ))?;

            let ctx = EVP_PKEY_CTX_new(pkey, null_mut());

            let res = EVP_PKEY_decapsulate(
                ctx,
                shared_secret.as_mut_ptr(),
                &mut 32,
                enc.as_ptr() as *mut u8,
                enc.len(),
            );

            EVP_PKEY_CTX_free(ctx);
            EVP_PKEY_free(pkey);

            res
        };

        (res == 1)
            .then_some(shared_secret)
            .ok_or(Unspecified.into())
    }

    fn generate_deterministic(
        &self,
        ikm: &[u8],
    ) -> Result<(HpkeSecretKey, HpkePublicKey), Self::Error> {
        let nid = self.kyber.algorithm()?.id().nid();
        let secret_key_size = self.secret_key_size();
        let public_key_size = self.public_key_size();

        if ikm.len() == self.seed_length_for_derive() {
            Ok(unsafe { kem_derive(nid, ikm, secret_key_size, public_key_size) }?)
        } else {
            let ikm = self.kdf.expand(ikm, &[], self.seed_length_for_derive())?;
            Ok(unsafe { kem_derive(nid, &ikm, secret_key_size, public_key_size) }?)
        }
    }

    fn public_key_validate(&self, _key: &HpkePublicKey) -> Result<(), Self::Error> {
        Ok(())
    }

    fn seed_length_for_derive(&self) -> usize {
        64
    }

    fn generate(&self) -> Result<(HpkeSecretKey, HpkePublicKey), Self::Error> {
        let mut out = vec![0u8; self.seed_length_for_derive()];
        random_bytes(&mut out)?;

        self.generate_deterministic(&out)
    }

    fn public_key_size(&self) -> usize {
        match self.kyber {
            Kyber::KYBER512 => 800,
            Kyber::KYBER768 => 1184,
            Kyber::KYBER1024 => 1568,
        }
    }

    fn secret_key_size(&self) -> usize {
        match self.kyber {
            Kyber::KYBER512 => 1632,
            Kyber::KYBER768 => 2400,
            Kyber::KYBER1024 => 3168,
        }
    }

    fn enc_size(&self) -> usize {
        match self.kyber {
            Kyber::KYBER512 => 768,
            Kyber::KYBER768 => 1088,
            Kyber::KYBER1024 => 1568,
        }
    }
}

unsafe fn kem_derive(
    nid: i32,
    ikm: &[u8],
    mut secret_key_len: usize,
    mut public_key_len: usize,
) -> Result<(HpkeSecretKey, HpkePublicKey), Unspecified> {
    let ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_KEM, null_mut());

    if 1 != EVP_PKEY_CTX_kem_set_params(ctx, nid) || 1 != EVP_PKEY_keygen_init(ctx) {
        EVP_PKEY_CTX_free(ctx);
        return Err(Unspecified);
    }

    let mut pkey: *mut EVP_PKEY = null_mut();
    let mut ikm_len = ikm.len();

    if 1 != EVP_PKEY_keygen_deterministic(ctx, &mut pkey, ikm.as_ptr(), &mut ikm_len) {
        EVP_PKEY_CTX_free(ctx);
        return Err(Unspecified);
    }

    let mut secret_key = vec![0u8; secret_key_len];
    let mut public_key = vec![0u8; public_key_len];

    let err = 1 != EVP_PKEY_get_raw_private_key(pkey, secret_key.as_mut_ptr(), &mut secret_key_len)
        || 1 != EVP_PKEY_get_raw_public_key(pkey, public_key.as_mut_ptr(), &mut public_key_len);

    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(pkey);

    (!err)
        .then_some((secret_key.into(), public_key.into()))
        .ok_or(Unspecified)
}

#[cfg(test)]
mod test {
    use mls_rs_core::crypto::CipherSuite;
    use mls_rs_crypto_hpke::{dhkem::DhKem, kem_combiner::CombinedKem};
    use mls_rs_crypto_traits::{KemId, KemResult, KemType, SamplingMethod};

    use crate::{
        kdf::{shake::AwsLcShake128, AwsLcHash, AwsLcHkdf, Sha3},
        kem::ecdh::Ecdh,
    };

    use super::KyberKem;

    #[test]
    fn round_trip() {
        let kem = KyberKem::new(CipherSuite::KYBER768).unwrap();

        let (secret_key, public_key) = kem.generate_deterministic(&[1u8; 64]).unwrap();
        let KemResult { shared_secret, enc } = kem.encap(&public_key).unwrap();

        assert_eq!(
            kem.decap(&enc, &secret_key, &public_key).unwrap(),
            shared_secret
        );
    }

    #[test]
    fn xwing_rfc_test_vector() {
        #[derive(serde::Deserialize)]
        struct RfcTest {
            #[serde(with = "hex::serde")]
            seed: Vec<u8>,
            #[serde(with = "hex::serde")]
            pk: Vec<u8>,
        }

        let rfc_test: RfcTest = serde_json::from_slice(include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/test_data/xwing_rfc.json",
        )))
        .unwrap();

        let kem_id = KemId::new(CipherSuite::CURVE25519_AES128).unwrap();
        let dh = Ecdh::new(CipherSuite::CURVE25519_AES128)
            .unwrap()
            .with_sampling_method(SamplingMethod::Raw);
        let kdf = AwsLcHkdf::new(CipherSuite::CURVE25519_AES128).unwrap();

        let kem = CombinedKem::new_xwing(
            KyberKem::new(CipherSuite::KYBER768).unwrap(),
            DhKem::new(dh, kdf, kem_id as u16, kem_id.n_secret()),
            AwsLcHash::new_sha3(Sha3::SHA3_256).unwrap(),
            AwsLcShake128,
        );

        let (seed1, seed2) = rfc_test.seed.split_at(64);
        // We don't have to store the secret key in the format mandated by the RFC
        let (_sk, pk) = kem.generate_key_pair_derand(seed1, seed2).unwrap();
        assert_eq!(pk.as_ref(), rfc_test.pk);
    }
}
