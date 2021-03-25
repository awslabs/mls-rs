use crate::asym::{
    p256,
    p521,
    x25519,
    x448,
    AsymmetricKey,
    AsymmetricKeyEngine,
    AsymmetricKeyError,
    EcdhEngine,
};
use crate::kdf::{HkdfSha256, HkdfSha512, KdfError};
use rand_core::{CryptoRng, RngCore};
use thiserror::Error;
use serde::{Serialize, Deserialize};

#[derive(Error, Debug)]
pub enum KemError {
    #[error("Asymmetric key engine error: {0}")]
    AsymmetricKey(#[from] AsymmetricKeyError),
    #[error("Error in KDF: {0}")]
    KeyDerivationFunctionError(#[from] KdfError),
}

pub struct KemResult {
    pub shared_secret: Vec<u8>,
    pub enc: Vec<u8>,
}

pub trait Kem {
    type KDF: HpkeKdf;
    type E: AsymmetricKeyEngine;

    const KEM_ID: KemId;
    const N_SECRET: u16;
    const CURVE_BITMASK: Option<u8>;

    #[inline]
    fn kem_suite_id() -> Vec<u8> {
        [b"KEM", &(Self::KEM_ID as u16).to_be_bytes() as &[u8]].concat()
    }

    /*
    draft-irtf-cfrg-hpke section 4.1 DH-Based KEM
    */
    fn encap<RNG: CryptoRng + RngCore + 'static>(
        rng: &mut RNG,
        remote_key: &<Self::E as AsymmetricKeyEngine>::PK,
    ) -> Result<KemResult, KemError>;

    /*
    draft-irtf-cfrg-hpke section 4.1 DH-Based KEM
    */
    fn decap(
        enc: &[u8],
        secret_key: &<Self::E as AsymmetricKeyEngine>::SK,
    ) -> Result<Vec<u8>, KemError>;

    #[allow(clippy::type_complexity)]
    fn generate_kem_key_pair<RNG: CryptoRng + RngCore + 'static>(rng: &mut RNG) -> Result<(
                                                               <Self::E as AsymmetricKeyEngine>::PK,
                                                               <Self::E as AsymmetricKeyEngine>::SK,
                                                           ), AsymmetricKeyError> {
        let mut ikm: Vec<u8> = vec![0; Self::E::SK_LEN as usize];
        rng.try_fill_bytes(&mut ikm)?;
        Self::derive_key_pair(&ikm)
    }

    #[allow(clippy::type_complexity)]
    fn derive_key_pair(ikm: &[u8]) -> Result<(
        <Self::E as AsymmetricKeyEngine>::PK,
        <Self::E as AsymmetricKeyEngine>::SK
    ), AsymmetricKeyError> {
        let dkp_prk = Self::KDF::labeled_extract(&Self::kem_suite_id(),
                                                 &[], b"dkp_prk", ikm)?;

        // NIST curves require a special behavior here to ensure correctness
        if let Some(curve_bitmask) = Self::CURVE_BITMASK {
            for i in 0u8..255 {
                let mut bytes = Self::KDF::labeled_expand(&Self::kem_suite_id(),
                                                          &dkp_prk,
                                                          b"candidate",
                                                          &[i],
                                                          Self::E::SK_LEN)?;
                bytes[0] &= curve_bitmask;

                if let Ok(secret_key) = <Self::E as AsymmetricKeyEngine>::SK::from_bytes(&bytes) {
                    if let Ok(pub_key) = Self::E::get_pub_key(&secret_key) {
                        return Ok((pub_key, secret_key));
                    }
                }
            }
            Err(AsymmetricKeyError::KeyDerivationError())
        } else {
            let dkp_prk = Self::KDF::labeled_extract(&Self::kem_suite_id(),
                                                     &[], b"dkp_prk", ikm)?;
            let sk_vec = Self::KDF::labeled_expand(&Self::kem_suite_id(),
                                                   &dkp_prk,
                                                   b"sk",
                                                   &[],
                                                   Self::E::SK_LEN)?;
            let sk = <Self::E as AsymmetricKeyEngine>::SK::from_bytes(&sk_vec)?;
            let pk = Self::E::get_pub_key(&sk)?;
            Ok((pk, sk))
        }
    }
}

pub trait EcdhKem: Kem
where
    Self::E: EcdhEngine,
{
    /*
    draft-irtf-cfrg-hpke section 4.1 DH-Based KEM
    */
    fn ecdh_encap<RNG: CryptoRng + RngCore + 'static>(
        rng: &mut RNG,
        remote_key: &<Self::E as AsymmetricKeyEngine>::PK,
    ) -> Result<KemResult, KemError> {
        let (pk_e, sk_e) =
            Self::generate_kem_key_pair(rng)?;

        let ecdh_res = Self::E::shared_secret(&sk_e, remote_key)?;
        let enc = pk_e.to_bytes()?;

        let kem_context = [enc.clone(), remote_key.to_bytes()?].concat();

        let shared_secret = Self::KDF::labeled_extract_and_expand(
            &Self::kem_suite_id(),
            &ecdh_res,
            &kem_context,
            Self::N_SECRET,
        )?;

        Ok(KemResult { shared_secret, enc })
    }

    /*
    draft-irtf-cfrg-hpke section 4.1 DH-Based KEM
    */
    fn ecdh_decap(
        enc: &[u8],
        secret_key: &<Self::E as AsymmetricKeyEngine>::SK,
    ) -> Result<Vec<u8>, KemError> {
        let dh = Self::E::shared_secret(
            secret_key,
            &<Self::E as AsymmetricKeyEngine>::PK::from_bytes(enc)?,
        )?;

        let kem_context = [enc, &Self::E::get_pub_key(secret_key)?.to_bytes()?].concat();

        Self::KDF::labeled_extract_and_expand(
            &Self::kem_suite_id(),
            &dh,
            &kem_context,
            Self::N_SECRET,
        )
        .map_err(|e| e.into())
    }
}

use num_enum::{IntoPrimitive, TryFromPrimitive};
use crate::hpke_kdf::HpkeKdf;

#[derive(IntoPrimitive, TryFromPrimitive, Serialize, Deserialize, Clone, PartialEq, Debug)]
#[serde(into = "u16", try_from = "u16")]
#[repr(u16)]
pub enum KemId {
    P256HkdfSha256 = 0x0010,
    P384HkdfSha384 = 0x0011, // Unsupported
    P521HkdfSha512 = 0x0012,
    X25519HkdfSha256 = 0x0020,
    X448HkdfSha512 = 0x0021,
    #[cfg(test)]
    Test = 0xFFFF,
}

impl KemId {
    pub fn is_supported(&self) -> bool {
        !matches!(self, Self::P384HkdfSha384)
    }
}

macro_rules! impl_ecdh_kem {
    ($name:ident, $kdf:ty, $engine:ty, $kem_id:expr, $n_secret:expr, $curve_bitmask:expr) => {
        pub struct $name;

        impl Kem for $name
        where
            Self: EcdhKem,
        {
            type KDF = $kdf;
            type E = $engine;
            const KEM_ID: KemId = $kem_id;
            const N_SECRET: u16 = $n_secret;
            const CURVE_BITMASK: Option<u8> = $curve_bitmask;

            fn encap<RNG: CryptoRng + RngCore + 'static>(
                rng: &mut RNG,
                remote_key: &<Self::E as AsymmetricKeyEngine>::PK,
            ) -> Result<KemResult, KemError> {
                Self::ecdh_encap(rng, remote_key)
            }

            fn decap(
                enc: &[u8],
                secret_key: &<Self::E as AsymmetricKeyEngine>::SK,
            ) -> Result<Vec<u8>, KemError> {
                Self::ecdh_decap(enc, secret_key)
            }
        }

        impl EcdhKem for $name {}
    };
}

#[cfg(test)]
pub mod test_util {
    use mockall::mock;
    use super::{
        Kem, KemId, KemError, KemResult,
        CryptoRng, RngCore, AsymmetricKeyEngine
    };
    use crate::hpke_kdf::test_util::MockTestHpkeKdf;
    use crate::asym::test_util::MockTestKeyEngine;
    use crate::asym::AsymmetricKeyError;

    mock! {
        pub TestKem {}
        impl Kem for TestKem {
            type KDF = MockTestHpkeKdf;
            type E = MockTestKeyEngine;

            const KEM_ID: KemId = KemId::Test;
            const N_SECRET: u16 = 42;
            const CURVE_BITMASK: Option<u8> = None;

            fn encap<RNG: CryptoRng + RngCore + 'static>(
                rng: &mut RNG,
                remote_key: &<<MockTestKem as Kem>::E as AsymmetricKeyEngine>::PK,
            ) -> Result<KemResult, KemError>;

            fn decap(
                enc: &[u8],
                secret_key: &<<MockTestKem as Kem>::E as AsymmetricKeyEngine>::SK,
            ) -> Result<Vec<u8>, KemError>;

            fn generate_kem_key_pair<RNG: CryptoRng + RngCore + 'static>(rng: &mut RNG) -> Result<(
                <<MockTestKem as Kem>::E as AsymmetricKeyEngine>::PK,
                <<MockTestKem as Kem>::E as AsymmetricKeyEngine>::SK
            ), AsymmetricKeyError>;

            fn derive_key_pair(ikm: &[u8],) -> Result<(
                <<MockTestKem as Kem>::E as AsymmetricKeyEngine>::PK,
                <<MockTestKem as Kem>::E as AsymmetricKeyEngine>::SK,
            ), AsymmetricKeyError>;
        }
    }
}

/* draft-irtf-cfrg-hpke */
impl_ecdh_kem!(
    P256HkdfSha256,
    HkdfSha256,
    p256::Engine,
    KemId::P256HkdfSha256,
    32,
    Some(0xFF)
);
impl_ecdh_kem!(
    P521HkdfSha512,
    HkdfSha512,
    p521::Engine,
    KemId::P521HkdfSha512,
    64,
    Some(0x01)
);
impl_ecdh_kem!(
    X25519HkdfSha256,
    HkdfSha256,
    x25519::Engine,
    KemId::X25519HkdfSha256,
    32,
    None
);
impl_ecdh_kem!(
    X448HkdfSha512,
    HkdfSha512,
    x448::Engine,
    KemId::X448HkdfSha512,
    64,
    None
);
