use thiserror::Error;
use crate::kdf::{KdfError, HkdfSha256, HkdfSha512, LabeledKdf};
use rand_core::{ RngCore, CryptoRng };
use crate::asym::{
    AsymmetricKeyError,
    KemKeyEngine,
    AsymmetricKey,
    EcdhEngine,
    x25519,
    x448,
    p256,
    p521,
    AsymmetricKeyEngine
};
use num_derive::FromPrimitive;
use num_traits::FromPrimitive;

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
    type KDF: LabeledKdf;
    type E: KemKeyEngine;

    const KEM_ID: u16;
    const N_SECRET: u16;

    #[inline]
    fn kem_suite_id() -> Vec<u8> {
        [b"KEM", &Self::KEM_ID.to_be_bytes() as &[u8]].concat()
    }

    /*
    draft-irtf-cfrg-hpke section 4.1 DH-Based KEM
    */
    fn encap<RNG: CryptoRng + RngCore>(rng: RNG,
                                       remote_key: &<Self::E as AsymmetricKeyEngine>::PK)
        -> Result<KemResult, KemError>;

    /*
    draft-irtf-cfrg-hpke section 4.1 DH-Based KEM
    */
    fn decap(enc: &[u8], secret_key: &<Self::E as AsymmetricKeyEngine>::SK)
        -> Result<Vec<u8>, KemError>;
}

pub trait EcdhKem: Kem {

    type ECDH: EcdhEngine;
    /*
    draft-irtf-cfrg-hpke section 4.1 DH-Based KEM
    */
    fn ecdh_encap<RNG: CryptoRng + RngCore>(rng: RNG,
                                            remote_key: &<Self::ECDH as AsymmetricKeyEngine>::PK)
        -> Result<KemResult, KemError> {
        let (pk_e,
            sk_e) = <Self::ECDH as KemKeyEngine>::
            generate_kem_key_pair::<RNG, Self::KDF>(rng, &Self::kem_suite_id())?;

        let ecdh_res = Self::ECDH::shared_secret(&sk_e, remote_key)?;
        let enc = pk_e.to_bytes()?;

        let kem_context = [
            enc.clone(),
            remote_key.to_bytes()?,
        ].concat();

        let shared_secret = Self::KDF::labeled_extract_and_expand(&Self::kem_suite_id(),
                                                                  &ecdh_res,
                                                                  &kem_context,
                                                                  Self::N_SECRET)?;

        Ok(KemResult {
            shared_secret,
            enc,
        })
    }

    /*
    draft-irtf-cfrg-hpke section 4.1 DH-Based KEM
    */
    fn ecdh_decap(enc: &[u8],
                  secret_key: &<Self::ECDH as AsymmetricKeyEngine>::SK)
        -> Result<Vec<u8>, KemError> {
        let dh = Self::ECDH::shared_secret(secret_key,
                                  &<Self::ECDH as AsymmetricKeyEngine>::PK::from_bytes(enc)?)?;

        let kem_context = [
            enc,
            &<Self::ECDH as KemKeyEngine>::get_pub_key(secret_key)?.to_bytes()?
        ].concat();

        Self::KDF::labeled_extract_and_expand(&Self::kem_suite_id(),
                                              &dh,
                                              &kem_context,
                                              Self::N_SECRET).map_err(|e| e.into())
    }
}

#[derive(FromPrimitive, Debug, PartialEq)]
pub enum KemId {
    P256HkdfSha256 = 0x0010,
    P384HkdfSha384 = 0x0011, // Unsupported
    P521HkdfSha512 = 0x0012,
    X25519HkdfSha256 = 0x0020,
    X448HkdfSha512 = 0x0021
}

impl KemId {
    pub fn is_supported(&self) -> bool {
        match self {
            Self::P384HkdfSha384 => false,
            _ => true
        }
    }

    pub fn from_u16(val: u16) -> Option<KemId> {
        FromPrimitive::from_u16(val)
    }
}

macro_rules! impl_ecdh_kem {
    ($name:ident, $kdf:ty, $engine:ty, $kem_id:expr, $n_secret:expr) => {
        pub struct $name;

        impl Kem for $name where Self: EcdhKem {
            type KDF = $kdf;
            type E = $engine;
            const KEM_ID: u16 = $kem_id;
            const N_SECRET: u16 = $n_secret;

            fn encap<RNG: CryptoRng + RngCore>(rng: RNG,
               remote_key: &<Self::E as AsymmetricKeyEngine>::PK)-> Result<KemResult, KemError> {
                Self::ecdh_encap(rng, remote_key)
            }

            fn decap(enc: &[u8], secret_key: &<Self::E as AsymmetricKeyEngine>::SK)
                -> Result<Vec<u8>, KemError> {
                Self::ecdh_decap(enc, secret_key)
            }
        }

        impl EcdhKem for $name {
            type ECDH = $engine;
        }
    };
}

/* draft-irtf-cfrg-hpke */
impl_ecdh_kem!(P256HkdfSha256, HkdfSha256, p256::Engine, KemId::P256HkdfSha256 as u16, 32);
impl_ecdh_kem!(P521HkdfSha512, HkdfSha512, p521::Engine, KemId::P521HkdfSha512 as u16, 64);
impl_ecdh_kem!(X25519HkdfSha256, HkdfSha256, x25519::Engine, KemId::X25519HkdfSha256 as u16, 32);
impl_ecdh_kem!(X448HkdfSha512, HkdfSha512, x448::Engine, KemId::X448HkdfSha512 as u16, 64);
