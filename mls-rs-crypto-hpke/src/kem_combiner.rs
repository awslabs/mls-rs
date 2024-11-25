use alloc::vec::Vec;
use mls_rs_core::{
    crypto::{HpkePublicKey, HpkeSecretKey},
    error::{AnyError, IntoAnyError},
};
use mls_rs_crypto_traits::{Hash, KemResult, KemType, VariableLengthHash};
use zeroize::Zeroize;

#[derive(Debug)]
#[cfg_attr(feature = "std", derive(thiserror::Error))]
pub enum Error {
    #[cfg_attr(feature = "std", error(transparent))]
    KemError(AnyError),
    #[cfg_attr(feature = "std", error(transparent))]
    HashError(AnyError),
    #[cfg_attr(feature = "std", error("invalid key data"))]
    InvalidKeyData,
    #[cfg_attr(feature = "std", error(transparent))]
    MlsCodecError(mls_rs_core::mls_rs_codec::Error),
}

impl From<mls_rs_core::mls_rs_codec::Error> for Error {
    #[inline]
    fn from(e: mls_rs_core::mls_rs_codec::Error) -> Self {
        Error::MlsCodecError(e)
    }
}

impl IntoAnyError for Error {}

#[derive(Clone)]
pub struct CombinedKem<KEM1, KEM2, H, VH, F> {
    kem1: KEM1,
    kem2: KEM2,
    hash: H,
    variable_length_hash: VH,
    shared_secret_hash_input: F,
}

impl<KEM1, KEM2, H, VH, F> CombinedKem<KEM1, KEM2, H, VH, F> {
    pub fn new_custom(
        kem1: KEM1,
        kem2: KEM2,
        hash: H,
        variable_length_hash: VH,
        shared_secret_hash_input: F,
    ) -> Self {
        Self {
            kem1,
            kem2,
            hash,
            variable_length_hash,
            shared_secret_hash_input,
        }
    }
}

pub trait SharedSecretHashInput: Send + Sync {
    fn input<'a>(
        &self,
        ss_details1: SharedSecretDetails<'a>,
        ss_details2: SharedSecretDetails<'a>,
    ) -> Vec<u8>;
}

#[derive(Debug, Clone, Copy)]
pub struct DefaultSharedSecretHashInput;

impl<KEM1, KEM2, H, VH> CombinedKem<KEM1, KEM2, H, VH, DefaultSharedSecretHashInput> {
    pub fn new(kem1: KEM1, kem2: KEM2, hash: H, variable_length_hash: VH) -> Self {
        Self {
            kem1,
            kem2,
            hash,
            variable_length_hash,
            shared_secret_hash_input: DefaultSharedSecretHashInput,
        }
    }
}

/// Secure for any combiner KEMs.
impl SharedSecretHashInput for DefaultSharedSecretHashInput {
    fn input<'a>(
        &self,
        ss_details1: SharedSecretDetails<'a>,
        ss_details2: SharedSecretDetails<'a>,
    ) -> Vec<u8> {
        [
            ss_details1.enc,
            ss_details1.shared_secret,
            ss_details1.public_key,
            ss_details2.enc,
            ss_details2.shared_secret,
            ss_details2.public_key,
        ]
        .concat()
    }
}

#[derive(Debug, Clone, Copy)]
pub struct XWingSharedSecretHashInput;

impl<KEM1, KEM2, H, VH> CombinedKem<KEM1, KEM2, H, VH, XWingSharedSecretHashInput> {
    pub fn new_xwing(kem1: KEM1, kem2: KEM2, hash: H, variable_length_hash: VH) -> Self {
        Self {
            kem1,
            kem2,
            hash,
            variable_length_hash,
            shared_secret_hash_input: XWingSharedSecretHashInput,
        }
    }
}

/// Defined in https://www.ietf.org/archive/id/draft-connolly-cfrg-xwing-kem-01.html
///
/// IND-CCA secure for some KEMs (also, IND-RCCA secure for all KEMs)
impl SharedSecretHashInput for XWingSharedSecretHashInput {
    fn input<'a>(
        &self,
        ss_details1: SharedSecretDetails<'a>,
        ss_details2: SharedSecretDetails<'a>,
    ) -> Vec<u8> {
        [
            b"\\./\n/^\\",
            ss_details1.shared_secret,
            ss_details2.shared_secret,
            ss_details2.enc,
            ss_details2.public_key,
        ]
        .concat()
    }
}

pub struct SharedSecretDetails<'a> {
    pub shared_secret: &'a [u8],
    pub enc: &'a [u8],
    pub public_key: &'a HpkePublicKey,
}

impl<'a> SharedSecretDetails<'a> {
    pub fn new(shared_secret: &'a [u8], enc: &'a [u8], public_key: &'a HpkePublicKey) -> Self {
        Self {
            shared_secret,
            enc,
            public_key,
        }
    }
}

#[cfg_attr(not(mls_build_async), maybe_async::must_be_sync)]
#[cfg_attr(all(target_arch = "wasm32", mls_build_async), maybe_async::must_be_async(?Send))]
#[cfg_attr(
    all(not(target_arch = "wasm32"), mls_build_async),
    maybe_async::must_be_async
)]
impl<KEM1, KEM2, H, VH, F> KemType for CombinedKem<KEM1, KEM2, H, VH, F>
where
    KEM1: KemType,
    KEM2: KemType,
    H: Hash,
    VH: VariableLengthHash,
    F: SharedSecretHashInput,
{
    type Error = Error;

    fn kem_id(&self) -> u16 {
        // TODO not set by any RFC
        15
    }

    async fn generate_deterministic(
        &self,
        seed: &[u8],
    ) -> Result<(HpkeSecretKey, HpkePublicKey), Self::Error> {
        self.generate_deterministic(seed).await
    }

    async fn encap(&self, remote_key: &HpkePublicKey) -> Result<KemResult, Self::Error> {
        let (pk1, pk2) = self.parse_key(remote_key, self.kem1.public_key_size())?;

        let pk1 = pk1.into();
        let pk2 = pk2.into();

        let ct1 = self
            .kem1
            .encap(&pk1)
            .await
            .map_err(|e| Error::KemError(e.into_any_error()))?;

        let ct2 = self
            .kem2
            .encap(&pk2)
            .await
            .map_err(|e| Error::KemError(e.into_any_error()))?;

        let enc = [&ct1.enc[..], &ct2.enc].concat();

        let ss_details1 = SharedSecretDetails::new(&ct1.shared_secret, &ct1.enc, &pk1);
        let ss_details2 = SharedSecretDetails::new(&ct2.shared_secret, &ct2.enc, &pk2);
        let mut shared_secret_input = self
            .shared_secret_hash_input
            .input(ss_details1, ss_details2);

        let shared_secret = self
            .hash
            .hash(&shared_secret_input)
            .map_err(|e| Error::KemError(e.into_any_error()))?;

        shared_secret_input.zeroize();

        Ok(KemResult { shared_secret, enc })
    }

    async fn decap(
        &self,
        enc: &[u8],
        secret_key: &HpkeSecretKey,
        local_public: &HpkePublicKey,
    ) -> Result<Vec<u8>, Self::Error> {
        let (pk1, pk2) = self.parse_key(local_public, self.kem1.public_key_size())?;
        let (sk1, sk2) = self.parse_key(secret_key, self.kem1.secret_key_size())?;
        let (enc1, enc2) = self.parse_key(enc, self.kem1.enc_size())?;

        let pk1 = pk1.into();
        let pk2 = pk2.into();
        let sk1 = sk1.into();
        let sk2 = sk2.into();

        let shared_secret1 = self
            .kem1
            .decap(&enc1, &sk1, &pk1)
            .await
            .map_err(|e| Error::KemError(e.into_any_error()))?;

        let shared_secret2 = self
            .kem2
            .decap(&enc2, &sk2, &pk2)
            .await
            .map_err(|e| Error::KemError(e.into_any_error()))?;

        let ss_details1 = SharedSecretDetails::new(&shared_secret1, &enc1, &pk1);
        let ss_details2 = SharedSecretDetails::new(&shared_secret2, &enc2, &pk2);

        let mut shared_secret_input = self
            .shared_secret_hash_input
            .input(ss_details1, ss_details2);

        let shared_secret = self
            .hash
            .hash(&shared_secret_input)
            .map_err(|e| Error::KemError(e.into_any_error()))?;

        shared_secret_input.zeroize();

        Ok(shared_secret)
    }

    fn public_key_validate(&self, _key: &HpkePublicKey) -> Result<(), Self::Error> {
        Ok(())
    }

    async fn generate(&self) -> Result<(HpkeSecretKey, HpkePublicKey), Self::Error> {
        let (sk1, pk1) = self
            .kem1
            .generate()
            .await
            .map_err(|e| Error::KemError(e.into_any_error()))?;

        let (sk2, pk2) = self
            .kem2
            .generate()
            .await
            .map_err(|e| Error::KemError(e.into_any_error()))?;

        let sk = [sk1.as_ref(), &sk2].concat();
        let pk = [pk1.as_ref(), &pk2].concat();

        Ok((sk.into(), pk.into()))
    }

    fn seed_length_for_derive(&self) -> usize {
        self.kem1.seed_length_for_derive() + self.kem2.seed_length_for_derive()
    }

    fn public_key_size(&self) -> usize {
        self.kem1.public_key_size() + self.kem2.public_key_size()
    }

    fn secret_key_size(&self) -> usize {
        self.kem1.secret_key_size() + self.kem1.secret_key_size()
    }
}

impl<KEM1, KEM2, H, VH, F> CombinedKem<KEM1, KEM2, H, VH, F>
where
    KEM1: KemType,
    KEM2: KemType,
    H: Hash,
    VH: VariableLengthHash,
    F: SharedSecretHashInput,
{
    #[cfg_attr(not(mls_build_async), maybe_async::must_be_sync)]
    async fn generate_deterministic(
        &self,
        ikm: &[u8],
    ) -> Result<(HpkeSecretKey, HpkePublicKey), Error> {
        let ikm = self
            .variable_length_hash
            .hash(ikm, self.seed_length_for_derive())
            .map_err(|e| Error::KemError(e.into_any_error()))?;

        let (ikm1, ikm2) = ikm.split_at(self.kem1.seed_length_for_derive());

        self.generate_key_pair_derand(ikm1, ikm2).await
    }

    // The funciton is useful for X-Wing RFC test.
    #[cfg_attr(not(mls_build_async), maybe_async::must_be_sync)]
    pub async fn generate_key_pair_derand(
        &self,
        ikm1: &[u8],
        ikm2: &[u8],
    ) -> Result<(HpkeSecretKey, HpkePublicKey), Error> {
        let (sk1, pk1) = self
            .kem1
            .generate_deterministic(ikm1)
            .await
            .map_err(|e| Error::KemError(e.into_any_error()))?;

        let (sk2, pk2) = self
            .kem2
            .generate_deterministic(ikm2)
            .await
            .map_err(|e| Error::KemError(e.into_any_error()))?;

        let sk = [sk1.as_ref(), &sk2].concat();
        let pk = [pk1.as_ref(), &pk2].concat();

        Ok((sk.into(), pk.into()))
    }

    fn parse_key(&self, key: &[u8], size: usize) -> Result<(Vec<u8>, Vec<u8>), Error> {
        (key.len() >= size)
            .then_some(())
            .ok_or(Error::InvalidKeyData)?;

        let (key1, key2) = key.split_at(size);

        Ok((key1.to_vec(), key2.to_vec()))
    }
}
