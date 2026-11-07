//! The CG-framework hybrid KEM (draft-irtf-cfrg-hybrid-kems-12 §5.5) that MLKEM768-X25519
//! (HPKE KEM 0x647a, draft-ietf-hpke-pq-05 §4) is built on, following
//! <https://www.ietf.org/archive/id/draft-irtf-cfrg-concrete-hybrid-kems-04.html#name-mlkem768-x25519>.

use alloc::vec;
use alloc::vec::Vec;

use mls_rs_core::{
    crypto::{HpkePublicKey, HpkeSecretKey},
    error::IntoAnyError,
};
use mls_rs_crypto_traits::{DhType, Hash, KemResult, KemType, VariableLengthHash};
use zeroize::Zeroizing;

use super::{Error, FixedLengthKemType, SeedRng};
use crate::kdf::labeled_derive;

/// `Label` of MLKEM768-X25519, `\.//^\` (concrete-hybrid-kems §4.2).
pub const MLKEM768_X25519_LABEL: &[u8] = b"\\.//^\\";

/// HPKE KEM id of MLKEM768-X25519 (hpke-pq §8.2).
pub const MLKEM768_X25519_KEM_ID: u16 = 0x647a;

/// `Nseed` of the hybrid KEM (concrete-hybrid-kems §4).
const NSEED: usize = 32;

/// A hybrid KEM in the CG framework (hybrid-kems §5.5); the secret key is the 32-byte seed.
/// `group` must have an identity `RandomScalar`, as X25519 does (concrete-hybrid-kems §3.1.2).
#[derive(Clone, Debug)]
pub struct CgHybridKem<PQ, G, PRG, KDF, RNG> {
    pq: PQ,
    group: G,
    prg: PRG,
    kdf: KDF,
    rng: RNG,
    label: &'static [u8],
    kem_id: u16,
}

/// The output of `expandDecapsKeyG` (hybrid-kems §5.1.1).
struct ExpandedKey {
    ek_pq: HpkePublicKey,
    ek_t: HpkePublicKey,
    dk_pq: HpkeSecretKey,
    dk_t: HpkeSecretKey,
}

impl<PQ, G, PRG, KDF, RNG> CgHybridKem<PQ, G, PRG, KDF, RNG> {
    pub fn new(
        pq: PQ,
        group: G,
        prg: PRG,
        kdf: KDF,
        rng: RNG,
        label: &'static [u8],
        kem_id: u16,
    ) -> Self {
        Self {
            pq,
            group,
            prg,
            kdf,
            rng,
            label,
            kem_id,
        }
    }
}

impl<PQ, G, PRG, KDF, RNG> CgHybridKem<PQ, G, PRG, KDF, RNG>
where
    PQ: FixedLengthKemType,
    G: DhType,
    PRG: VariableLengthHash,
    KDF: Hash,
    RNG: SeedRng,
{
    fn ek_len(&self) -> usize {
        self.pq.public_key_size() + self.group.public_key_size()
    }

    fn ct_len(&self) -> usize {
        self.pq.enc_size() + self.group.public_key_size()
    }

    /// `expandDecapsKeyG(seed)` (hybrid-kems §5.1.1).
    #[cfg_attr(not(mls_build_async), maybe_async::must_be_sync)]
    async fn expand_decaps_key(&self, seed: &[u8]) -> Result<ExpandedKey, Error> {
        let pq_seed_len = self.pq.seed_length_for_derive();
        let t_seed_len = self.group.secret_key_size();

        let seed_full = Zeroizing::new(
            self.prg
                .hash(seed, pq_seed_len + t_seed_len)
                .map_err(|e| Error::PrgError(e.into_any_error()))?,
        );

        if seed_full.len() != pq_seed_len + t_seed_len {
            return Err(Error::InvalidPrgOutputLength);
        }

        let (seed_pq, seed_t) = seed_full.split_at(pq_seed_len);

        let (dk_pq, ek_pq) = self
            .pq
            .generate_deterministic(seed_pq)
            .await
            .map_err(|e| Error::KemError(e.into_any_error()))?;

        let dk_t = HpkeSecretKey::from(seed_t.to_vec());

        let ek_t = self
            .group
            .to_public(&dk_t)
            .await
            .map_err(|e| Error::KemError(e.into_any_error()))?;

        Ok(ExpandedKey {
            ek_pq,
            ek_t,
            dk_pq,
            dk_t,
        })
    }

    /// `DeriveKeyPair(seed) = (seed, concat(ek_PQ, ek_T))` (hybrid-kems §5.5).
    #[cfg_attr(not(mls_build_async), maybe_async::must_be_sync)]
    async fn key_pair_from_seed(
        &self,
        seed: Zeroizing<Vec<u8>>,
    ) -> Result<(HpkeSecretKey, HpkePublicKey), Error> {
        let expanded = self.expand_decaps_key(&seed).await?;
        let ek = [expanded.ek_pq.as_ref(), expanded.ek_t.as_ref()].concat();

        Ok((HpkeSecretKey::from(seed.to_vec()), ek.into()))
    }

    /// `C2PRICombiner` (hybrid-kems §5.1.3).
    fn combine(
        &self,
        ss_pq: &[u8],
        ss_t: &[u8],
        ct_t: &[u8],
        ek_t: &[u8],
    ) -> Result<Vec<u8>, Error> {
        let input = Zeroizing::new([ss_pq, ss_t, ct_t, ek_t, self.label].concat());

        self.kdf
            .hash(&input)
            .map_err(|e| Error::KdfError(e.into_any_error()))
    }
}

#[cfg_attr(not(mls_build_async), maybe_async::must_be_sync)]
#[cfg_attr(all(target_arch = "wasm32", mls_build_async), maybe_async::must_be_async(?Send))]
#[cfg_attr(
    all(not(target_arch = "wasm32"), mls_build_async),
    maybe_async::must_be_async
)]
impl<PQ, G, PRG, KDF, RNG> KemType for CgHybridKem<PQ, G, PRG, KDF, RNG>
where
    PQ: FixedLengthKemType,
    G: DhType,
    PRG: VariableLengthHash,
    KDF: Hash,
    RNG: SeedRng,
{
    type Error = Error;

    fn kem_id(&self) -> u16 {
        self.kem_id
    }

    /// HPKE `DeriveKeyPair(ikm)` (hpke-pq §4).
    async fn generate_deterministic(
        &self,
        ikm: &[u8],
    ) -> Result<(HpkeSecretKey, HpkePublicKey), Error> {
        let suite_id = [b"KEM" as &[u8], &self.kem_id.to_be_bytes()].concat();

        let seed = Zeroizing::new(
            labeled_derive(
                &self.prg,
                &suite_id,
                ikm,
                b"DeriveKeyPair",
                b"",
                NSEED as u16,
            )
            .map_err(|e| Error::KdfError(e.into_any_error()))?,
        );

        self.key_pair_from_seed(seed).await
    }

    /// `GenerateKeyPair` (hybrid-kems §5.2).
    async fn generate(&self) -> Result<(HpkeSecretKey, HpkePublicKey), Error> {
        let mut seed = Zeroizing::new(vec![0u8; NSEED]);

        self.rng
            .fill(&mut seed)
            .map_err(|e| Error::KemError(e.into_any_error()))?;

        self.key_pair_from_seed(seed).await
    }

    fn public_key_validate(&self, key: &HpkePublicKey) -> Result<(), Error> {
        if key.len() != self.ek_len() {
            return Err(Error::InvalidKeyData);
        }

        let (ek_pq, ek_t) = key.split_at(self.pq.public_key_size());

        self.pq
            .public_key_validate(&ek_pq.to_vec().into())
            .map_err(|e| Error::KemError(e.into_any_error()))?;

        self.group
            .public_key_validate(&ek_t.to_vec().into())
            .map_err(|e| Error::KemError(e.into_any_error()))
    }

    /// `Encaps(ek)` (hybrid-kems §5.5, `prepareEncapsG` §5.1.1).
    async fn encap(&self, remote_key: &HpkePublicKey) -> Result<KemResult, Error> {
        if remote_key.len() != self.ek_len() {
            return Err(Error::InvalidKeyData);
        }

        let (ek_pq, ek_t) = remote_key.split_at(self.pq.public_key_size());
        let ek_t = HpkePublicKey::from(ek_t.to_vec());

        let pq_result = self
            .pq
            .encap(&ek_pq.to_vec().into())
            .await
            .map_err(|e| Error::KemError(e.into_any_error()))?;

        let (sk_e, ct_t) = self
            .group
            .generate()
            .await
            .map_err(|e| Error::KemError(e.into_any_error()))?;

        let ss_t = Zeroizing::new(
            self.group
                .dh(&sk_e, &ek_t)
                .await
                .map_err(|e| Error::KemError(e.into_any_error()))?,
        );

        let shared_secret = self.combine(&pq_result.shared_secret, &ss_t, &ct_t, &ek_t)?;

        let enc = [pq_result.enc.as_slice(), ct_t.as_ref()].concat();

        Ok(KemResult { shared_secret, enc })
    }

    /// `Decaps(dk, ct)` (hybrid-kems §5.5, `prepareDecapsG` §5.1.1).
    async fn decap(
        &self,
        enc: &[u8],
        secret_key: &HpkeSecretKey,
        _local_public: &HpkePublicKey,
    ) -> Result<Vec<u8>, Error> {
        if enc.len() != self.ct_len() || secret_key.len() != NSEED {
            return Err(Error::InvalidKeyData);
        }

        let (ct_pq, ct_t) = enc.split_at(self.pq.enc_size());
        let ct_t = HpkePublicKey::from(ct_t.to_vec());

        let expanded = self.expand_decaps_key(secret_key).await?;

        let ss_pq = Zeroizing::new(
            self.pq
                .decap(ct_pq, &expanded.dk_pq, &expanded.ek_pq)
                .await
                .map_err(|e| Error::KemError(e.into_any_error()))?,
        );

        let ss_t = Zeroizing::new(
            self.group
                .dh(&expanded.dk_t, &ct_t)
                .await
                .map_err(|e| Error::KemError(e.into_any_error()))?,
        );

        self.combine(&ss_pq, &ss_t, &ct_t, &expanded.ek_t)
    }

    fn seed_length_for_derive(&self) -> usize {
        NSEED
    }

    fn derive_key_pair_uses_dkp_prk(&self) -> bool {
        false
    }
}

impl<PQ, G, PRG, KDF, RNG> FixedLengthKemType for CgHybridKem<PQ, G, PRG, KDF, RNG>
where
    PQ: FixedLengthKemType,
    G: DhType,
    PRG: VariableLengthHash,
    KDF: Hash,
    RNG: SeedRng,
{
    fn public_key_size(&self) -> usize {
        self.ek_len()
    }

    fn secret_key_size(&self) -> usize {
        NSEED
    }

    fn enc_size(&self) -> usize {
        self.ct_len()
    }
}

#[cfg(all(test, not(mls_build_async)))]
mod tests {
    use alloc::vec;
    use alloc::vec::Vec;

    use assert_matches::assert_matches;
    use mls_rs_core::crypto::{HpkePublicKey, HpkeSecretKey};
    use mls_rs_crypto_traits::{
        mock::{MockDhType, MockHash, MockKemType, MockVariableLengthHash},
        KemType,
    };

    use super::{CgHybridKem, MLKEM768_X25519_KEM_ID, MLKEM768_X25519_LABEL};
    use crate::kem_combiner::{Error, FixedLengthKemType, MockSeedRng};

    const PQ_EK_LEN: usize = 4;
    const PQ_CT_LEN: usize = 4;
    const PQ_SEED_LEN: usize = 64;
    const T_ELEM_LEN: usize = 3;
    const T_SEED_LEN: usize = 32;

    impl FixedLengthKemType for MockKemType {
        fn public_key_size(&self) -> usize {
            PQ_EK_LEN
        }

        fn secret_key_size(&self) -> usize {
            unreachable!("CgHybridKem never asks the PQ KEM for its secret key size")
        }

        fn enc_size(&self) -> usize {
            PQ_CT_LEN
        }
    }

    type TestKem =
        CgHybridKem<MockKemType, MockDhType, MockVariableLengthHash, MockHash, MockSeedRng>;

    fn test_kem() -> TestKem {
        let mut pq = MockKemType::new();
        pq.expect_seed_length_for_derive().return_const(PQ_SEED_LEN);

        let mut group = MockDhType::new();
        group.expect_secret_key_size().return_const(T_SEED_LEN);
        group.expect_public_key_size().return_const(T_ELEM_LEN);

        CgHybridKem::new(
            pq,
            group,
            MockVariableLengthHash::new(),
            MockHash::new(),
            MockSeedRng::new(),
            MLKEM768_X25519_LABEL,
            MLKEM768_X25519_KEM_ID,
        )
    }

    fn seed_full() -> Vec<u8> {
        [vec![0x01; PQ_SEED_LEN], vec![0x02; T_SEED_LEN]].concat()
    }

    fn expect_expand(kem: &mut TestKem, seed: Vec<u8>) {
        kem.prg
            .expect_hash()
            .withf(move |input, len| input == seed.as_slice() && *len == PQ_SEED_LEN + T_SEED_LEN)
            .once()
            .returning(|_, _| Ok(seed_full()));

        kem.pq
            .expect_generate_deterministic()
            .withf(|seed_pq| seed_pq == [0x01; PQ_SEED_LEN].as_slice())
            .once()
            .returning(|_| Ok((b"dkPQ".to_vec().into(), b"ekPQ".to_vec().into())));

        kem.group
            .expect_to_public()
            .withf(|dk_t| dk_t.as_ref() == [0x02; T_SEED_LEN].as_slice())
            .once()
            .returning(|_| Ok(b"ekT".to_vec().into()));
    }

    fn expect_combiner(kem: &mut TestKem) {
        let expected = [b"ssPQ" as &[u8], b"ssT", b"ctT", b"ekT", b"\\.//^\\"].concat();

        kem.kdf
            .expect_hash()
            .withf(move |input| input == expected.as_slice())
            .once()
            .returning(|_| Ok(b"ssH".to_vec()));
    }

    #[test]
    fn decap_reexpands_the_seed_and_combines_in_spec_order() {
        let mut kem = test_kem();
        expect_expand(&mut kem, vec![0x44; 32]);

        kem.pq
            .expect_decap()
            .withf(|ct, dk, ek| ct == b"ctPQ" && dk.as_ref() == b"dkPQ" && ek.as_ref() == b"ekPQ")
            .once()
            .returning(|_, _, _| Ok(b"ssPQ".to_vec()));

        kem.group
            .expect_dh()
            .withf(|dk_t, ct_t| {
                dk_t.as_ref() == [0x02; T_SEED_LEN].as_slice() && ct_t.as_ref() == b"ctT"
            })
            .once()
            .returning(|_, _| Ok(b"ssT".to_vec()));

        expect_combiner(&mut kem);

        let unrelated_public = HpkePublicKey::from(b"not the public key".to_vec());

        let ss = kem
            .decap(
                b"ctPQctT",
                &HpkeSecretKey::from(vec![0x44; 32]),
                &unrelated_public,
            )
            .unwrap();

        assert_eq!(ss, b"ssH");
    }

    #[test]
    fn rejects_prg_output_of_wrong_length() {
        let mut kem = test_kem();

        kem.rng.expect_fill().once().returning(|_| Ok(()));

        kem.prg
            .expect_hash()
            .once()
            .returning(|_, len| Ok(vec![0; len - 1]));

        assert_matches!(kem.generate(), Err(Error::InvalidPrgOutputLength));
    }
}
