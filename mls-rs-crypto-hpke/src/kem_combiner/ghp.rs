use alloc::string::String;
use alloc::vec::Vec;
use mls_rs_core::{
    crypto::{HpkePublicKey, HpkeSecretKey},
    error::IntoAnyError,
};
use mls_rs_crypto_traits::{KemResult, KemType};
use zeroize::Zeroize;

use super::{codec_error, kem_error, prg_error, ro_error, Error};

#[cfg_attr(test, mockall::automock(type Error = mls_rs_crypto_traits::mock::TestError;))]
pub trait Prg: Send + Sync {
    type Error: Send + Sync + IntoAnyError;

    fn eval(&self, key: &[u8], out_len: usize) -> Result<Vec<u8>, Self::Error>;
}

// FIXME. not supported by automock yet
pub trait ByteVecCodec<const N: usize>: ByteVecEncoder<N> {
    fn decode(&self, data: &[u8]) -> Result<[Vec<u8>; N], Self::Error>;

    fn decode_and_parse<T: From<Vec<u8>>>(&self, data: &[u8]) -> Result<[T; N], Error> {
        Ok(self.decode(data).map_err(codec_error)?.map(Into::into))
    }
}

// FIXME. not supported by automock yet
pub trait ByteVecEncoder<const N: usize>: Send + Sync {
    type Error: Send + Sync + IntoAnyError;

    fn encode(&self, data: [&[u8]; N]) -> Result<Vec<u8>, Self::Error>;
}

#[cfg_attr(test, mockall::automock(type Error = mls_rs_crypto_traits::mock::TestError;))]
pub trait RandomOracle: Send + Sync {
    type Error: Send + Sync + IntoAnyError;

    fn eval(&self, data: &[u8]) -> Result<Vec<u8>, Self::Error>;
}

/// A generalization of the GHP KEM combiner defined in the [RFC draft](https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-hybrid-kems)
/// with a security analysis by Giacon, Heuer and Poettering [[GHP]](https://link.springer.com/chapter/10.1007/978-3-319-76578-5_7).
/// Security requirements for input KEM's, PRG and Random Oracle are specified in the above RFC draft and research paper.
///
/// This combiner generalizes the GHP construction from the RFC draft by using generic [ByteVecCodec] objects for encoding
/// and decoding public keys, ciphertexts and Random Oracle inputs. The RFC draft fxes the choice of these codecs to be
/// concatenation. The advantage of this is efficiency. The disadvantage is that it introduces a requirement on the input
/// KEM's that the public keys and ciphertexts must be of fixed size. This crate provides two implementaions of [ByteVecCodec]:
/// [CatCodec] that matches the RFC draft and [MlsByteVecCodec] that removes the above requirement.
///
/// This combiner also differs from the RFC draft in that the combined secret key encodes the two input keys. In the RFC draft
/// the secret key is instead a seed from which the actual secret key is derived via [GhpKemCombiner::derive_key_pair].
/// Encoding the two secret keys gives implementations more flexibility in the storage-computation trade-off. Storing a single
/// seed is more storage-efficient but calling `derive_key_pair` makes decryption less efficient. Using [GhpKemCombiner],
/// implementations can still choose to store either two seeds or two expanded keys.
#[derive(Clone)]
pub struct GhpKemCombiner<KEM1, KEM2, PRG, C2, C7, RO> {
    pub kem1: KEM1,
    pub kem2: KEM2,
    pub prg: PRG,
    pub pk_codec: C2,
    pub sk_codec: C2,
    pub ct_codec: C2,
    pub ro_input_encoder: C7,
    pub random_oracle: RO,
    pub label: String,
    pub kem_id: u16,
}

impl<KEM1, KEM2, PRG, C2, C7, RO> GhpKemCombiner<KEM1, KEM2, PRG, C2, C7, RO>
where
    KEM1: KemType,
    KEM2: KemType,
    PRG: Prg,
    C2: ByteVecCodec<2>,
    C7: ByteVecEncoder<7>,
    RO: RandomOracle,
{
    pub fn derive_key_pair(&self, seed: &[u8]) -> Result<(HpkeSecretKey, HpkePublicKey), Error> {
        let seed_full = self
            .prg
            .eval(seed, self.seed_length_for_derive())
            .map_err(prg_error)?;

        if seed_full.len() != self.seed_length_for_derive() {
            return Err(Error::InvalidPrgOutputLength);
        }

        let (seed1, seed2) = seed_full.split_at(self.kem1.seed_length_for_derive());

        let (sk1, pk1) = self.kem1.generate_deterministic(seed1).map_err(kem_error)?;
        let (sk2, pk2) = self.kem2.generate_deterministic(seed2).map_err(kem_error)?;

        let sk = self.sk_codec.encode([&sk1, &sk2]).map_err(codec_error)?;
        let pk = self.pk_codec.encode([&pk1, &pk2]).map_err(codec_error)?;

        Ok((sk.into(), pk.into()))
    }

    pub fn generate_key_pair(&self) -> Result<(HpkeSecretKey, HpkePublicKey), Error> {
        let (sk1, pk1) = self.kem1.generate().map_err(kem_error)?;
        let (sk2, pk2) = self.kem2.generate().map_err(kem_error)?;

        let sk = self.sk_codec.encode([&sk1, &sk2]).map_err(codec_error)?;
        let pk = self.pk_codec.encode([&pk1, &pk2]).map_err(codec_error)?;

        Ok((sk.into(), pk.into()))
    }

    pub fn encap(&self, remote_key: &HpkePublicKey) -> Result<KemResult, Error> {
        let [pk1, pk2] = self.pk_codec.decode_and_parse(remote_key)?;
        let res1 = self.kem1.encap(&pk1).map_err(kem_error)?;
        let res2 = self.kem2.encap(&pk2).map_err(kem_error)?;

        let mut ro_input = self
            .ro_input_encoder
            .encode([
                &res1.shared_secret,
                &res2.shared_secret,
                &res1.enc,
                &res2.enc,
                &pk1,
                &pk2,
                self.label.as_bytes(),
            ])
            .map_err(codec_error)?;

        let enc = self
            .ct_codec
            .encode([&res1.enc, &res2.enc])
            .map_err(codec_error)?;

        let res = KemResult {
            enc,
            shared_secret: self.random_oracle.eval(&ro_input).map_err(ro_error)?,
        };

        ro_input.zeroize();

        Ok(res)
    }

    pub fn decap(
        &self,
        enc: &[u8],
        secret_key: &HpkeSecretKey,
        local_public: &HpkePublicKey,
    ) -> Result<Vec<u8>, Error> {
        let [enc1, enc2] = self.ct_codec.decode(enc).map_err(codec_error)?;
        let [sk1, sk2] = self.sk_codec.decode_and_parse(secret_key)?;
        let [pk1, pk2] = self.pk_codec.decode_and_parse(local_public)?;

        let shared_secret1 = self.kem1.decap(&enc1, &sk1, &pk1).map_err(kem_error)?;
        let shared_secret2 = self.kem2.decap(&enc2, &sk2, &pk2).map_err(kem_error)?;

        let ro_input = self
            .ro_input_encoder
            .encode([
                &shared_secret1,
                &shared_secret2,
                &enc1,
                &enc2,
                &pk1,
                &pk2,
                self.label.as_bytes(),
            ])
            .map_err(codec_error)?;

        let shared_secret = self.random_oracle.eval(&ro_input).map_err(ro_error)?;

        for mut secret in [shared_secret1, shared_secret2, ro_input] {
            secret.zeroize();
        }

        Ok(shared_secret)
    }

    pub fn seed_length_for_derive(&self) -> usize {
        self.kem1.seed_length_for_derive() + self.kem2.seed_length_for_derive()
    }
}

#[cfg_attr(not(mls_build_async), maybe_async::must_be_sync)]
#[cfg_attr(all(target_arch = "wasm32", mls_build_async), maybe_async::must_be_async(?Send))]
#[cfg_attr(
    all(not(target_arch = "wasm32"), mls_build_async),
    maybe_async::must_be_async
)]
impl<KEM1, KEM2, PRG, C2, C7, RO> KemType for GhpKemCombiner<KEM1, KEM2, PRG, C2, C7, RO>
where
    KEM1: KemType,
    KEM2: KemType,
    PRG: Prg,
    C2: ByteVecCodec<2>,
    C7: ByteVecCodec<7>,
    RO: RandomOracle,
{
    type Error = Error;

    /// KEM Id, as specified in RFC 9180, Section 5.1 and Table 2.
    fn kem_id(&self) -> u16 {
        self.kem_id
    }

    async fn generate_deterministic(
        &self,
        seed: &[u8],
    ) -> Result<(HpkeSecretKey, HpkePublicKey), Error> {
        self.derive_key_pair(seed)
    }

    async fn generate(&self) -> Result<(HpkeSecretKey, HpkePublicKey), Error> {
        self.generate_key_pair()
    }

    async fn encap(&self, remote_key: &HpkePublicKey) -> Result<KemResult, Error> {
        self.encap(remote_key)
    }

    async fn decap(
        &self,
        enc: &[u8],
        secret_key: &HpkeSecretKey,
        local_public: &HpkePublicKey,
    ) -> Result<Vec<u8>, Error> {
        self.decap(enc, secret_key, local_public)
    }

    fn seed_length_for_derive(&self) -> usize {
        self.seed_length_for_derive()
    }

    fn public_key_validate(&self, _key: &HpkePublicKey) -> Result<(), Error> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use assert_matches::assert_matches;
    use mls_rs_crypto_traits::{mock::MockKemType, KemResult, KemType};

    use crate::kem_combiner::byte_vec_codecs::MlsByteVecCodec;
    use crate::kem_combiner::Error;

    use super::ByteVecEncoder;

    use super::{GhpKemCombiner, MockPrg, MockRandomOracle};

    fn test_combiner() -> GhpKemCombiner<
        MockKemType,
        MockKemType,
        MockPrg,
        MlsByteVecCodec,
        MlsByteVecCodec,
        MockRandomOracle,
    > {
        GhpKemCombiner {
            kem1: MockKemType::new(),
            kem2: MockKemType::new(),
            prg: MockPrg::new(),
            pk_codec: MlsByteVecCodec,
            sk_codec: MlsByteVecCodec,
            ct_codec: MlsByteVecCodec,
            ro_input_encoder: MlsByteVecCodec,
            random_oracle: MockRandomOracle::new(),
            label: "1234".to_string(),
            kem_id: 42,
        }
    }

    #[test]
    fn generate() {
        let mut combiner = test_combiner();

        combiner
            .kem1
            .expect_generate()
            .once()
            .return_once(|| Ok((b"sk1".to_vec().into(), b"pk1".to_vec().into())));

        combiner
            .kem2
            .expect_generate()
            .once()
            .return_once(|| Ok((b"sk2".to_vec().into(), b"pk2".to_vec().into())));

        let (sk, pk) = combiner.generate_key_pair().unwrap();

        assert_eq!(
            sk.as_ref(),
            MlsByteVecCodec.encode([b"sk1", b"sk2"]).unwrap()
        );

        assert_eq!(
            pk.as_ref(),
            MlsByteVecCodec.encode([b"pk1", b"pk2"]).unwrap()
        );
    }

    #[test]
    fn generate_deterministic() {
        let mut combiner = test_combiner();

        combiner
            .kem1
            .expect_seed_length_for_derive()
            .returning(|| 5);

        combiner
            .kem2
            .expect_seed_length_for_derive()
            .returning(|| 10);

        combiner
            .prg
            .expect_eval()
            .once()
            .withf(|seed, len| seed == b"seed" && *len == 15)
            .return_once(|_, _| Ok(b"seed1seed200000".to_vec()));

        combiner
            .kem1
            .expect_generate_deterministic()
            .once()
            .withf(|seed1| seed1 == b"seed1")
            .return_once(|_| Ok((b"sk1".to_vec().into(), b"pk1".to_vec().into())));

        combiner
            .kem2
            .expect_generate_deterministic()
            .once()
            .withf(|seed2| seed2 == b"seed200000")
            .return_once(|_| Ok((b"sk2".to_vec().into(), b"pk2".to_vec().into())));

        let (sk, pk) = combiner.generate_deterministic(b"seed").unwrap();

        assert_eq!(
            sk.as_ref(),
            MlsByteVecCodec.encode([b"sk1", b"sk2"]).unwrap()
        );

        assert_eq!(
            pk.as_ref(),
            MlsByteVecCodec.encode([b"pk1", b"pk2"]).unwrap()
        );
    }

    #[test]
    fn encap() {
        let mut combiner = test_combiner();

        combiner
            .kem1
            .expect_encap()
            .once()
            .withf(|pk1| pk1.as_ref() == b"pk1")
            .return_once(|_| Ok(KemResult::new(b"ss1".to_vec(), b"enc1".to_vec())));

        combiner
            .kem2
            .expect_encap()
            .once()
            .withf(|pk2| pk2.as_ref() == b"pk2")
            .return_once(|_| Ok(KemResult::new(b"ss2".to_vec(), b"enc2".to_vec())));

        combiner
            .random_oracle
            .expect_eval()
            .withf(|input| {
                input
                    == MlsByteVecCodec
                        .encode([b"ss1", b"ss2", b"enc1", b"enc2", b"pk1", b"pk2", b"1234"])
                        .unwrap()
            })
            .return_once(|_| Ok(b"ss".to_vec()));

        let result = combiner
            .encap(&MlsByteVecCodec.encode([b"pk1", b"pk2"]).unwrap().into())
            .unwrap();

        assert_eq!(
            result.enc,
            MlsByteVecCodec.encode([b"enc1", b"enc2"]).unwrap()
        );

        assert_eq!(result.shared_secret, b"ss");
    }

    #[test]
    fn decap() {
        let mut combiner = test_combiner();

        combiner
            .kem1
            .expect_decap()
            .once()
            .withf(|enc, sk, pk| enc == b"enc1" && sk.as_ref() == b"sk1" && pk.as_ref() == b"pk1")
            .return_once(|_, _, _| Ok(b"ss1".to_vec()));

        combiner
            .kem2
            .expect_decap()
            .once()
            .withf(|enc, sk, pk| enc == b"enc2" && sk.as_ref() == b"sk2" && pk.as_ref() == b"pk2")
            .return_once(|_, _, _| Ok(b"ss2".to_vec()));

        combiner
            .random_oracle
            .expect_eval()
            .withf(|input| {
                input
                    == MlsByteVecCodec
                        .encode([b"ss1", b"ss2", b"enc1", b"enc2", b"pk1", b"pk2", b"1234"])
                        .unwrap()
            })
            .return_once(|_| Ok(b"ss".to_vec()));

        let shared_secret = combiner
            .decap(
                &MlsByteVecCodec.encode([b"enc1", b"enc2"]).unwrap(),
                &MlsByteVecCodec.encode([b"sk1", b"sk2"]).unwrap().into(),
                &MlsByteVecCodec.encode([b"pk1", b"pk2"]).unwrap().into(),
            )
            .unwrap();

        assert_eq!(shared_secret, b"ss");
    }

    #[test]
    fn invalid_eval_output() {
        let mut combiner = test_combiner();

        combiner
            .kem1
            .expect_seed_length_for_derive()
            .returning(|| 5);

        combiner
            .kem2
            .expect_seed_length_for_derive()
            .returning(|| 10);

        combiner
            .prg
            .expect_eval()
            .once()
            .withf(|seed, len| seed == b"seed" && *len == 15)
            .return_once(|_, _| Ok(vec![]));

        let res = combiner.generate_deterministic(b"seed");

        assert_matches!(res, Err(Error::InvalidPrgOutputLength));
    }
}
