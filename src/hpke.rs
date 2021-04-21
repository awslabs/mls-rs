use crate::aead::{aes, chacha20, Cipher, CipherError};
use crate::asym::AsymmetricKeyEngine;
use crate::hpke_kdf::HpkeKdf;
use crate::kdf::{Kdf, KdfError};
use crate::kem::{Kem, KemError, P256HkdfSha256, P521HkdfSha512, X25519HkdfSha256, X448HkdfSha512};
use crate::rand::SecureRng;
use serde::{Deserialize, Serialize};
use std::fmt::Debug;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum HPKEError {
    #[error("cipher error: {0}")]
    CipherError(#[from] CipherError),
    #[error("kem error: {0}")]
    KemError(#[from] KemError),
    #[error("kdf error: {0}")]
    KdfError(#[from] KdfError),
    #[error("invalid psk")]
    InvalidPsk,
    #[error("sequence number overflow")]
    SeqNumberOverflow,
}

/* Currently only basic mode is supported */
#[derive(PartialEq, Debug, Clone)]
pub enum Mode {
    Basic = 0x00,
}

impl Mode {
    fn to_bytes(&self) -> [u8; 1] {
        match self {
            Self::Basic => (Self::Basic as u8).to_be_bytes(),
        }
    }
}

#[derive(PartialEq, Debug)]
pub struct KeySchedule {
    mode: Mode,
    key: Vec<u8>,
    base_nonce: Vec<u8>,
    seq_number: u64,
    exporter_secret: Vec<u8>,
}

#[derive(PartialEq, Debug)]
pub struct Context<CT: Cipher> {
    key_schedule: KeySchedule,
    cipher: CT,
}

impl<CT: Cipher> Context<CT> {
    #[inline]
    //draft-irtf-cfrg-hpke Section 5.2.  Encryption and Decryption
    fn compute_nonce(&self) -> Vec<u8> {
        // Extend the sequence number out to the same number of bytes as the base nonce
        let seq_num_bytes = &self.key_schedule.seq_number.to_be_bytes() as &[u8];
        let mut seq_bytes: Vec<u8> = vec![0; CT::NONCE_LEN as usize - seq_num_bytes.len()];
        seq_bytes.extend_from_slice(seq_num_bytes);

        // XOR base nonce with current sequence bytes
        self.key_schedule
            .base_nonce
            .iter()
            .zip(seq_bytes.iter())
            .map(|(&a, &b)| a ^ b)
            .collect()
    }

    #[inline]
    fn increment_seq(&mut self) -> Result<(), HPKEError> {
        // If the sequence number is going to roll over just throw an error
        if self.key_schedule.seq_number == u64::MAX {
            Err(HPKEError::SeqNumberOverflow)
        } else {
            self.key_schedule.seq_number += 1;
            Ok(())
        }
    }

    /*
    draft-irtf-cfrg-hpke section 6.1. Encryption and Decryption
    */
    pub fn seal(&mut self, aad: &[u8], pt: &[u8]) -> Result<Vec<u8>, HPKEError> {
        let nonce = self.compute_nonce();
        let ct = self.cipher.encrypt(pt, aad, &nonce)?;
        self.increment_seq()?;
        Ok(ct)
    }

    /*
    draft-irtf-cfrg-hpke section 6.1. Encryption and Decryption
    */
    pub fn open(&mut self, ct: &[u8], aad: &[u8]) -> Result<Vec<u8>, HPKEError> {
        let pt = self.cipher.decrypt(&self.compute_nonce(), ct, aad)?;
        self.increment_seq()?;
        Ok(pt)
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct HPKECiphertext {
    pub kem_output: Vec<u8>,
    pub ciphertext: Vec<u8>,
}

pub trait Hpke: Sized {
    type CT: Cipher + PartialEq + Debug;
    type KEM: Kem;

    #[inline]
    fn get_suite_id() -> Vec<u8> {
        [
            b"HPKE",
            &(Self::KEM::KEM_ID as u16).to_be_bytes() as &[u8],
            &(<Self::KEM as Kem>::KDF::KDF_ID as u16).to_be_bytes() as &[u8],
            &(Self::CT::CIPHER_ID as u16).to_be_bytes() as &[u8],
        ]
        .concat()
    }

    fn key_schedule(
        mode: Mode,
        shared_secret: &[u8],
        info: &[u8],
        psk: Option<&[u8]>,
        psk_id: Option<&[u8]>,
    ) -> Result<KeySchedule, HPKEError> {
        if mode != Mode::Basic && (psk.is_none() || psk_id.is_none()) {
            return Err(HPKEError::InvalidPsk);
        }

        let psk = psk.unwrap_or(&[]);
        let psk_id = psk_id.unwrap_or(&[]);

        let psk_id_hash = <Self::KEM as Kem>::KDF::labeled_extract(
            &Self::get_suite_id(),
            &[],
            b"psk_id_hash",
            psk_id,
        )?;

        let info_hash = <Self::KEM as Kem>::KDF::labeled_extract(
            &Self::get_suite_id(),
            &[],
            b"info_hash",
            info,
        )?;

        let key_schedule_context = [&mode.to_bytes() as &[u8], &psk_id_hash, &info_hash].concat();

        let secret = <Self::KEM as Kem>::KDF::labeled_extract(
            &Self::get_suite_id(),
            &shared_secret,
            b"secret",
            psk,
        )?;

        let key = <Self::KEM as Kem>::KDF::labeled_expand(
            &Self::get_suite_id(),
            &secret,
            b"key",
            &key_schedule_context,
            Self::CT::KEY_LEN,
        )?;

        let base_nonce = <Self::KEM as Kem>::KDF::labeled_expand(
            &Self::get_suite_id(),
            &secret,
            b"base_nonce",
            &key_schedule_context,
            Self::CT::NONCE_LEN,
        )?;

        let exporter_secret = <Self::KEM as Kem>::KDF::labeled_expand(
            &Self::get_suite_id(),
            &secret,
            b"exp",
            &key_schedule_context,
            <Self::KEM as Kem>::KDF::EXTRACT_SIZE,
        )?;

        Ok(KeySchedule {
            mode,
            key,
            base_nonce,
            seq_number: 0,
            exporter_secret,
        })
    }

    fn setup_basic_sender<RNG: SecureRng + 'static>(
        rng: &mut RNG,
        remote_key: &<<Self::KEM as Kem>::E as AsymmetricKeyEngine>::PK,
        info: &[u8],
    ) -> Result<(Vec<u8>, Context<Self::CT>), HPKEError> {
        let kem_res = Self::KEM::encap(rng, remote_key)?;

        let key_schedule =
            Self::key_schedule(Mode::Basic, &kem_res.shared_secret, info, None, None)?;

        let cipher = Self::CT::new(key_schedule.key.clone())?;

        let ctx = Context {
            cipher,
            key_schedule,
        };

        Ok((kem_res.enc, ctx))
    }

    fn setup_basic_receiver(
        enc: &[u8],
        local_secret: &<<Self::KEM as Kem>::E as AsymmetricKeyEngine>::SK,
        info: &[u8],
    ) -> Result<Context<Self::CT>, HPKEError> {
        let shared_secret = Self::KEM::decap(enc, local_secret)?;

        let key_schedule = Self::key_schedule(Mode::Basic, &shared_secret, info, None, None)?;

        let cipher = Self::CT::new(key_schedule.key.clone())?;

        Ok(Context {
            cipher,
            key_schedule,
        })
    }

    /*
    draft-irtf-cfrg-hpke section 6 Single-Shot APIs
    */
    fn seal_basic<RNG: SecureRng + 'static>(
        rng: &mut RNG,
        remote_key: &<<Self::KEM as Kem>::E as AsymmetricKeyEngine>::PK,
        info: &[u8],
        aad: &[u8],
        pt: &[u8],
    ) -> Result<HPKECiphertext, HPKEError> {
        let (enc, mut ctx) = Self::setup_basic_sender(rng, remote_key, info)?;

        Ok(HPKECiphertext {
            kem_output: enc,
            ciphertext: ctx.seal(aad, pt)?,
        })
    }

    fn open_basic(
        ciphertext: &HPKECiphertext,
        local_secret: &<<Self::KEM as Kem>::E as AsymmetricKeyEngine>::SK,
        info: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, HPKEError> {
        let mut hpke_ctx = Self::setup_basic_receiver(&ciphertext.kem_output, local_secret, info)?;
        hpke_ctx.open(&ciphertext.ciphertext, aad)
    }
}

pub struct X25519HkdfSha256Aes128Gcm();

impl Hpke for X25519HkdfSha256Aes128Gcm {
    type CT = aes::Gcm128;
    type KEM = X25519HkdfSha256;
}

pub struct X25519HkdfSha256ChaCha20();

impl Hpke for X25519HkdfSha256ChaCha20 {
    type CT = chacha20::Poly1305;
    type KEM = X25519HkdfSha256;
}

pub struct P256HkdfSha256Aes128Gcm();

impl Hpke for P256HkdfSha256Aes128Gcm {
    type CT = aes::Gcm128;
    type KEM = P256HkdfSha256;
}

pub struct P521HkdfSha512Aes256Gcm();

impl Hpke for P521HkdfSha512Aes256Gcm {
    type CT = aes::Gcm256;
    type KEM = P521HkdfSha512;
}

pub struct X448HkdfSha512Aes256Gcm();

impl Hpke for X448HkdfSha512Aes256Gcm {
    type CT = aes::Gcm256;
    type KEM = X448HkdfSha512;
}

pub struct X448HkdfSha512ChaCha20();

impl Hpke for X448HkdfSha512ChaCha20 {
    type CT = chacha20::Poly1305;
    type KEM = X448HkdfSha512;
}

#[cfg(test)]
pub(crate) mod test_util {
    use super::Hpke;
    use crate::aead::test_util::MockTestCipher;
    use crate::kem::test_util::MockTestKem;
    use mockall::mock;

    mock! {
        pub TestHpke {}
        impl Hpke for TestHpke {
            type CT = MockTestCipher;
            type KEM = MockTestKem;
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::aead::AeadId;
    use crate::asym::{AsymmetricKey, AsymmetricKeyEngine};
    use crate::hpke::{
        Hpke, Mode, P256HkdfSha256Aes128Gcm, P521HkdfSha512Aes256Gcm, X25519HkdfSha256Aes128Gcm,
        X25519HkdfSha256ChaCha20, X448HkdfSha512Aes256Gcm, X448HkdfSha512ChaCha20,
    };
    use crate::kdf::KdfId;
    use crate::kem::{Kem, KemId};
    use crate::rand::test_rng::OneValRng;
    use serde::{Deserialize, Deserializer};
    use std::fs::File;
    use std::io::BufReader;
    use std::ops::Deref;

    macro_rules! assert_eq_hpke {
        ($a:expr, $b:expr, $tv:expr) => {
            assert_eq!(
                $a, $b,
                "failing vector: Mode: {:?} KEM: {:?} KDF: {:?} AEAD: {:?}",
                $tv.mode, $tv.kem_id, $tv.kdf_id, $tv.aead_id
            )
        };
    }

    fn setup_sender<OUT: Hpke>(
        ikm_e: &Vec<u8>,
        pk_rm: &Vec<u8>,
        info: &Vec<u8>,
    ) -> (Vec<u8>, super::Context<OUT::CT>) {
        /* Force the input of the ecdh ephemeral key generation to be what we need */
        let mut sender_rng = OneValRng { val: ikm_e.clone() };
        let remote_key =
            <<OUT::KEM as Kem>::E as AsymmetricKeyEngine>::PK::from_bytes(pk_rm).unwrap();
        OUT::setup_basic_sender(&mut sender_rng, &remote_key, info).unwrap()
    }

    fn setup_receiver<OUT: Hpke>(
        enc: &Vec<u8>,
        sk_rm: &Vec<u8>,
        info: &Vec<u8>,
    ) -> super::Context<OUT::CT> {
        let local_secret =
            <<OUT::KEM as Kem>::E as AsymmetricKeyEngine>::SK::from_bytes(sk_rm).unwrap();
        OUT::setup_basic_receiver(enc, &local_secret, info).unwrap()
    }

    fn test_hpke<T: Hpke>(vector: &TestVector) {
        let (enc, mut s_context) = setup_sender::<T>(&vector.ikm_e, &vector.pk_rm, &vector.info);
        let mut r_context = setup_receiver::<T>(&vector.enc, &vector.sk_rm, &vector.info);

        assert_eq_hpke!(enc, *vector.enc, vector);
        assert_eq_hpke!(s_context.key_schedule.key, *vector.key, vector);
        assert_eq_hpke!(s_context.key_schedule.seq_number, 0, vector);
        assert_eq_hpke!(s_context.key_schedule.mode, Mode::Basic, vector);
        assert_eq_hpke!(
            s_context.key_schedule.exporter_secret,
            *vector.exporter_secret,
            vector
        );
        assert_eq_hpke!(
            s_context.key_schedule.base_nonce,
            *vector.base_nonce,
            vector
        );
        assert_eq_hpke!(s_context, r_context, vector);

        vector
            .encryptions
            .iter()
            .enumerate()
            .for_each(|(seq, one_vector)| {
                /* Encrypt */
                let ct = s_context
                    .seal(&one_vector.aad.clone(), &one_vector.plaintext)
                    .unwrap();
                assert_eq_hpke!(ct, *one_vector.ciphertext, vector);
                assert_eq_hpke!(s_context.key_schedule.seq_number, seq as u64 + 1, vector);

                /* Decrypt */
                let pt = r_context.open(&ct, &one_vector.aad.clone()).unwrap();
                assert_eq_hpke!(pt, *one_vector.plaintext, vector);
                assert_eq_hpke!(s_context, r_context, vector);
            })
    }

    #[derive(Debug, Clone, PartialEq)]
    struct HexData(Vec<u8>);

    impl Deref for HexData {
        type Target = Vec<u8>;

        fn deref(&self) -> &Self::Target {
            &self.0
        }
    }

    impl<'de> Deserialize<'de> for HexData {
        fn deserialize<D>(deserializer: D) -> Result<Self, <D as Deserializer<'de>>::Error>
        where
            D: Deserializer<'de>,
        {
            let string = String::deserialize(deserializer)?;
            Ok(HexData(hex::decode(string).unwrap()))
        }
    }

    #[derive(Deserialize, Debug)]
    struct TestVector {
        mode: u8,
        kem_id: KemId,
        kdf_id: KdfId,
        aead_id: AeadId,
        info: HexData,
        #[serde(rename(deserialize = "ikmE"))]
        ikm_e: HexData,
        #[serde(rename(deserialize = "pkRm"))]
        pk_rm: HexData,
        #[serde(rename(deserialize = "skRm"))]
        sk_rm: HexData,
        enc: HexData,
        key: HexData,
        base_nonce: HexData,
        exporter_secret: HexData,
        encryptions: Vec<EncryptionVector>,
    }

    #[derive(Deserialize, Debug)]
    struct EncryptionVector {
        plaintext: HexData,
        aad: HexData,
        nonce: HexData,
        ciphertext: HexData,
    }

    #[test]
    // Runs the test vectors in test_data/hpke.json
    fn test_hpke_vectors() {
        let file = File::open("test_data/hpke.json").expect("failed to open file");

        let test_vectors: Vec<TestVector> =
            serde_json::from_reader(BufReader::new(file)).expect("failed to parse vector file");

        // We only support basic mode right now
        let supported_vectors = test_vectors.iter().filter(|e| {
            e.mode == 0
                && e.kem_id.is_supported()
                && e.kdf_id.is_supported()
                && e.aead_id.is_supported()
        });

        supported_vectors.for_each(|v| match v.kem_id {
            KemId::P256HkdfSha256 => {
                if v.kdf_id == KdfId::HkdfSha256 && v.aead_id == AeadId::Aes128Gcm {
                    test_hpke::<P256HkdfSha256Aes128Gcm>(v)
                }
            }
            KemId::P521HkdfSha512 => {
                if v.kdf_id == KdfId::HkdfSha512 && v.aead_id == AeadId::Aes256Gcm {
                    test_hpke::<P521HkdfSha512Aes256Gcm>(v)
                }
            }
            KemId::X25519HkdfSha256 => {
                if v.kdf_id == KdfId::HkdfSha256 && v.aead_id == AeadId::Aes128Gcm {
                    test_hpke::<X25519HkdfSha256Aes128Gcm>(v)
                } else if v.kdf_id == KdfId::HkdfSha256 && v.aead_id == AeadId::ChaCha20Poly1305 {
                    test_hpke::<X25519HkdfSha256ChaCha20>(v)
                }
            }
            KemId::X448HkdfSha512 => {
                if v.kdf_id == KdfId::HkdfSha512 && v.aead_id == AeadId::Aes256Gcm {
                    test_hpke::<X448HkdfSha512Aes256Gcm>(v)
                } else if v.kdf_id == KdfId::HkdfSha512 && v.aead_id == AeadId::ChaCha20Poly1305 {
                    test_hpke::<X448HkdfSha512ChaCha20>(v)
                }
            }
            _ => (),
        })
    }
}
