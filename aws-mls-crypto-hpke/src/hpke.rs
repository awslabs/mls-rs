use std::fmt::Debug;

use aws_mls_core::crypto::{
    HpkeCiphertext, HpkeContextR, HpkeContextS, HpkePublicKey, HpkeSecretKey,
};

use aws_mls_crypto_traits::{AeadType, KdfType, KemType, AEAD_ID_EXPORT_ONLY};

use thiserror::Error;
use zeroize::Zeroizing;

use crate::{
    context::{Context, ContextR, ContextS, EncryptionContext},
    kdf::HpkeKdf,
};

#[derive(Debug, Error)]
pub enum HpkeError {
    #[error(transparent)]
    KemError(Box<dyn std::error::Error + Send + Sync + 'static>),
    #[error(transparent)]
    KdfError(Box<dyn std::error::Error + Send + Sync + 'static>),
    #[error(transparent)]
    AeadError(Box<dyn std::error::Error + Send + Sync + 'static>),
    /// An invalid PSK was supplied. A PSK MUST have 32 bytes of entropy
    #[error("PSK must be at least 32 bytes in length")]
    InsufficientPskLength,
    /// An AEAD nonce of incorrect length was supplied.
    #[error("AEAD nonce of length {0} does not match the expected length {1}")]
    IncorrectNonceLen(usize, usize),
    /// An AEAD key of incorrect length was supplied.
    #[error("AEAD key of length {0} does not match the expected length {1}")]
    IncorrectKeyLen(usize, usize),
    #[error("Encryption API disabled due to export only AeadId")]
    ExportOnlyMode,
    /// Max sequence number exceeded, currently allowed up to MAX u64
    #[error("Sequence number overflow")]
    SequenceNumberOverflow,
}

#[derive(Clone)]
pub struct Hpke<KEM: KemType, KDF: KdfType, AEAD: AeadType> {
    kem: KEM,
    kdf: HpkeKdf<KDF>,
    aead: Option<AEAD>,
}

/// Modes of HPKE operation. Currently only `Base` is supported.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum ModeId {
    /// Base mode of HPKE for key exchange and AEAD cipher
    Base = 0x00,
    /// Base mode with a user provided PSK
    Psk = 0x01,
    /// Authenticated variant that authenticates possession of a KEM private key.
    Auth = 0x02,
    /// Authenticated variant that authenticates possession of a PSK as well as a KEM private key.
    AuthPsk = 0x03,
}

#[derive(Debug, Clone, Eq, PartialEq, Default)]
pub struct Psk<'a> {
    id: &'a [u8],
    value: &'a [u8],
}

impl<'a> Psk<'a> {
    pub fn new(id: &'a [u8], value: &'a [u8]) -> Self {
        Self { id, value }
    }
}

impl<KEM, KDF, AEAD> Hpke<KEM, KDF, AEAD>
where
    KEM: KemType,
    KDF: KdfType + Clone,
    AEAD: AeadType + Clone,
{
    pub fn new(kem: KEM, kdf: KDF, aead: Option<AEAD>) -> Self {
        let aead_id = aead
            .as_ref()
            .map(|aead| aead.aead_id())
            .unwrap_or(AEAD_ID_EXPORT_ONLY);

        let suite_id = [
            b"HPKE",
            &kem.kem_id().to_be_bytes() as &[u8],
            &kdf.kdf_id().to_be_bytes() as &[u8],
            &aead_id.to_be_bytes() as &[u8],
        ]
        .concat();

        let kdf = HpkeKdf::new(suite_id, kdf);
        Self { kem, kdf, aead }
    }

    /// Based on RFC 9180 Single-Shot APIs. This function combines the action
    /// of the [setup_sender](Hpke::setup_sender) and then calling [seal](Context::seal)
    /// on the resulting [Context](self::Context).
    pub fn seal(
        &self,
        remote_key: &HpkePublicKey,
        info: &[u8],
        psk: Option<Psk>,
        aad: Option<&[u8]>,
        pt: &[u8],
    ) -> Result<HpkeCiphertext, HpkeError> {
        let (kem_output, mut ctx) = self.setup_sender(remote_key, info, psk)?;

        Ok(HpkeCiphertext {
            kem_output,
            ciphertext: ctx.seal(aad, pt)?,
        })
    }

    /// Based on RFC 9180 Single-Shot APIs. This function combines the action
    /// of the [setup_receiver](Hpke::setup_receiver) and then calling
    /// [seal](Context::open) on the resulting [Context](self::Context).
    pub fn open(
        &self,
        ciphertext: &HpkeCiphertext,
        local_secret: &HpkeSecretKey,
        info: &[u8],
        psk: Option<Psk>,
        aad: Option<&[u8]>,
    ) -> Result<Vec<u8>, HpkeError> {
        let mut hpke_ctx = self.setup_receiver(&ciphertext.kem_output, local_secret, info, psk)?;
        hpke_ctx.open(aad, &ciphertext.ciphertext)
    }

    /// Generate an HPKE context using the base setup mode. This function returns a tuple
    /// containing the `enc` value that can be used as the input to
    /// [setup_receiver](Hpke::setup_receiver), as well as the [Context](self::Context)
    /// that can be used to generate and receive AEAD ciphertexts. Note that for ECDH based kem
    /// functions, `remote_key` is expected to be in uncompressed public key format.
    pub fn setup_sender(
        &self,
        remote_key: &HpkePublicKey,
        info: &[u8],
        psk: Option<Psk>,
    ) -> Result<(Vec<u8>, ContextS<KDF, AEAD>), HpkeError> {
        let mode = self.base_mode(&psk);

        let kem_res = self
            .kem
            .encap(remote_key)
            .map_err(|e| HpkeError::KemError(e.into()))?;

        let ctx = self.key_schedule(mode, kem_res.shared_secret(), info, psk)?;

        Ok((kem_res.enc().to_owned(), ContextS(ctx)))
    }

    /// Set up an HPKE context by receiving an `enc` value from the output of
    /// [setup_sender](Hpke::setup_sender) as well as your `local_secret` key based on
    /// the KEM type being used. This function returns an HPKE context that can be used for AEAD
    /// encryption and decryption. Note that for ECDH based kem functions, `local_secret`
    /// is expected to be in raw byte key format.
    pub fn setup_receiver(
        &self,
        enc: &[u8],
        local_secret: &HpkeSecretKey,
        info: &[u8],
        psk: Option<Psk>,
    ) -> Result<ContextR<KDF, AEAD>, HpkeError> {
        let mode = self.base_mode(&psk);

        let shared_secret = self
            .kem
            .decap(enc, local_secret)
            .map_err(|e| HpkeError::KemError(e.into()))?;

        self.key_schedule(mode, &shared_secret, info, psk)
            .map(ContextR)
    }

    pub fn derive(&self, ikm: &[u8]) -> Result<(HpkeSecretKey, HpkePublicKey), HpkeError> {
        self.kem
            .derive(ikm)
            .map_err(|e| HpkeError::KemError(e.into()))
    }

    pub fn generate(&self) -> Result<(HpkeSecretKey, HpkePublicKey), HpkeError> {
        self.kem
            .generate()
            .map_err(|e| HpkeError::KemError(e.into()))
    }

    pub fn public_key_validate(&self, key: &HpkePublicKey) -> Result<(), HpkeError> {
        self.kem
            .public_key_validate(key)
            .map_err(|e| HpkeError::KemError(e.into()))
    }

    fn key_schedule(
        &self,
        mode: ModeId,
        shared_secret: &[u8],
        info: &[u8],
        psk: Option<Psk>,
    ) -> Result<Context<KDF, AEAD>, HpkeError> {
        self.check_psk(psk.as_ref())?;

        let psk = psk.unwrap_or_default();

        let psk_id_hash = self
            .kdf
            .labeled_extract(&[], b"psk_id_hash", psk.id)
            .map_err(|e| HpkeError::KdfError(e.into()))?;

        let info_hash = self
            .kdf
            .labeled_extract(&[], b"info_hash", info)
            .map_err(|e| HpkeError::KdfError(e.into()))?;

        let secret = self
            .kdf
            .labeled_extract(shared_secret, b"secret", psk.value)
            .map(Zeroizing::new)
            .map_err(|e| HpkeError::KdfError(e.into()))?;

        let key_schedule_context = [
            &(mode as u8).to_be_bytes() as &[u8],
            &psk_id_hash,
            &info_hash,
        ]
        .concat();

        let encryption_context = self
            .aead
            .as_ref()
            .map(|aead| {
                let key = self.kdf.labeled_expand(
                    &secret,
                    b"key",
                    &key_schedule_context,
                    aead.key_size(),
                )?;

                let base_nonce = self.kdf.labeled_expand(
                    &secret,
                    b"base_nonce",
                    &key_schedule_context,
                    aead.nonce_size(),
                )?;

                Ok(EncryptionContext::new(base_nonce, aead.clone(), key))
            })
            .transpose()
            .map_err(|e: <KDF as KdfType>::Error| HpkeError::KdfError(e.into()))?
            .transpose()?;

        let len = self.kdf.extract_size();

        let exporter_secret = self
            .kdf
            .labeled_expand(&secret, b"exp", &key_schedule_context, len)
            .map_err(|e| HpkeError::KdfError(e.into()))?;

        Ok(Context::new(
            encryption_context,
            exporter_secret,
            self.kdf.clone(),
        ))
    }

    fn check_psk(&self, psk: Option<&Psk>) -> Result<(), HpkeError> {
        if let Some(psk) = &psk {
            if psk.value.len() < 32 {
                return Err(HpkeError::InsufficientPskLength);
            }
        }

        Ok(())
    }

    #[inline(always)]
    fn base_mode(&self, psk: &Option<Psk>) -> ModeId {
        if psk.is_some() {
            ModeId::Psk
        } else {
            ModeId::Base
        }
    }

    #[cfg(test)]
    pub(crate) fn hpke_kdf(&self) -> HpkeKdf<KDF> {
        self.kdf.clone()
    }
}

#[cfg(test)]
mod test {

    use assert_matches::assert_matches;
    use aws_mls_core::crypto::{CipherSuite, HpkeContextR, HpkeContextS, CURVE25519_AES128};
    use aws_mls_crypto_openssl::{aead::Aead, ecdh::*, kdf::Kdf};
    use serde::Deserialize;

    use crate::{
        dhkem::DhKem,
        hpke::HpkeError,
        test_utils::{filter_test_case, test_dhkem, TestCaseAlgo},
    };

    use super::{Hpke, ModeId, Psk};

    #[test]
    fn rfc_test_vector() {
        let file = include_str!("../test_data/test_hpke.json");
        let test_vectors: Vec<HpkeTestCase> = serde_json::from_str(file).unwrap();
        test_vectors.into_iter().for_each(run_test_case);
    }

    #[derive(Deserialize, Debug, Clone)]
    struct HpkeTestCase {
        #[serde(flatten)]
        algo: TestCaseAlgo,
        #[serde(with = "hex::serde")]
        info: Vec<u8>,
        #[serde(with = "hex::serde", rename(deserialize = "ikmE"))]
        ikm_e: Vec<u8>,
        #[serde(with = "hex::serde", rename(deserialize = "pkRm"))]
        pk_rm: Vec<u8>,
        #[serde(with = "hex::serde", rename(deserialize = "skRm"))]
        sk_rm: Vec<u8>,
        #[serde(with = "hex::serde")]
        enc: Vec<u8>,
        #[serde(with = "hex::serde")]
        exporter_secret: Vec<u8>,
        #[serde(with = "hex::serde", default)]
        psk: Vec<u8>,
        #[serde(with = "hex::serde", default)]
        psk_id: Vec<u8>,
        #[serde(with = "hex::serde")]
        base_nonce: Vec<u8>,
        #[serde(with = "hex::serde")]
        key: Vec<u8>,
    }

    fn run_test_case(test_case: HpkeTestCase) {
        let Some(cipher_suite) =  filter_test_case(&test_case.algo) else { return; };

        println!("Testing HPKE for ciphersuite {cipher_suite:?}",);

        let psk = (test_case.algo.mode == ModeId::Psk as u8).then_some(Psk {
            id: &test_case.psk_id,
            value: &test_case.psk,
        });

        let mut hpke = test_hpke(cipher_suite, false);
        hpke.kem.set_test_data(test_case.ikm_e);

        let (enc, context) = hpke
            .setup_sender(&test_case.pk_rm.into(), &test_case.info, psk.clone())
            .unwrap();

        assert_eq!(enc, test_case.enc);
        assert_eq!(context.0.exporter_secret(), &test_case.exporter_secret);
        assert_eq!(context.0.aead_key(), Some(test_case.key.as_slice()));

        assert_eq!(
            context.0.base_nonce(),
            Some(test_case.base_nonce.as_slice())
        );

        let context = hpke
            .setup_receiver(&enc, &test_case.sk_rm.into(), &test_case.info, psk)
            .unwrap();

        assert_eq!(context.0.exporter_secret(), &test_case.exporter_secret);
        assert_eq!(context.0.aead_key(), Some(test_case.key.as_slice()));

        assert_eq!(
            context.0.base_nonce(),
            Some(test_case.base_nonce.as_slice())
        );
    }

    #[test]
    fn test_invalid_psk() {
        let hpke = test_hpke(CURVE25519_AES128, false);
        let remote_pub = hpke.generate().unwrap().1;

        let basic_res = hpke.setup_sender(&remote_pub, &[], Some(Psk::default()));

        assert_matches!(basic_res, Err(HpkeError::InsufficientPskLength));
    }

    #[test]
    fn test_encrypt_api_disabled() {
        let hpke = test_hpke(CURVE25519_AES128, true);
        let (secret, remote_pub) = hpke.generate().unwrap();

        let (enc, mut sender_ctx) = hpke.setup_sender(&remote_pub, &[], None).unwrap();
        let mut receiver_ctx = hpke.setup_receiver(&enc, &secret, &[], None).unwrap();

        assert_matches!(
            sender_ctx.seal(None, b"test"),
            Err(HpkeError::ExportOnlyMode)
        );

        assert_matches!(
            receiver_ctx.open(None, b"test"),
            Err(HpkeError::ExportOnlyMode)
        );
    }

    fn test_hpke(
        cipher_suite: CipherSuite,
        export_only: bool,
    ) -> Hpke<DhKem<Ecdh, Kdf>, Kdf, Aead> {
        let kdf = Kdf::new(cipher_suite).unwrap();
        let aead = (!export_only).then_some(Aead::new(cipher_suite).unwrap());
        let kem = test_dhkem(cipher_suite);
        Hpke::new(kem, kdf, aead)
    }
}
