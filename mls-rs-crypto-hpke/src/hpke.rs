// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// Copyright by contributors to this project.
// SPDX-License-Identifier: (Apache-2.0 OR MIT)

use core::fmt::Debug;

use crate::alloc::borrow::ToOwned;

use mls_rs_core::{
    crypto::{HpkeCiphertext, HpkeContextR, HpkeContextS, HpkePublicKey, HpkeSecretKey},
    error::{AnyError, IntoAnyError},
};

use mls_rs_crypto_traits::{AeadType, KdfType, KemType, AEAD_ID_EXPORT_ONLY};

use zeroize::Zeroizing;

use crate::{
    context::{Context, ContextR, ContextS, EncryptionContext},
    kdf::HpkeKdf,
};

use alloc::vec::Vec;

#[derive(Debug)]
#[cfg_attr(feature = "std", derive(thiserror::Error))]
pub enum HpkeError {
    #[cfg_attr(feature = "std", error(transparent))]
    KemError(AnyError),
    #[cfg_attr(feature = "std", error(transparent))]
    KdfError(AnyError),
    #[cfg_attr(feature = "std", error(transparent))]
    AeadError(AnyError),
    /// An invalid PSK was supplied. A PSK MUST have 32 bytes of entropy
    #[cfg_attr(feature = "std", error("PSK must be at least 32 bytes in length"))]
    InsufficientPskLength,
    /// An AEAD nonce of incorrect length was supplied.
    #[cfg_attr(
        feature = "std",
        error("AEAD nonce of length {0} does not match the expected length {1}")
    )]
    IncorrectNonceLen(usize, usize),
    /// An AEAD key of incorrect length was supplied.
    #[cfg_attr(
        feature = "std",
        error("AEAD key of length {0} does not match the expected length {1}")
    )]
    IncorrectKeyLen(usize, usize),
    #[cfg_attr(
        feature = "std",
        error("Encryption API disabled due to export only AeadId")
    )]
    ExportOnlyMode,
    /// Max sequence number exceeded, currently allowed up to MAX u64
    #[cfg_attr(feature = "std", error("Sequence number overflow"))]
    SequenceNumberOverflow,
}

impl IntoAnyError for HpkeError {
    #[cfg(feature = "std")]
    fn into_dyn_error(self) -> Result<Box<dyn std::error::Error + Send + Sync>, Self> {
        Ok(self.into())
    }
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
    /// of the [setup_sender](Hpke::setup_sender) and then calling [seal](ContextS::seal)
    /// on the resulting [ContextS](self::ContextS).
    #[cfg_attr(not(mls_build_async), maybe_async::must_be_sync)]
    pub async fn seal(
        &self,
        remote_key: &HpkePublicKey,
        info: &[u8],
        psk: Option<Psk<'_>>,
        aad: Option<&[u8]>,
        pt: &[u8],
    ) -> Result<HpkeCiphertext, HpkeError> {
        let (kem_output, mut ctx) = self.setup_sender(remote_key, info, psk)?;

        Ok(HpkeCiphertext {
            kem_output,
            ciphertext: ctx.seal(aad, pt).await?,
        })
    }

    /// Based on RFC 9180 Single-Shot APIs. This function combines the action
    /// of the [setup_receiver](Hpke::setup_receiver) and then calling
    /// [open](ContextR::open) on the resulting [ContextR](self::ContextR).
    #[cfg_attr(not(mls_build_async), maybe_async::must_be_sync)]
    pub async fn open(
        &self,
        ciphertext: &HpkeCiphertext,
        local_secret: &HpkeSecretKey,
        local_public: &HpkePublicKey,
        info: &[u8],
        psk: Option<Psk<'_>>,
        aad: Option<&[u8]>,
    ) -> Result<Vec<u8>, HpkeError> {
        let mut hpke_ctx = self.setup_receiver(
            &ciphertext.kem_output,
            local_secret,
            local_public,
            info,
            psk,
        )?;

        hpke_ctx.open(aad, &ciphertext.ciphertext).await
    }

    /// Generate an HPKE context using the base setup mode. This function returns a tuple
    /// containing the `enc` value that can be used as the input to
    /// [setup_receiver](Hpke::setup_receiver), as well as the [ContextS]
    /// that can be used to generate AEAD ciphertexts. Note that for ECDH based kem
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
            .map_err(|e| HpkeError::KemError(e.into_any_error()))?;

        let ctx = self.key_schedule(mode, kem_res.shared_secret(), info, psk)?;

        Ok((kem_res.enc().to_owned(), ContextS(ctx)))
    }

    /// Set up an HPKE context by receiving an `enc` value from the output of
    /// [setup_sender](Hpke::setup_sender) as well as your `local_secret` key based on
    /// the KEM type being used. This function returns an HPKE context that can be used for AEAD
    /// decryption. Note that for ECDH based kem functions, `local_secret`
    /// is expected to be in raw byte key format.
    pub fn setup_receiver(
        &self,
        enc: &[u8],
        local_secret: &HpkeSecretKey,
        local_public: &HpkePublicKey,
        info: &[u8],
        psk: Option<Psk>,
    ) -> Result<ContextR<KDF, AEAD>, HpkeError> {
        let mode = self.base_mode(&psk);

        let shared_secret = self
            .kem
            .decap(enc, local_secret, local_public)
            .map_err(|e| HpkeError::KemError(e.into_any_error()))?;

        self.key_schedule(mode, &shared_secret, info, psk)
            .map(ContextR)
    }

    pub fn derive(&self, ikm: &[u8]) -> Result<(HpkeSecretKey, HpkePublicKey), HpkeError> {
        self.kem
            .derive(ikm)
            .map_err(|e| HpkeError::KemError(e.into_any_error()))
    }

    pub fn generate(&self) -> Result<(HpkeSecretKey, HpkePublicKey), HpkeError> {
        self.kem
            .generate()
            .map_err(|e| HpkeError::KemError(e.into_any_error()))
    }

    pub fn public_key_validate(&self, key: &HpkePublicKey) -> Result<(), HpkeError> {
        self.kem
            .public_key_validate(key)
            .map_err(|e| HpkeError::KemError(e.into_any_error()))
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
            .map_err(|e| HpkeError::KdfError(e.into_any_error()))?;

        let info_hash = self
            .kdf
            .labeled_extract(&[], b"info_hash", info)
            .map_err(|e| HpkeError::KdfError(e.into_any_error()))?;

        let secret = self
            .kdf
            .labeled_extract(shared_secret, b"secret", psk.value)
            .map(Zeroizing::new)
            .map_err(|e| HpkeError::KdfError(e.into_any_error()))?;

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
            .map_err(|e: <KDF as KdfType>::Error| HpkeError::KdfError(e.into_any_error()))?
            .transpose()?;

        let len = self.kdf.extract_size();

        let exporter_secret = self
            .kdf
            .labeled_expand(&secret, b"exp", &key_schedule_context, len)
            .map_err(|e| HpkeError::KdfError(e.into_any_error()))?;

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
}
