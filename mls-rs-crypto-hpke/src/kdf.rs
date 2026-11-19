// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// Copyright by contributors to this project.
// SPDX-License-Identifier: (Apache-2.0 OR MIT)

use mls_rs_core::error::{AnyError, IntoAnyError};
use mls_rs_crypto_traits::{KdfType, VariableLengthHash};

use alloc::vec::Vec;
use core::fmt::{self, Debug};

#[derive(Clone, Eq, PartialEq)]
pub(crate) struct HpkeKdf<K: KdfType> {
    suite_id: Vec<u8>,
    kdf: K,
}

impl<K: KdfType + Debug> Debug for HpkeKdf<K> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HpkeKdf")
            .field(
                "suite_id",
                &mls_rs_core::debug::pretty_bytes(&self.suite_id),
            )
            .field("kdf", &self.kdf)
            .finish()
    }
}

impl<K: KdfType> HpkeKdf<K> {
    pub fn new(suite_id: Vec<u8>, kdf: K) -> Self {
        Self { suite_id, kdf }
    }

    pub fn extract_size(&self) -> usize {
        self.kdf.extract_size()
    }

    /* draft-irtf-cfrg-hpke-09 section 4 Cryptographic Dependencies */
    #[cfg_attr(not(mls_build_async), maybe_async::must_be_sync)]
    pub async fn labeled_extract(
        &self,
        salt: &[u8],
        label: &[u8],
        ikm: &[u8],
    ) -> Result<Vec<u8>, <K as KdfType>::Error> {
        self.kdf
            .extract(
                salt,
                &[b"HPKE-v1" as &[u8], &self.suite_id, label, ikm].concat(),
            )
            .await
    }

    /* draft-irtf-cfrg-hpke-09 section 4 Cryptographic Dependencies */
    #[cfg_attr(not(mls_build_async), maybe_async::must_be_sync)]
    pub async fn labeled_expand(
        &self,
        key: &[u8],
        label: &[u8],
        info: &[u8],
        len: usize,
    ) -> Result<Vec<u8>, <K as KdfType>::Error> {
        let labeled_info = [
            &(len as u16).to_be_bytes() as &[u8],
            b"HPKE-v1",
            &self.suite_id,
            label,
            info,
        ]
        .concat();

        self.kdf.expand(key, &labeled_info, len).await
    }

    /* draft-irtf-cfrg-hpke-09 section 4.1 DH-Based KEM */
    #[cfg_attr(not(mls_build_async), maybe_async::must_be_sync)]
    pub async fn labeled_extract_then_expand(
        &self,
        ikm: &[u8],
        ctx: &[u8],
        len: usize,
    ) -> Result<Vec<u8>, <K as KdfType>::Error> {
        let eae_prk = self.labeled_extract(&[], b"eae_prk", ikm).await?;

        self.labeled_expand(&eae_prk, b"shared_secret", ctx, len)
            .await
    }
}

#[derive(Debug)]
#[cfg_attr(feature = "std", derive(thiserror::Error))]
pub enum LabeledDeriveError {
    #[cfg_attr(feature = "std", error(transparent))]
    DeriveError(AnyError),
    /// Label longer than 65535 bytes (draft-ietf-hpke-hpke-06 §3).
    #[cfg_attr(feature = "std", error("label is longer than 65535 bytes"))]
    LabelTooLong,
}

impl IntoAnyError for LabeledDeriveError {}

/// `LabeledDerive` for one-stage KDFs (draft-ietf-hpke-hpke-06 §4.4).
pub fn labeled_derive<D: VariableLengthHash>(
    derive: &D,
    suite_id: &[u8],
    ikm: &[u8],
    label: &[u8],
    context: &[u8],
    len: u16,
) -> Result<Vec<u8>, LabeledDeriveError> {
    let label_len = u16::try_from(label.len()).map_err(|_| LabeledDeriveError::LabelTooLong)?;

    let labeled_ikm = [
        ikm,
        b"HPKE-v1",
        suite_id,
        &label_len.to_be_bytes(),
        label,
        &len.to_be_bytes(),
        context,
    ]
    .concat();

    derive
        .hash(&labeled_ikm, len.into())
        .map_err(|e| LabeledDeriveError::DeriveError(e.into_any_error()))
}

#[cfg(test)]
mod tests {
    use super::{labeled_derive, LabeledDeriveError};
    use alloc::vec;
    use mls_rs_crypto_traits::mock::MockVariableLengthHash;

    #[test]
    fn labeled_derive_formats_input() {
        let expected_input = [
            b"ikm" as &[u8],
            b"HPKE-v1",
            b"KEM\x00\x41",
            &[0x00, 0x0d],
            b"DeriveKeyPair",
            &[0x00, 0x40],
            b"ctx",
        ]
        .concat();

        let mut xof = MockVariableLengthHash::new();
        xof.expect_hash()
            .withf(move |input, len| input == expected_input.as_slice() && *len == 64)
            .times(1)
            .returning(|_, len| Ok(vec![0xaa; len]));

        let out =
            labeled_derive(&xof, b"KEM\x00\x41", b"ikm", b"DeriveKeyPair", b"ctx", 64).unwrap();
        assert_eq!(out, vec![0xaa; 64]);
    }

    #[test]
    fn labeled_derive_rejects_label_longer_than_u16() {
        let xof = MockVariableLengthHash::new();
        let label = vec![0u8; 65536];

        let res = labeled_derive(&xof, b"KEM\x00\x41", b"", &label, b"", 32);
        assert!(matches!(res, Err(LabeledDeriveError::LabelTooLong)));
    }
}
