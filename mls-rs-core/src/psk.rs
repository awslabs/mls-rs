// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// Copyright by contributors to this project.
// SPDX-License-Identifier: (Apache-2.0 OR MIT)

use crate::error::IntoAnyError;
#[cfg(mls_build_async)]
use alloc::boxed::Box;
use alloc::vec::Vec;
use core::{
    fmt::{self, Debug},
    ops::Deref,
};
use mls_rs_codec::{MlsDecode, MlsEncode, MlsSize};
use zeroize::Zeroizing;

#[derive(Clone, PartialEq, Eq, MlsSize, MlsEncode, MlsDecode)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
/// Wrapper type that holds a pre-shared key value and zeroizes on drop.
pub struct PreSharedKey(
    #[mls_codec(with = "mls_rs_codec::byte_vec")]
    #[cfg_attr(feature = "serde", serde(with = "crate::zeroizing_serde"))]
    Zeroizing<Vec<u8>>,
);

impl Debug for PreSharedKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PreSharedKey").finish()
    }
}

impl PreSharedKey {
    /// Create a new PreSharedKey.
    pub fn new(data: Vec<u8>) -> Self {
        PreSharedKey(Zeroizing::new(data))
    }

    /// Raw byte value.
    pub fn raw_value(&self) -> &[u8] {
        &self.0
    }
}

impl From<Vec<u8>> for PreSharedKey {
    fn from(bytes: Vec<u8>) -> Self {
        Self::new(bytes)
    }
}

impl From<Zeroizing<Vec<u8>>> for PreSharedKey {
    fn from(bytes: Zeroizing<Vec<u8>>) -> Self {
        Self(bytes)
    }
}

impl AsRef<[u8]> for PreSharedKey {
    fn as_ref(&self) -> &[u8] {
        self.raw_value()
    }
}

impl Deref for PreSharedKey {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        self.raw_value()
    }
}

#[derive(Clone, Eq, Hash, Ord, PartialOrd, PartialEq, MlsSize, MlsEncode, MlsDecode)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
/// An external pre-shared key identifier.
pub struct ExternalPskId(
    #[mls_codec(with = "mls_rs_codec::byte_vec")]
    #[cfg_attr(feature = "serde", serde(with = "crate::vec_serde"))]
    Vec<u8>,
);

impl Debug for ExternalPskId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        crate::debug::pretty_bytes(&self.0)
            .named("ExternalPskId")
            .fmt(f)
    }
}

impl ExternalPskId {
    pub fn new(id_data: Vec<u8>) -> Self {
        Self(id_data)
    }
}

impl AsRef<[u8]> for ExternalPskId {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl Deref for ExternalPskId {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl From<Vec<u8>> for ExternalPskId {
    fn from(value: Vec<u8>) -> Self {
        ExternalPskId(value)
    }
}

/// A pre-shared key value bundled with its identifier, for use with PSK-mode
/// HPKE (RFC 9180).
///
/// Use [`PskBundle::new`] when no identifier is needed (empty `psk_id`),
/// or [`PskBundle::new_with_id`] to set an explicit identifier.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PskBundle {
    pub psk: PreSharedKey,
    pub psk_id: ExternalPskId,
}

impl PskBundle {
    /// Create a [`PskBundle`] with the given PSK value and an empty identifier.
    pub fn new(psk: PreSharedKey) -> Self {
        Self {
            psk,
            psk_id: ExternalPskId::new(Vec::new()),
        }
    }

    /// Create a [`PskBundle`] with the given PSK value and identifier.
    pub fn new_with_id(psk: PreSharedKey, psk_id: ExternalPskId) -> Self {
        Self { psk, psk_id }
    }
}

/// Storage trait to maintain a set of pre-shared key values.
#[cfg_attr(not(mls_build_async), maybe_async::must_be_sync)]
#[cfg_attr(mls_build_async, maybe_async::must_be_async)]
pub trait PreSharedKeyStorage: Send + Sync {
    /// Error type that the underlying storage mechanism returns on internal
    /// failure.
    type Error: IntoAnyError;

    /// Get a pre-shared key by [`ExternalPskId`](ExternalPskId).
    ///
    /// `None` should be returned if a pre-shared key can not be found for `id`.
    async fn get(&self, id: &ExternalPskId) -> Result<Option<PreSharedKey>, Self::Error>;

    /// Determines if a PSK is located within the store
    async fn contains(&self, id: &ExternalPskId) -> Result<bool, Self::Error> {
        self.get(id).await.map(|key| key.is_some())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn psk_bundle_new_creates_empty_id() {
        let psk_data = vec![1u8; 32];
        let psk = PreSharedKey::new(psk_data.clone());
        let bundle = PskBundle::new(psk);

        assert_eq!(bundle.psk.raw_value(), &psk_data);
        assert!(bundle.psk_id.is_empty());
    }

    #[test]
    fn psk_bundle_new_with_id_sets_both_fields() {
        let psk_data = vec![2u8; 32];
        let psk_id_data = vec![3u8; 16];
        let psk = PreSharedKey::new(psk_data.clone());
        let psk_id = ExternalPskId::new(psk_id_data.clone());
        let bundle = PskBundle::new_with_id(psk, psk_id);

        assert_eq!(bundle.psk.raw_value(), &psk_data);
        assert_eq!(bundle.psk_id.as_ref(), &psk_id_data);
    }
}
