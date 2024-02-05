// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// Copyright by contributors to this project.
// SPDX-License-Identifier: (Apache-2.0 OR MIT)

use alloc::vec;
use alloc::vec::Vec;
use mls_rs_codec::{MlsDecode, MlsEncode, MlsSize};

use crate::{cipher_suite::CipherSuite, protocol_version::ProtocolVersion, ExtensionList};

use super::ConfirmedTranscriptHash;

#[derive(Clone, Debug, PartialEq, MlsSize, MlsEncode, MlsDecode)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[cfg_attr(
    all(feature = "ffi", not(test)),
    safer_ffi_gen::ffi_type(clone, opaque)
)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct GroupContext {
    pub(crate) protocol_version: ProtocolVersion,
    pub(crate) cipher_suite: CipherSuite,
    #[mls_codec(with = "mls_rs_codec::byte_vec")]
    pub(crate) group_id: Vec<u8>,
    pub(crate) epoch: u64,
    #[mls_codec(with = "mls_rs_codec::byte_vec")]
    pub(crate) tree_hash: Vec<u8>,
    pub(crate) confirmed_transcript_hash: ConfirmedTranscriptHash,
    pub(crate) extensions: ExtensionList,
}

#[cfg_attr(all(feature = "ffi", not(test)), ::safer_ffi_gen::safer_ffi_gen)]
impl GroupContext {
    pub(crate) fn new_group(
        protocol_version: ProtocolVersion,
        cipher_suite: CipherSuite,
        group_id: Vec<u8>,
        tree_hash: Vec<u8>,
        extensions: ExtensionList,
    ) -> Self {
        GroupContext {
            protocol_version,
            cipher_suite,
            group_id,
            epoch: 0,
            tree_hash,
            confirmed_transcript_hash: ConfirmedTranscriptHash::from(vec![]),
            extensions,
        }
    }

    /// Get the current protocol version in use by the group.
    pub fn version(&self) -> ProtocolVersion {
        self.protocol_version
    }

    /// Get the current cipher suite in use by the group.
    pub fn cipher_suite(&self) -> CipherSuite {
        self.cipher_suite
    }

    /// Get the unique identifier of this group.
    pub fn group_id(&self) -> &[u8] {
        &self.group_id
    }

    /// Get the current epoch number of the group's state.
    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    pub fn extensions(&self) -> &ExtensionList {
        &self.extensions
    }
}
