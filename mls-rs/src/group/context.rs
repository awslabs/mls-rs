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
pub struct GroupContext {
    pub protocol_version: ProtocolVersion,
    pub cipher_suite: CipherSuite,
    #[mls_codec(with = "mls_rs_codec::byte_vec")]
    pub group_id: Vec<u8>,
    pub epoch: u64,
    #[mls_codec(with = "mls_rs_codec::byte_vec")]
    pub tree_hash: Vec<u8>,
    pub confirmed_transcript_hash: ConfirmedTranscriptHash,
    pub extensions: ExtensionList,
}

impl GroupContext {
    pub fn new_group(
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
}
