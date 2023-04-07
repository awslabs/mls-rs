use alloc::vec;
use alloc::vec::Vec;
use aws_mls_codec::{MlsDecode, MlsEncode, MlsSize};
use serde_with::serde_as;

use crate::{
    cipher_suite::CipherSuite, protocol_version::ProtocolVersion,
    serde_utils::vec_u8_as_base64::VecAsBase64, ExtensionList,
};

use super::ConfirmedTranscriptHash;

#[serde_as]
#[derive(
    Clone, Debug, PartialEq, MlsSize, MlsEncode, MlsDecode, serde::Deserialize, serde::Serialize,
)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct GroupContext {
    pub protocol_version: ProtocolVersion,
    pub cipher_suite: CipherSuite,
    #[mls_codec(with = "aws_mls_codec::byte_vec")]
    #[serde_as(as = "VecAsBase64")]
    pub group_id: Vec<u8>,
    pub epoch: u64,
    #[mls_codec(with = "aws_mls_codec::byte_vec")]
    #[serde_as(as = "VecAsBase64")]
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
