use serde_with::serde_as;
use tls_codec_derive::{TlsDeserialize, TlsSerialize, TlsSize};

use crate::{
    cipher_suite::CipherSuite, extension::ExtensionList, protocol_version::ProtocolVersion,
    serde_utils::vec_u8_as_base64::VecAsBase64,
};

use super::ConfirmedTranscriptHash;

#[serde_as]
#[derive(
    Clone,
    Debug,
    PartialEq,
    TlsDeserialize,
    TlsSerialize,
    TlsSize,
    serde::Deserialize,
    serde::Serialize,
)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct GroupContext {
    pub protocol_version: ProtocolVersion,
    pub cipher_suite: CipherSuite,
    #[tls_codec(with = "crate::tls::ByteVec")]
    #[serde_as(as = "VecAsBase64")]
    pub group_id: Vec<u8>,
    pub epoch: u64,
    #[tls_codec(with = "crate::tls::ByteVec")]
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
