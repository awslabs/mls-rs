use super::*;

impl From<&GroupInfo> for GroupContext {
    fn from(group_info: &GroupInfo) -> Self {
        GroupContext {
            group_id: group_info.group_id.clone(),
            epoch: group_info.epoch,
            tree_hash: group_info.tree_hash.clone(),
            confirmed_transcript_hash: group_info.confirmed_transcript_hash.clone(),
            extensions: group_info.group_context_extensions.clone(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, TlsDeserialize, TlsSerialize, TlsSize)]
pub struct GroupInfo {
    pub cipher_suite: CipherSuite,
    #[tls_codec(with = "crate::tls::ByteVec")]
    pub group_id: Vec<u8>,
    pub epoch: u64,
    #[tls_codec(with = "crate::tls::ByteVec")]
    pub tree_hash: Vec<u8>,
    pub confirmed_transcript_hash: ConfirmedTranscriptHash,
    pub group_context_extensions: ExtensionList,
    pub other_extensions: ExtensionList,
    pub confirmation_tag: ConfirmationTag,
    pub signer: LeafIndex,
    #[tls_codec(with = "crate::tls::ByteVec")]
    pub signature: Vec<u8>,
}

#[derive(TlsSerialize, TlsSize)]
struct SignableGroupInfo<'a> {
    cipher_suite: CipherSuite,
    #[tls_codec(with = "crate::tls::ByteVec")]
    group_id: &'a Vec<u8>,
    epoch: u64,
    #[tls_codec(with = "crate::tls::ByteVec")]
    tree_hash: &'a Vec<u8>,
    #[tls_codec(with = "crate::tls::ByteVec")]
    confirmed_transcript_hash: &'a Vec<u8>,
    #[tls_codec(with = "crate::tls::DefRef")]
    group_context_extensions: &'a ExtensionList,
    #[tls_codec(with = "crate::tls::DefRef")]
    other_extensions: &'a ExtensionList,
    #[tls_codec(with = "crate::tls::ByteVec")]
    confirmation_tag: &'a Tag,
    signer: LeafIndex,
}

impl<'a> Signable<'a> for GroupInfo {
    const SIGN_LABEL: &'static str = "GroupInfoTBS";
    type SigningContext = ();

    fn signature(&self) -> &[u8] {
        &self.signature
    }

    fn signable_content(
        &self,
        _context: &Self::SigningContext,
    ) -> Result<Vec<u8>, tls_codec::Error> {
        SignableGroupInfo {
            cipher_suite: self.cipher_suite,
            group_id: &self.group_id,
            epoch: self.epoch,
            tree_hash: &self.tree_hash,
            confirmed_transcript_hash: &self.confirmed_transcript_hash,
            group_context_extensions: &self.group_context_extensions,
            other_extensions: &self.other_extensions,
            confirmation_tag: &self.confirmation_tag,
            signer: self.signer,
        }
        .tls_serialize_detached()
    }

    fn write_signature(&mut self, signature: Vec<u8>) {
        self.signature = signature
    }
}
