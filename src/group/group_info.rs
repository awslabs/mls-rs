use super::*;

#[derive(Clone, Debug, PartialEq, TlsDeserialize, TlsSerialize, TlsSize)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct GroupInfo {
    pub group_context: GroupContextWire,
    pub extensions: ExtensionList,
    pub confirmation_tag: ConfirmationTag,
    pub signer: LeafIndex,
    #[tls_codec(with = "crate::tls::ByteVec")]
    pub signature: Vec<u8>,
}

#[derive(TlsSerialize, TlsSize)]
struct SignableGroupInfo<'a> {
    #[tls_codec(with = "crate::tls::DefRef")]
    group_context: &'a GroupContextWire,
    #[tls_codec(with = "crate::tls::DefRef")]
    extensions: &'a ExtensionList,
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
            group_context: &self.group_context,
            extensions: &self.extensions,
            confirmation_tag: &self.confirmation_tag,
            signer: self.signer,
        }
        .tls_serialize_detached()
    }

    fn write_signature(&mut self, signature: Vec<u8>) {
        self.signature = signature
    }
}
