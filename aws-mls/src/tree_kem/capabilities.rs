use aws_mls_core::crypto::CipherSuite;
use tls_codec_derive::{TlsDeserialize, TlsSerialize, TlsSize};

use crate::{
    extension::ExtensionType, group::proposal::ProposalType, identity::CredentialType,
    protocol_version::ProtocolVersion,
};

#[derive(
    Clone,
    PartialEq,
    Eq,
    Debug,
    TlsDeserialize,
    TlsSerialize,
    TlsSize,
    serde::Deserialize,
    serde::Serialize,
)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct Capabilities {
    #[tls_codec(with = "crate::tls::DefVec")]
    pub protocol_versions: Vec<ProtocolVersion>,
    #[tls_codec(with = "crate::tls::DefVec")]
    pub cipher_suites: Vec<CipherSuite>,
    #[tls_codec(with = "crate::tls::DefVec")]
    pub extensions: Vec<ExtensionType>,
    #[tls_codec(with = "crate::tls::DefVec")]
    pub proposals: Vec<ProposalType>,
    #[tls_codec(with = "crate::tls::DefVec")]
    pub credentials: Vec<CredentialType>,
}

#[cfg(any(feature = "benchmark", test))]
impl Default for Capabilities {
    fn default() -> Self {
        use crate::identity::BasicCredential;
        use crate::protocol_version::MLS_10;

        Self {
            protocol_versions: vec![MLS_10],
            cipher_suites: CipherSuite::all().collect(),
            extensions: Default::default(),
            proposals: Default::default(),
            credentials: vec![BasicCredential::credential_type()],
        }
    }
}
