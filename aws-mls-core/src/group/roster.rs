use tls_codec_derive::{TlsDeserialize, TlsSerialize, TlsSize};

use crate::{
    crypto::CipherSuite,
    extension::{ExtensionList, ExtensionType},
    identity::{CredentialType, SigningIdentity},
    protocol_version::ProtocolVersion,
};

use super::ProposalType;

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

impl Default for Capabilities {
    fn default() -> Self {
        use crate::identity::BasicCredential;

        Self {
            protocol_versions: vec![ProtocolVersion::MLS_10],
            cipher_suites: CipherSuite::all().collect(),
            extensions: Default::default(),
            proposals: Default::default(),
            credentials: vec![BasicCredential::credential_type()],
        }
    }
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct Member {
    index: u32,
    signing_identity: SigningIdentity,
    capabilities: Capabilities,
    extensions: ExtensionList,
    #[cfg(feature = "benchmark")]
    leaf_bytes: Vec<u8>,
}

impl Member {
    #[cfg(not(feature = "benchmark"))]
    pub fn new(
        index: u32,
        signing_identity: SigningIdentity,
        capabilities: Capabilities,
        extensions: ExtensionList,
    ) -> Self {
        Self {
            index,
            signing_identity,
            capabilities,
            extensions,
        }
    }

    #[cfg(feature = "benchmark")]
    pub fn new(
        index: u32,
        signing_identity: SigningIdentity,
        capabilities: Capabilities,
        extensions: ExtensionList,
        leaf_bytes: Vec<u8>,
    ) -> Self {
        Self {
            index,
            signing_identity,
            capabilities,
            extensions,
            leaf_bytes,
        }
    }

    pub fn index(&self) -> u32 {
        self.index
    }

    pub fn signing_identity(&self) -> &SigningIdentity {
        &self.signing_identity
    }

    pub fn capabilities(&self) -> &Capabilities {
        &self.capabilities
    }

    pub fn extensions(&self) -> &ExtensionList {
        &self.extensions
    }

    #[cfg(feature = "benchmark")]
    pub fn leaf_bytes(&self) -> &[u8] {
        &self.leaf_bytes
    }
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct RosterUpdate {
    pub added: Vec<Member>,
    pub removed: Vec<Member>,
    pub updated: Vec<Member>,
}
