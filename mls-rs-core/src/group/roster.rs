// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// Copyright by contributors to this project.
// SPDX-License-Identifier: (Apache-2.0 OR MIT)

use alloc::vec;
use alloc::vec::Vec;
use mls_rs_codec::{MlsDecode, MlsEncode, MlsSize};

use crate::{
    crypto::CipherSuite,
    extension::{ExtensionList, ExtensionType},
    identity::{CredentialType, SigningIdentity},
    protocol_version::ProtocolVersion,
};

use super::ProposalType;

#[derive(Clone, PartialEq, Eq, Debug, MlsSize, MlsEncode, MlsDecode)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[cfg_attr(
    all(feature = "ffi", not(test)),
    safer_ffi_gen::ffi_type(clone, opaque)
)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
///  Capabilities of a MLS client
pub struct Capabilities {
    pub protocol_versions: Vec<ProtocolVersion>,
    pub cipher_suites: Vec<CipherSuite>,
    pub extensions: Vec<ExtensionType>,
    pub proposals: Vec<ProposalType>,
    pub credentials: Vec<CredentialType>,
}

#[cfg_attr(all(feature = "ffi", not(test)), safer_ffi_gen::safer_ffi_gen)]
impl Capabilities {
    /// Supported protocol versions
    #[cfg(feature = "ffi")]
    pub fn protocol_versions(&self) -> &[ProtocolVersion] {
        &self.protocol_versions
    }

    /// Supported ciphersuites
    #[cfg(feature = "ffi")]
    pub fn cipher_suites(&self) -> &[CipherSuite] {
        &self.cipher_suites
    }

    /// Supported extensions
    #[cfg(feature = "ffi")]
    pub fn extensions(&self) -> &[ExtensionType] {
        &self.extensions
    }

    /// Supported proposals
    #[cfg(feature = "ffi")]
    pub fn proposals(&self) -> &[ProposalType] {
        &self.proposals
    }

    /// Supported credentials
    #[cfg(feature = "ffi")]
    pub fn credentials(&self) -> &[CredentialType] {
        &self.credentials
    }

    /// Canonical form
    pub fn sorted(mut self) -> Self {
        self.protocol_versions.sort();
        self.cipher_suites.sort();
        self.extensions.sort();
        self.proposals.sort();
        self.credentials.sort();

        self
    }
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

/// A member of a MLS group.
#[cfg_attr(
    all(feature = "ffi", not(test)),
    safer_ffi_gen::ffi_type(clone, opaque)
)]
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Member {
    /// The index of this member within a group.
    ///
    /// This value is consistent for all clients and will not change as the
    /// group evolves.
    pub index: u32,
    /// Current identity public key and credential of this member.
    pub signing_identity: SigningIdentity,
    /// Current client [Capabilities] of this member.
    pub capabilities: Capabilities,
    /// Current leaf node extensions in use by this member.
    pub extensions: ExtensionList,
}

#[cfg_attr(all(feature = "ffi", not(test)), safer_ffi_gen::safer_ffi_gen)]
impl Member {
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

    /// The index of this member within a group.
    ///
    /// This value is consistent for all clients and will not change as the
    /// group evolves.
    #[cfg(feature = "ffi")]
    pub fn index(&self) -> u32 {
        self.index
    }

    /// Current identity public key and credential of this member.
    #[cfg(feature = "ffi")]
    pub fn signing_identity(&self) -> &SigningIdentity {
        &self.signing_identity
    }

    /// Current client [Capabilities] of this member.
    #[cfg(feature = "ffi")]
    pub fn capabilities(&self) -> &Capabilities {
        &self.capabilities
    }

    /// Current leaf node extensions in use by this member.
    #[cfg(feature = "ffi")]
    pub fn extensions(&self) -> &ExtensionList {
        &self.extensions
    }
}
