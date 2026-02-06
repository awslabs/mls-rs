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
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
///  Capabilities of a MLS client
pub struct Capabilities {
    pub protocol_versions: Vec<ProtocolVersion>,
    pub cipher_suites: Vec<CipherSuite>,
    pub extensions: Vec<ExtensionType>,
    pub proposals: Vec<ProposalType>,
    pub credentials: Vec<CredentialType>,
}

impl Capabilities {
    /// Supported protocol versions
    pub fn protocol_versions(&self) -> &[ProtocolVersion] {
        &self.protocol_versions
    }

    /// Supported ciphersuites
    pub fn cipher_suites(&self) -> &[CipherSuite] {
        &self.cipher_suites
    }

    /// Supported extensions
    pub fn extensions(&self) -> &[ExtensionType] {
        &self.extensions
    }

    /// Supported proposals
    pub fn proposals(&self) -> &[ProposalType] {
        &self.proposals
    }

    /// Supported credentials
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
    pub fn index(&self) -> u32 {
        self.index
    }

    /// Current identity public key and credential of this member.
    pub fn signing_identity(&self) -> &SigningIdentity {
        &self.signing_identity
    }

    /// Current client [Capabilities] of this member.
    pub fn capabilities(&self) -> &Capabilities {
        &self.capabilities
    }

    /// Current leaf node extensions in use by this member.
    pub fn extensions(&self) -> &ExtensionList {
        &self.extensions
    }
}
