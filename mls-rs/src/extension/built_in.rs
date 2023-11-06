// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// Copyright by contributors to this project.
// SPDX-License-Identifier: (Apache-2.0 OR MIT)

#[cfg(any(feature = "by_ref_proposal", feature = "all_extensions"))]
use alloc::vec::Vec;
use mls_rs_codec::{MlsDecode, MlsEncode, MlsSize};
use mls_rs_core::extension::{ExtensionType, MlsCodecExtension};

#[cfg(feature = "all_extensions")]
use mls_rs_core::{group::ProposalType, identity::CredentialType};

#[cfg(feature = "by_ref_proposal")]
use mls_rs_core::{
    extension::ExtensionList,
    identity::{IdentityProvider, SigningIdentity},
    time::MlsTime,
};

use crate::tree_kem::node::NodeVec;

#[cfg(feature = "external_commit")]
use mls_rs_core::crypto::HpkePublicKey;

/// Application specific identifier.
///
/// A custom application level identifier that can be optionally stored
/// within the `leaf_node_extensions` of a group [Member](crate::group::Member).
#[cfg(feature = "all_extensions")]
#[cfg_attr(
    all(feature = "ffi", not(test)),
    safer_ffi_gen::ffi_type(clone, opaque)
)]
#[derive(Clone, Debug, PartialEq, Eq, MlsSize, MlsEncode, MlsDecode)]
pub struct ApplicationIdExt {
    #[mls_codec(with = "mls_rs_codec::byte_vec")]
    pub(crate) identifier: Vec<u8>,
}

#[cfg(feature = "all_extensions")]
#[cfg_attr(all(feature = "ffi", not(test)), safer_ffi_gen::safer_ffi_gen)]
impl ApplicationIdExt {
    /// Create a new application level identifier extension.
    pub fn new(identifier: Vec<u8>) -> Self {
        ApplicationIdExt { identifier }
    }

    /// Get the application level identifier presented by this extension.
    pub fn identifier(&self) -> &[u8] {
        &self.identifier
    }
}

#[cfg(feature = "all_extensions")]
impl MlsCodecExtension for ApplicationIdExt {
    fn extension_type() -> ExtensionType {
        ExtensionType::APPLICATION_ID
    }
}

/// Representation of an MLS ratchet tree.
///
/// Used to provide new members
/// a copy of the current group state in-band.
#[cfg_attr(
    all(feature = "ffi", not(test)),
    safer_ffi_gen::ffi_type(clone, opaque)
)]
#[derive(Clone, Debug, PartialEq, MlsSize, MlsEncode, MlsDecode)]
pub struct RatchetTreeExt {
    pub(crate) tree_data: NodeVec,
}

impl MlsCodecExtension for RatchetTreeExt {
    fn extension_type() -> ExtensionType {
        ExtensionType::RATCHET_TREE
    }
}

/// Require members to have certain capabilities.
///
/// Used within a
/// [Group Context Extensions Proposal](crate::group::proposal::Proposal)
/// in order to require that all current and future members of a group MUST
/// support specific extensions, proposals, or credentials.
///
/// # Warning
///
/// Extension, proposal, and credential types defined by the MLS RFC and
/// provided are considered required by default and should NOT be used
/// within this extension.
#[cfg(feature = "all_extensions")]
#[cfg_attr(
    all(feature = "ffi", not(test)),
    safer_ffi_gen::ffi_type(clone, opaque)
)]
#[derive(Clone, Debug, PartialEq, Eq, MlsSize, MlsEncode, MlsDecode, Default)]
pub struct RequiredCapabilitiesExt {
    pub extensions: Vec<ExtensionType>,
    pub proposals: Vec<ProposalType>,
    pub credentials: Vec<CredentialType>,
}

#[cfg(feature = "all_extensions")]
#[cfg_attr(all(feature = "ffi", not(test)), safer_ffi_gen::safer_ffi_gen)]
impl RequiredCapabilitiesExt {
    /// Create a required capabilities extension.
    pub fn new(
        extensions: Vec<ExtensionType>,
        proposals: Vec<ProposalType>,
        credentials: Vec<CredentialType>,
    ) -> Self {
        Self {
            extensions,
            proposals,
            credentials,
        }
    }

    /// Required custom extension types.
    pub fn extensions(&self) -> &[ExtensionType] {
        &self.extensions
    }

    /// Required custom proposal types.
    pub fn proposals(&self) -> &[ProposalType] {
        &self.proposals
    }

    /// Required custom credential types.
    pub fn credentials(&self) -> &[CredentialType] {
        &self.credentials
    }
}

#[cfg(feature = "all_extensions")]
impl MlsCodecExtension for RequiredCapabilitiesExt {
    fn extension_type() -> ExtensionType {
        ExtensionType::REQUIRED_CAPABILITIES
    }
}

/// External public key used for [External Commits](crate::Client::commit_external).
///
/// This proposal type is optionally provided as part of a
/// [Group Info](crate::group::Group::group_info_message).
#[cfg(feature = "external_commit")]
#[cfg_attr(
    all(feature = "ffi", not(test)),
    safer_ffi_gen::ffi_type(clone, opaque)
)]
#[derive(Clone, Debug, PartialEq, Eq, MlsSize, MlsEncode, MlsDecode)]
pub struct ExternalPubExt {
    #[mls_codec(with = "mls_rs_codec::byte_vec")]
    pub(crate) external_pub: HpkePublicKey,
}

#[cfg(feature = "external_commit")]
#[cfg_attr(all(feature = "ffi", not(test)), safer_ffi_gen::safer_ffi_gen)]
impl ExternalPubExt {
    /// Get the public key to be used for an external commit.
    pub fn external_pub(&self) -> &HpkePublicKey {
        &self.external_pub
    }
}

#[cfg(feature = "external_commit")]
impl MlsCodecExtension for ExternalPubExt {
    fn extension_type() -> ExtensionType {
        ExtensionType::EXTERNAL_PUB
    }
}

/// Enable proposals by an [ExternalClient](crate::external_client::ExternalClient).
#[cfg(feature = "by_ref_proposal")]
#[cfg_attr(
    all(feature = "ffi", not(test)),
    safer_ffi_gen::ffi_type(clone, opaque)
)]
#[derive(Clone, Debug, PartialEq, Eq, MlsSize, MlsEncode, MlsDecode)]
#[non_exhaustive]
pub struct ExternalSendersExt {
    pub(crate) allowed_senders: Vec<SigningIdentity>,
}

#[cfg(feature = "by_ref_proposal")]
#[cfg_attr(all(feature = "ffi", not(test)), safer_ffi_gen::safer_ffi_gen)]
impl ExternalSendersExt {
    pub fn new(allowed_senders: Vec<SigningIdentity>) -> Self {
        Self { allowed_senders }
    }

    pub fn allowed_senders(&self) -> &[SigningIdentity] {
        &self.allowed_senders
    }

    #[cfg_attr(not(mls_build_async), maybe_async::must_be_sync)]
    pub(crate) async fn verify_all<I: IdentityProvider>(
        &self,
        provider: &I,
        timestamp: Option<MlsTime>,
        group_context_extensions: &ExtensionList,
    ) -> Result<(), I::Error> {
        for id in self.allowed_senders.iter() {
            provider
                .validate_external_sender(id, timestamp, Some(group_context_extensions))
                .await?;
        }

        Ok(())
    }
}

#[cfg(feature = "by_ref_proposal")]
impl MlsCodecExtension for ExternalSendersExt {
    fn extension_type() -> ExtensionType {
        ExtensionType::EXTERNAL_SENDERS
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "by_ref_proposal")]
    use crate::{
        client::test_utils::TEST_CIPHER_SUITE, identity::test_utils::get_test_signing_identity,
    };

    use mls_rs_core::extension::MlsExtension;

    #[cfg(feature = "all_extensions")]
    use mls_rs_core::identity::BasicCredential;

    use alloc::vec;

    #[cfg(target_arch = "wasm32")]
    use wasm_bindgen_test::wasm_bindgen_test as test;

    #[cfg(feature = "all_extensions")]
    #[test]
    fn test_application_id_extension() {
        let test_id = vec![0u8; 32];
        let test_extension = ApplicationIdExt {
            identifier: test_id.clone(),
        };

        let as_extension = test_extension.into_extension().unwrap();

        assert_eq!(as_extension.extension_type(), ExtensionType::APPLICATION_ID);

        let restored = ApplicationIdExt::from_extension(&as_extension).unwrap();
        assert_eq!(restored.identifier, test_id);
    }

    #[test]
    fn test_ratchet_tree() {
        let ext = RatchetTreeExt {
            tree_data: NodeVec::from(vec![None, None]),
        };

        let as_extension = ext.clone().into_extension().unwrap();
        assert_eq!(as_extension.extension_type(), ExtensionType::RATCHET_TREE);

        let restored = RatchetTreeExt::from_extension(&as_extension).unwrap();
        assert_eq!(ext, restored)
    }

    #[cfg(feature = "all_extensions")]
    #[test]
    fn test_required_capabilities() {
        let ext = RequiredCapabilitiesExt {
            extensions: vec![0.into(), 1.into()],
            proposals: vec![42.into(), 43.into()],
            credentials: vec![BasicCredential::credential_type()],
        };

        let as_extension = ext.clone().into_extension().unwrap();

        assert_eq!(
            as_extension.extension_type(),
            ExtensionType::REQUIRED_CAPABILITIES
        );

        let restored = RequiredCapabilitiesExt::from_extension(&as_extension).unwrap();
        assert_eq!(ext, restored)
    }

    #[cfg(feature = "by_ref_proposal")]
    #[maybe_async::test(not(mls_build_async), async(mls_build_async, crate::futures_test))]
    async fn test_external_senders() {
        let identity = get_test_signing_identity(TEST_CIPHER_SUITE, &[1]).await.0;
        let ext = ExternalSendersExt::new(vec![identity]);

        let as_extension = ext.clone().into_extension().unwrap();

        assert_eq!(
            as_extension.extension_type(),
            ExtensionType::EXTERNAL_SENDERS
        );

        let restored = ExternalSendersExt::from_extension(&as_extension).unwrap();
        assert_eq!(ext, restored)
    }

    #[cfg(feature = "external_commit")]
    #[test]
    fn test_external_pub() {
        let ext = ExternalPubExt {
            external_pub: vec![0, 1, 2, 3].into(),
        };

        let as_extension = ext.clone().into_extension().unwrap();
        assert_eq!(as_extension.extension_type(), ExtensionType::EXTERNAL_PUB);

        let restored = ExternalPubExt::from_extension(&as_extension).unwrap();
        assert_eq!(ext, restored)
    }
}
