// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// Copyright by contributors to this project.
// SPDX-License-Identifier: (Apache-2.0 OR MIT)

use mls_rs_core::identity::IdentityProvider;

use crate::{
    crypto::SignaturePublicKey, group::mls_rules::MlsRules, protocol_version::ProtocolVersion,
    CryptoProvider,
};

pub trait ExternalClientConfig: Send + Sync + Clone {
    type IdentityProvider: IdentityProvider + Clone;
    type MlsRules: MlsRules + Clone;
    type CryptoProvider: CryptoProvider;

    fn supported_protocol_versions(&self) -> Vec<ProtocolVersion>;
    fn identity_provider(&self) -> Self::IdentityProvider;
    fn crypto_provider(&self) -> Self::CryptoProvider;
    fn external_signing_key(&self, external_key_id: &[u8]) -> Option<SignaturePublicKey>;
    fn mls_rules(&self) -> Self::MlsRules;
    fn cache_proposals(&self) -> bool;

    fn max_epoch_jitter(&self) -> Option<u64> {
        None
    }

    fn version_supported(&self, version: ProtocolVersion) -> bool {
        self.supported_protocol_versions().contains(&version)
    }
}
