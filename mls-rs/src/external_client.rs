// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// Copyright by contributors to this project.
// SPDX-License-Identifier: (Apache-2.0 OR MIT)

use crate::{
    client::MlsError,
    group::{
        cipher_suite_provider, framing::MlsMessage, message_processor::validate_key_package,
        ExportedTree,
    },
    time::MlsTime,
    KeyPackage,
};

pub mod builder;
mod config;
mod group;

pub(crate) use config::ExternalClientConfig;
use mls_rs_core::{
    crypto::{CryptoProvider, SignatureSecretKey},
    identity::SigningIdentity,
};

use builder::{ExternalBaseConfig, ExternalClientBuilder};

pub use group::{ExternalGroup, ExternalReceivedMessage, ExternalSnapshot};

/// A client capable of observing a group's state without having
/// private keys required to read content.
///
/// This structure is useful when an application is sending
/// plaintext control messages in order to allow a central server
/// to facilitate communication between users.
///
/// # Warning
///
/// This structure will only be able to observe groups that were
/// created by clients that have the `encrypt_control_messages`
/// option returned by [`MlsRules::encryption_options`](`crate::MlsRules::encryption_options`)
/// set to `false`. Any control messages that are sent encrypted
/// over the wire will break the ability of this client to track
/// the resulting group state.
pub struct ExternalClient<C> {
    config: C,
    signing_data: Option<(SignatureSecretKey, SigningIdentity)>,
}

impl ExternalClient<()> {
    pub fn builder() -> ExternalClientBuilder<ExternalBaseConfig> {
        ExternalClientBuilder::new()
    }
}

impl<C> ExternalClient<C>
where
    C: ExternalClientConfig + Clone,
{
    pub(crate) fn new(
        config: C,
        signing_data: Option<(SignatureSecretKey, SigningIdentity)>,
    ) -> Self {
        Self {
            config,
            signing_data,
        }
    }

    /// Begin observing a group based on a GroupInfo message created by
    /// [Group::group_info_message](crate::group::Group::group_info_message)
    ///
    ///`tree_data` is required to be provided out of band if the client that
    /// created GroupInfo message did not did not use the `ratchet_tree_extension`
    /// according to [`MlsRules::commit_options`](crate::MlsRules::commit_options)
    /// at the time the welcome message
    /// was created. `tree_data` can be exported from a group using the
    /// [export tree function](crate::group::Group::export_tree).
    #[cfg_attr(not(mls_build_async), maybe_async::must_be_sync)]
    pub async fn observe_group(
        &self,
        group_info: MlsMessage,
        tree_data: Option<ExportedTree<'_>>,
        maybe_time: Option<MlsTime>,
    ) -> Result<ExternalGroup<C>, MlsError> {
        ExternalGroup::join(
            self.config.clone(),
            self.signing_data.clone(),
            group_info,
            tree_data,
            maybe_time,
        )
        .await
    }

    /// Load an existing observed group by loading a snapshot that was
    /// generated by
    /// [ExternalGroup::snapshot](self::ExternalGroup::snapshot).
    #[cfg_attr(not(mls_build_async), maybe_async::must_be_sync)]
    pub async fn load_group(
        &self,
        snapshot: ExternalSnapshot,
    ) -> Result<ExternalGroup<C>, MlsError> {
        #[cfg(feature = "tree_index")]
        let identity_provider = self.config.identity_provider();

        let cipher_suite_provider = cipher_suite_provider(
            self.config.crypto_provider(),
            snapshot.state.context.cipher_suite,
        )?;

        Ok(ExternalGroup {
            config: self.config.clone(),
            signing_data: self.signing_data.clone(),
            state: snapshot
                .state
                .import(
                    #[cfg(feature = "tree_index")]
                    &identity_provider,
                )
                .await?,
            cipher_suite_provider,
        })
    }

    /// Load an existing observed group by loading a snapshot that was
    /// generated by
    /// [ExternalGroup::snapshot](self::ExternalGroup::snapshot). The tree
    /// is taken from `tree_data` instead of the stored state.
    #[cfg_attr(not(mls_build_async), maybe_async::must_be_sync)]
    pub async fn load_group_with_ratchet_tree(
        &self,
        mut snapshot: ExternalSnapshot,
        tree_data: ExportedTree<'_>,
    ) -> Result<ExternalGroup<C>, MlsError> {
        snapshot.state.public_tree.nodes = tree_data.0.into_owned();

        self.load_group(snapshot).await
    }

    #[cfg_attr(not(mls_build_async), maybe_async::must_be_sync)]
    pub async fn validate_key_package(
        &self,
        key_package: MlsMessage,
        timestamp: Option<MlsTime>,
    ) -> Result<KeyPackage, MlsError> {
        let version = key_package.version;

        let key_package = key_package
            .into_key_package()
            .ok_or(MlsError::UnexpectedMessageType)?;

        let cs = self
            .config
            .crypto_provider()
            .cipher_suite_provider(key_package.cipher_suite)
            .ok_or(MlsError::UnsupportedCipherSuite(key_package.cipher_suite))?;

        let id = self.config.identity_provider();

        validate_key_package(&key_package, version, &cs, &id, timestamp).await?;

        Ok(key_package)
    }

    /// The [IdentityProvider](crate::IdentityProvider) that this client was configured to use.
    pub fn identity_provider(&self) -> <C as ExternalClientConfig>::IdentityProvider {
        self.config.identity_provider()
    }
}

#[cfg(test)]
pub(crate) mod tests_utils {
    use crate::{
        client::test_utils::{TEST_CIPHER_SUITE, TEST_PROTOCOL_VERSION},
        key_package::test_utils::test_key_package_message,
    };

    pub use super::builder::test_utils::*;

    #[maybe_async::test(not(mls_build_async), async(mls_build_async, crate::futures_test))]
    async fn external_client_can_validate_key_package() {
        let kp = test_key_package_message(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE, "john").await;
        let server = TestExternalClientBuilder::new_for_test().build();
        let validated_kp = server.validate_key_package(kp.clone(), None).await.unwrap();

        assert_eq!(kp.into_key_package().unwrap(), validated_kp);
    }
}
