// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// Copyright by contributors to this project.
// SPDX-License-Identifier: (Apache-2.0 OR MIT)

use core::fmt::Debug;

use alloc::vec;
use mls_rs_codec::{MlsDecode, MlsEncode, MlsSize};
use mls_rs_core::error::IntoAnyError;
use mls_rs_core::extension::MlsExtension;
use mls_rs_core::key_package::KeyPackageData;

use crate::client::MlsError;
use crate::client_config::ClientConfig;
use crate::Client;
use crate::{
    crypto::{HpkeSecretKey, SignatureSecretKey},
    group::framing::MlsMessagePayload,
    identity::SigningIdentity,
    protocol_version::ProtocolVersion,
    signer::Signable,
    tree_kem::{
        leaf_node::{ConfigProperties, LeafNode},
        Capabilities, Lifetime,
    },
    CipherSuiteProvider, ExtensionList, MlsMessage,
};

use super::{KeyPackage, KeyPackageRef};

#[derive(Clone, Debug)]
pub struct KeyPackageBuilder<'a, CP> {
    protocol_version: ProtocolVersion,
    cipher_suite_provider: CP,
    signing_identity: Option<SigningIdentity>,
    signing_key: Option<&'a SignatureSecretKey>,
    key_package_extensions: ExtensionList,
    leaf_node_extensions: ExtensionList,
    validity_sec: u64,
    // This I feel like can still be fixed for client as it rarely changes?
    capabilities: Capabilities,
}

impl<'a, CP> KeyPackageBuilder<'a, CP> {
    pub fn signing_data(
        self,
        signing_identity: SigningIdentity,
        signing_key: &'a SignatureSecretKey,
    ) -> Self {
        Self {
            signing_identity: Some(signing_identity),
            signing_key: Some(signing_key),
            ..self
        }
    }

    pub fn with_key_package_extension<T: MlsExtension>(
        mut self,
        extension: T,
    ) -> Result<Self, MlsError> {
        self.key_package_extensions.set_from(extension)?;

        Ok(self)
    }

    pub fn with_leaf_node_extension<T: MlsExtension>(
        mut self,
        extension: T,
    ) -> Result<Self, MlsError> {
        self.leaf_node_extensions.set_from(extension)?;

        Ok(self)
    }

    pub fn valid_for_sec(self, validity_sec: u64) -> Self {
        Self {
            validity_sec,
            ..self
        }
    }
}

impl<CP: CipherSuiteProvider> KeyPackageBuilder<'_, CP> {
    #[cfg_attr(not(mls_build_async), maybe_async::must_be_sync)]
    pub async fn build(self) -> Result<KeyPackageGeneration, MlsError> {
        let (signing_identity, signing_key) = self
            .signing_identity
            .zip(self.signing_key)
            .ok_or(MlsError::SignerNotFound)?;

        let (init_secret_key, public_init) = self
            .cipher_suite_provider
            .kem_generate()
            .await
            .map_err(|e| MlsError::CryptoProviderError(e.into_any_error()))?;

        let properties = ConfigProperties {
            capabilities: self.capabilities,
            extensions: self.leaf_node_extensions,
        };

        let lifetime = Lifetime::seconds(self.validity_sec)?;

        let (leaf_node, leaf_node_secret) = LeafNode::generate(
            &self.cipher_suite_provider,
            properties,
            signing_identity,
            signing_key,
            lifetime,
        )
        .await?;

        let mut package = KeyPackage {
            version: self.protocol_version,
            cipher_suite: self.cipher_suite_provider.cipher_suite(),
            hpke_init_key: public_init,
            leaf_node,
            extensions: self.key_package_extensions,
            signature: vec![],
        };

        package.grease(&self.cipher_suite_provider)?;

        package
            .sign(&self.cipher_suite_provider, signing_key, &())
            .await?;

        let package_bytes = package.mls_encode_to_vec()?;
        let reference = package.to_reference(&self.cipher_suite_provider).await?;

        let key_package_message = MlsMessage::new(
            self.protocol_version,
            MlsMessagePayload::KeyPackage(package),
        );

        Ok(KeyPackageGeneration {
            reference,
            key_package_data: KeyPackageData::new(
                package_bytes,
                init_secret_key,
                leaf_node_secret,
                lifetime.not_after,
            ),
            key_package_message,
        })
    }
}

#[derive(Clone, PartialEq, MlsEncode, MlsDecode, MlsSize, Debug)]
#[non_exhaustive]
pub struct KeyPackageSecrets {
    pub init_secret_key: HpkeSecretKey,
    pub leaf_node_secret: HpkeSecretKey,
}

#[derive(Clone, Debug)]
pub struct KeyPackageGeneration {
    pub reference: KeyPackageRef,
    pub key_package_message: MlsMessage,
    pub key_package_data: KeyPackageData,
}

impl<'a, CP> KeyPackageBuilder<'a, CP> {
    pub(crate) fn new<C: ClientConfig>(client: &'a Client<C>, cipher_suite_provider: CP) -> Self {
        Self {
            protocol_version: client.version,
            cipher_suite_provider,
            signing_identity: client.signing_identity.clone().map(|(id, _)| id),
            signing_key: client.signer.as_ref(),
            key_package_extensions: Default::default(),
            leaf_node_extensions: Default::default(),
            validity_sec: 86400 * 366,
            capabilities: client.config.capabilities(),
        }
    }
}

#[cfg(test)]
mod tests {
    #[cfg(feature = "std")]
    use std::collections::HashSet;

    #[cfg(not(feature = "std"))]
    use alloc::collections::BTreeSet as HashSet;

    use mls_rs_core::crypto::CipherSuiteProvider;

    use crate::{
        client::test_utils::{TestClientBuilder, TEST_CIPHER_SUITE, TEST_PROTOCOL_VERSION},
        crypto::test_utils::{test_cipher_suite_provider, TestCryptoProvider},
        extension::test_utils::TestExtension,
        group::test_utils::random_bytes,
        identity::basic::BasicIdentityProvider,
        key_package::validate_key_package_properties,
        protocol_version::ProtocolVersion,
        tree_kem::leaf_node_validator::{LeafNodeValidator, ValidationContext},
    };

    #[maybe_async::test(not(mls_build_async), async(mls_build_async, crate::futures_test))]
    async fn test_key_generation() {
        for (protocol_version, cipher_suite) in ProtocolVersion::all().flat_map(|p| {
            TestCryptoProvider::all_supported_cipher_suites()
                .into_iter()
                .map(move |cs| (p, cs))
        }) {
            let cipher_suite_provider = test_cipher_suite_provider(cipher_suite);

            let client = TestClientBuilder::new_for_test()
                .with_random_signing_identity("something", cipher_suite)
                .await
                .protocol_version(protocol_version)
                .extension_types([42.into()])
                .build();

            let generated = client
                .key_package_builder(cipher_suite)
                .unwrap()
                .with_key_package_extension(TestExtension::from(32))
                .unwrap()
                .with_leaf_node_extension(TestExtension::from(42))
                .unwrap()
                .build()
                .await
                .unwrap();

            let generated_kp = generated.key_package_message.into_key_package().unwrap();

            assert_eq!(
                TestExtension::from(32),
                generated_kp.extensions.get_as().unwrap().unwrap()
            );

            assert_eq!(
                TestExtension::from(32),
                generated_kp.extensions.get_as().unwrap().unwrap()
            );

            assert_eq!(
                TestExtension::from(42),
                generated_kp.leaf_node.extensions.get_as().unwrap().unwrap()
            );

            assert_ne!(
                generated_kp.hpke_init_key,
                generated_kp.leaf_node.public_key
            );

            assert_eq!(generated_kp.cipher_suite, cipher_suite);
            assert_eq!(generated_kp.version, protocol_version);

            // Verify that the hpke key pair generated will work
            let test_data = random_bytes(32);

            let sealed = cipher_suite_provider
                .hpke_seal(&generated_kp.hpke_init_key, &[], None, &test_data)
                .await
                .unwrap();

            let opened = cipher_suite_provider
                .hpke_open(
                    &sealed,
                    &generated.key_package_data.init_key,
                    &generated_kp.hpke_init_key,
                    &[],
                    None,
                )
                .await
                .unwrap();

            assert_eq!(opened, test_data);

            let validator =
                LeafNodeValidator::new_for_test(&cipher_suite_provider, &BasicIdentityProvider);

            validator
                .check_if_valid(&generated_kp.leaf_node, ValidationContext::Add(None))
                .await
                .unwrap();

            validate_key_package_properties(
                &generated_kp,
                protocol_version,
                &cipher_suite_provider,
            )
            .await
            .unwrap();
        }
    }

    #[maybe_async::test(not(mls_build_async), async(mls_build_async, crate::futures_test))]
    async fn test_randomness() {
        let client = TestClientBuilder::new_for_test()
            .with_random_signing_identity("something", TEST_CIPHER_SUITE)
            .await
            .protocol_version(TEST_PROTOCOL_VERSION)
            .extension_types([42.into()])
            .build();

        let builder = client.key_package_builder(TEST_CIPHER_SUITE).unwrap();
        let mut generated_keys = HashSet::new();

        for _ in 0..100 {
            let pkg = builder.clone().build().await.unwrap();
            let pkg = pkg.key_package_message.into_key_package().unwrap();
            assert!(generated_keys.insert(pkg.hpke_init_key));
            assert!(generated_keys.insert(pkg.leaf_node.public_key));
        }
    }
}
