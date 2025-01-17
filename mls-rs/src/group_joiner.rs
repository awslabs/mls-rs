// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// Copyright by contributors to this project.
// SPDX-License-Identifier: (Apache-2.0 OR MIT)

use mls_rs_codec::MlsDecode;
use mls_rs_core::{
    crypto::{CipherSuite, HpkeSecretKey, SignatureSecretKey},
    key_package::KeyPackageData,
    protocol_version::ProtocolVersion,
};

use crate::{
    client_config::ClientConfig,
    error::MlsError,
    group::{
        cipher_suite_provider,
        key_schedule::{KeySchedule, WelcomeSecret},
        validate_tree_and_info_joiner, ExportedTree, GroupInfo, GroupSecrets, NewMemberInfo,
        Welcome,
    },
    psk::secret::PskSecret,
    tree_kem::{TreeKemPrivate, TreeKemPublic},
    Group, KeyPackage, MlsMessage,
};

#[cfg(feature = "psk")]
use alloc::vec::Vec;

#[cfg(feature = "psk")]
use crate::psk::{
    secret::PskSecretInput, ExternalPskId, JustPreSharedKeyID, PreSharedKey, ResumptionPSKUsage,
    ResumptionPsk,
};

pub struct GroupJoiner<'a, 'b, C> {
    // Parsed data
    group_secrets: GroupSecrets,
    welcome: &'a Welcome,
    version: ProtocolVersion,
    key_package: KeyPackage,
    leaf_secret: HpkeSecretKey,
    config: C,

    // Inputted by application
    tree: Option<ExportedTree<'b>>,
    signer: Option<SignatureSecretKey>,
    #[cfg(feature = "psk")]
    psks: Vec<(JustPreSharedKeyID, PreSharedKey)>,

    // Needed for reinit
    #[cfg(feature = "psk")]
    additional_psk: Option<crate::psk::secret::PskSecretInput>,
}

impl<'a, 'b, C: ClientConfig> GroupJoiner<'a, 'b, C> {
    // Info
    #[cfg(feature = "psk")]
    pub fn required_external_psks(&self) -> impl Iterator<Item = &ExternalPskId> {
        self.group_secrets
            .psks
            .iter()
            .filter_map(|psk| match &psk.key_id {
                JustPreSharedKeyID::External(psk) => Some(psk),
                _ => None,
            })
    }

    #[cfg(feature = "psk")]
    pub fn required_resumption_psks(&self) -> impl Iterator<Item = &ResumptionPsk> {
        self.group_secrets
            .psks
            .iter()
            .filter_map(|psk| match &psk.key_id {
                JustPreSharedKeyID::Resumption(psk) => Some(psk),
                _ => None,
            })
    }

    pub fn cipher_suite(&self) -> CipherSuite {
        self.welcome.cipher_suite
    }

    // Settings
    pub fn ratchet_tree(self, tree: ExportedTree<'b>) -> Self {
        Self {
            tree: Some(tree),
            ..self
        }
    }

    pub fn signature_secret_key(self, signature_secret_key: SignatureSecretKey) -> Self {
        Self {
            signer: Some(signature_secret_key),
            ..self
        }
    }

    #[cfg(feature = "psk")]
    pub fn with_external_psk(mut self, id: ExternalPskId, psk: PreSharedKey) -> Self {
        self.psks.push((JustPreSharedKeyID::External(id), psk));
        self
    }

    #[cfg(feature = "psk")]
    pub fn with_resumption_psk(mut self, id: ResumptionPsk, psk: PreSharedKey) -> Self {
        self.psks.push((JustPreSharedKeyID::Resumption(id), psk));
        self
    }

    // Reinit
    #[cfg(feature = "psk")]
    pub(crate) fn additional_psk(self, additional_psk: PskSecretInput) -> Self {
        Self {
            additional_psk: Some(additional_psk),
            ..self
        }
    }

    // Joining
    #[cfg_attr(not(mls_build_async), maybe_async::must_be_sync)]
    pub(crate) async fn new(
        config: C,
        welcome_msg: &'a MlsMessage,
        key_package_data: KeyPackageData,
        signer: Option<SignatureSecretKey>,
    ) -> Result<Self, MlsError> {
        let key_package = KeyPackage::mls_decode(&mut &*key_package_data.key_package_bytes)?;
        let init_key = &key_package_data.init_key;

        let (group_secrets, welcome) =
            Group::decrypt_group_secrets(welcome_msg, &config, &key_package, init_key).await?;

        Ok(Self {
            group_secrets,
            welcome,
            tree: None,
            config,
            version: welcome_msg.version,
            key_package,
            leaf_secret: key_package_data.leaf_node_key,
            signer,
            #[cfg(feature = "psk")]
            additional_psk: None,
            #[cfg(feature = "psk")]
            psks: Default::default(),
        })
    }

    /// Decrypt and validate the GroupInfo from this Welcome message. This requires
    /// that the ratchet tree is a part of GroupInfo or has been provided with
    /// [GroupJoiner::tree], and that all required PSKs have been provided [TODO].
    #[cfg_attr(not(mls_build_async), maybe_async::must_be_sync)]
    pub async fn decrypt_group_info(&mut self) -> Result<DecryptedGroupInfo, MlsError> {
        let cipher_suite_provider =
            cipher_suite_provider(self.config.crypto_provider(), self.welcome.cipher_suite)?;

        #[cfg(feature = "psk")]
        let psk_secret = if let Some(psk) = &self.additional_psk {
            let psk_id = self
                .group_secrets
                .psks
                .first()
                .ok_or(MlsError::UnexpectedPskId)?;

            match &psk_id.key_id {
                JustPreSharedKeyID::Resumption(r) if r.usage != ResumptionPSKUsage::Application => {
                    Ok(())
                }
                _ => Err(MlsError::UnexpectedPskId),
            }?;

            let mut psk = psk.clone();
            psk.id.psk_nonce = psk_id.psk_nonce.clone();
            PskSecret::calculate(&[psk], &cipher_suite_provider).await
        } else {
            let psk_inputs = self
                .group_secrets
                .psks
                .iter()
                .map(|id| {
                    self.psks
                        .iter()
                        .find_map(|(psk_id, psk)| {
                            (*psk_id == id.key_id).then(|| PskSecretInput {
                                id: id.clone(),
                                psk: psk.clone(),
                            })
                        })
                        .ok_or_else(|| MlsError::MissingRequiredPsk)
                })
                .collect::<Result<Vec<_>, _>>()?;

            PskSecret::calculate(&psk_inputs, &cipher_suite_provider).await
        }?;

        #[cfg(not(feature = "psk"))]
        let psk_secret = PskSecret::new(&cipher_suite_provider);

        // From the joiner_secret in the decrypted GroupSecrets object and the PSKs specified in
        // the GroupSecrets, derive the welcome_secret and using that the welcome_key and
        // welcome_nonce.
        let welcome_secret = WelcomeSecret::from_joiner_secret(
            &cipher_suite_provider,
            &self.group_secrets.joiner_secret,
            &psk_secret,
        )
        .await?;

        // Use the key and nonce to decrypt the encrypted_group_info field.
        let decrypted_group_info = welcome_secret
            .decrypt(&self.welcome.encrypted_group_info)
            .await?;

        let group_info = GroupInfo::mls_decode(&mut &**decrypted_group_info)?;

        let id_provider = self.config.identity_provider();

        let public_tree = validate_tree_and_info_joiner(
            self.version,
            &group_info,
            self.tree.take(),
            &id_provider,
            &cipher_suite_provider,
        )
        .await?;

        Ok(DecryptedGroupInfo {
            group_info,
            public_tree,
            psk_secret,
        })
    }

    #[cfg_attr(not(mls_build_async), maybe_async::must_be_sync)]
    pub async fn join(mut self) -> Result<(Group<C>, NewMemberInfo), MlsError> {
        let DecryptedGroupInfo {
            group_info,
            public_tree,
            psk_secret,
        } = self.decrypt_group_info().await?;

        let cipher_suite_provider =
            cipher_suite_provider(self.config.crypto_provider(), self.welcome.cipher_suite)?;

        // [RFC] Identify a leaf whose LeafNode is identical to the one in the KeyPackage. If no
        // such field exists, return an error.
        let self_index = public_tree
            .find_leaf_node(&self.key_package.leaf_node)
            .ok_or(MlsError::WelcomeKeyPackageNotFound)?;

        let mut private_tree = TreeKemPrivate::new_self_leaf(self_index, self.leaf_secret);

        // If the path_secret value is set in the GroupSecrets object
        if let Some(path_secret) = self.group_secrets.path_secret {
            private_tree
                .update_secrets(
                    &cipher_suite_provider,
                    group_info.signer,
                    path_secret,
                    &public_tree,
                )
                .await?;
        }

        // Use the joiner_secret from the GroupSecrets object to generate the epoch secret and
        // other derived secrets for the current epoch.
        let key_schedule_result = KeySchedule::from_joiner(
            &cipher_suite_provider,
            &self.group_secrets.joiner_secret,
            &group_info.group_context,
            #[cfg(any(feature = "secret_tree_access", feature = "private_message"))]
            public_tree.total_leaf_count(),
            &psk_secret,
        )
        .await?;

        // Verify the confirmation tag in the GroupInfo using the derived confirmation key and the
        // confirmed_transcript_hash from the GroupInfo.
        if !group_info
            .confirmation_tag
            .matches(
                &key_schedule_result.confirmation_key,
                &group_info.group_context.confirmed_transcript_hash,
                &cipher_suite_provider,
            )
            .await?
        {
            return Err(MlsError::InvalidConfirmationTag);
        }

        Group::join_with(
            self.config,
            group_info,
            public_tree,
            key_schedule_result.key_schedule,
            key_schedule_result.epoch_secrets,
            private_tree,
            self.signer.ok_or(MlsError::SignerNotFound)?,
        )
        .await
        .map_err(Into::into)
    }
}

pub struct DecryptedGroupInfo {
    pub group_info: GroupInfo,
    public_tree: TreeKemPublic,
    psk_secret: PskSecret,
}

#[cfg(feature = "psk")]
#[cfg(test)]
mod tests {
    use alloc::{vec, vec::Vec};
    use mls_rs_core::psk::{ExternalPskId, PreSharedKey};

    use crate::{
        client::test_utils::{test_client_with_key_pkg, TEST_CIPHER_SUITE, TEST_PROTOCOL_VERSION},
        psk::{PskGroupId, ResumptionPSKUsage, ResumptionPsk},
    };

    #[maybe_async::test(not(mls_build_async), async(mls_build_async, crate::futures_test))]
    async fn outputs_correct_join_info() {
        let (alice, _kp_alice) =
            test_client_with_key_pkg(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE, "alice").await;

        let (bob, kp_bob) =
            test_client_with_key_pkg(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE, "bob").await;

        let mut group_alice = alice
            .create_group(Default::default(), Default::default())
            .await
            .unwrap();

        let commit1 = group_alice
            .commit_builder()
            .add_member(kp_bob)
            .unwrap()
            .build()
            .await
            .unwrap();

        group_alice.apply_pending_commit().await.unwrap();

        let commit2 = group_alice.commit(vec![]).await.unwrap();
        group_alice.apply_pending_commit().await.unwrap();
        group_alice.write_to_storage().await.unwrap();

        let resumption_psk = group_alice.resumption_secret(1).await.unwrap();

        let mut group_bob = bob
            .join_group(None, &commit1.welcome_messages[0])
            .await
            .unwrap()
            .0;

        group_bob
            .process_incoming_message_oneshot(commit2.commit_message)
            .await
            .unwrap();

        group_bob.write_to_storage().await.unwrap();

        let psk_id = ExternalPskId::new(b"123".into());
        let psk_secret = PreSharedKey::new(b"456".into());

        let kp_alice = alice
            .key_package_builder(None)
            .unwrap()
            .build()
            .await
            .unwrap();

        let mut bob_group = bob
            .create_group(Default::default(), Default::default())
            .await
            .unwrap();

        let commit = bob_group
            .commit_builder()
            .add_member(kp_alice.key_package_message)
            .unwrap()
            .add_external_psk(psk_id.clone(), psk_secret.clone())
            .unwrap()
            .add_resumption_psk_for_group(
                1,
                group_alice.group_id().to_vec(),
                resumption_psk.clone(),
            )
            .unwrap()
            .build()
            .await
            .unwrap();

        let joiner = alice
            .group_joiner(&commit.welcome_messages[0], kp_alice.key_package_data)
            .await
            .unwrap();

        let external_psks = joiner.required_external_psks().collect::<Vec<_>>();
        assert_eq!(external_psks, vec![&psk_id]);

        let resumption_psks = joiner
            .required_resumption_psks()
            .cloned()
            .collect::<Vec<_>>();

        let expected_resumption_psk = ResumptionPsk {
            usage: ResumptionPSKUsage::Application,
            psk_group_id: PskGroupId(group_alice.group_id().to_vec()),
            psk_epoch: 1,
        };

        assert_eq!(resumption_psks, vec![expected_resumption_psk]);
        assert_eq!(joiner.cipher_suite(), TEST_CIPHER_SUITE);

        joiner
            .with_resumption_psk(resumption_psks[0].clone(), resumption_psk)
            .with_external_psk(psk_id.clone(), psk_secret)
            .join()
            .await
            .unwrap();
    }
}
