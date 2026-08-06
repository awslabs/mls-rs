// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// Copyright by contributors to this project.
// SPDX-License-Identifier: (Apache-2.0 OR MIT)

#[cfg(feature = "std")]
use std::collections::HashSet;

#[cfg(mls_build_async)]
use futures::{stream::FuturesUnordered, TryStreamExt};

use alloc::{vec, vec::Vec};

use mls_rs_core::{
    crypto::SignatureSecretKey,
    error::IntoAnyError,
    extension::ExtensionList,
    identity::{IdentityProvider, SigningIdentity},
};

use crate::{client::MlsError, tree_kem::TreeKemPublic, Client, Group, MlsMessage};
use crate::{group::Roster, time::MlsTime};

use super::{
    builder::GroupBuilder, proposal::ReInitProposal, ClientConfig, ExportedTree,
    JustPreSharedKeyID, MessageProcessor, NewMemberInfo, PreSharedKeyID, PskGroupId,
    PskSecretInput, ResumptionPSKUsage, ResumptionPsk,
};

pub struct ReinitClient<C: ClientConfig + Clone> {
    client: Client<C>,
    reinit: ReInitProposal,
    psk_input: PskSecretInput,
    old_public_tree: TreeKemPublic,
}

impl<C> Group<C>
where
    C: ClientConfig + Clone,
{
    fn branch_group_builder(
        &self,
        timestamp: Option<MlsTime>,
        group_id: Vec<u8>,
    ) -> Result<ResumptionGroupBuilder<C>, MlsError> {
        let mut builder = GroupBuilder::new(
            self.config.clone(),
            self.cipher_suite(),
            self.current_member_signing_identity()?.clone(),
            self.signer.clone(),
        )
        .with_group_id(group_id)
        .with_protocol_version(self.protocol_version())
        .with_group_context_extensions(self.group_state().context.extensions.clone());

        if let Some(time) = timestamp {
            builder = builder.with_now_time(time);
        }

        Ok(ResumptionGroupBuilder {
            builder,
            psk_input: self.resumption_psk_input(ResumptionPSKUsage::Branch)?,
            typ: GroupCreationType::Branch,
        })
    }

    ///
    /// Create a sub-group from a subset of the current group members.
    ///
    /// Membership within the resulting sub-group is indicated by providing a
    /// key package that produces the same
    /// [identity](crate::IdentityProvider::identity) value
    /// as an existing group member. The identity value of each key package
    /// is determined using the
    /// [`IdentityProvider`](crate::IdentityProvider)
    /// that is currently in use by this group instance.
    #[cfg_attr(not(mls_build_async), maybe_async::must_be_sync)]
    pub async fn branch(
        &self,
        sub_group_id: Vec<u8>,
        new_key_packages: Vec<MlsMessage>,
        timestamp: Option<MlsTime>,
    ) -> Result<(Group<C>, Vec<MlsMessage>), MlsError> {
        self.branch_group_builder(timestamp, sub_group_id)?
            .create(
                new_key_packages,
                self.current_user_leaf_node()?.ungreased_extensions(),
                self.roster(),
            )
            .await
    }

    /// Join a subgroup that was created by [`Group::branch`].
    #[cfg_attr(not(mls_build_async), maybe_async::must_be_sync)]
    pub async fn join_subgroup(
        &self,
        welcome: &MlsMessage,
        tree_data: Option<ExportedTree<'_>>,
        timestamp: Option<MlsTime>,
    ) -> Result<(Group<C>, NewMemberInfo), MlsError> {
        self.branch_group_builder(timestamp, vec![])?
            .join(welcome, tree_data, false, self.roster())
            .await
    }

    /// Generate a [`ReinitClient`] that can be used to create or join a new group
    /// that is based on properties defined by a [`ReInitProposal`]
    /// committed in a previously accepted commit. This is the only action available
    /// after accepting such a commit. The old group can no longer be used according to the RFC.
    ///
    /// If the [`ReInitProposal`] changes the ciphersuite, then `new_signer`
    /// and `new_signer_identity` must be set and match the new ciphersuite, as indicated by
    /// the [`CommitEffect::ReInit`](crate::group::CommitEffect::ReInit) outputted after processing the
    /// commit to the reinit proposal. The value of [identity](crate::IdentityProvider::identity)
    /// must be the same for `new_signing_identity` and the current identity in use by this
    /// group instance.
    pub fn get_reinit_client(
        self,
        new_signer: Option<SignatureSecretKey>,
        new_signing_identity: Option<SigningIdentity>,
    ) -> Result<ReinitClient<C>, MlsError> {
        let psk_input = self.resumption_psk_input(ResumptionPSKUsage::Reinit)?;

        let new_signing_identity = new_signing_identity
            .map(Ok)
            .unwrap_or_else(|| self.current_member_signing_identity().cloned())?;

        let reinit = self
            .state
            .pending_reinit
            .ok_or(MlsError::PendingReInitNotFound)?;

        let new_signer = match new_signer {
            Some(signer) => signer,
            None => self.signer,
        };

        let client = Client::new(
            self.config,
            Some(new_signer),
            Some((new_signing_identity, reinit.new_cipher_suite())),
            reinit.new_version(),
        );

        Ok(ReinitClient {
            client,
            reinit,
            psk_input,
            old_public_tree: self.state.public_tree,
        })
    }

    fn resumption_psk_input(&self, usage: ResumptionPSKUsage) -> Result<PskSecretInput, MlsError> {
        let psk = self.epoch_secrets.resumption_secret.clone();

        let id = JustPreSharedKeyID::Resumption(ResumptionPsk {
            usage,
            psk_group_id: PskGroupId(self.group_id().to_vec()),
            psk_epoch: self.current_epoch(),
        });

        let id = PreSharedKeyID::new(id, self.cipher_suite_provider())?;
        Ok(PskSecretInput { id, psk })
    }
}

/// A [`Client`] that can be used to create or join a new group
/// that is based on properties defined by a [`ReInitProposal`]
/// committed in a previously accepted commit.
impl<C: ClientConfig + Clone> ReinitClient<C> {
    /// Generate a key package for the new group. The key package can
    /// be used in [`ReinitClient::commit`].
    #[cfg_attr(not(mls_build_async), maybe_async::must_be_sync)]
    pub async fn generate_key_package(
        &self,
        timestamp: Option<MlsTime>,
    ) -> Result<MlsMessage, MlsError> {
        self.client
            .generate_key_package_message(Default::default(), Default::default(), timestamp)
            .await
    }

    fn group_builder(self, timestamp: Option<MlsTime>) -> ResumptionGroupBuilder<C> {
        let mut builder = GroupBuilder::new(
            self.client.config,
            self.reinit.cipher_suite,
            self.client.signing_identity.unwrap().0,
            self.client.signer.unwrap(),
        )
        .with_group_id(self.reinit.group_id)
        .with_protocol_version(self.reinit.version)
        .with_group_context_extensions(self.reinit.extensions);

        if let Some(time) = timestamp {
            builder = builder.with_now_time(time);
        }

        ResumptionGroupBuilder {
            builder,
            psk_input: self.psk_input,
            typ: GroupCreationType::Reinit,
        }
    }

    /// Create the new group using new key packages of all group members, possibly
    /// generated by [`ReinitClient::generate_key_package`].
    ///
    /// # Warning
    ///
    /// This function will fail if the number of members in the reinitialized
    /// group is not the same as the prior group roster.
    #[cfg_attr(not(mls_build_async), maybe_async::must_be_sync)]
    pub async fn commit(
        mut self,
        new_key_packages: Vec<MlsMessage>,
        new_leaf_node_extensions: ExtensionList,
        timestamp: Option<MlsTime>,
    ) -> Result<(Group<C>, Vec<MlsMessage>), MlsError> {
        let old_public_tree = core::mem::take(&mut self.old_public_tree);

        self.group_builder(timestamp)
            .create(
                new_key_packages,
                new_leaf_node_extensions,
                old_public_tree.roster(),
            )
            .await
    }

    /// Join a reinitialized group that was created by [`ReinitClient::commit`].
    #[cfg_attr(not(mls_build_async), maybe_async::must_be_sync)]
    pub async fn join(
        mut self,
        welcome: &MlsMessage,
        tree_data: Option<ExportedTree<'_>>,
        timestamp: Option<MlsTime>,
    ) -> Result<(Group<C>, NewMemberInfo), MlsError> {
        let old_public_tree = core::mem::take(&mut self.old_public_tree);

        self.group_builder(timestamp)
            .join(welcome, tree_data, true, old_public_tree.roster())
            .await
    }
}

// The wrapped builder must keep its default start epoch of 0: a branch/re-init
// subgroup's Welcome epoch must be 1 (enforced in `join`).
struct ResumptionGroupBuilder<C> {
    builder: GroupBuilder<C>,
    psk_input: PskSecretInput,
    typ: GroupCreationType,
}

impl<C: ClientConfig + Clone> ResumptionGroupBuilder<C> {
    #[cfg_attr(not(mls_build_async), maybe_async::must_be_sync)]
    async fn create(
        self,
        new_key_packages: Vec<MlsMessage>,
        leaf_node_extensions: ExtensionList,
        old_roster: Roster<'_>,
    ) -> Result<(Group<C>, Vec<MlsMessage>), MlsError> {
        // Create a new group with new parameters
        let mut group = self
            .builder
            .with_leaf_node_extensions(leaf_node_extensions)
            .build()
            .await?;

        // Install the resumption psk in the new group
        group.previous_psk = Some(self.psk_input);

        // Create a commit that adds new key packages and uses the resumption PSK
        let mut commit = group.commit_builder();

        for kp in new_key_packages.into_iter() {
            commit = commit.add_member(kp)?;
        }

        let commit = commit.build().await?;
        group.apply_pending_commit().await?;

        // Uninstall the resumption psk on success (in case of failure, the new group is discarded anyway)
        group.previous_psk = None;

        check_that_subgroup_is_a_subset(old_roster, &group, self.typ).await?;

        Ok((group, commit.welcome_messages))
    }

    #[cfg_attr(not(mls_build_async), maybe_async::must_be_sync)]
    async fn join(
        self,
        welcome: &MlsMessage,
        tree_data: Option<ExportedTree<'_>>,
        verify_group_id: bool,
        old_roster: Roster<'_>,
    ) -> Result<(Group<C>, NewMemberInfo), MlsError> {
        let expected_version = self.builder.protocol_version;
        let expected_cipher_suite = self.builder.cipher_suite;
        let expected_group_id = self.builder.group_id;
        let expected_extensions = self.builder.group_context_extensions;

        let (group, new_member_info) = Group::from_welcome_message(
            welcome,
            tree_data,
            self.builder.config,
            self.builder.signer,
            Some(self.psk_input),
            self.builder.now_time,
        )
        .await?;

        check_that_subgroup_is_a_subset(old_roster, &group, self.typ).await?;

        // The version and cipher_suite values in the Welcome message are the same as those used
        // by the old group.
        if group.protocol_version() != expected_version {
            Err(MlsError::ProtocolVersionMismatch)
        } else if group.cipher_suite() != expected_cipher_suite {
            Err(MlsError::CipherSuiteMismatch)
        }
        // The epoch in the Welcome message MUST be 1.
        else if group.current_epoch() != 1 {
            Err(MlsError::InitialEpochNotOne)
        } else if verify_group_id
            && group.group_id() != expected_group_id.as_deref().unwrap_or_default()
        {
            Err(MlsError::GroupIdMismatch)
        } else if group.group_state().context.extensions != expected_extensions {
            Err(MlsError::ReInitExtensionsMismatch)
        } else {
            Ok((group, new_member_info))
        }
    }
}

enum GroupCreationType {
    Branch,
    Reinit,
}

#[cfg_attr(not(mls_build_async), maybe_async::must_be_sync)]
async fn check_that_subgroup_is_a_subset<C: ClientConfig>(
    old_roster: Roster<'_>,
    new_group: &Group<C>,
    typ: GroupCreationType,
) -> Result<(), MlsError> {
    if matches!(typ, GroupCreationType::Reinit)
        && old_roster.public_tree.len() != new_group.roster().public_tree.len()
    {
        return Err(MlsError::NotASubgroup);
    }

    let provider = new_group.identity_provider();
    let extensions = new_group.context().extensions();

    let old_identities = collect_identities(extensions, old_roster, &provider).await?;
    let new_identities = collect_identities(extensions, new_group.roster(), &provider).await?;

    new_identities
        .is_subset(&old_identities)
        .then_some(())
        .ok_or(MlsError::NotASubgroup)?;

    Ok(())
}

#[cfg(feature = "std")]
#[cfg(not(mls_build_async))]
fn collect_identities<I: IdentityProvider>(
    extensions: &ExtensionList,
    roster: Roster<'_>,
    provider: &I,
) -> Result<HashSet<Vec<u8>>, MlsError> {
    roster
        .members_iter()
        .map(|m| {
            provider
                .identity(&m.signing_identity, extensions)
                .map_err(|e| MlsError::IdentityProviderError(e.into_any_error()))
        })
        .collect()
}

#[cfg(feature = "std")]
#[cfg(mls_build_async)]
async fn collect_identities<I: IdentityProvider>(
    extensions: &ExtensionList,
    roster: Roster<'_>,
    provider: &I,
) -> Result<HashSet<Vec<u8>>, MlsError> {
    roster
        .members_iter()
        .map(async move |m| {
            provider
                .identity(&m.signing_identity, extensions)
                .await
                .map_err(|e| MlsError::IdentityProviderError(e.into_any_error()))
        })
        .collect::<FuturesUnordered<_>>()
        .try_collect()
        .await
}

#[cfg(not(feature = "std"))]
struct Identities(Vec<Vec<u8>>);

#[cfg(not(feature = "std"))]
impl Identities {
    fn is_subset(&self, other: &Self) -> bool {
        self.0.iter().all(|i| other.0.contains(i))
    }
}

#[cfg(not(feature = "std"))]
fn collect_identities<I: IdentityProvider>(
    extensions: &ExtensionList,
    roster: Roster<'_>,
    provider: &I,
) -> Result<Identities, MlsError> {
    roster
        .members_iter()
        .map(|m| {
            provider
                .identity(&m.signing_identity, extensions)
                .map_err(|e| MlsError::IdentityProviderError(e.into_any_error()))
        })
        .collect::<Result<Vec<_>, _>>()
        .map(Identities)
}
