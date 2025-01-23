// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// Copyright by contributors to this project.
// SPDX-License-Identifier: (Apache-2.0 OR MIT)

use alloc::vec::Vec;

use super::{message_processor::ProvisionalState, CommitSource, GroupState, ProposalOrRef};
use crate::{
    client::MlsError,
    group::{
        proposal_filter::{ProposalApplier, ProposalBundle, ProposalSource},
        Sender,
    },
    time::MlsTime,
};

#[cfg(feature = "psk")]
use crate::psk::JustPreSharedKeyID;

#[cfg(feature = "by_ref_proposal")]
use crate::{
    group::{
        message_hash::MessageHash, Proposal, ProposalMessageDescription, ProposalRef,
        ProtocolVersion,
    },
    MlsMessage,
};

use crate::tree_kem::leaf_node::LeafNode;

#[cfg(feature = "by_ref_proposal")]
use mls_rs_codec::{MlsDecode, MlsEncode, MlsSize};

use mls_rs_core::{crypto::CipherSuiteProvider, identity::IdentityProvider};

#[cfg(feature = "by_ref_proposal")]
use core::fmt::{self, Debug};

#[cfg(feature = "by_ref_proposal")]
#[derive(Debug, Clone, MlsSize, MlsEncode, MlsDecode, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct CachedProposal {
    pub(crate) proposal: Proposal,
    pub(crate) sender: Sender,
}

#[cfg(feature = "by_ref_proposal")]
#[derive(Clone, MlsSize, MlsEncode, MlsDecode)]
pub(crate) struct ProposalCache {
    protocol_version: ProtocolVersion,
    group_id: Vec<u8>,
    pub(crate) proposals: crate::map::SmallMap<ProposalRef, CachedProposal>,
    pub(crate) own_proposals: crate::map::SmallMap<MessageHash, ProposalMessageDescription>,
}

#[cfg(feature = "by_ref_proposal")]
impl PartialEq for ProposalCache {
    fn eq(&self, other: &Self) -> bool {
        self.protocol_version == other.protocol_version
            && self.group_id == other.group_id
            && self.proposals == other.proposals
    }
}

#[cfg(feature = "by_ref_proposal")]
impl Debug for ProposalCache {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ProposalCache")
            .field("protocol_version", &self.protocol_version)
            .field(
                "group_id",
                &mls_rs_core::debug::pretty_group_id(&self.group_id),
            )
            .field("proposals", &self.proposals)
            .finish()
    }
}

#[cfg(feature = "by_ref_proposal")]
impl ProposalCache {
    pub fn new(protocol_version: ProtocolVersion, group_id: Vec<u8>) -> Self {
        Self {
            protocol_version,
            group_id,
            proposals: Default::default(),
            own_proposals: Default::default(),
        }
    }

    pub fn import(
        protocol_version: ProtocolVersion,
        group_id: Vec<u8>,
        proposals: crate::map::SmallMap<ProposalRef, CachedProposal>,
        own_proposals: crate::map::SmallMap<MessageHash, ProposalMessageDescription>,
    ) -> Self {
        Self {
            protocol_version,
            group_id,
            proposals,
            own_proposals,
        }
    }

    pub fn clear(&mut self) {
        self.proposals.clear();
        self.own_proposals.clear();
    }

    #[cfg(feature = "by_ref_proposal")]
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.proposals.is_empty()
    }

    pub fn insert(&mut self, proposal_ref: ProposalRef, proposal: Proposal, sender: Sender) {
        let cached_proposal = CachedProposal { proposal, sender };

        #[cfg(feature = "std")]
        self.proposals.insert(proposal_ref, cached_proposal);

        #[cfg(not(feature = "std"))]
        // This may result in dups but it does not matter
        self.proposals.push((proposal_ref, cached_proposal));
    }

    #[cfg_attr(not(mls_build_async), maybe_async::must_be_sync)]
    pub async fn insert_own<CS: CipherSuiteProvider>(
        &mut self,
        proposal: ProposalMessageDescription,
        message: &MlsMessage,
        sender: Sender,
        cs: &CS,
    ) -> Result<(), MlsError> {
        self.insert(
            proposal.proposal_ref.clone(),
            proposal.proposal.clone(),
            sender,
        );

        let message_hash = MessageHash::compute(cs, message).await?;
        self.own_proposals.insert(message_hash, proposal);

        Ok(())
    }

    pub fn prepare_commit(&self) -> ProposalBundle {
        self.proposals
            .iter()
            .map(|(r, p)| {
                (
                    p.proposal.clone(),
                    p.sender,
                    ProposalSource::ByReference(r.clone()),
                )
            })
            .collect()
    }

    pub fn resolve_for_commit(
        &self,
        sender: Sender,
        proposal_list: Vec<ProposalOrRef>,
    ) -> Result<ProposalBundle, MlsError> {
        let mut proposals = ProposalBundle::default();

        for p in proposal_list {
            match p {
                ProposalOrRef::Proposal(p) => proposals.add(*p, sender, ProposalSource::ByValue),
                ProposalOrRef::Reference(r) => {
                    #[cfg(feature = "std")]
                    let p = self
                        .proposals
                        .get(&r)
                        .ok_or(MlsError::ProposalNotFound)?
                        .clone();
                    #[cfg(not(feature = "std"))]
                    let p = self
                        .proposals
                        .iter()
                        .find_map(|(rr, p)| (rr == &r).then_some(p))
                        .ok_or(MlsError::ProposalNotFound)?
                        .clone();

                    proposals.add(p.proposal, p.sender, ProposalSource::ByReference(r));
                }
            };
        }

        Ok(proposals)
    }

    #[cfg_attr(not(mls_build_async), maybe_async::must_be_sync)]
    pub async fn get_own<CS: CipherSuiteProvider>(
        &self,
        cs: &CS,
        message: &MlsMessage,
    ) -> Result<Option<ProposalMessageDescription>, MlsError> {
        let message_hash = MessageHash::compute(cs, message).await?;

        Ok(self.own_proposals.get(&message_hash).cloned())
    }
}

#[cfg(not(feature = "by_ref_proposal"))]
pub(crate) fn resolve_for_commit(
    sender: Sender,
    proposal_list: Vec<ProposalOrRef>,
) -> Result<ProposalBundle, MlsError> {
    let mut proposals = ProposalBundle::default();

    for p in proposal_list {
        let ProposalOrRef::Proposal(p) = p;
        proposals.add(*p, sender, ProposalSource::ByValue);
    }

    Ok(proposals)
}

impl GroupState {
    #[inline(never)]
    #[allow(clippy::too_many_arguments)]
    #[cfg_attr(not(mls_build_async), maybe_async::must_be_sync)]
    pub(crate) async fn apply_resolved<C, CSP>(
        &self,
        proposals: ProposalBundle,
        external_leaf: Option<&LeafNode>,
        identity_provider: &C,
        cipher_suite_provider: &CSP,
        commit_time: Option<MlsTime>,
        #[cfg(feature = "psk")] psks: &[JustPreSharedKeyID],
        sender: &CommitSource,
    ) -> Result<ProvisionalState, MlsError>
    where
        C: IdentityProvider,
        CSP: CipherSuiteProvider,
    {
        #[cfg(feature = "custom_proposal")]
        crate::group::proposal_filter::filter_out_unsupported_custom_proposals(
            &proposals,
            &self.public_tree,
        )?;

        let applier = ProposalApplier::new(
            &self.public_tree,
            cipher_suite_provider,
            &self.context,
            external_leaf,
            identity_provider,
            #[cfg(feature = "psk")]
            psks,
        );

        let applier_output = applier
            .apply_proposals(sender, proposals, commit_time)
            .await?;

        let mut group_context = self.context.clone();
        group_context.epoch += 1;

        if let Some(ext) = applier_output.new_context_extensions {
            group_context.extensions = ext;
        }

        Ok(ProvisionalState {
            public_tree: applier_output.new_tree,
            group_context,
            applied_proposals: applier_output.applied_proposals,
            external_init_index: applier_output.external_init_index,
            indexes_of_added_kpkgs: applier_output.indexes_of_added_kpkgs,
        })
    }
}

#[cfg(feature = "by_ref_proposal")]
impl Extend<(ProposalRef, CachedProposal)> for ProposalCache {
    fn extend<T>(&mut self, iter: T)
    where
        T: IntoIterator<Item = (ProposalRef, CachedProposal)>,
    {
        self.proposals.extend(iter);
    }
}

#[cfg(all(feature = "by_ref_proposal", test))]
pub(crate) mod test_utils {
    use mls_rs_core::{
        crypto::CipherSuiteProvider, extension::ExtensionList, identity::IdentityProvider,
    };

    use crate::{
        client::test_utils::{TEST_CIPHER_SUITE, TEST_PROTOCOL_VERSION},
        crypto::test_utils::test_cipher_suite_provider,
        group::{
            confirmation_tag::ConfirmationTag,
            proposal::{Proposal, ProposalOrRef},
            proposal_filter::ProposalSource,
            proposal_ref::ProposalRef,
            state::GroupState,
            test_utils::{get_test_group_context, TEST_GROUP},
            CommitSource, GroupContext, LeafIndex, LeafNode, ProvisionalState, Sender,
            TreeKemPublic,
        },
        identity::{basic::BasicIdentityProvider, test_utils::BasicWithCustomProvider},
    };

    use super::{CachedProposal, JustPreSharedKeyID, MlsError, ProposalCache};

    use alloc::vec;
    use alloc::vec::Vec;

    impl CachedProposal {
        pub fn new(proposal: Proposal, sender: Sender) -> Self {
            Self { proposal, sender }
        }
    }

    #[derive(Debug)]
    pub(crate) struct CommitReceiver<'a, C, CSP> {
        tree: &'a TreeKemPublic,
        sender: Sender,
        receiver: LeafIndex,
        cache: ProposalCache,
        identity_provider: C,
        cipher_suite_provider: CSP,
        group_context_extensions: ExtensionList,
        psks: Vec<JustPreSharedKeyID>,
    }

    impl<'a, CSP> CommitReceiver<'a, BasicWithCustomProvider, CSP> {
        pub fn new<S>(
            tree: &'a TreeKemPublic,
            sender: S,
            receiver: LeafIndex,
            cipher_suite_provider: CSP,
        ) -> Self
        where
            S: Into<Sender>,
        {
            Self {
                tree,
                sender: sender.into(),
                receiver,
                cache: make_proposal_cache(),
                identity_provider: BasicWithCustomProvider::new(BasicIdentityProvider),
                group_context_extensions: Default::default(),
                psks: vec![],
                cipher_suite_provider,
            }
        }
    }

    impl<'a, C, CSP> CommitReceiver<'a, C, CSP>
    where
        C: IdentityProvider,
        CSP: CipherSuiteProvider,
    {
        pub fn with_identity_provider<V>(self, validator: V) -> CommitReceiver<'a, V, CSP>
        where
            V: IdentityProvider,
        {
            CommitReceiver {
                tree: self.tree,
                sender: self.sender,
                receiver: self.receiver,
                cache: self.cache,
                identity_provider: validator,
                group_context_extensions: self.group_context_extensions,
                psks: self.psks,
                cipher_suite_provider: self.cipher_suite_provider,
            }
        }

        pub fn with_psks(self, v: Vec<JustPreSharedKeyID>) -> CommitReceiver<'a, C, CSP> {
            CommitReceiver {
                tree: self.tree,
                sender: self.sender,
                receiver: self.receiver,
                cache: self.cache,
                identity_provider: self.identity_provider,
                group_context_extensions: self.group_context_extensions,
                psks: v,
                cipher_suite_provider: self.cipher_suite_provider,
            }
        }

        #[cfg(feature = "by_ref_proposal")]
        pub fn with_extensions(self, extensions: ExtensionList) -> Self {
            Self {
                group_context_extensions: extensions,
                ..self
            }
        }

        pub fn cache<S>(mut self, r: ProposalRef, p: Proposal, proposer: S) -> Self
        where
            S: Into<Sender>,
        {
            self.cache.insert(r, p, proposer.into());
            self
        }

        #[cfg_attr(not(mls_build_async), maybe_async::must_be_sync)]
        pub async fn receive<I>(&self, proposals: I) -> Result<ProvisionalState, MlsError>
        where
            I: IntoIterator,
            I::Item: Into<ProposalOrRef>,
        {
            self.cache
                .resolve_for_commit_default(
                    self.sender,
                    proposals.into_iter().map(Into::into).collect(),
                    None,
                    &self.group_context_extensions,
                    &self.identity_provider,
                    &self.cipher_suite_provider,
                    self.tree,
                    &self.psks,
                )
                .await
        }
    }

    pub(crate) fn make_proposal_cache() -> ProposalCache {
        ProposalCache::new(TEST_PROTOCOL_VERSION, TEST_GROUP.to_vec())
    }

    impl ProposalCache {
        #[allow(clippy::too_many_arguments)]
        #[cfg_attr(not(mls_build_async), maybe_async::must_be_sync)]
        pub async fn resolve_for_commit_default<C, CSP>(
            &self,
            sender: Sender,
            proposal_list: Vec<ProposalOrRef>,
            external_leaf: Option<&LeafNode>,
            group_extensions: &ExtensionList,
            identity_provider: &C,
            cipher_suite_provider: &CSP,
            public_tree: &TreeKemPublic,
            #[cfg(feature = "psk")] psks: &[JustPreSharedKeyID],
        ) -> Result<ProvisionalState, MlsError>
        where
            C: IdentityProvider,
            CSP: CipherSuiteProvider,
        {
            let mut context =
                get_test_group_context(123, cipher_suite_provider.cipher_suite()).await;

            context.extensions = group_extensions.clone();

            let mut state = GroupState::new(
                context,
                public_tree.clone(),
                Vec::new().into(),
                ConfirmationTag::empty(cipher_suite_provider).await,
            );

            state.proposals.proposals.clone_from(&self.proposals);
            let proposals = self.resolve_for_commit(sender, proposal_list)?;
            let committer = CommitSource::new(&sender, public_tree, external_leaf)?;

            state
                .apply_resolved(
                    proposals,
                    external_leaf,
                    identity_provider,
                    cipher_suite_provider,
                    None,
                    #[cfg(feature = "psk")]
                    psks,
                    &committer,
                )
                .await
        }

        #[cfg_attr(not(mls_build_async), maybe_async::must_be_sync)]
        pub async fn prepare_commit_default<I: IdentityProvider>(
            &self,
            sender: Sender,
            additional_proposals: Vec<Proposal>,
            context: &GroupContext,
            identity_provider: &I,
            public_tree: &TreeKemPublic,
            #[cfg(feature = "psk")] psks: &[JustPreSharedKeyID],
        ) -> Result<ProvisionalState, MlsError> {
            let cipher_suite_provider = test_cipher_suite_provider(TEST_CIPHER_SUITE);

            let state = GroupState::new(
                context.clone(),
                public_tree.clone(),
                Vec::new().into(),
                ConfirmationTag::empty(&cipher_suite_provider).await,
            );

            let proposals =
                additional_proposals
                    .into_iter()
                    .fold(self.prepare_commit(), |mut proposals, p| {
                        proposals.add(p, sender, ProposalSource::ByValue);
                        proposals
                    });

            let committer = CommitSource::new(&sender, public_tree, None)?;

            state
                .apply_resolved(
                    proposals,
                    None,
                    identity_provider,
                    &cipher_suite_provider,
                    None,
                    #[cfg(feature = "psk")]
                    psks,
                    &committer,
                )
                .await
        }
    }
}

// FIXME some of these tests do not belong here
#[cfg(all(feature = "by_ref_proposal", test))]
mod tests {
    use alloc::{boxed::Box, vec, vec::Vec};

    use super::test_utils::{make_proposal_cache, CommitReceiver};
    use super::{CachedProposal, ProposalCache};
    use crate::client::test_utils::test_client;
    use crate::client::MlsError;
    use crate::group::message_processor::ProvisionalState;
    use crate::group::proposal_filter::{ProposalBundle, ProposalSource};
    use crate::group::proposal_ref::test_utils::auth_content_from_proposal;
    use crate::group::proposal_ref::ProposalRef;
    use crate::group::{
        AddProposal, AuthenticatedContent, Content, ExternalInit, Proposal, ProposalOrRef,
        ReInitProposal, RemoveProposal, Sender, UpdateProposal,
    };
    use crate::key_package::test_utils::test_key_package_with_signer;
    use crate::signer::Signable;
    use crate::tree_kem::leaf_node::LeafNode;
    use crate::tree_kem::node::LeafIndex;
    use crate::tree_kem::TreeKemPublic;
    use crate::KeyPackage;
    use crate::{
        client::test_utils::{TEST_CIPHER_SUITE, TEST_PROTOCOL_VERSION},
        crypto::{self, test_utils::test_cipher_suite_provider},
        extension::test_utils::TestExtension,
        group::{
            message_processor::path_update_required,
            proposal_filter::proposer_can_propose,
            test_utils::{get_test_group_context, test_group, TEST_GROUP},
        },
        identity::basic::BasicIdentityProvider,
        identity::test_utils::{get_test_signing_identity, BasicWithCustomProvider},
        key_package::test_utils::test_key_package,
        tree_kem::leaf_node::{
            test_utils::{
                default_properties, get_basic_test_node, get_basic_test_node_capabilities,
                get_basic_test_node_sig_key, get_test_capabilities,
            },
            LeafNodeSigningContext,
        },
    };

    use crate::extension::RequiredCapabilitiesExt;

    #[cfg(feature = "by_ref_proposal")]
    use crate::{
        extension::ExternalSendersExt,
        tree_kem::leaf_node_validator::test_utils::FailureIdentityProvider,
    };

    #[cfg(feature = "psk")]
    use crate::{
        group::proposal::PreSharedKeyProposal,
        psk::{
            ExternalPskId, JustPreSharedKeyID, PreSharedKeyID, PskGroupId, PskNonce,
            ResumptionPSKUsage, ResumptionPsk,
        },
    };

    #[cfg(feature = "custom_proposal")]
    use crate::group::proposal::CustomProposal;

    use assert_matches::assert_matches;
    use itertools::Itertools;
    use mls_rs_core::crypto::{CipherSuite, CipherSuiteProvider};
    use mls_rs_core::extension::ExtensionList;
    use mls_rs_core::group::{Capabilities, ProposalType};
    use mls_rs_core::identity::IdentityProvider;
    use mls_rs_core::protocol_version::ProtocolVersion;
    use mls_rs_core::{
        extension::MlsExtension,
        identity::{Credential, CredentialType, CustomCredential},
    };

    fn test_sender() -> u32 {
        1
    }

    #[cfg_attr(not(mls_build_async), maybe_async::must_be_sync)]
    async fn new_tree_custom_proposals(
        name: &str,
        proposal_types: Vec<ProposalType>,
    ) -> (LeafIndex, TreeKemPublic) {
        let (leaf, secret, _) = get_basic_test_node_capabilities(
            TEST_CIPHER_SUITE,
            name,
            Capabilities {
                proposals: proposal_types,
                ..get_test_capabilities()
            },
        )
        .await;

        let (pub_tree, priv_tree) =
            TreeKemPublic::derive(leaf, secret, &BasicIdentityProvider, &Default::default())
                .await
                .unwrap();

        (priv_tree.self_index, pub_tree)
    }

    #[cfg_attr(not(mls_build_async), maybe_async::must_be_sync)]
    async fn new_tree(name: &str) -> (LeafIndex, TreeKemPublic) {
        new_tree_custom_proposals(name, vec![]).await
    }

    #[cfg_attr(not(mls_build_async), maybe_async::must_be_sync)]
    async fn add_member(tree: &mut TreeKemPublic, name: &str) -> LeafIndex {
        let test_node = get_basic_test_node(TEST_CIPHER_SUITE, name).await;

        tree.add_leaves(
            vec![test_node],
            &BasicIdentityProvider,
            &test_cipher_suite_provider(TEST_CIPHER_SUITE),
        )
        .await
        .unwrap()[0]
    }

    #[cfg_attr(not(mls_build_async), maybe_async::must_be_sync)]
    async fn update_leaf_node(name: &str, leaf_index: u32) -> LeafNode {
        let (mut leaf, _, signer) = get_basic_test_node_sig_key(TEST_CIPHER_SUITE, name).await;

        leaf.update(
            &test_cipher_suite_provider(TEST_CIPHER_SUITE),
            TEST_GROUP,
            leaf_index,
            Some(default_properties()),
            None,
            &signer,
        )
        .await
        .unwrap();

        leaf
    }

    struct TestProposals {
        test_sender: u32,
        test_proposals: Vec<AuthenticatedContent>,
        expected_effects: ProvisionalState,
        tree: TreeKemPublic,
    }

    #[cfg_attr(not(mls_build_async), maybe_async::must_be_sync)]
    async fn test_proposals(
        protocol_version: ProtocolVersion,
        cipher_suite: CipherSuite,
    ) -> TestProposals {
        let cipher_suite_provider = test_cipher_suite_provider(cipher_suite);

        let (sender_leaf, sender_leaf_secret, _) =
            get_basic_test_node_sig_key(cipher_suite, "alice").await;

        let sender = LeafIndex(0);

        let (mut tree, _) = TreeKemPublic::derive(
            sender_leaf,
            sender_leaf_secret,
            &BasicIdentityProvider,
            &Default::default(),
        )
        .await
        .unwrap();

        let add_package = test_key_package(protocol_version, cipher_suite, "dave").await;

        let remove_leaf_index = add_member(&mut tree, "carol").await;

        let add = Proposal::Add(Box::new(AddProposal {
            key_package: add_package.clone(),
        }));

        let remove = Proposal::Remove(RemoveProposal {
            to_remove: remove_leaf_index,
        });

        let extensions = Proposal::GroupContextExtensions(ExtensionList::new());

        let proposals = vec![add, remove, extensions];

        let test_node = get_basic_test_node(cipher_suite, "charlie").await;

        let test_sender = *tree
            .add_leaves(
                vec![test_node],
                &BasicIdentityProvider,
                &cipher_suite_provider,
            )
            .await
            .unwrap()[0];

        let mut expected_tree = tree.clone();

        let mut bundle = ProposalBundle::default();

        let plaintext = proposals
            .iter()
            .cloned()
            .map(|p| auth_content_from_proposal(p, sender))
            .collect_vec();

        for i in 0..proposals.len() {
            let pref = ProposalRef::from_content(&cipher_suite_provider, &plaintext[i])
                .await
                .unwrap();

            bundle.add(
                proposals[i].clone(),
                Sender::Member(test_sender),
                ProposalSource::ByReference(pref),
            )
        }

        expected_tree
            .batch_edit(
                &bundle,
                &Default::default(),
                &BasicIdentityProvider,
                &cipher_suite_provider,
            )
            .await
            .unwrap();

        let expected_effects = ProvisionalState {
            public_tree: expected_tree,
            group_context: get_test_group_context(1, cipher_suite).await,
            external_init_index: None,
            indexes_of_added_kpkgs: vec![LeafIndex(1)],
            applied_proposals: bundle,
        };

        TestProposals {
            test_sender,
            test_proposals: plaintext,
            expected_effects,
            tree,
        }
    }

    #[cfg_attr(not(mls_build_async), maybe_async::must_be_sync)]
    async fn filter_proposals(
        cipher_suite: CipherSuite,
        proposals: Vec<AuthenticatedContent>,
    ) -> Vec<(ProposalRef, CachedProposal)> {
        let mut contents = Vec::new();

        for p in proposals {
            if let Content::Proposal(proposal) = &p.content.content {
                let proposal_ref =
                    ProposalRef::from_content(&test_cipher_suite_provider(cipher_suite), &p)
                        .await
                        .unwrap();
                contents.push((
                    proposal_ref,
                    CachedProposal::new(proposal.as_ref().clone(), p.content.sender),
                ));
            }
        }

        contents
    }

    #[cfg_attr(not(mls_build_async), maybe_async::must_be_sync)]
    async fn make_proposal_ref<S>(p: &Proposal, sender: S) -> ProposalRef
    where
        S: Into<Sender>,
    {
        ProposalRef::from_content(
            &test_cipher_suite_provider(TEST_CIPHER_SUITE),
            &auth_content_from_proposal(p.clone(), sender),
        )
        .await
        .unwrap()
    }

    #[cfg_attr(not(mls_build_async), maybe_async::must_be_sync)]
    async fn test_proposal_cache_setup(proposals: Vec<AuthenticatedContent>) -> ProposalCache {
        let mut cache = make_proposal_cache();
        cache.extend(filter_proposals(TEST_CIPHER_SUITE, proposals).await);
        cache
    }

    fn assert_matches(mut expected_state: ProvisionalState, state: ProvisionalState) {
        let expected_proposals = expected_state.applied_proposals.proposals_or_refs();
        let proposals = state.applied_proposals.proposals_or_refs();

        assert_eq!(proposals.len(), expected_proposals.len());

        // Determine there are no duplicates in the proposals returned
        assert!(!proposals.iter().enumerate().any(|(i, p1)| proposals
            .iter()
            .enumerate()
            .any(|(j, p2)| p1 == p2 && i != j)),);

        // Proposal order may change so we just compare the length and contents are the same
        expected_proposals
            .iter()
            .for_each(|p| assert!(proposals.contains(p)));

        assert_eq!(
            expected_state.external_init_index,
            state.external_init_index
        );

        // We don't compare the epoch in this test.
        expected_state.group_context.epoch = state.group_context.epoch;
        assert_eq!(expected_state.group_context, state.group_context);

        assert_eq!(
            expected_state.indexes_of_added_kpkgs,
            state.indexes_of_added_kpkgs
        );

        assert_eq!(expected_state.public_tree, state.public_tree);
    }

    #[maybe_async::test(not(mls_build_async), async(mls_build_async, crate::futures_test))]
    async fn test_proposal_cache_commit_all_cached() {
        let TestProposals {
            test_sender,
            test_proposals,
            expected_effects,
            tree,
            ..
        } = test_proposals(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE).await;

        let cache = test_proposal_cache_setup(test_proposals.clone()).await;

        let provisional_state = cache
            .prepare_commit_default(
                Sender::Member(test_sender),
                vec![],
                &get_test_group_context(0, TEST_CIPHER_SUITE).await,
                &BasicIdentityProvider,
                &tree,
                &[],
            )
            .await
            .unwrap();

        assert_matches(expected_effects, provisional_state)
    }

    #[maybe_async::test(not(mls_build_async), async(mls_build_async, crate::futures_test))]
    async fn test_proposal_cache_commit_additional() {
        let cipher_suite_provider = test_cipher_suite_provider(TEST_CIPHER_SUITE);

        let TestProposals {
            test_sender,
            test_proposals,
            mut expected_effects,
            tree,
            ..
        } = test_proposals(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE).await;

        let additional_key_package =
            test_key_package(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE, "frank").await;

        let additional = AddProposal {
            key_package: additional_key_package.clone(),
        };

        let cache = test_proposal_cache_setup(test_proposals.clone()).await;

        let provisional_state = cache
            .prepare_commit_default(
                Sender::Member(test_sender),
                vec![Proposal::Add(Box::new(additional.clone()))],
                &get_test_group_context(0, TEST_CIPHER_SUITE).await,
                &BasicIdentityProvider,
                &tree,
                &[],
            )
            .await
            .unwrap();

        expected_effects.applied_proposals.add(
            Proposal::Add(Box::new(additional.clone())),
            Sender::Member(test_sender),
            ProposalSource::ByValue,
        );

        let leaf = vec![additional_key_package.leaf_node.clone()];

        expected_effects
            .public_tree
            .add_leaves(leaf, &BasicIdentityProvider, &cipher_suite_provider)
            .await
            .unwrap();

        expected_effects.indexes_of_added_kpkgs.push(LeafIndex(3));

        assert_matches(expected_effects, provisional_state);
    }

    #[maybe_async::test(not(mls_build_async), async(mls_build_async, crate::futures_test))]
    async fn test_proposal_cache_update_filter() {
        let TestProposals {
            test_proposals,
            tree,
            ..
        } = test_proposals(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE).await;

        let update_proposal = make_update_proposal("foo").await;

        let additional = vec![Proposal::Update(update_proposal)];

        let cache = test_proposal_cache_setup(test_proposals).await;

        let res = cache
            .prepare_commit_default(
                Sender::Member(test_sender()),
                additional,
                &get_test_group_context(0, TEST_CIPHER_SUITE).await,
                &BasicIdentityProvider,
                &tree,
                &[],
            )
            .await;

        assert_matches!(res, Err(MlsError::InvalidProposalTypeForSender));
    }

    // [FIXME] This test does not make sense anymore, as it requires us to filter out update instead of remove.
    // In the follow-up we'll have a convenience method that deletes invalid proposals, and this test will test
    // that method. No need to generate real proposals.
    #[ignore]
    #[maybe_async::test(not(mls_build_async), async(mls_build_async, crate::futures_test))]
    async fn test_proposal_cache_removal_override_update() {
        let TestProposals {
            test_sender,
            test_proposals,
            tree,
            ..
        } = test_proposals(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE).await;

        let update = Proposal::Update(make_update_proposal("foo").await);
        let update_proposal_ref = make_proposal_ref(&update, LeafIndex(1)).await;
        let mut cache = test_proposal_cache_setup(test_proposals).await;

        cache.insert(update_proposal_ref.clone(), update, Sender::Member(1));

        let provisional_state = cache
            .prepare_commit_default(
                Sender::Member(test_sender),
                vec![],
                &get_test_group_context(0, TEST_CIPHER_SUITE).await,
                &BasicIdentityProvider,
                &tree,
                &[],
            )
            .await
            .unwrap();

        assert!(provisional_state
            .applied_proposals
            .removals
            .iter()
            .any(|p| *p.proposal.to_remove == 1));

        assert!(!provisional_state
            .applied_proposals
            .proposals_or_refs()
            .contains(&ProposalOrRef::Reference(update_proposal_ref)))
    }

    #[cfg(feature = "private_message")]
    #[maybe_async::test(not(mls_build_async), async(mls_build_async, crate::futures_test))]
    async fn test_proposal_cache_is_empty() {
        let mut cache = make_proposal_cache();
        assert!(cache.is_empty());

        let test_proposal = Proposal::Remove(RemoveProposal {
            to_remove: LeafIndex(test_sender()),
        });

        let proposer = test_sender();
        let test_proposal_ref = make_proposal_ref(&test_proposal, LeafIndex(proposer)).await;
        cache.insert(test_proposal_ref, test_proposal, Sender::Member(proposer));

        assert!(!cache.is_empty())
    }

    #[maybe_async::test(not(mls_build_async), async(mls_build_async, crate::futures_test))]
    async fn test_proposal_cache_resolve() {
        let cipher_suite_provider = test_cipher_suite_provider(TEST_CIPHER_SUITE);

        let TestProposals {
            test_sender,
            test_proposals,
            tree,
            ..
        } = test_proposals(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE).await;

        let cache = test_proposal_cache_setup(test_proposals).await;

        let proposal = Proposal::Add(Box::new(AddProposal {
            key_package: test_key_package(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE, "frank").await,
        }));

        let additional = vec![proposal];

        let expected_effects = cache
            .prepare_commit_default(
                Sender::Member(test_sender),
                additional,
                &get_test_group_context(0, TEST_CIPHER_SUITE).await,
                &BasicIdentityProvider,
                &tree,
                &[],
            )
            .await
            .unwrap();

        let proposals = expected_effects
            .applied_proposals
            .clone()
            .proposals_or_refs();

        let resolution = cache
            .resolve_for_commit_default(
                Sender::Member(test_sender),
                proposals,
                None,
                &ExtensionList::new(),
                &BasicIdentityProvider,
                &cipher_suite_provider,
                &tree,
                &[],
            )
            .await
            .unwrap();

        assert_matches(expected_effects, resolution);
    }

    #[cfg(feature = "psk")]
    #[maybe_async::test(not(mls_build_async), async(mls_build_async, crate::futures_test))]
    async fn proposal_cache_filters_duplicate_psk_ids() {
        let (alice, tree) = new_tree("alice").await;
        let cache = make_proposal_cache();

        let psk_id = b"ted";

        let proposal = Proposal::Psk(make_external_psk(
            psk_id,
            crate::psk::PskNonce::random(&test_cipher_suite_provider(TEST_CIPHER_SUITE)).unwrap(),
        ));

        let res = cache
            .prepare_commit_default(
                Sender::Member(*alice),
                vec![proposal.clone(), proposal],
                &get_test_group_context(0, TEST_CIPHER_SUITE).await,
                &BasicIdentityProvider,
                &tree,
                &[JustPreSharedKeyID::External(psk_id.to_vec().into())],
            )
            .await;

        assert_matches!(res, Err(MlsError::DuplicatePskIds));
    }

    #[cfg_attr(not(mls_build_async), maybe_async::must_be_sync)]
    async fn test_node() -> LeafNode {
        let (mut leaf_node, _, signer) =
            get_basic_test_node_sig_key(TEST_CIPHER_SUITE, "foo").await;

        leaf_node
            .commit(
                &test_cipher_suite_provider(TEST_CIPHER_SUITE),
                TEST_GROUP,
                0,
                Some(default_properties()),
                None,
                &signer,
            )
            .await
            .unwrap();

        leaf_node
    }

    #[maybe_async::test(not(mls_build_async), async(mls_build_async, crate::futures_test))]
    async fn external_commit_must_have_new_leaf() {
        let cache = make_proposal_cache();
        let cipher_suite_provider = test_cipher_suite_provider(TEST_CIPHER_SUITE);

        let kem_output = vec![0; cipher_suite_provider.kdf_extract_size()];
        let group = test_group().await;
        let public_tree = &group.state.public_tree;

        let res = cache
            .resolve_for_commit_default(
                Sender::NewMemberCommit,
                vec![ProposalOrRef::Proposal(Box::new(Proposal::ExternalInit(
                    ExternalInit { kem_output },
                )))],
                None,
                &group.context().extensions,
                &BasicIdentityProvider,
                &cipher_suite_provider,
                public_tree,
                &[],
            )
            .await;

        assert_matches!(res, Err(MlsError::ExternalCommitMustHaveNewLeaf));
    }

    #[maybe_async::test(not(mls_build_async), async(mls_build_async, crate::futures_test))]
    async fn proposal_cache_rejects_proposals_by_ref_for_new_member() {
        let mut cache = make_proposal_cache();
        let cipher_suite_provider = test_cipher_suite_provider(TEST_CIPHER_SUITE);

        let proposal = {
            let kem_output = vec![0; cipher_suite_provider.kdf_extract_size()];
            Proposal::ExternalInit(ExternalInit { kem_output })
        };

        let proposal_ref = make_proposal_ref(&proposal, test_sender()).await;

        cache.insert(
            proposal_ref.clone(),
            proposal,
            Sender::Member(test_sender()),
        );

        let group = test_group().await;
        let public_tree = &group.state.public_tree;

        let res = cache
            .resolve_for_commit_default(
                Sender::NewMemberCommit,
                vec![ProposalOrRef::Reference(proposal_ref)],
                Some(&test_node().await),
                &group.context().extensions,
                &BasicIdentityProvider,
                &cipher_suite_provider,
                public_tree,
                &[],
            )
            .await;

        assert_matches!(res, Err(MlsError::OnlyMembersCanCommitProposalsByRef));
    }

    #[maybe_async::test(not(mls_build_async), async(mls_build_async, crate::futures_test))]
    async fn proposal_cache_rejects_multiple_external_init_proposals_in_commit() {
        let cache = make_proposal_cache();
        let cipher_suite_provider = test_cipher_suite_provider(TEST_CIPHER_SUITE);
        let kem_output = vec![0; cipher_suite_provider.kdf_extract_size()];
        let group = test_group().await;
        let public_tree = &group.state.public_tree;

        let res = cache
            .resolve_for_commit_default(
                Sender::NewMemberCommit,
                [
                    Proposal::ExternalInit(ExternalInit {
                        kem_output: kem_output.clone(),
                    }),
                    Proposal::ExternalInit(ExternalInit { kem_output }),
                ]
                .into_iter()
                .map(|p| ProposalOrRef::Proposal(Box::new(p)))
                .collect(),
                Some(&test_node().await),
                &group.context().extensions,
                &BasicIdentityProvider,
                &cipher_suite_provider,
                public_tree,
                &[],
            )
            .await;

        assert_matches!(
            res,
            Err(MlsError::ExternalCommitMustHaveExactlyOneExternalInit)
        );
    }

    #[cfg_attr(not(mls_build_async), maybe_async::must_be_sync)]
    async fn new_member_commits_proposal(proposal: Proposal) -> Result<ProvisionalState, MlsError> {
        let cache = make_proposal_cache();
        let cipher_suite_provider = test_cipher_suite_provider(TEST_CIPHER_SUITE);
        let kem_output = vec![0; cipher_suite_provider.kdf_extract_size()];
        let group = test_group().await;
        let public_tree = &group.state.public_tree;

        cache
            .resolve_for_commit_default(
                Sender::NewMemberCommit,
                [
                    Proposal::ExternalInit(ExternalInit { kem_output }),
                    proposal,
                ]
                .into_iter()
                .map(|p| ProposalOrRef::Proposal(Box::new(p)))
                .collect(),
                Some(&test_node().await),
                &group.context().extensions,
                &BasicIdentityProvider,
                &cipher_suite_provider,
                public_tree,
                &[],
            )
            .await
    }

    #[maybe_async::test(not(mls_build_async), async(mls_build_async, crate::futures_test))]
    async fn new_member_cannot_commit_add_proposal() {
        let res = new_member_commits_proposal(Proposal::Add(Box::new(AddProposal {
            key_package: test_key_package(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE, "frank").await,
        })))
        .await;

        assert_matches!(
            res,
            Err(MlsError::InvalidProposalTypeInExternalCommit(
                ProposalType::ADD
            ))
        );
    }

    #[maybe_async::test(not(mls_build_async), async(mls_build_async, crate::futures_test))]
    async fn new_member_cannot_commit_more_than_one_remove_proposal() {
        let cache = make_proposal_cache();
        let cipher_suite_provider = test_cipher_suite_provider(TEST_CIPHER_SUITE);
        let kem_output = vec![0; cipher_suite_provider.kdf_extract_size()];
        let group = test_group().await;
        let group_extensions = group.context().extensions.clone();
        let mut public_tree = group.group.state.public_tree;

        let foo = get_basic_test_node(TEST_CIPHER_SUITE, "foo").await;

        let bar = get_basic_test_node(TEST_CIPHER_SUITE, "bar").await;

        let test_leaf_nodes = vec![foo, bar];

        let test_leaf_node_indexes = public_tree
            .add_leaves(
                test_leaf_nodes,
                &BasicIdentityProvider,
                &cipher_suite_provider,
            )
            .await
            .unwrap();

        let proposals = vec![
            Proposal::ExternalInit(ExternalInit { kem_output }),
            Proposal::Remove(RemoveProposal {
                to_remove: test_leaf_node_indexes[0],
            }),
            Proposal::Remove(RemoveProposal {
                to_remove: test_leaf_node_indexes[1],
            }),
        ];

        let res = cache
            .resolve_for_commit_default(
                Sender::NewMemberCommit,
                proposals
                    .into_iter()
                    .map(|p| ProposalOrRef::Proposal(Box::new(p)))
                    .collect(),
                Some(&test_node().await),
                &group_extensions,
                &BasicIdentityProvider,
                &cipher_suite_provider,
                &public_tree,
                &[],
            )
            .await;

        assert_matches!(res, Err(MlsError::ExternalCommitWithMoreThanOneRemove));
    }

    #[maybe_async::test(not(mls_build_async), async(mls_build_async, crate::futures_test))]
    async fn new_member_remove_proposal_invalid_credential() {
        let cache = make_proposal_cache();
        let cipher_suite_provider = test_cipher_suite_provider(TEST_CIPHER_SUITE);
        let kem_output = vec![0; cipher_suite_provider.kdf_extract_size()];
        let group = test_group().await;
        let group_extensions = group.context().extensions.clone();
        let mut public_tree = group.group.state.public_tree;

        let node = get_basic_test_node(TEST_CIPHER_SUITE, "bar").await;

        let test_leaf_nodes = vec![node];

        let test_leaf_node_indexes = public_tree
            .add_leaves(
                test_leaf_nodes,
                &BasicIdentityProvider,
                &cipher_suite_provider,
            )
            .await
            .unwrap();

        let proposals = vec![
            Proposal::ExternalInit(ExternalInit { kem_output }),
            Proposal::Remove(RemoveProposal {
                to_remove: test_leaf_node_indexes[0],
            }),
        ];

        let res = cache
            .resolve_for_commit_default(
                Sender::NewMemberCommit,
                proposals
                    .into_iter()
                    .map(|p| ProposalOrRef::Proposal(Box::new(p)))
                    .collect(),
                Some(&test_node().await),
                &group_extensions,
                &BasicIdentityProvider,
                &cipher_suite_provider,
                &public_tree,
                &[],
            )
            .await;

        assert_matches!(res, Err(MlsError::ExternalCommitRemovesOtherIdentity));
    }

    #[maybe_async::test(not(mls_build_async), async(mls_build_async, crate::futures_test))]
    async fn new_member_remove_proposal_valid_credential() {
        let cache = make_proposal_cache();
        let cipher_suite_provider = test_cipher_suite_provider(TEST_CIPHER_SUITE);
        let kem_output = vec![0; cipher_suite_provider.kdf_extract_size()];
        let group = test_group().await;
        let group_extensions = group.context().extensions.clone();
        let mut public_tree = group.group.state.public_tree;

        let node = get_basic_test_node(TEST_CIPHER_SUITE, "foo").await;

        let test_leaf_nodes = vec![node];

        let test_leaf_node_indexes = public_tree
            .add_leaves(
                test_leaf_nodes,
                &BasicIdentityProvider,
                &cipher_suite_provider,
            )
            .await
            .unwrap();

        let proposals = vec![
            Proposal::ExternalInit(ExternalInit { kem_output }),
            Proposal::Remove(RemoveProposal {
                to_remove: test_leaf_node_indexes[0],
            }),
        ];

        let res = cache
            .resolve_for_commit_default(
                Sender::NewMemberCommit,
                proposals
                    .into_iter()
                    .map(|p| ProposalOrRef::Proposal(Box::new(p)))
                    .collect(),
                Some(&test_node().await),
                &group_extensions,
                &BasicIdentityProvider,
                &cipher_suite_provider,
                &public_tree,
                &[],
            )
            .await;

        assert_matches!(res, Ok(_));
    }

    #[maybe_async::test(not(mls_build_async), async(mls_build_async, crate::futures_test))]
    async fn new_member_cannot_commit_update_proposal() {
        let res = new_member_commits_proposal(Proposal::Update(UpdateProposal {
            leaf_node: get_basic_test_node(TEST_CIPHER_SUITE, "foo").await,
        }))
        .await;

        assert_matches!(
            res,
            Err(MlsError::InvalidProposalTypeInExternalCommit(
                ProposalType::UPDATE
            ))
        );
    }

    #[maybe_async::test(not(mls_build_async), async(mls_build_async, crate::futures_test))]
    async fn new_member_cannot_commit_group_extensions_proposal() {
        let res =
            new_member_commits_proposal(Proposal::GroupContextExtensions(ExtensionList::new()))
                .await;

        assert_matches!(
            res,
            Err(MlsError::InvalidProposalTypeInExternalCommit(
                ProposalType::GROUP_CONTEXT_EXTENSIONS,
            ))
        );
    }

    #[maybe_async::test(not(mls_build_async), async(mls_build_async, crate::futures_test))]
    async fn new_member_cannot_commit_reinit_proposal() {
        let res = new_member_commits_proposal(Proposal::ReInit(ReInitProposal {
            group_id: b"foo".to_vec(),
            version: TEST_PROTOCOL_VERSION,
            cipher_suite: TEST_CIPHER_SUITE,
            extensions: ExtensionList::new(),
        }))
        .await;

        assert_matches!(
            res,
            Err(MlsError::InvalidProposalTypeInExternalCommit(
                ProposalType::RE_INIT
            ))
        );
    }

    #[maybe_async::test(not(mls_build_async), async(mls_build_async, crate::futures_test))]
    async fn new_member_commit_must_contain_an_external_init_proposal() {
        let cache = make_proposal_cache();
        let cipher_suite_provider = test_cipher_suite_provider(TEST_CIPHER_SUITE);
        let group = test_group().await;
        let public_tree = &group.state.public_tree;

        let res = cache
            .resolve_for_commit_default(
                Sender::NewMemberCommit,
                Vec::new(),
                Some(&test_node().await),
                &group.context().extensions,
                &BasicIdentityProvider,
                &cipher_suite_provider,
                public_tree,
                &[],
            )
            .await;

        assert_matches!(
            res,
            Err(MlsError::ExternalCommitMustHaveExactlyOneExternalInit)
        );
    }

    #[maybe_async::test(not(mls_build_async), async(mls_build_async, crate::futures_test))]
    async fn test_path_update_required_empty() {
        let cache = make_proposal_cache();

        let mut tree = TreeKemPublic::new();
        add_member(&mut tree, "alice").await;
        add_member(&mut tree, "bob").await;

        let effects = cache
            .prepare_commit_default(
                Sender::Member(test_sender()),
                vec![],
                &get_test_group_context(1, TEST_CIPHER_SUITE).await,
                &BasicIdentityProvider,
                &tree,
                &[],
            )
            .await
            .unwrap();

        assert!(path_update_required(&effects.applied_proposals))
    }

    #[maybe_async::test(not(mls_build_async), async(mls_build_async, crate::futures_test))]
    async fn test_path_update_required_updates() {
        let mut proposals = ProposalBundle::default();
        let sender = Sender::Member(2);
        let update = Proposal::Update(make_update_proposal("bar").await);
        let reference = ProposalSource::ByReference(make_proposal_ref(&update, sender)).await;
        proposals.add(update, sender, reference);

        assert!(path_update_required(&proposals))
    }

    #[maybe_async::test(not(mls_build_async), async(mls_build_async, crate::futures_test))]
    async fn test_path_update_required_removes() {
        let cache = make_proposal_cache();
        let cipher_suite_provider = test_cipher_suite_provider(TEST_CIPHER_SUITE);

        let (alice_leaf, alice_secret, _) =
            get_basic_test_node_sig_key(TEST_CIPHER_SUITE, "alice").await;
        let alice = 0;

        let (mut tree, _) = TreeKemPublic::derive(
            alice_leaf,
            alice_secret,
            &BasicIdentityProvider,
            &Default::default(),
        )
        .await
        .unwrap();

        let bob_node = get_basic_test_node(TEST_CIPHER_SUITE, "bob").await;

        let bob = tree
            .add_leaves(
                vec![bob_node],
                &BasicIdentityProvider,
                &cipher_suite_provider,
            )
            .await
            .unwrap()[0];

        let remove = Proposal::Remove(RemoveProposal { to_remove: bob });

        let effects = cache
            .prepare_commit_default(
                Sender::Member(alice),
                vec![remove],
                &get_test_group_context(1, TEST_CIPHER_SUITE).await,
                &BasicIdentityProvider,
                &tree,
                &[],
            )
            .await
            .unwrap();

        assert!(path_update_required(&effects.applied_proposals))
    }

    #[cfg(feature = "psk")]
    #[maybe_async::test(not(mls_build_async), async(mls_build_async, crate::futures_test))]
    async fn test_path_update_not_required() {
        let (alice, tree) = new_tree("alice").await;

        let cache = make_proposal_cache();
        let psk_id = JustPreSharedKeyID::External(ExternalPskId::new(vec![]));

        let psk = Proposal::Psk(PreSharedKeyProposal {
            psk: PreSharedKeyID::new(
                psk_id.clone(),
                &test_cipher_suite_provider(TEST_CIPHER_SUITE),
            )
            .unwrap(),
        });

        let add = Proposal::Add(Box::new(AddProposal {
            key_package: test_key_package(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE, "bob").await,
        }));

        let effects = cache
            .prepare_commit_default(
                Sender::Member(*alice),
                vec![psk, add],
                &get_test_group_context(1, TEST_CIPHER_SUITE).await,
                &BasicIdentityProvider,
                &tree,
                &[psk_id],
            )
            .await
            .unwrap();

        assert!(!path_update_required(&effects.applied_proposals))
    }

    #[maybe_async::test(not(mls_build_async), async(mls_build_async, crate::futures_test))]
    async fn path_update_is_not_required_for_re_init() {
        let (alice, tree) = new_tree("alice").await;
        let cache = make_proposal_cache();

        let reinit = Proposal::ReInit(ReInitProposal {
            group_id: vec![],
            version: TEST_PROTOCOL_VERSION,
            cipher_suite: TEST_CIPHER_SUITE,
            extensions: Default::default(),
        });

        let effects = cache
            .prepare_commit_default(
                Sender::Member(*alice),
                vec![reinit],
                &get_test_group_context(1, TEST_CIPHER_SUITE).await,
                &BasicIdentityProvider,
                &tree,
                &[],
            )
            .await
            .unwrap();

        assert!(!path_update_required(&effects.applied_proposals))
    }

    #[derive(Debug)]
    struct CommitSender<'a, C, CSP> {
        cipher_suite_provider: CSP,
        tree: &'a TreeKemPublic,
        sender: LeafIndex,
        cache: ProposalCache,
        additional_proposals: Vec<Proposal>,
        identity_provider: C,
        psks: Vec<JustPreSharedKeyID>,
    }
    impl<'a, CSP> CommitSender<'a, BasicWithCustomProvider, CSP> {
        fn new(tree: &'a TreeKemPublic, sender: LeafIndex, cipher_suite_provider: CSP) -> Self {
            Self {
                tree,
                sender,
                cache: make_proposal_cache(),
                additional_proposals: Vec::new(),
                identity_provider: BasicWithCustomProvider::new(BasicIdentityProvider::new()),
                psks: vec![],
                cipher_suite_provider,
            }
        }
    }

    impl<'a, C, CSP> CommitSender<'a, C, CSP>
    where
        C: IdentityProvider,
        CSP: CipherSuiteProvider,
    {
        fn with_identity_provider<V>(self, identity_provider: V) -> CommitSender<'a, V, CSP>
        where
            V: IdentityProvider,
        {
            CommitSender {
                identity_provider,
                cipher_suite_provider: self.cipher_suite_provider,
                tree: self.tree,
                sender: self.sender,
                cache: self.cache,
                additional_proposals: self.additional_proposals,
                psks: self.psks,
            }
        }

        fn with_additional<I>(mut self, proposals: I) -> Self
        where
            I: IntoIterator<Item = Proposal>,
        {
            self.additional_proposals.extend(proposals);
            self
        }

        fn with_psks(self, psks: Vec<JustPreSharedKeyID>) -> CommitSender<'a, C, CSP> {
            CommitSender { psks, ..self }
        }

        #[cfg_attr(not(mls_build_async), maybe_async::must_be_sync)]
        async fn send(&self) -> Result<(Vec<ProposalOrRef>, ProvisionalState), MlsError> {
            let state = self
                .cache
                .prepare_commit_default(
                    Sender::Member(*self.sender),
                    self.additional_proposals.clone(),
                    &get_test_group_context(1, TEST_CIPHER_SUITE).await,
                    &self.identity_provider,
                    self.tree,
                    &self.psks,
                )
                .await?;

            let proposals = state.applied_proposals.clone().proposals_or_refs();

            Ok((proposals, state))
        }
    }

    #[cfg_attr(not(mls_build_async), maybe_async::must_be_sync)]
    async fn key_package_with_invalid_signature() -> KeyPackage {
        let mut kp = test_key_package(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE, "mallory").await;
        kp.signature.clear();
        kp
    }

    #[cfg_attr(not(mls_build_async), maybe_async::must_be_sync)]
    async fn key_package_with_public_key(key: crypto::HpkePublicKey) -> KeyPackage {
        let cs = test_cipher_suite_provider(TEST_CIPHER_SUITE);

        let (mut key_package, signer) =
            test_key_package_with_signer(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE, "test").await;

        key_package.leaf_node.public_key = key;

        key_package
            .leaf_node
            .sign(
                &cs,
                &signer,
                &LeafNodeSigningContext {
                    group_id: None,
                    leaf_index: None,
                },
            )
            .await
            .unwrap();

        key_package.sign(&cs, &signer, &()).await.unwrap();

        key_package
    }

    #[maybe_async::test(not(mls_build_async), async(mls_build_async, crate::futures_test))]
    async fn receiving_add_with_invalid_key_package_fails() {
        let (alice, tree) = new_tree("alice").await;

        let res = CommitReceiver::new(
            &tree,
            alice,
            alice,
            test_cipher_suite_provider(TEST_CIPHER_SUITE),
        )
        .receive([Proposal::Add(Box::new(AddProposal {
            key_package: key_package_with_invalid_signature().await,
        }))])
        .await;

        assert_matches!(res, Err(MlsError::InvalidSignature));
    }

    #[maybe_async::test(not(mls_build_async), async(mls_build_async, crate::futures_test))]
    async fn sending_additional_add_with_invalid_key_package_fails() {
        let (alice, tree) = new_tree("alice").await;

        let res = CommitSender::new(&tree, alice, test_cipher_suite_provider(TEST_CIPHER_SUITE))
            .with_additional([Proposal::Add(Box::new(AddProposal {
                key_package: key_package_with_invalid_signature().await,
            }))])
            .send()
            .await;

        assert_matches!(res, Err(MlsError::InvalidSignature));
    }

    #[maybe_async::test(not(mls_build_async), async(mls_build_async, crate::futures_test))]
    async fn sending_add_with_hpke_key_of_another_member_fails() {
        let (alice, tree) = new_tree("alice").await;

        let res = CommitSender::new(&tree, alice, test_cipher_suite_provider(TEST_CIPHER_SUITE))
            .with_additional([Proposal::Add(Box::new(AddProposal {
                key_package: key_package_with_public_key(
                    tree.get_leaf_node(alice).unwrap().public_key.clone(),
                )
                .await,
            }))])
            .send()
            .await;

        assert_matches!(res, Err(MlsError::DuplicateLeafData(_)));
    }

    #[maybe_async::test(not(mls_build_async), async(mls_build_async, crate::futures_test))]
    async fn receiving_update_with_invalid_leaf_node_fails() {
        let (alice, mut tree) = new_tree("alice").await;
        let bob = add_member(&mut tree, "bob").await;

        let proposal = Proposal::Update(UpdateProposal {
            leaf_node: get_basic_test_node(TEST_CIPHER_SUITE, "alice").await,
        });

        let proposal_ref = make_proposal_ref(&proposal, bob).await;

        let res = CommitReceiver::new(
            &tree,
            alice,
            bob,
            test_cipher_suite_provider(TEST_CIPHER_SUITE),
        )
        .cache(proposal_ref.clone(), proposal, bob)
        .receive([proposal_ref])
        .await;

        assert_matches!(res, Err(MlsError::InvalidLeafNodeSource));
    }

    #[maybe_async::test(not(mls_build_async), async(mls_build_async, crate::futures_test))]
    async fn receiving_remove_with_invalid_index_fails() {
        let (alice, tree) = new_tree("alice").await;

        let res = CommitReceiver::new(
            &tree,
            alice,
            alice,
            test_cipher_suite_provider(TEST_CIPHER_SUITE),
        )
        .receive([Proposal::Remove(RemoveProposal {
            to_remove: LeafIndex(10),
        })])
        .await;

        assert_matches!(res, Err(MlsError::InvalidNodeIndex(20)));
    }

    #[maybe_async::test(not(mls_build_async), async(mls_build_async, crate::futures_test))]
    async fn sending_additional_remove_with_invalid_index_fails() {
        let (alice, tree) = new_tree("alice").await;

        let res = CommitSender::new(&tree, alice, test_cipher_suite_provider(TEST_CIPHER_SUITE))
            .with_additional([Proposal::Remove(RemoveProposal {
                to_remove: LeafIndex(10),
            })])
            .send()
            .await;

        assert_matches!(res, Err(MlsError::InvalidNodeIndex(20)));
    }

    #[cfg(feature = "psk")]
    fn make_external_psk(id: &[u8], nonce: PskNonce) -> PreSharedKeyProposal {
        PreSharedKeyProposal {
            psk: PreSharedKeyID {
                key_id: JustPreSharedKeyID::External(ExternalPskId::new(id.to_vec())),
                psk_nonce: nonce,
            },
        }
    }

    #[cfg(feature = "psk")]
    fn new_external_psk(id: &[u8]) -> PreSharedKeyProposal {
        make_external_psk(
            id,
            PskNonce::random(&test_cipher_suite_provider(TEST_CIPHER_SUITE)).unwrap(),
        )
    }

    #[cfg(feature = "psk")]
    #[maybe_async::test(not(mls_build_async), async(mls_build_async, crate::futures_test))]
    async fn receiving_psk_with_invalid_nonce_fails() {
        let invalid_nonce = PskNonce(vec![0, 1, 2]);
        let (alice, tree) = new_tree("alice").await;

        let res = CommitReceiver::new(
            &tree,
            alice,
            alice,
            test_cipher_suite_provider(TEST_CIPHER_SUITE),
        )
        .receive([Proposal::Psk(make_external_psk(
            b"foo",
            invalid_nonce.clone(),
        ))])
        .await;

        assert_matches!(res, Err(MlsError::InvalidPskNonceLength,));
    }

    #[cfg(feature = "psk")]
    #[maybe_async::test(not(mls_build_async), async(mls_build_async, crate::futures_test))]
    async fn sending_additional_psk_with_invalid_nonce_fails() {
        let invalid_nonce = PskNonce(vec![0, 1, 2]);
        let (alice, tree) = new_tree("alice").await;

        let res = CommitSender::new(&tree, alice, test_cipher_suite_provider(TEST_CIPHER_SUITE))
            .with_additional([Proposal::Psk(make_external_psk(
                b"foo",
                invalid_nonce.clone(),
            ))])
            .send()
            .await;

        assert_matches!(res, Err(MlsError::InvalidPskNonceLength));
    }

    #[cfg(feature = "psk")]
    fn make_resumption_psk(usage: ResumptionPSKUsage) -> PreSharedKeyProposal {
        PreSharedKeyProposal {
            psk: PreSharedKeyID {
                key_id: JustPreSharedKeyID::Resumption(ResumptionPsk {
                    usage,
                    psk_group_id: PskGroupId(TEST_GROUP.to_vec()),
                    psk_epoch: 1,
                }),
                psk_nonce: PskNonce::random(&test_cipher_suite_provider(TEST_CIPHER_SUITE))
                    .unwrap(),
            },
        }
    }

    #[cfg(feature = "psk")]
    #[cfg_attr(not(mls_build_async), maybe_async::must_be_sync)]
    async fn receiving_resumption_psk_with_bad_usage_fails(usage: ResumptionPSKUsage) {
        let (alice, tree) = new_tree("alice").await;

        let res = CommitReceiver::new(
            &tree,
            alice,
            alice,
            test_cipher_suite_provider(TEST_CIPHER_SUITE),
        )
        .receive([Proposal::Psk(make_resumption_psk(usage))])
        .await;

        assert_matches!(res, Err(MlsError::InvalidTypeOrUsageInPreSharedKeyProposal));
    }

    #[cfg(feature = "psk")]
    #[cfg_attr(not(mls_build_async), maybe_async::must_be_sync)]
    async fn sending_additional_resumption_psk_with_bad_usage_fails(usage: ResumptionPSKUsage) {
        let (alice, tree) = new_tree("alice").await;

        let res = CommitSender::new(&tree, alice, test_cipher_suite_provider(TEST_CIPHER_SUITE))
            .with_additional([Proposal::Psk(make_resumption_psk(usage))])
            .send()
            .await;

        assert_matches!(res, Err(MlsError::InvalidTypeOrUsageInPreSharedKeyProposal));
    }

    #[cfg(feature = "psk")]
    #[maybe_async::test(not(mls_build_async), async(mls_build_async, crate::futures_test))]
    async fn receiving_resumption_psk_with_reinit_usage_fails() {
        receiving_resumption_psk_with_bad_usage_fails(ResumptionPSKUsage::Reinit).await;
    }

    #[cfg(feature = "psk")]
    #[maybe_async::test(not(mls_build_async), async(mls_build_async, crate::futures_test))]
    async fn sending_additional_resumption_psk_with_reinit_usage_fails() {
        sending_additional_resumption_psk_with_bad_usage_fails(ResumptionPSKUsage::Reinit).await;
    }

    #[cfg(feature = "psk")]
    #[maybe_async::test(not(mls_build_async), async(mls_build_async, crate::futures_test))]
    async fn receiving_resumption_psk_with_branch_usage_fails() {
        receiving_resumption_psk_with_bad_usage_fails(ResumptionPSKUsage::Branch).await;
    }

    #[cfg(feature = "psk")]
    #[maybe_async::test(not(mls_build_async), async(mls_build_async, crate::futures_test))]
    async fn sending_additional_resumption_psk_with_branch_usage_fails() {
        sending_additional_resumption_psk_with_bad_usage_fails(ResumptionPSKUsage::Branch).await;
    }

    fn make_reinit(version: ProtocolVersion) -> ReInitProposal {
        ReInitProposal {
            group_id: TEST_GROUP.to_vec(),
            version,
            cipher_suite: TEST_CIPHER_SUITE,
            extensions: ExtensionList::new(),
        }
    }

    #[maybe_async::test(not(mls_build_async), async(mls_build_async, crate::futures_test))]
    async fn receiving_reinit_downgrading_version_fails() {
        let smaller_protocol_version = ProtocolVersion::from(0);
        let (alice, tree) = new_tree("alice").await;

        let res = CommitReceiver::new(
            &tree,
            alice,
            alice,
            test_cipher_suite_provider(TEST_CIPHER_SUITE),
        )
        .receive([Proposal::ReInit(make_reinit(smaller_protocol_version))])
        .await;

        assert_matches!(res, Err(MlsError::InvalidProtocolVersionInReInit));
    }

    #[maybe_async::test(not(mls_build_async), async(mls_build_async, crate::futures_test))]
    async fn sending_additional_reinit_downgrading_version_fails() {
        let smaller_protocol_version = ProtocolVersion::from(0);
        let (alice, tree) = new_tree("alice").await;

        let res = CommitSender::new(&tree, alice, test_cipher_suite_provider(TEST_CIPHER_SUITE))
            .with_additional([Proposal::ReInit(make_reinit(smaller_protocol_version))])
            .send()
            .await;

        assert_matches!(res, Err(MlsError::InvalidProtocolVersionInReInit));
    }

    #[maybe_async::test(not(mls_build_async), async(mls_build_async, crate::futures_test))]
    async fn receiving_update_for_committer_fails() {
        let (alice, tree) = new_tree("alice").await;
        let update = Proposal::Update(make_update_proposal("alice").await);
        let update_ref = make_proposal_ref(&update, alice).await;

        let res = CommitReceiver::new(
            &tree,
            alice,
            alice,
            test_cipher_suite_provider(TEST_CIPHER_SUITE),
        )
        .cache(update_ref.clone(), update, alice)
        .receive([update_ref])
        .await;

        assert_matches!(res, Err(MlsError::InvalidCommitSelfUpdate));
    }

    #[maybe_async::test(not(mls_build_async), async(mls_build_async, crate::futures_test))]
    async fn sending_additional_update_for_committer_fails() {
        let (alice, tree) = new_tree("alice").await;

        let res = CommitSender::new(&tree, alice, test_cipher_suite_provider(TEST_CIPHER_SUITE))
            .with_additional([Proposal::Update(make_update_proposal("alice").await)])
            .send()
            .await;

        assert_matches!(res, Err(MlsError::InvalidProposalTypeForSender));
    }

    #[maybe_async::test(not(mls_build_async), async(mls_build_async, crate::futures_test))]
    async fn receiving_remove_for_committer_fails() {
        let (alice, tree) = new_tree("alice").await;

        let res = CommitReceiver::new(
            &tree,
            alice,
            alice,
            test_cipher_suite_provider(TEST_CIPHER_SUITE),
        )
        .receive([Proposal::Remove(RemoveProposal { to_remove: alice })])
        .await;

        assert_matches!(res, Err(MlsError::CommitterSelfRemoval));
    }

    #[maybe_async::test(not(mls_build_async), async(mls_build_async, crate::futures_test))]
    async fn sending_additional_remove_for_committer_fails() {
        let (alice, tree) = new_tree("alice").await;

        let res = CommitSender::new(&tree, alice, test_cipher_suite_provider(TEST_CIPHER_SUITE))
            .with_additional([Proposal::Remove(RemoveProposal { to_remove: alice })])
            .send()
            .await;

        assert_matches!(res, Err(MlsError::CommitterSelfRemoval));
    }

    #[maybe_async::test(not(mls_build_async), async(mls_build_async, crate::futures_test))]
    async fn receiving_update_and_remove_for_same_leaf_fails() {
        let (alice, mut tree) = new_tree("alice").await;
        let bob = add_member(&mut tree, "bob").await;

        let update = Proposal::Update(make_update_proposal("bob").await);
        let update_ref = make_proposal_ref(&update, bob).await;

        let remove = Proposal::Remove(RemoveProposal { to_remove: bob });
        let remove_ref = make_proposal_ref(&remove, bob).await;

        let res = CommitReceiver::new(
            &tree,
            alice,
            alice,
            test_cipher_suite_provider(TEST_CIPHER_SUITE),
        )
        .cache(update_ref.clone(), update, bob)
        .cache(remove_ref.clone(), remove, bob)
        .receive([update_ref, remove_ref])
        .await;

        assert_matches!(res, Err(MlsError::UpdatingNonExistingMember));
    }

    #[cfg_attr(not(mls_build_async), maybe_async::must_be_sync)]
    async fn make_add_proposal() -> Box<AddProposal> {
        Box::new(AddProposal {
            key_package: test_key_package(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE, "frank").await,
        })
    }

    #[maybe_async::test(not(mls_build_async), async(mls_build_async, crate::futures_test))]
    async fn receiving_add_proposals_for_same_client_fails() {
        let (alice, tree) = new_tree("alice").await;

        let res = CommitReceiver::new(
            &tree,
            alice,
            alice,
            test_cipher_suite_provider(TEST_CIPHER_SUITE),
        )
        .receive([
            Proposal::Add(make_add_proposal().await),
            Proposal::Add(make_add_proposal().await),
        ])
        .await;

        assert_matches!(res, Err(MlsError::DuplicateLeafData(1)));
    }

    #[maybe_async::test(not(mls_build_async), async(mls_build_async, crate::futures_test))]
    async fn sending_additional_add_proposals_for_same_client_fails() {
        let (alice, tree) = new_tree("alice").await;

        let res = CommitSender::new(&tree, alice, test_cipher_suite_provider(TEST_CIPHER_SUITE))
            .with_additional([
                Proposal::Add(make_add_proposal().await),
                Proposal::Add(make_add_proposal().await),
            ])
            .send()
            .await;

        assert_matches!(res, Err(MlsError::DuplicateLeafData(1)));
    }

    #[maybe_async::test(not(mls_build_async), async(mls_build_async, crate::futures_test))]
    async fn receiving_update_for_different_identity_fails() {
        let (alice, mut tree) = new_tree("alice").await;
        let bob = add_member(&mut tree, "bob").await;

        let update = Proposal::Update(make_update_proposal_custom("carol", 1).await);
        let update_ref = make_proposal_ref(&update, bob).await;

        let res = CommitReceiver::new(
            &tree,
            alice,
            alice,
            test_cipher_suite_provider(TEST_CIPHER_SUITE),
        )
        .cache(update_ref.clone(), update, bob)
        .receive([update_ref])
        .await;

        assert_matches!(res, Err(MlsError::InvalidSuccessor));
    }

    #[maybe_async::test(not(mls_build_async), async(mls_build_async, crate::futures_test))]
    async fn receiving_add_for_same_client_as_existing_member_fails() {
        let (alice, public_tree) = new_tree("alice").await;
        let add = Proposal::Add(make_add_proposal().await);

        let ProvisionalState { public_tree, .. } = CommitReceiver::new(
            &public_tree,
            alice,
            alice,
            test_cipher_suite_provider(TEST_CIPHER_SUITE),
        )
        .receive([add.clone()])
        .await
        .unwrap();

        let res = CommitReceiver::new(
            &public_tree,
            alice,
            alice,
            test_cipher_suite_provider(TEST_CIPHER_SUITE),
        )
        .receive([add])
        .await;

        assert_matches!(res, Err(MlsError::DuplicateLeafData(1)));
    }

    #[maybe_async::test(not(mls_build_async), async(mls_build_async, crate::futures_test))]
    async fn sending_additional_add_for_same_client_as_existing_member_fails() {
        let (alice, public_tree) = new_tree("alice").await;
        let add = Proposal::Add(make_add_proposal().await);

        let ProvisionalState { public_tree, .. } = CommitReceiver::new(
            &public_tree,
            alice,
            alice,
            test_cipher_suite_provider(TEST_CIPHER_SUITE),
        )
        .receive([add.clone()])
        .await
        .unwrap();

        let res = CommitSender::new(
            &public_tree,
            alice,
            test_cipher_suite_provider(TEST_CIPHER_SUITE),
        )
        .with_additional([add])
        .send()
        .await;

        assert_matches!(res, Err(MlsError::DuplicateLeafData(1)));
    }

    #[cfg(feature = "psk")]
    #[maybe_async::test(not(mls_build_async), async(mls_build_async, crate::futures_test))]
    async fn receiving_psk_proposals_with_same_psk_id_fails() {
        let (alice, tree) = new_tree("alice").await;
        let psk_proposal = Proposal::Psk(new_external_psk(b"foo"));

        let res = CommitReceiver::new(
            &tree,
            alice,
            alice,
            test_cipher_suite_provider(TEST_CIPHER_SUITE),
        )
        .with_psks(vec![JustPreSharedKeyID::External(b"foo".to_vec().into())])
        .receive([psk_proposal.clone(), psk_proposal])
        .await;

        assert_matches!(res, Err(MlsError::DuplicatePskIds));
    }

    #[cfg(feature = "psk")]
    #[maybe_async::test(not(mls_build_async), async(mls_build_async, crate::futures_test))]
    async fn sending_additional_psk_proposals_with_same_psk_id_fails() {
        let (alice, tree) = new_tree("alice").await;
        let psk_proposal = Proposal::Psk(new_external_psk(b"foo"));

        let res = CommitSender::new(&tree, alice, test_cipher_suite_provider(TEST_CIPHER_SUITE))
            .with_psks(vec![JustPreSharedKeyID::External(b"foo".to_vec().into())])
            .with_additional([psk_proposal.clone(), psk_proposal])
            .send()
            .await;

        assert_matches!(res, Err(MlsError::DuplicatePskIds));
    }

    #[maybe_async::test(not(mls_build_async), async(mls_build_async, crate::futures_test))]
    async fn receiving_multiple_group_context_extensions_fails() {
        let (alice, tree) = new_tree("alice").await;

        let res = CommitReceiver::new(
            &tree,
            alice,
            alice,
            test_cipher_suite_provider(TEST_CIPHER_SUITE),
        )
        .receive([
            Proposal::GroupContextExtensions(ExtensionList::new()),
            Proposal::GroupContextExtensions(ExtensionList::new()),
        ])
        .await;

        assert_matches!(
            res,
            Err(MlsError::MoreThanOneGroupContextExtensionsProposal)
        );
    }

    #[maybe_async::test(not(mls_build_async), async(mls_build_async, crate::futures_test))]
    async fn sending_multiple_additional_group_context_extensions_fails() {
        let (alice, tree) = new_tree("alice").await;

        let res = CommitSender::new(&tree, alice, test_cipher_suite_provider(TEST_CIPHER_SUITE))
            .with_additional([
                Proposal::GroupContextExtensions(ExtensionList::new()),
                Proposal::GroupContextExtensions(ExtensionList::new()),
            ])
            .send()
            .await;

        assert_matches!(
            res,
            Err(MlsError::MoreThanOneGroupContextExtensionsProposal)
        );
    }

    fn make_extension_list(something: u8) -> ExtensionList {
        vec![TestExtension { foo: something }.into_extension().unwrap()].into()
    }

    #[cfg_attr(not(mls_build_async), maybe_async::must_be_sync)]
    async fn make_external_senders_extension() -> ExtensionList {
        let identity = get_test_signing_identity(TEST_CIPHER_SUITE, b"alice")
            .await
            .0;

        vec![ExternalSendersExt::new(vec![identity])
            .into_extension()
            .unwrap()]
        .into()
    }

    #[maybe_async::test(not(mls_build_async), async(mls_build_async, crate::futures_test))]
    async fn receiving_invalid_external_senders_extension_fails() {
        let (alice, tree) = new_tree("alice").await;

        let res = CommitReceiver::new(
            &tree,
            alice,
            alice,
            test_cipher_suite_provider(TEST_CIPHER_SUITE),
        )
        .with_identity_provider(FailureIdentityProvider::new())
        .receive([Proposal::GroupContextExtensions(
            make_external_senders_extension().await,
        )])
        .await;

        assert_matches!(res, Err(MlsError::IdentityProviderError(_)));
    }

    #[maybe_async::test(not(mls_build_async), async(mls_build_async, crate::futures_test))]
    async fn sending_additional_invalid_external_senders_extension_fails() {
        let (alice, tree) = new_tree("alice").await;

        let res = CommitSender::new(&tree, alice, test_cipher_suite_provider(TEST_CIPHER_SUITE))
            .with_identity_provider(FailureIdentityProvider::new())
            .with_additional([Proposal::GroupContextExtensions(
                make_external_senders_extension().await,
            )])
            .send()
            .await;

        assert_matches!(res, Err(MlsError::IdentityProviderError(_)));
    }

    #[maybe_async::test(not(mls_build_async), async(mls_build_async, crate::futures_test))]
    async fn receiving_reinit_with_other_proposals_fails() {
        let (alice, tree) = new_tree("alice").await;

        let res = CommitReceiver::new(
            &tree,
            alice,
            alice,
            test_cipher_suite_provider(TEST_CIPHER_SUITE),
        )
        .receive([
            Proposal::ReInit(make_reinit(TEST_PROTOCOL_VERSION)),
            Proposal::Add(make_add_proposal().await),
        ])
        .await;

        assert_matches!(res, Err(MlsError::OtherProposalWithReInit));
    }

    #[maybe_async::test(not(mls_build_async), async(mls_build_async, crate::futures_test))]
    async fn sending_additional_reinit_with_other_proposals_fails() {
        let (alice, tree) = new_tree("alice").await;

        let res = CommitSender::new(&tree, alice, test_cipher_suite_provider(TEST_CIPHER_SUITE))
            .with_additional([
                Proposal::ReInit(make_reinit(TEST_PROTOCOL_VERSION)),
                Proposal::Add(make_add_proposal().await),
            ])
            .send()
            .await;

        assert_matches!(res, Err(MlsError::OtherProposalWithReInit));
    }

    #[maybe_async::test(not(mls_build_async), async(mls_build_async, crate::futures_test))]
    async fn receiving_multiple_reinits_fails() {
        let (alice, tree) = new_tree("alice").await;

        let res = CommitReceiver::new(
            &tree,
            alice,
            alice,
            test_cipher_suite_provider(TEST_CIPHER_SUITE),
        )
        .receive([
            Proposal::ReInit(make_reinit(TEST_PROTOCOL_VERSION)),
            Proposal::ReInit(make_reinit(TEST_PROTOCOL_VERSION)),
        ])
        .await;

        assert_matches!(res, Err(MlsError::OtherProposalWithReInit));
    }

    #[maybe_async::test(not(mls_build_async), async(mls_build_async, crate::futures_test))]
    async fn sending_additional_multiple_reinits_fails() {
        let (alice, tree) = new_tree("alice").await;

        let res = CommitSender::new(&tree, alice, test_cipher_suite_provider(TEST_CIPHER_SUITE))
            .with_additional([
                Proposal::ReInit(make_reinit(TEST_PROTOCOL_VERSION)),
                Proposal::ReInit(make_reinit(TEST_PROTOCOL_VERSION)),
            ])
            .send()
            .await;

        assert_matches!(res, Err(MlsError::OtherProposalWithReInit));
    }

    fn make_external_init() -> ExternalInit {
        ExternalInit {
            kem_output: vec![33; test_cipher_suite_provider(TEST_CIPHER_SUITE).kdf_extract_size()],
        }
    }

    #[maybe_async::test(not(mls_build_async), async(mls_build_async, crate::futures_test))]
    async fn receiving_external_init_from_member_fails() {
        let (alice, tree) = new_tree("alice").await;

        let res = CommitReceiver::new(
            &tree,
            alice,
            alice,
            test_cipher_suite_provider(TEST_CIPHER_SUITE),
        )
        .receive([Proposal::ExternalInit(make_external_init())])
        .await;

        assert_matches!(res, Err(MlsError::InvalidProposalTypeForSender));
    }

    #[maybe_async::test(not(mls_build_async), async(mls_build_async, crate::futures_test))]
    async fn sending_additional_external_init_from_member_fails() {
        let (alice, tree) = new_tree("alice").await;

        let res = CommitSender::new(&tree, alice, test_cipher_suite_provider(TEST_CIPHER_SUITE))
            .with_additional([Proposal::ExternalInit(make_external_init())])
            .send()
            .await;

        assert_matches!(res, Err(MlsError::InvalidProposalTypeForSender));
    }

    fn required_capabilities_proposal(extension: u16) -> Proposal {
        let required_capabilities = RequiredCapabilitiesExt {
            extensions: vec![extension.into()],
            ..Default::default()
        };

        let ext = vec![required_capabilities.into_extension().unwrap()];

        Proposal::GroupContextExtensions(ext.into())
    }

    #[maybe_async::test(not(mls_build_async), async(mls_build_async, crate::futures_test))]
    async fn receiving_required_capabilities_not_supported_by_member_fails() {
        let (alice, tree) = new_tree("alice").await;

        let res = CommitReceiver::new(
            &tree,
            alice,
            alice,
            test_cipher_suite_provider(TEST_CIPHER_SUITE),
        )
        .receive([required_capabilities_proposal(33)])
        .await;

        assert_matches!(
            res,
            Err(MlsError::RequiredExtensionNotFound(v)) if v == 33.into()
        );
    }

    #[maybe_async::test(not(mls_build_async), async(mls_build_async, crate::futures_test))]
    async fn sending_required_capabilities_not_supported_by_member_fails() {
        let (alice, tree) = new_tree("alice").await;

        let res = CommitSender::new(&tree, alice, test_cipher_suite_provider(TEST_CIPHER_SUITE))
            .with_additional([required_capabilities_proposal(33)])
            .send()
            .await;

        assert_matches!(
            res,
            Err(MlsError::RequiredExtensionNotFound(v)) if v == 33.into()
        );
    }

    #[cfg_attr(not(mls_build_async), maybe_async::must_be_sync)]
    async fn unsupported_credential_key_package(name: &str) -> KeyPackage {
        let (client, _) = test_client(name).await;

        let mut kp_builder = client.key_package_builder(None).unwrap();

        kp_builder.signing_data.signing_identity.credential =
            Credential::Custom(CustomCredential::new(
                CredentialType::new(BasicWithCustomProvider::CUSTOM_CREDENTIAL_TYPE),
                vec![0u8; 32],
            ));

        kp_builder.capabilities.credentials = vec![42.into()];

        kp_builder
            .build()
            .await
            .unwrap()
            .key_package_message
            .into_key_package()
            .unwrap()
    }

    #[maybe_async::test(not(mls_build_async), async(mls_build_async, crate::futures_test))]
    async fn receiving_add_with_leaf_not_supporting_credential_type_of_other_leaf_fails() {
        let (alice, tree) = new_tree("alice").await;

        let res = CommitReceiver::new(
            &tree,
            alice,
            alice,
            test_cipher_suite_provider(TEST_CIPHER_SUITE),
        )
        .receive([Proposal::Add(Box::new(AddProposal {
            key_package: unsupported_credential_key_package("bob").await,
        }))])
        .await;

        assert_matches!(res, Err(MlsError::InUseCredentialTypeUnsupportedByNewLeaf));
    }

    #[maybe_async::test(not(mls_build_async), async(mls_build_async, crate::futures_test))]
    async fn sending_additional_add_with_leaf_not_supporting_credential_type_of_other_leaf_fails() {
        let (alice, tree) = new_tree("alice").await;

        let res = CommitSender::new(&tree, alice, test_cipher_suite_provider(TEST_CIPHER_SUITE))
            .with_additional([Proposal::Add(Box::new(AddProposal {
                key_package: unsupported_credential_key_package("bob").await,
            }))])
            .send()
            .await;

        assert_matches!(res, Err(MlsError::InUseCredentialTypeUnsupportedByNewLeaf));
    }

    #[cfg(feature = "custom_proposal")]
    #[maybe_async::test(not(mls_build_async), async(mls_build_async, crate::futures_test))]
    async fn sending_custom_proposal_with_member_not_supporting_proposal_type_fails() {
        let (alice, tree) = new_tree("alice").await;

        let custom_proposal = Proposal::Custom(CustomProposal::new(ProposalType::new(42), vec![]));

        let res = CommitSender::new(&tree, alice, test_cipher_suite_provider(TEST_CIPHER_SUITE))
            .with_additional([custom_proposal.clone()])
            .send()
            .await;

        assert_matches!(
            res,
            Err(
                MlsError::UnsupportedCustomProposal(c)
            ) if c == custom_proposal.proposal_type()
        );
    }

    #[cfg(feature = "custom_proposal")]
    #[maybe_async::test(not(mls_build_async), async(mls_build_async, crate::futures_test))]
    async fn sending_custom_proposal_with_member_not_supporting_fails() {
        let (alice, tree) = new_tree("alice").await;

        let proposal_type = ProposalType::new(42);
        let custom_proposal = Proposal::Custom(CustomProposal::new(proposal_type, vec![]));

        let res = CommitSender::new(&tree, alice, test_cipher_suite_provider(TEST_CIPHER_SUITE))
            .with_additional(vec![custom_proposal])
            .send()
            .await;

        assert_matches!(
            res,
            Err(MlsError::UnsupportedCustomProposal(c)) if c == proposal_type
        );
    }

    #[cfg(feature = "custom_proposal")]
    #[maybe_async::test(not(mls_build_async), async(mls_build_async, crate::futures_test))]
    async fn receiving_custom_proposal_with_member_not_supporting_fails() {
        let (alice, tree) = new_tree("alice").await;

        let custom_proposal = Proposal::Custom(CustomProposal::new(ProposalType::new(42), vec![]));

        let res = CommitReceiver::new(
            &tree,
            alice,
            alice,
            test_cipher_suite_provider(TEST_CIPHER_SUITE),
        )
        .receive([custom_proposal.clone()])
        .await;

        assert_matches!(
            res,
            Err(MlsError::UnsupportedCustomProposal(c)) if c == custom_proposal.proposal_type()
        );
    }

    #[maybe_async::test(not(mls_build_async), async(mls_build_async, crate::futures_test))]
    async fn receiving_group_extension_unsupported_by_leaf_fails() {
        let (alice, tree) = new_tree("alice").await;

        let res = CommitReceiver::new(
            &tree,
            alice,
            alice,
            test_cipher_suite_provider(TEST_CIPHER_SUITE),
        )
        .receive([Proposal::GroupContextExtensions(make_extension_list(0))])
        .await;

        assert_matches!(
            res,
            Err(
                MlsError::UnsupportedGroupExtension(v)
            ) if v == 42.into()
        );
    }

    #[maybe_async::test(not(mls_build_async), async(mls_build_async, crate::futures_test))]
    async fn sending_additional_group_extension_unsupported_by_leaf_fails() {
        let (alice, tree) = new_tree("alice").await;

        let res = CommitSender::new(&tree, alice, test_cipher_suite_provider(TEST_CIPHER_SUITE))
            .with_additional([Proposal::GroupContextExtensions(make_extension_list(0))])
            .send()
            .await;

        assert_matches!(
            res,
            Err(
                MlsError::UnsupportedGroupExtension(v)
            ) if v == 42.into()
        );
    }

    #[cfg(feature = "psk")]
    #[maybe_async::test(not(mls_build_async), async(mls_build_async, crate::futures_test))]
    async fn receiving_external_psk_with_unknown_id_fails() {
        let (alice, tree) = new_tree("alice").await;

        let res = CommitReceiver::new(
            &tree,
            alice,
            alice,
            test_cipher_suite_provider(TEST_CIPHER_SUITE),
        )
        .with_psks(vec![])
        .receive([Proposal::Psk(new_external_psk(b"abc"))])
        .await;

        assert_matches!(res, Err(MlsError::MissingRequiredPsk));
    }

    #[cfg(feature = "psk")]
    #[maybe_async::test(not(mls_build_async), async(mls_build_async, crate::futures_test))]
    async fn sending_additional_external_psk_with_unknown_id_fails() {
        let (alice, tree) = new_tree("alice").await;

        let res = CommitSender::new(&tree, alice, test_cipher_suite_provider(TEST_CIPHER_SUITE))
            .with_psks(vec![])
            .with_additional([Proposal::Psk(new_external_psk(b"abc"))])
            .send()
            .await;

        assert_matches!(res, Err(MlsError::MissingRequiredPsk));
    }

    #[maybe_async::test(not(mls_build_async), async(mls_build_async, crate::futures_test))]
    async fn by_ref_proposers_are_verified() {
        let (alice, mut tree) = new_tree("alice").await;
        let bob = add_member(&mut tree, "bob").await;

        let identity = get_test_signing_identity(TEST_CIPHER_SUITE, b"carol")
            .await
            .0;

        let external_senders = ExternalSendersExt::new(vec![identity]);

        let proposals: &[Proposal] = &[
            Proposal::Add(make_add_proposal().await),
            Proposal::Update(make_update_proposal("alice").await),
            Proposal::Remove(RemoveProposal { to_remove: bob }),
            #[cfg(feature = "psk")]
            Proposal::Psk(make_external_psk(
                b"ted",
                PskNonce::random(&test_cipher_suite_provider(TEST_CIPHER_SUITE)).unwrap(),
            )),
            Proposal::ReInit(make_reinit(TEST_PROTOCOL_VERSION)),
            Proposal::ExternalInit(make_external_init()),
            Proposal::GroupContextExtensions(Default::default()),
        ];

        let proposers = [
            Sender::Member(*alice),
            Sender::External(0),
            Sender::NewMemberCommit,
            Sender::NewMemberProposal,
        ];

        for (proposer, proposal) in proposers.into_iter().cartesian_product(proposals) {
            let committer = Sender::Member(*alice);

            let receiver = CommitReceiver::new(
                &tree,
                committer,
                alice,
                test_cipher_suite_provider(TEST_CIPHER_SUITE),
            )
            .with_psks(vec![JustPreSharedKeyID::External(b"ted".to_vec().into())]);

            let extensions: ExtensionList =
                vec![external_senders.clone().into_extension().unwrap()].into();

            let receiver = receiver.with_extensions(extensions);

            let proposal_ref = make_proposal_ref(proposal, proposer).await;
            let receiver = receiver.cache(proposal_ref.clone(), proposal.clone(), proposer);
            let proposals = vec![ProposalOrRef::from(proposal_ref.clone())];
            let source = ProposalSource::ByReference(proposal_ref);

            let res = receiver.receive(proposals).await;

            if proposer_can_propose(proposer, proposal.proposal_type(), &source).is_err() {
                assert_matches!(res, Err(MlsError::InvalidProposalTypeForSender));
            } else {
                let is_self_update = proposal.proposal_type() == ProposalType::UPDATE
                    && matches!(proposer, Sender::Member(_));

                if !is_self_update {
                    res.unwrap();
                }
            }
        }
    }

    #[cfg_attr(not(mls_build_async), maybe_async::must_be_sync)]
    async fn make_update_proposal(name: &str) -> UpdateProposal {
        UpdateProposal {
            leaf_node: update_leaf_node(name, 1).await,
        }
    }

    #[cfg_attr(not(mls_build_async), maybe_async::must_be_sync)]
    async fn make_update_proposal_custom(name: &str, leaf_index: u32) -> UpdateProposal {
        UpdateProposal {
            leaf_node: update_leaf_node(name, leaf_index).await,
        }
    }
}
