use super::*;
use crate::{
    group::proposal_filter::{ProposalApplier, ProposalBundle, ProposalRules, ProposalSource},
    time::MlsTime,
};

#[cfg(feature = "by_ref_proposal")]
use crate::group::proposal_filter::FilterStrategy;

#[cfg(feature = "external_commit")]
use crate::tree_kem::leaf_node::LeafNode;

#[cfg(all(feature = "std", feature = "by_ref_proposal"))]
use std::collections::HashMap;

use aws_mls_core::{error::IntoAnyError, psk::PreSharedKeyStorage};

#[cfg(feature = "by_ref_proposal")]
#[derive(Debug, Clone, MlsSize, MlsEncode, MlsDecode, PartialEq)]
pub struct CachedProposal {
    proposal: Proposal,
    sender: Sender,
}

#[cfg(feature = "by_ref_proposal")]
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct ProposalCache {
    protocol_version: ProtocolVersion,
    group_id: Vec<u8>,
    #[cfg(feature = "std")]
    pub(crate) proposals: HashMap<ProposalRef, CachedProposal>,
    #[cfg(not(feature = "std"))]
    pub(crate) proposals: Vec<(ProposalRef, CachedProposal)>,
}

#[cfg(feature = "by_ref_proposal")]
impl ProposalCache {
    pub fn new(protocol_version: ProtocolVersion, group_id: Vec<u8>) -> Self {
        Self {
            protocol_version,
            group_id,
            proposals: Default::default(),
        }
    }

    pub fn import(
        protocol_version: ProtocolVersion,
        group_id: Vec<u8>,
        #[cfg(feature = "std")] proposals: HashMap<ProposalRef, CachedProposal>,
        #[cfg(not(feature = "std"))] proposals: Vec<(ProposalRef, CachedProposal)>,
    ) -> Self {
        Self {
            protocol_version,
            group_id,
            proposals,
        }
    }

    #[inline]
    pub fn clear(&mut self) {
        self.proposals.clear();
    }

    #[cfg(feature = "private_message")]
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

    pub fn prepare_commit(
        &self,
        sender: Sender,
        additional_proposals: Vec<Proposal>,
    ) -> Result<ProposalBundle, MlsError> {
        let mut proposals = ProposalBundle::default();

        for (r, p) in &self.proposals {
            proposals.add(
                p.proposal.clone(),
                p.sender,
                ProposalSource::ByReference(r.clone()),
            )?;
        }

        for p in additional_proposals.into_iter() {
            proposals.add(p, sender, ProposalSource::ByValue)?;
        }

        Ok(proposals)
    }

    pub fn resolve_for_commit(
        &self,
        sender: Sender,
        proposal_list: Vec<ProposalOrRef>,
    ) -> Result<ProposalBundle, MlsError> {
        let mut proposals = ProposalBundle::default();

        for p in proposal_list {
            match p {
                ProposalOrRef::Proposal(p) => proposals.add(*p, sender, ProposalSource::ByValue)?,
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

                    proposals.add(p.proposal, p.sender, ProposalSource::ByReference(r))?;
                }
            };
        }

        Ok(proposals)
    }
}

#[cfg(not(feature = "by_ref_proposal"))]
pub(crate) fn prepare_commit(
    sender: Sender,
    additional_proposals: Vec<Proposal>,
) -> Result<ProposalBundle, MlsError> {
    let mut proposals = ProposalBundle::default();

    for p in additional_proposals.into_iter() {
        proposals.add(p, sender, ProposalSource::ByValue)?;
    }

    Ok(proposals)
}

#[cfg(not(feature = "by_ref_proposal"))]
pub(crate) fn resolve_for_commit(
    sender: Sender,
    proposal_list: Vec<ProposalOrRef>,
) -> Result<ProposalBundle, MlsError> {
    let mut proposals = ProposalBundle::default();

    for p in proposal_list {
        let ProposalOrRef::Proposal(p) = p;
        proposals.add(*p, sender, ProposalSource::ByValue)?;
    }

    Ok(proposals)
}

impl GroupState {
    #[inline(never)]
    #[allow(clippy::too_many_arguments)]
    #[maybe_async::maybe_async]
    pub(crate) async fn apply_resolved<C, F, P, CSP>(
        &self,
        sender: Sender,
        #[cfg(all(feature = "by_ref_proposal", feature = "state_update"))] receiver: Option<Sender>,
        proposals: ProposalBundle,
        #[cfg(feature = "external_commit")] external_leaf: Option<&LeafNode>,
        identity_provider: &C,
        cipher_suite_provider: &CSP,
        psk_storage: &P,
        user_rules: F,
        commit_time: Option<MlsTime>,
        #[cfg(feature = "by_ref_proposal")] for_prepare_commit: bool,
    ) -> Result<ProvisionalState, MlsError>
    where
        C: IdentityProvider,
        F: ProposalRules,
        P: PreSharedKeyStorage,
        CSP: CipherSuiteProvider,
    {
        let roster = self.roster();
        let group_extensions = &self.context.extensions;

        #[cfg(all(feature = "by_ref_proposal", feature = "state_update"))]
        let all_proposals = proposals.clone();

        #[cfg(feature = "by_ref_proposal")]
        let mut proposals = proposals;

        #[cfg(feature = "by_ref_proposal")]
        if for_prepare_commit {
            proposals = user_rules
                .filter(sender, &roster, group_extensions, proposals)
                .await
                .map_err(|e| MlsError::UserDefinedProposalFilterError(e.into_any_error()))?;
        } else {
            user_rules
                .validate(sender, &roster, group_extensions, &proposals)
                .await
                .map_err(|e| MlsError::UserDefinedProposalFilterError(e.into_any_error()))?;
        }

        #[cfg(not(feature = "by_ref_proposal"))]
        user_rules
            .validate(sender, &roster, group_extensions, &proposals)
            .await
            .map_err(|e| MlsError::UserDefinedProposalFilterError(e.into_any_error()))?;

        #[cfg(feature = "custom_proposal")]
        let mut proposals = proposals;

        #[cfg(feature = "custom_proposal")]
        expand_custom_proposals(&roster, group_extensions, &mut proposals, &user_rules).await?;

        let applier = ProposalApplier::new(
            &self.public_tree,
            self.context.protocol_version,
            cipher_suite_provider,
            group_extensions,
            #[cfg(feature = "external_commit")]
            external_leaf,
            identity_provider,
            psk_storage,
            #[cfg(feature = "by_ref_proposal")]
            &self.context.group_id,
        );

        #[cfg(feature = "by_ref_proposal")]
        let applier_output = if for_prepare_commit {
            applier
                .apply_proposals(FilterStrategy::IgnoreByRef, &sender, proposals, commit_time)
                .await?
        } else {
            applier
                .apply_proposals(FilterStrategy::IgnoreNone, &sender, proposals, commit_time)
                .await?
        };

        #[cfg(not(feature = "by_ref_proposal"))]
        let applier_output = applier
            .apply_proposals(&sender, &proposals, commit_time)
            .await?;

        #[cfg(all(feature = "by_ref_proposal", feature = "state_update"))]
        let rejected_proposals = receiver
            .map(|sender| {
                rejected_proposals(all_proposals, &applier_output.applied_proposals, &sender)
            })
            .unwrap_or_default();

        let mut group_context = self.context.clone();
        group_context.epoch += 1;

        #[cfg(feature = "by_ref_proposal")]
        if let Some(ext) = applier_output
            .applied_proposals
            .group_context_extensions_proposal()
        {
            group_context.extensions = ext.proposal.clone();
        }

        #[cfg(feature = "by_ref_proposal")]
        let proposals = applier_output.applied_proposals;

        Ok(ProvisionalState {
            public_tree: applier_output.new_tree,
            group_context,
            applied_proposals: proposals,
            #[cfg(feature = "external_commit")]
            external_init_index: applier_output.external_init_index,
            indexes_of_added_kpkgs: applier_output.indexes_of_added_kpkgs,
            #[cfg(all(feature = "by_ref_proposal", feature = "state_update"))]
            rejected_proposals,
        })
    }
}

#[cfg(feature = "custom_proposal")]
#[maybe_async::maybe_async]
pub async fn expand_custom_proposals<F>(
    roster: &[Member],
    group_extensions: &ExtensionList,
    proposal_bundle: &mut ProposalBundle,
    user_rules: &F,
) -> Result<(), MlsError>
where
    F: ProposalRules,
{
    let new_proposals = user_rules
        .expand_custom_proposals(roster, group_extensions, proposal_bundle.custom_proposals())
        .await
        .map_err(|e| MlsError::UserDefinedProposalFilterError(e.into_any_error()))?;

    for info in new_proposals {
        proposal_bundle.add(info.proposal, info.sender, info.source)?;
    }

    Ok(())
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

#[cfg(all(feature = "by_ref_proposal", feature = "state_update"))]
fn has_ref(proposals: &ProposalBundle, reference: &ProposalRef) -> bool {
    proposals
        .iter_proposals()
        .any(|p| matches!(&p.source, ProposalSource::ByReference(r) if r == reference))
}

#[cfg(all(feature = "by_ref_proposal", feature = "state_update"))]
fn rejected_proposals(
    all_proposals: ProposalBundle,
    accepted_proposals: &ProposalBundle,
    sender: &Sender,
) -> Vec<(ProposalRef, Proposal)> {
    all_proposals
        .into_proposals()
        .filter_map(|p| match p.source {
            ProposalSource::ByReference(r)
                if !has_ref(accepted_proposals, &r) && &p.sender == sender =>
            {
                Some((r, p.proposal))
            }
            _ => None,
        })
        .collect()
}

// TODO add tests for lite version of filtering
#[cfg(all(feature = "by_ref_proposal", test))]
pub(crate) mod test_utils {
    use aws_mls_core::{
        crypto::CipherSuiteProvider, extension::ExtensionList, identity::IdentityProvider,
        psk::PreSharedKeyStorage,
    };

    use crate::{
        client::test_utils::TEST_PROTOCOL_VERSION,
        group::{
            confirmation_tag::ConfirmationTag,
            internal::{LeafIndex, LeafNode, ProvisionalState, TreeKemPublic},
            proposal::{Proposal, ProposalOrRef},
            proposal_filter::{PassThroughProposalRules, ProposalRules},
            proposal_ref::ProposalRef,
            state::GroupState,
            test_utils::{get_test_group_context, TEST_GROUP},
            GroupContext, Sender,
        },
        identity::{basic::BasicIdentityProvider, test_utils::BasicWithCustomProvider},
        psk::AlwaysFoundPskStorage,
    };

    use super::{CachedProposal, MlsError, ProposalCache};

    use alloc::vec::Vec;

    impl CachedProposal {
        pub fn new(proposal: Proposal, sender: Sender) -> Self {
            Self { proposal, sender }
        }
    }

    #[derive(Debug)]
    pub(crate) struct CommitReceiver<'a, C, F, P, CSP> {
        tree: &'a TreeKemPublic,
        sender: Sender,
        receiver: LeafIndex,
        cache: ProposalCache,
        identity_provider: C,
        cipher_suite_provider: CSP,
        group_context_extensions: ExtensionList,
        user_rules: F,
        with_psk_storage: P,
    }

    impl<'a, CSP>
        CommitReceiver<
            'a,
            BasicWithCustomProvider,
            PassThroughProposalRules,
            AlwaysFoundPskStorage,
            CSP,
        >
    {
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
                user_rules: pass_through_rules(),
                with_psk_storage: AlwaysFoundPskStorage,
                cipher_suite_provider,
            }
        }
    }

    impl<'a, C, F, P, CSP> CommitReceiver<'a, C, F, P, CSP>
    where
        C: IdentityProvider,
        F: ProposalRules,
        P: PreSharedKeyStorage,
        CSP: CipherSuiteProvider,
    {
        #[cfg(feature = "external_proposal")]
        pub fn with_identity_provider<V>(self, validator: V) -> CommitReceiver<'a, V, F, P, CSP>
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
                user_rules: self.user_rules,
                with_psk_storage: self.with_psk_storage,
                cipher_suite_provider: self.cipher_suite_provider,
            }
        }

        pub fn with_user_rules<G>(self, f: G) -> CommitReceiver<'a, C, G, P, CSP>
        where
            G: ProposalRules,
        {
            CommitReceiver {
                tree: self.tree,
                sender: self.sender,
                receiver: self.receiver,
                cache: self.cache,
                identity_provider: self.identity_provider,
                group_context_extensions: self.group_context_extensions,
                user_rules: f,
                with_psk_storage: self.with_psk_storage,
                cipher_suite_provider: self.cipher_suite_provider,
            }
        }

        pub fn with_psk_storage<V>(self, v: V) -> CommitReceiver<'a, C, F, V, CSP>
        where
            V: PreSharedKeyStorage,
        {
            CommitReceiver {
                tree: self.tree,
                sender: self.sender,
                receiver: self.receiver,
                cache: self.cache,
                identity_provider: self.identity_provider,
                group_context_extensions: self.group_context_extensions,
                user_rules: self.user_rules,
                with_psk_storage: v,
                cipher_suite_provider: self.cipher_suite_provider,
            }
        }

        #[cfg(feature = "external_proposal")]
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

        #[maybe_async::maybe_async]
        pub async fn receive<I>(&self, proposals: I) -> Result<ProvisionalState, MlsError>
        where
            I: IntoIterator,
            I::Item: Into<ProposalOrRef>,
        {
            self.cache
                .resolve_for_commit_default(
                    self.sender,
                    #[cfg(feature = "state_update")]
                    Some(self.receiver),
                    proposals.into_iter().map(Into::into).collect(),
                    None,
                    &self.group_context_extensions,
                    &self.identity_provider,
                    &self.cipher_suite_provider,
                    self.tree,
                    &self.with_psk_storage,
                    &self.user_rules,
                )
                .await
        }
    }

    pub(crate) fn make_proposal_cache() -> ProposalCache {
        ProposalCache::new(TEST_PROTOCOL_VERSION, TEST_GROUP.to_vec())
    }

    pub fn pass_through_rules() -> PassThroughProposalRules {
        PassThroughProposalRules::new()
    }

    impl ProposalCache {
        #[allow(clippy::too_many_arguments)]
        #[maybe_async::maybe_async]
        pub async fn resolve_for_commit_default<C, F, P, CSP>(
            &self,
            sender: Sender,
            #[cfg(feature = "state_update")] receiver: Option<LeafIndex>,
            proposal_list: Vec<ProposalOrRef>,
            external_leaf: Option<&LeafNode>,
            group_extensions: &ExtensionList,
            identity_provider: &C,
            cipher_suite_provider: &CSP,
            public_tree: &TreeKemPublic,
            psk_storage: &P,
            user_rules: F,
        ) -> Result<ProvisionalState, MlsError>
        where
            C: IdentityProvider,
            F: ProposalRules,
            P: PreSharedKeyStorage,
            CSP: CipherSuiteProvider,
        {
            let mut context = get_test_group_context(123, cipher_suite_provider.cipher_suite());
            context.extensions = group_extensions.clone();

            let state = GroupState::new(
                context,
                public_tree.clone(),
                Vec::new().into(),
                ConfirmationTag::empty(cipher_suite_provider),
            );

            let proposals = self.resolve_for_commit(sender, proposal_list)?;

            state
                .apply_resolved(
                    sender,
                    #[cfg(all(feature = "by_ref_proposal", feature = "state_update"))]
                    receiver.map(|l| Sender::Member(*l)),
                    proposals,
                    #[cfg(feature = "external_commit")]
                    external_leaf,
                    identity_provider,
                    cipher_suite_provider,
                    psk_storage,
                    user_rules,
                    None,
                    false,
                )
                .await
        }

        #[allow(clippy::too_many_arguments)]
        #[maybe_async::maybe_async]
        pub async fn prepare_commit_default<C, F, P, CSP>(
            &self,
            sender: Sender,
            additional_proposals: Vec<Proposal>,
            context: &GroupContext,
            identity_provider: &C,
            cipher_suite_provider: &CSP,
            public_tree: &TreeKemPublic,
            #[cfg(feature = "external_commit")] external_leaf: Option<&LeafNode>,
            psk_storage: &P,
            user_rules: F,
        ) -> Result<ProvisionalState, MlsError>
        where
            C: IdentityProvider,
            F: ProposalRules,
            P: PreSharedKeyStorage,
            CSP: CipherSuiteProvider,
        {
            let state = GroupState::new(
                context.clone(),
                public_tree.clone(),
                Vec::new().into(),
                ConfirmationTag::empty(cipher_suite_provider),
            );

            let proposals = self.prepare_commit(sender, additional_proposals)?;

            state
                .apply_resolved(
                    sender,
                    #[cfg(all(feature = "by_ref_proposal", feature = "state_update"))]
                    Some(sender),
                    proposals,
                    #[cfg(feature = "external_commit")]
                    external_leaf,
                    identity_provider,
                    cipher_suite_provider,
                    psk_storage,
                    user_rules,
                    None,
                    true,
                )
                .await
        }
    }
}

// TODO add tests for lite version of filtering
#[cfg(all(feature = "by_ref_proposal", test))]
mod tests {
    use super::test_utils::{pass_through_rules, CommitReceiver};
    use super::*;
    use super::{
        proposal_ref::test_utils::auth_content_from_proposal, test_utils::make_proposal_cache,
    };
    use crate::key_package::KeyPackageGeneration;
    use crate::tree_kem::leaf_node::test_utils::{
        get_basic_test_node_capabilities, get_test_capabilities,
    };
    use crate::tree_kem::leaf_node::LeafNodeSigningContext;
    use crate::{
        client::test_utils::{TEST_CIPHER_SUITE, TEST_PROTOCOL_VERSION},
        crypto::{self, test_utils::test_cipher_suite_provider},
        extension::test_utils::TestExtension,
        group::{
            message_processor::path_update_required,
            proposal_filter::proposer_can_propose,
            test_utils::{random_bytes, test_group, TEST_GROUP},
        },
        identity::basic::BasicIdentityProvider,
        identity::test_utils::{get_test_signing_identity, BasicWithCustomProvider},
        key_package::{
            test_utils::{test_key_package, test_key_package_custom},
            KeyPackageGenerator,
        },
        psk::AlwaysFoundPskStorage,
        tree_kem::{
            leaf_node::{
                test_utils::{
                    default_properties, get_basic_test_node, get_basic_test_node_sig_key,
                },
                ConfigProperties, LeafNodeSource,
            },
            Lifetime,
        },
    };

    #[cfg(feature = "all_extensions")]
    use crate::extension::RequiredCapabilitiesExt;

    #[cfg(feature = "external_proposal")]
    use crate::{
        extension::ExternalSendersExt,
        tree_kem::leaf_node_validator::test_utils::FailureIdentityProvider,
    };

    use assert_matches::assert_matches;
    use aws_mls_core::psk::PreSharedKey;
    use aws_mls_core::{
        extension::MlsExtension,
        identity::{Credential, CredentialType, CustomCredential},
    };
    use core::convert::Infallible;
    use internal::proposal_filter::{PassThroughProposalRules, ProposalInfo};
    use internal::test_utils::get_test_group_context;
    use itertools::Itertools;

    #[cfg(not(sync))]
    use futures::FutureExt;

    fn test_sender() -> u32 {
        1
    }

    #[maybe_async::maybe_async]
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

        let (pub_tree, priv_tree) = TreeKemPublic::derive(leaf, secret, &BasicIdentityProvider)
            .await
            .unwrap();

        (priv_tree.self_index, pub_tree)
    }

    #[maybe_async::maybe_async]
    async fn new_tree(name: &str) -> (LeafIndex, TreeKemPublic) {
        new_tree_custom_proposals(name, vec![]).await
    }

    #[maybe_async::maybe_async]
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

    #[maybe_async::maybe_async]
    async fn update_leaf_node(name: &str, leaf_index: u32) -> LeafNode {
        let (mut leaf, _, signer) = get_basic_test_node_sig_key(TEST_CIPHER_SUITE, name).await;

        leaf.update(
            &test_cipher_suite_provider(TEST_CIPHER_SUITE),
            TEST_GROUP,
            leaf_index,
            default_properties(),
            None,
            &signer,
        )
        .unwrap();

        leaf
    }

    struct TestProposals {
        test_sender: u32,
        test_proposals: Vec<AuthenticatedContent>,
        expected_effects: ProvisionalState,
        tree: TreeKemPublic,
    }

    #[maybe_async::maybe_async]
    async fn test_proposals(
        protocol_version: ProtocolVersion,
        cipher_suite: CipherSuite,
    ) -> TestProposals {
        let cipher_suite_provider = test_cipher_suite_provider(cipher_suite);

        let (sender_leaf, sender_leaf_secret, _) =
            get_basic_test_node_sig_key(cipher_suite, "alice").await;

        let sender = LeafIndex(0);

        let (mut tree, _) =
            TreeKemPublic::derive(sender_leaf, sender_leaf_secret, &BasicIdentityProvider)
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
            let pref = ProposalRef::from_content(&cipher_suite_provider, &plaintext[i]).unwrap();

            bundle
                .add(
                    proposals[i].clone(),
                    Sender::Member(test_sender),
                    ProposalSource::ByReference(pref),
                )
                .unwrap();
        }

        expected_tree
            .batch_edit(
                &mut bundle,
                &BasicIdentityProvider,
                &cipher_suite_provider,
                true,
            )
            .await
            .unwrap();

        let expected_effects = ProvisionalState {
            public_tree: expected_tree,
            group_context: get_test_group_context(1, cipher_suite),
            #[cfg(feature = "external_commit")]
            external_init_index: None,
            indexes_of_added_kpkgs: vec![LeafIndex(1)],
            #[cfg(feature = "state_update")]
            rejected_proposals: vec![],
            applied_proposals: bundle,
        };

        TestProposals {
            test_sender,
            test_proposals: plaintext,
            expected_effects,
            tree,
        }
    }

    fn filter_proposals(
        cipher_suite: CipherSuite,
        proposals: Vec<AuthenticatedContent>,
    ) -> impl Iterator<Item = (ProposalRef, CachedProposal)> {
        proposals
            .into_iter()
            .filter_map(move |p| match &p.content.content {
                Content::Proposal(proposal) => {
                    let proposal_ref =
                        ProposalRef::from_content(&test_cipher_suite_provider(cipher_suite), &p)
                            .unwrap();
                    Some((
                        proposal_ref,
                        CachedProposal::new(proposal.as_ref().clone(), p.content.sender),
                    ))
                }
                _ => None,
            })
    }

    fn make_proposal_ref<S>(p: &Proposal, sender: S) -> ProposalRef
    where
        S: Into<Sender>,
    {
        ProposalRef::from_content(
            &test_cipher_suite_provider(TEST_CIPHER_SUITE),
            &auth_content_from_proposal(p.clone(), sender),
        )
        .unwrap()
    }

    fn test_proposal_cache_setup(proposals: Vec<AuthenticatedContent>) -> ProposalCache {
        let mut cache = make_proposal_cache();
        cache.extend(filter_proposals(TEST_CIPHER_SUITE, proposals));
        cache
    }

    fn assert_matches(mut expected_state: ProvisionalState, state: ProvisionalState) {
        let expected_proposals = expected_state.applied_proposals.into_proposals_or_refs();
        let proposals = state.applied_proposals.into_proposals_or_refs();

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

        #[cfg(feature = "external_commit")]
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

        #[cfg(feature = "state_update")]
        assert_eq!(expected_state.rejected_proposals, state.rejected_proposals);
    }

    #[maybe_async::test(sync, async(not(sync), crate::futures_test))]
    async fn test_proposal_cache_commit_all_cached() {
        let cipher_suite_provider = test_cipher_suite_provider(TEST_CIPHER_SUITE);

        let TestProposals {
            test_sender,
            test_proposals,
            expected_effects,
            tree,
            ..
        } = test_proposals(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE).await;

        let cache = test_proposal_cache_setup(test_proposals.clone());

        let provisional_state = cache
            .prepare_commit_default(
                Sender::Member(test_sender),
                vec![],
                &get_test_group_context(0, TEST_CIPHER_SUITE),
                &BasicIdentityProvider,
                &cipher_suite_provider,
                &tree,
                #[cfg(feature = "external_commit")]
                None,
                &AlwaysFoundPskStorage,
                pass_through_rules(),
            )
            .await
            .unwrap();

        assert_matches(expected_effects, provisional_state)
    }

    #[maybe_async::test(sync, async(not(sync), crate::futures_test))]
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

        let cache = test_proposal_cache_setup(test_proposals.clone());

        let provisional_state = cache
            .prepare_commit_default(
                Sender::Member(test_sender),
                vec![Proposal::Add(Box::new(additional.clone()))],
                &get_test_group_context(0, TEST_CIPHER_SUITE),
                &BasicIdentityProvider,
                &cipher_suite_provider,
                &tree,
                #[cfg(feature = "external_commit")]
                None,
                &AlwaysFoundPskStorage,
                pass_through_rules(),
            )
            .await
            .unwrap();

        expected_effects
            .applied_proposals
            .add(
                Proposal::Add(Box::new(additional.clone())),
                Sender::Member(test_sender),
                ProposalSource::ByValue,
            )
            .unwrap();

        let leaf = vec![additional_key_package.leaf_node.clone()];

        expected_effects
            .public_tree
            .add_leaves(leaf, &BasicIdentityProvider, &cipher_suite_provider)
            .await
            .unwrap();

        expected_effects.indexes_of_added_kpkgs.push(LeafIndex(3));

        assert_matches(expected_effects, provisional_state);
    }

    #[maybe_async::test(sync, async(not(sync), crate::futures_test))]
    async fn test_proposal_cache_update_filter() {
        let cipher_suite_provider = test_cipher_suite_provider(TEST_CIPHER_SUITE);

        let TestProposals {
            test_proposals,
            tree,
            ..
        } = test_proposals(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE).await;

        let update_proposal = make_update_proposal("foo").await;

        let additional = vec![Proposal::Update(update_proposal)];

        let cache = test_proposal_cache_setup(test_proposals);

        let res = cache
            .prepare_commit_default(
                Sender::Member(test_sender()),
                additional,
                &get_test_group_context(0, TEST_CIPHER_SUITE),
                &BasicIdentityProvider,
                &cipher_suite_provider,
                &tree,
                #[cfg(feature = "external_commit")]
                None,
                &AlwaysFoundPskStorage,
                pass_through_rules(),
            )
            .await;

        assert_matches!(res, Err(MlsError::InvalidProposalTypeForSender));
    }

    #[maybe_async::test(sync, async(not(sync), crate::futures_test))]
    async fn test_proposal_cache_removal_override_update() {
        let cipher_suite_provider = test_cipher_suite_provider(TEST_CIPHER_SUITE);

        let TestProposals {
            test_sender,
            test_proposals,
            tree,
            ..
        } = test_proposals(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE).await;

        let update = Proposal::Update(make_update_proposal("foo").await);
        let update_proposal_ref = make_proposal_ref(&update, LeafIndex(1));
        let mut cache = test_proposal_cache_setup(test_proposals);

        cache.insert(update_proposal_ref.clone(), update, Sender::Member(1));

        let provisional_state = cache
            .prepare_commit_default(
                Sender::Member(test_sender),
                vec![],
                &get_test_group_context(0, TEST_CIPHER_SUITE),
                &BasicIdentityProvider,
                &cipher_suite_provider,
                &tree,
                #[cfg(feature = "external_commit")]
                None,
                &AlwaysFoundPskStorage,
                pass_through_rules(),
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
            .into_proposals_or_refs()
            .contains(&ProposalOrRef::Reference(update_proposal_ref)))
    }

    #[maybe_async::test(sync, async(not(sync), crate::futures_test))]
    async fn test_proposal_cache_filter_duplicates_insert() {
        let cipher_suite_provider = test_cipher_suite_provider(TEST_CIPHER_SUITE);

        let TestProposals {
            test_sender,
            test_proposals,
            expected_effects,
            tree,
            ..
        } = test_proposals(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE).await;

        let mut cache = test_proposal_cache_setup(test_proposals.clone());
        cache.extend(filter_proposals(TEST_CIPHER_SUITE, test_proposals.clone()));

        let provisional_state = cache
            .prepare_commit_default(
                Sender::Member(test_sender),
                vec![],
                &get_test_group_context(0, TEST_CIPHER_SUITE),
                &BasicIdentityProvider,
                &cipher_suite_provider,
                &tree,
                #[cfg(feature = "external_commit")]
                None,
                &AlwaysFoundPskStorage,
                pass_through_rules(),
            )
            .await
            .unwrap();

        assert_matches(expected_effects, provisional_state)
    }

    #[maybe_async::test(sync, async(not(sync), crate::futures_test))]
    async fn test_proposal_cache_filter_duplicates_additional() {
        let cipher_suite_provider = test_cipher_suite_provider(TEST_CIPHER_SUITE);

        let TestProposals {
            test_proposals,
            expected_effects,
            tree,
            ..
        } = test_proposals(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE).await;

        let mut cache = test_proposal_cache_setup(test_proposals.clone());

        // Updates from different senders will be allowed so we test duplicates for add / remove
        let additional = test_proposals
            .clone()
            .into_iter()
            .filter_map(|plaintext| match plaintext.content.content {
                Content::Proposal(p) if p.proposal_type() == ProposalType::UPDATE => None,
                Content::Proposal(_) => Some(plaintext),
                _ => None,
            })
            .collect::<Vec<_>>();

        cache.extend(filter_proposals(TEST_CIPHER_SUITE, additional));

        let provisional_state = cache
            .prepare_commit_default(
                Sender::Member(2),
                Vec::new(),
                &get_test_group_context(0, TEST_CIPHER_SUITE),
                &BasicIdentityProvider,
                &cipher_suite_provider,
                &tree,
                #[cfg(feature = "external_commit")]
                None,
                &AlwaysFoundPskStorage,
                pass_through_rules(),
            )
            .await
            .unwrap();

        assert_matches(expected_effects, provisional_state)
    }

    #[cfg(feature = "private_message")]
    #[maybe_async::test(sync, async(not(sync), crate::futures_test))]
    async fn test_proposal_cache_is_empty() {
        let mut cache = make_proposal_cache();
        assert!(cache.is_empty());

        let test_proposal = Proposal::Remove(RemoveProposal {
            to_remove: LeafIndex(test_sender()),
        });

        let proposer = test_sender();
        let test_proposal_ref = make_proposal_ref(&test_proposal, LeafIndex(proposer));
        cache.insert(test_proposal_ref, test_proposal, Sender::Member(proposer));

        assert!(!cache.is_empty())
    }

    #[maybe_async::test(sync, async(not(sync), crate::futures_test))]
    async fn test_proposal_cache_resolve() {
        let cipher_suite_provider = test_cipher_suite_provider(TEST_CIPHER_SUITE);

        let TestProposals {
            test_sender,
            test_proposals,
            tree,
            ..
        } = test_proposals(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE).await;

        let cache = test_proposal_cache_setup(test_proposals);

        let proposal = Proposal::Add(Box::new(AddProposal {
            key_package: test_key_package(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE, "frank").await,
        }));

        let additional = vec![proposal];

        let expected_effects = cache
            .prepare_commit_default(
                Sender::Member(test_sender),
                additional,
                &get_test_group_context(0, TEST_CIPHER_SUITE),
                &BasicIdentityProvider,
                &cipher_suite_provider,
                &tree,
                #[cfg(feature = "external_commit")]
                None,
                &AlwaysFoundPskStorage,
                pass_through_rules(),
            )
            .await
            .unwrap();

        let proposals = expected_effects
            .applied_proposals
            .clone()
            .into_proposals_or_refs();

        let resolution = cache
            .resolve_for_commit_default(
                Sender::Member(test_sender),
                #[cfg(feature = "state_update")]
                Some(LeafIndex(test_sender)),
                proposals,
                None,
                &ExtensionList::new(),
                &BasicIdentityProvider,
                &cipher_suite_provider,
                &tree,
                &AlwaysFoundPskStorage,
                pass_through_rules(),
            )
            .await
            .unwrap();

        assert_matches(expected_effects, resolution);
    }

    #[cfg(feature = "psk")]
    #[maybe_async::test(sync, async(not(sync), crate::futures_test))]
    async fn proposal_cache_filters_duplicate_psk_ids() {
        let cipher_suite_provider = test_cipher_suite_provider(TEST_CIPHER_SUITE);

        let (alice, tree) = new_tree("alice").await;
        let cache = make_proposal_cache();

        let proposal = Proposal::Psk(make_external_psk(
            b"ted",
            PskNonce::random(&test_cipher_suite_provider(TEST_CIPHER_SUITE)).unwrap(),
        ));

        let res = cache
            .prepare_commit_default(
                Sender::Member(*alice),
                vec![proposal.clone(), proposal],
                &get_test_group_context(0, TEST_CIPHER_SUITE),
                &BasicIdentityProvider,
                &cipher_suite_provider,
                &tree,
                #[cfg(feature = "external_commit")]
                None,
                &AlwaysFoundPskStorage,
                pass_through_rules(),
            )
            .await;

        assert_matches!(res, Err(MlsError::DuplicatePskIds));
    }

    #[maybe_async::maybe_async]
    async fn test_node() -> LeafNode {
        let (mut leaf_node, _, signer) =
            get_basic_test_node_sig_key(TEST_CIPHER_SUITE, "foo").await;

        leaf_node
            .commit(
                &test_cipher_suite_provider(TEST_CIPHER_SUITE),
                TEST_GROUP,
                0,
                default_properties(),
                None,
                &signer,
            )
            .unwrap();

        leaf_node
    }

    #[cfg(feature = "external_commit")]
    #[maybe_async::test(sync, async(not(sync), crate::futures_test))]
    async fn external_commit_must_have_new_leaf() {
        let cache = make_proposal_cache();
        let cipher_suite_provider = test_cipher_suite_provider(TEST_CIPHER_SUITE);

        let kem_output = vec![0; cipher_suite_provider.kdf_extract_size()];
        let group = test_group(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE).await;
        let public_tree = &group.group.state.public_tree;

        let res = cache
            .resolve_for_commit_default(
                Sender::NewMemberCommit,
                #[cfg(feature = "state_update")]
                None,
                vec![ProposalOrRef::Proposal(Box::new(Proposal::ExternalInit(
                    ExternalInit { kem_output },
                )))],
                None,
                &group.group.context().extensions,
                &BasicIdentityProvider,
                &cipher_suite_provider,
                public_tree,
                &AlwaysFoundPskStorage,
                pass_through_rules(),
            )
            .await;

        assert_matches!(res, Err(MlsError::ExternalCommitMustHaveNewLeaf));
    }

    #[cfg(feature = "external_commit")]
    #[maybe_async::test(sync, async(not(sync), crate::futures_test))]
    async fn proposal_cache_rejects_proposals_by_ref_for_new_member() {
        let mut cache = make_proposal_cache();
        let cipher_suite_provider = test_cipher_suite_provider(TEST_CIPHER_SUITE);

        let proposal = {
            let kem_output = vec![0; cipher_suite_provider.kdf_extract_size()];
            Proposal::ExternalInit(ExternalInit { kem_output })
        };

        let proposal_ref = make_proposal_ref(&proposal, test_sender());

        cache.insert(
            proposal_ref.clone(),
            proposal,
            Sender::Member(test_sender()),
        );

        let group = test_group(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE).await;
        let public_tree = &group.group.state.public_tree;

        let res = cache
            .resolve_for_commit_default(
                Sender::NewMemberCommit,
                #[cfg(feature = "state_update")]
                None,
                vec![ProposalOrRef::Reference(proposal_ref)],
                Some(&test_node().await),
                &group.group.context().extensions,
                &BasicIdentityProvider,
                &cipher_suite_provider,
                public_tree,
                &AlwaysFoundPskStorage,
                pass_through_rules(),
            )
            .await;

        assert_matches!(res, Err(MlsError::OnlyMembersCanCommitProposalsByRef));
    }

    #[cfg(feature = "external_commit")]
    #[maybe_async::test(sync, async(not(sync), crate::futures_test))]
    async fn proposal_cache_rejects_multiple_external_init_proposals_in_commit() {
        let cache = make_proposal_cache();
        let cipher_suite_provider = test_cipher_suite_provider(TEST_CIPHER_SUITE);
        let kem_output = vec![0; cipher_suite_provider.kdf_extract_size()];
        let group = test_group(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE).await;
        let public_tree = &group.group.state.public_tree;

        let res = cache
            .resolve_for_commit_default(
                Sender::NewMemberCommit,
                #[cfg(feature = "state_update")]
                None,
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
                &group.group.context().extensions,
                &BasicIdentityProvider,
                &cipher_suite_provider,
                public_tree,
                &AlwaysFoundPskStorage,
                pass_through_rules(),
            )
            .await;

        assert_matches!(
            res,
            Err(MlsError::ExternalCommitMustHaveExactlyOneExternalInit)
        );
    }

    #[cfg(feature = "external_commit")]
    #[maybe_async::maybe_async]
    async fn new_member_commits_proposal(proposal: Proposal) -> Result<ProvisionalState, MlsError> {
        let cache = make_proposal_cache();
        let cipher_suite_provider = test_cipher_suite_provider(TEST_CIPHER_SUITE);
        let kem_output = vec![0; cipher_suite_provider.kdf_extract_size()];
        let group = test_group(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE).await;
        let public_tree = &group.group.state.public_tree;

        cache
            .resolve_for_commit_default(
                Sender::NewMemberCommit,
                #[cfg(feature = "state_update")]
                None,
                [
                    Proposal::ExternalInit(ExternalInit { kem_output }),
                    proposal,
                ]
                .into_iter()
                .map(|p| ProposalOrRef::Proposal(Box::new(p)))
                .collect(),
                Some(&test_node().await),
                &group.group.context().extensions,
                &BasicIdentityProvider,
                &cipher_suite_provider,
                public_tree,
                &AlwaysFoundPskStorage,
                pass_through_rules(),
            )
            .await
    }

    #[cfg(feature = "external_commit")]
    #[maybe_async::test(sync, async(not(sync), crate::futures_test))]
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

    #[cfg(feature = "external_commit")]
    #[maybe_async::test(sync, async(not(sync), crate::futures_test))]
    async fn new_member_cannot_commit_more_than_one_remove_proposal() {
        let cache = make_proposal_cache();
        let cipher_suite_provider = test_cipher_suite_provider(TEST_CIPHER_SUITE);
        let kem_output = vec![0; cipher_suite_provider.kdf_extract_size()];
        let group = test_group(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE).await;
        let group_extensions = group.group.context().extensions.clone();
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
                #[cfg(feature = "state_update")]
                None,
                proposals
                    .into_iter()
                    .map(|p| ProposalOrRef::Proposal(Box::new(p)))
                    .collect(),
                Some(&test_node().await),
                &group_extensions,
                &BasicIdentityProvider,
                &cipher_suite_provider,
                &public_tree,
                &AlwaysFoundPskStorage,
                pass_through_rules(),
            )
            .await;

        assert_matches!(res, Err(MlsError::ExternalCommitWithMoreThanOneRemove));
    }

    #[cfg(feature = "external_commit")]
    #[maybe_async::test(sync, async(not(sync), crate::futures_test))]
    async fn new_member_remove_proposal_invalid_credential() {
        let cache = make_proposal_cache();
        let cipher_suite_provider = test_cipher_suite_provider(TEST_CIPHER_SUITE);
        let kem_output = vec![0; cipher_suite_provider.kdf_extract_size()];
        let group = test_group(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE).await;
        let group_extensions = group.group.context().extensions.clone();
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
                #[cfg(feature = "state_update")]
                None,
                proposals
                    .into_iter()
                    .map(|p| ProposalOrRef::Proposal(Box::new(p)))
                    .collect(),
                Some(&test_node().await),
                &group_extensions,
                &BasicIdentityProvider,
                &cipher_suite_provider,
                &public_tree,
                &AlwaysFoundPskStorage,
                pass_through_rules(),
            )
            .await;

        assert_matches!(res, Err(MlsError::ExternalCommitRemovesOtherIdentity));
    }

    #[cfg(feature = "external_commit")]
    #[maybe_async::test(sync, async(not(sync), crate::futures_test))]
    async fn new_member_remove_proposal_valid_credential() {
        let cache = make_proposal_cache();
        let cipher_suite_provider = test_cipher_suite_provider(TEST_CIPHER_SUITE);
        let kem_output = vec![0; cipher_suite_provider.kdf_extract_size()];
        let group = test_group(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE).await;
        let group_extensions = group.group.context().extensions.clone();
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
                #[cfg(feature = "state_update")]
                None,
                proposals
                    .into_iter()
                    .map(|p| ProposalOrRef::Proposal(Box::new(p)))
                    .collect(),
                Some(&test_node().await),
                &group_extensions,
                &BasicIdentityProvider,
                &cipher_suite_provider,
                &public_tree,
                &AlwaysFoundPskStorage,
                pass_through_rules(),
            )
            .await;

        assert_matches!(res, Ok(_));
    }

    #[cfg(feature = "external_commit")]
    #[maybe_async::test(sync, async(not(sync), crate::futures_test))]
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

    #[cfg(feature = "external_commit")]
    #[maybe_async::test(sync, async(not(sync), crate::futures_test))]
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

    #[cfg(feature = "external_commit")]
    #[maybe_async::test(sync, async(not(sync), crate::futures_test))]
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

    #[cfg(feature = "external_commit")]
    #[maybe_async::test(sync, async(not(sync), crate::futures_test))]
    async fn new_member_commit_must_contain_an_external_init_proposal() {
        let cache = make_proposal_cache();
        let cipher_suite_provider = test_cipher_suite_provider(TEST_CIPHER_SUITE);
        let group = test_group(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE).await;
        let public_tree = &group.group.state.public_tree;

        let res = cache
            .resolve_for_commit_default(
                Sender::NewMemberCommit,
                #[cfg(feature = "state_update")]
                None,
                Vec::new(),
                Some(&test_node().await),
                &group.group.context().extensions,
                &BasicIdentityProvider,
                &cipher_suite_provider,
                public_tree,
                &AlwaysFoundPskStorage,
                pass_through_rules(),
            )
            .await;

        assert_matches!(
            res,
            Err(MlsError::ExternalCommitMustHaveExactlyOneExternalInit)
        );
    }

    #[maybe_async::test(sync, async(not(sync), crate::futures_test))]
    async fn test_path_update_required_empty() {
        let cache = make_proposal_cache();
        let cipher_suite_provider = test_cipher_suite_provider(TEST_CIPHER_SUITE);

        let effects = cache
            .prepare_commit_default(
                Sender::Member(test_sender()),
                vec![],
                &get_test_group_context(1, TEST_CIPHER_SUITE),
                &BasicIdentityProvider,
                &cipher_suite_provider,
                &TreeKemPublic::new(),
                #[cfg(feature = "external_commit")]
                None,
                &AlwaysFoundPskStorage,
                pass_through_rules(),
            )
            .await
            .unwrap();

        assert!(path_update_required(&effects.applied_proposals))
    }

    #[maybe_async::test(sync, async(not(sync), crate::futures_test))]
    async fn test_path_update_required_updates() {
        let mut cache = make_proposal_cache();
        let update = Proposal::Update(make_update_proposal("bar").await);
        let cipher_suite_provider = test_cipher_suite_provider(TEST_CIPHER_SUITE);

        cache.insert(
            make_proposal_ref(&update, LeafIndex(2)),
            update,
            Sender::Member(2),
        );

        let mut tree = TreeKemPublic::new();
        add_member(&mut tree, "alice").await;
        add_member(&mut tree, "bob").await;
        add_member(&mut tree, "carol").await;

        let effects = cache
            .prepare_commit_default(
                Sender::Member(test_sender()),
                Vec::new(),
                &get_test_group_context(1, TEST_CIPHER_SUITE),
                &BasicIdentityProvider,
                &cipher_suite_provider,
                &tree,
                #[cfg(feature = "external_commit")]
                None,
                &AlwaysFoundPskStorage,
                pass_through_rules(),
            )
            .await
            .unwrap();

        assert!(path_update_required(&effects.applied_proposals))
    }

    #[maybe_async::test(sync, async(not(sync), crate::futures_test))]
    async fn test_path_update_required_removes() {
        let cache = make_proposal_cache();
        let cipher_suite_provider = test_cipher_suite_provider(TEST_CIPHER_SUITE);

        let (alice_leaf, alice_secret, _) =
            get_basic_test_node_sig_key(TEST_CIPHER_SUITE, "alice").await;
        let alice = 0;

        let (mut tree, _) = TreeKemPublic::derive(alice_leaf, alice_secret, &BasicIdentityProvider)
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
                &get_test_group_context(1, TEST_CIPHER_SUITE),
                &BasicIdentityProvider,
                &cipher_suite_provider,
                &tree,
                #[cfg(feature = "external_commit")]
                None,
                &AlwaysFoundPskStorage,
                pass_through_rules(),
            )
            .await
            .unwrap();

        assert!(path_update_required(&effects.applied_proposals))
    }

    #[cfg(feature = "psk")]
    #[maybe_async::test(sync, async(not(sync), crate::futures_test))]
    async fn test_path_update_not_required() {
        let (alice, tree) = new_tree("alice").await;
        let cipher_suite_provider = test_cipher_suite_provider(TEST_CIPHER_SUITE);
        let cache = make_proposal_cache();

        let psk = Proposal::Psk(PreSharedKeyProposal {
            psk: PreSharedKeyID {
                key_id: JustPreSharedKeyID::External(ExternalPskId::new(vec![])),
                psk_nonce: PskNonce::random(&test_cipher_suite_provider(TEST_CIPHER_SUITE))
                    .unwrap(),
            },
        });

        let add = Proposal::Add(Box::new(AddProposal {
            key_package: test_key_package(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE, "bob").await,
        }));

        let effects = cache
            .prepare_commit_default(
                Sender::Member(*alice),
                vec![psk, add],
                &get_test_group_context(1, TEST_CIPHER_SUITE),
                &BasicIdentityProvider,
                &cipher_suite_provider,
                &tree,
                #[cfg(feature = "external_commit")]
                None,
                &AlwaysFoundPskStorage,
                pass_through_rules(),
            )
            .await
            .unwrap();

        assert!(!path_update_required(&effects.applied_proposals))
    }

    #[maybe_async::test(sync, async(not(sync), crate::futures_test))]
    async fn path_update_is_not_required_for_re_init() {
        let cipher_suite_provider = test_cipher_suite_provider(TEST_CIPHER_SUITE);
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
                &get_test_group_context(1, TEST_CIPHER_SUITE),
                &BasicIdentityProvider,
                &cipher_suite_provider,
                &tree,
                #[cfg(feature = "external_commit")]
                None,
                &AlwaysFoundPskStorage,
                pass_through_rules(),
            )
            .await
            .unwrap();

        assert!(!path_update_required(&effects.applied_proposals))
    }

    #[derive(Debug)]
    struct CommitSender<'a, C, F, P, CSP> {
        cipher_suite_provider: CSP,
        tree: &'a TreeKemPublic,
        sender: LeafIndex,
        cache: ProposalCache,
        additional_proposals: Vec<Proposal>,
        identity_provider: C,
        user_rules: F,
        psk_storage: P,
    }

    impl<'a, CSP>
        CommitSender<
            'a,
            BasicWithCustomProvider,
            PassThroughProposalRules,
            AlwaysFoundPskStorage,
            CSP,
        >
    {
        fn new(tree: &'a TreeKemPublic, sender: LeafIndex, cipher_suite_provider: CSP) -> Self {
            Self {
                tree,
                sender,
                cache: make_proposal_cache(),
                additional_proposals: Vec::new(),
                identity_provider: BasicWithCustomProvider::new(BasicIdentityProvider::new()),
                user_rules: pass_through_rules(),
                psk_storage: AlwaysFoundPskStorage,
                cipher_suite_provider,
            }
        }
    }

    impl<'a, C, F, P, CSP> CommitSender<'a, C, F, P, CSP>
    where
        C: IdentityProvider,
        F: ProposalRules,
        P: PreSharedKeyStorage,
        CSP: CipherSuiteProvider,
    {
        #[cfg(feature = "external_proposal")]
        fn with_identity_provider<V>(self, identity_provider: V) -> CommitSender<'a, V, F, P, CSP>
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
                user_rules: self.user_rules,
                psk_storage: self.psk_storage,
            }
        }

        fn cache<S>(mut self, r: ProposalRef, p: Proposal, proposer: S) -> Self
        where
            S: Into<Sender>,
        {
            self.cache.insert(r, p, proposer.into());
            self
        }

        fn with_additional<I>(mut self, proposals: I) -> Self
        where
            I: IntoIterator<Item = Proposal>,
        {
            self.additional_proposals.extend(proposals);
            self
        }

        fn with_user_rules<G>(self, f: G) -> CommitSender<'a, C, G, P, CSP>
        where
            G: ProposalRules,
        {
            CommitSender {
                tree: self.tree,
                sender: self.sender,
                cache: self.cache,
                additional_proposals: self.additional_proposals,
                identity_provider: self.identity_provider,
                user_rules: f,
                psk_storage: self.psk_storage,
                cipher_suite_provider: self.cipher_suite_provider,
            }
        }

        fn with_psk_storage<V>(self, v: V) -> CommitSender<'a, C, F, V, CSP>
        where
            V: PreSharedKeyStorage,
        {
            CommitSender {
                tree: self.tree,
                sender: self.sender,
                cache: self.cache,
                additional_proposals: self.additional_proposals,
                identity_provider: self.identity_provider,
                user_rules: self.user_rules,
                psk_storage: v,
                cipher_suite_provider: self.cipher_suite_provider,
            }
        }

        #[maybe_async::maybe_async]
        async fn send(&self) -> Result<(Vec<ProposalOrRef>, ProvisionalState), MlsError> {
            let state = self
                .cache
                .prepare_commit_default(
                    Sender::Member(*self.sender),
                    self.additional_proposals.clone(),
                    &get_test_group_context(1, TEST_CIPHER_SUITE),
                    &self.identity_provider,
                    &self.cipher_suite_provider,
                    self.tree,
                    #[cfg(feature = "external_commit")]
                    None,
                    &self.psk_storage,
                    &self.user_rules,
                )
                .await?;

            let proposals = state.applied_proposals.clone().into_proposals_or_refs();

            Ok((proposals, state))
        }
    }

    #[maybe_async::maybe_async]
    async fn key_package_with_invalid_signature() -> KeyPackage {
        let mut kp = test_key_package(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE, "mallory").await;
        kp.signature.clear();
        kp
    }

    #[maybe_async::maybe_async]
    pub(crate) async fn modify_key_package<CSP: CipherSuiteProvider>(
        provider: &CSP,
        gen: KeyPackageGenerator<'_, BasicIdentityProvider, CSP>,
        key: crypto::HpkePublicKey,
    ) -> KeyPackageGeneration {
        let mut key_package_gen = gen
            .generate(
                Lifetime::years(1).unwrap(),
                Default::default(),
                Default::default(),
                Default::default(),
            )
            .await
            .unwrap();

        key_package_gen.key_package.leaf_node.public_key = key;

        key_package_gen
            .key_package
            .leaf_node
            .sign(
                provider,
                gen.signing_key,
                &LeafNodeSigningContext {
                    group_id: None,
                    leaf_index: None,
                },
            )
            .unwrap();

        key_package_gen
            .key_package
            .sign(provider, gen.signing_key, &())
            .unwrap();
        key_package_gen
    }

    #[maybe_async::async_impl]
    async fn key_package_with_public_key(key: crypto::HpkePublicKey) -> KeyPackage {
        let cipher_suite_provider = test_cipher_suite_provider(TEST_CIPHER_SUITE);

        test_key_package_custom(
            &cipher_suite_provider.clone(),
            TEST_PROTOCOL_VERSION,
            "test",
            |gen| async move { modify_key_package(&cipher_suite_provider, gen, key).await }.boxed(),
        )
        .await
    }

    #[maybe_async::sync_impl]
    fn key_package_with_public_key(key: crypto::HpkePublicKey) -> KeyPackage {
        let cipher_suite_provider = test_cipher_suite_provider(TEST_CIPHER_SUITE);

        test_key_package_custom(
            &cipher_suite_provider,
            TEST_PROTOCOL_VERSION,
            "test",
            |gen| modify_key_package(&cipher_suite_provider, gen, key),
        )
    }

    #[maybe_async::test(sync, async(not(sync), crate::futures_test))]
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

    #[maybe_async::test(sync, async(not(sync), crate::futures_test))]
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

    #[maybe_async::test(sync, async(not(sync), crate::futures_test))]
    async fn sending_add_with_invalid_key_package_filters_it_out() {
        let (alice, tree) = new_tree("alice").await;

        let proposal = Proposal::Add(Box::new(AddProposal {
            key_package: key_package_with_invalid_signature().await,
        }));
        let proposal_ref = make_proposal_ref(&proposal, alice);

        let processed_proposals =
            CommitSender::new(&tree, alice, test_cipher_suite_provider(TEST_CIPHER_SUITE))
                .cache(proposal_ref.clone(), proposal.clone(), alice)
                .send()
                .await
                .unwrap();

        assert_eq!(processed_proposals.0, Vec::new());

        #[cfg(feature = "state_update")]
        assert_eq!(
            processed_proposals.1.rejected_proposals,
            vec![(proposal_ref, proposal)]
        );
    }

    #[maybe_async::test(sync, async(not(sync), crate::futures_test))]
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

    #[maybe_async::test(sync, async(not(sync), crate::futures_test))]
    async fn sending_add_with_hpke_key_of_another_member_filters_it_out() {
        let (alice, tree) = new_tree("alice").await;

        let proposal = Proposal::Add(Box::new(AddProposal {
            key_package: key_package_with_public_key(
                tree.get_leaf_node(alice).unwrap().public_key.clone(),
            )
            .await,
        }));

        let proposal_ref = make_proposal_ref(&proposal, alice);

        let processed_proposals =
            CommitSender::new(&tree, alice, test_cipher_suite_provider(TEST_CIPHER_SUITE))
                .cache(proposal_ref.clone(), proposal.clone(), alice)
                .send()
                .await
                .unwrap();

        assert_eq!(processed_proposals.0, Vec::new());

        #[cfg(feature = "state_update")]
        assert_eq!(
            processed_proposals.1.rejected_proposals,
            vec![(proposal_ref, proposal)]
        );
    }

    #[maybe_async::test(sync, async(not(sync), crate::futures_test))]
    async fn receiving_update_with_invalid_leaf_node_fails() {
        let (alice, mut tree) = new_tree("alice").await;
        let bob = add_member(&mut tree, "bob").await;

        let proposal = Proposal::Update(UpdateProposal {
            leaf_node: get_basic_test_node(TEST_CIPHER_SUITE, "alice").await,
        });

        let proposal_ref = make_proposal_ref(&proposal, bob);

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

    #[maybe_async::test(sync, async(not(sync), crate::futures_test))]
    async fn sending_update_with_invalid_leaf_node_filters_it_out() {
        let (alice, mut tree) = new_tree("alice").await;
        let bob = add_member(&mut tree, "bob").await;

        let proposal = Proposal::Update(UpdateProposal {
            leaf_node: get_basic_test_node(TEST_CIPHER_SUITE, "alice").await,
        });
        let proposal_ref = make_proposal_ref(&proposal, bob);

        let processed_proposals =
            CommitSender::new(&tree, alice, test_cipher_suite_provider(TEST_CIPHER_SUITE))
                .cache(proposal_ref, proposal, bob)
                .send()
                .await
                .unwrap();

        assert_eq!(processed_proposals.0, Vec::new());

        // Alice didn't propose the update. Bob did. That's why it is not returned in the list of
        // rejected proposals.
        #[cfg(feature = "state_update")]
        assert_eq!(processed_proposals.1.rejected_proposals, Vec::new());
    }

    #[maybe_async::test(sync, async(not(sync), crate::futures_test))]
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

    #[maybe_async::test(sync, async(not(sync), crate::futures_test))]
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

    #[maybe_async::test(sync, async(not(sync), crate::futures_test))]
    async fn sending_remove_with_invalid_index_filters_it_out() {
        let (alice, tree) = new_tree("alice").await;

        let proposal = Proposal::Remove(RemoveProposal {
            to_remove: LeafIndex(10),
        });
        let proposal_ref = make_proposal_ref(&proposal, alice);

        let processed_proposals =
            CommitSender::new(&tree, alice, test_cipher_suite_provider(TEST_CIPHER_SUITE))
                .cache(proposal_ref.clone(), proposal.clone(), alice)
                .send()
                .await
                .unwrap();

        assert_eq!(processed_proposals.0, Vec::new());

        #[cfg(feature = "state_update")]
        assert_eq!(
            processed_proposals.1.rejected_proposals,
            vec![(proposal_ref, proposal)]
        );
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
    #[maybe_async::test(sync, async(not(sync), crate::futures_test))]
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
    #[maybe_async::test(sync, async(not(sync), crate::futures_test))]
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
    #[maybe_async::test(sync, async(not(sync), crate::futures_test))]
    async fn sending_psk_with_invalid_nonce_filters_it_out() {
        let invalid_nonce = PskNonce(vec![0, 1, 2]);
        let (alice, tree) = new_tree("alice").await;
        let proposal = Proposal::Psk(make_external_psk(b"foo", invalid_nonce));
        let proposal_ref = make_proposal_ref(&proposal, alice);

        let processed_proposals =
            CommitSender::new(&tree, alice, test_cipher_suite_provider(TEST_CIPHER_SUITE))
                .cache(proposal_ref.clone(), proposal.clone(), alice)
                .send()
                .await
                .unwrap();

        assert_eq!(processed_proposals.0, Vec::new());

        #[cfg(feature = "state_update")]
        assert_eq!(
            processed_proposals.1.rejected_proposals,
            vec![(proposal_ref, proposal)]
        );
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
    #[maybe_async::maybe_async]
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
    #[maybe_async::maybe_async]
    async fn sending_additional_resumption_psk_with_bad_usage_fails(usage: ResumptionPSKUsage) {
        let (alice, tree) = new_tree("alice").await;

        let res = CommitSender::new(&tree, alice, test_cipher_suite_provider(TEST_CIPHER_SUITE))
            .with_additional([Proposal::Psk(make_resumption_psk(usage))])
            .send()
            .await;

        assert_matches!(res, Err(MlsError::InvalidTypeOrUsageInPreSharedKeyProposal));
    }

    #[cfg(feature = "psk")]
    #[maybe_async::maybe_async]
    async fn sending_resumption_psk_with_bad_usage_filters_it_out(usage: ResumptionPSKUsage) {
        let (alice, tree) = new_tree("alice").await;
        let proposal = Proposal::Psk(make_resumption_psk(usage));
        let proposal_ref = make_proposal_ref(&proposal, alice);

        let processed_proposals =
            CommitSender::new(&tree, alice, test_cipher_suite_provider(TEST_CIPHER_SUITE))
                .cache(proposal_ref.clone(), proposal.clone(), alice)
                .send()
                .await
                .unwrap();

        assert_eq!(processed_proposals.0, Vec::new());

        #[cfg(feature = "state_update")]
        assert_eq!(
            processed_proposals.1.rejected_proposals,
            vec![(proposal_ref, proposal)]
        );
    }

    #[cfg(feature = "psk")]
    #[maybe_async::test(sync, async(not(sync), crate::futures_test))]
    async fn receiving_resumption_psk_with_reinit_usage_fails() {
        receiving_resumption_psk_with_bad_usage_fails(ResumptionPSKUsage::Reinit).await;
    }

    #[cfg(feature = "psk")]
    #[maybe_async::test(sync, async(not(sync), crate::futures_test))]
    async fn sending_additional_resumption_psk_with_reinit_usage_fails() {
        sending_additional_resumption_psk_with_bad_usage_fails(ResumptionPSKUsage::Reinit).await;
    }

    #[cfg(feature = "psk")]
    #[maybe_async::test(sync, async(not(sync), crate::futures_test))]
    async fn sending_resumption_psk_with_reinit_usage_filters_it_out() {
        sending_resumption_psk_with_bad_usage_filters_it_out(ResumptionPSKUsage::Reinit).await;
    }

    #[cfg(feature = "psk")]
    #[maybe_async::test(sync, async(not(sync), crate::futures_test))]
    async fn receiving_resumption_psk_with_branch_usage_fails() {
        receiving_resumption_psk_with_bad_usage_fails(ResumptionPSKUsage::Branch).await;
    }

    #[cfg(feature = "psk")]
    #[maybe_async::test(sync, async(not(sync), crate::futures_test))]
    async fn sending_additional_resumption_psk_with_branch_usage_fails() {
        sending_additional_resumption_psk_with_bad_usage_fails(ResumptionPSKUsage::Branch).await;
    }

    #[cfg(feature = "psk")]
    #[maybe_async::test(sync, async(not(sync), crate::futures_test))]
    async fn sending_resumption_psk_with_branch_usage_filters_it_out() {
        sending_resumption_psk_with_bad_usage_filters_it_out(ResumptionPSKUsage::Branch).await;
    }

    fn make_reinit(version: ProtocolVersion) -> ReInitProposal {
        ReInitProposal {
            group_id: TEST_GROUP.to_vec(),
            version,
            cipher_suite: TEST_CIPHER_SUITE,
            extensions: ExtensionList::new(),
        }
    }

    #[maybe_async::test(sync, async(not(sync), crate::futures_test))]
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

    #[maybe_async::test(sync, async(not(sync), crate::futures_test))]
    async fn sending_additional_reinit_downgrading_version_fails() {
        let smaller_protocol_version = ProtocolVersion::from(0);
        let (alice, tree) = new_tree("alice").await;

        let res = CommitSender::new(&tree, alice, test_cipher_suite_provider(TEST_CIPHER_SUITE))
            .with_additional([Proposal::ReInit(make_reinit(smaller_protocol_version))])
            .send()
            .await;

        assert_matches!(res, Err(MlsError::InvalidProtocolVersionInReInit));
    }

    #[maybe_async::test(sync, async(not(sync), crate::futures_test))]
    async fn sending_reinit_downgrading_version_filters_it_out() {
        let smaller_protocol_version = ProtocolVersion::from(0);
        let (alice, tree) = new_tree("alice").await;
        let proposal = Proposal::ReInit(make_reinit(smaller_protocol_version));
        let proposal_ref = make_proposal_ref(&proposal, alice);

        let processed_proposals =
            CommitSender::new(&tree, alice, test_cipher_suite_provider(TEST_CIPHER_SUITE))
                .cache(proposal_ref.clone(), proposal.clone(), alice)
                .send()
                .await
                .unwrap();

        assert_eq!(processed_proposals.0, Vec::new());

        #[cfg(feature = "state_update")]
        assert_eq!(
            processed_proposals.1.rejected_proposals,
            vec![(proposal_ref, proposal)]
        );
    }

    #[maybe_async::test(sync, async(not(sync), crate::futures_test))]
    async fn receiving_update_for_committer_fails() {
        let (alice, tree) = new_tree("alice").await;
        let update = Proposal::Update(make_update_proposal("alice").await);
        let update_ref = make_proposal_ref(&update, alice);

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

    #[maybe_async::test(sync, async(not(sync), crate::futures_test))]
    async fn sending_additional_update_for_committer_fails() {
        let (alice, tree) = new_tree("alice").await;

        let res = CommitSender::new(&tree, alice, test_cipher_suite_provider(TEST_CIPHER_SUITE))
            .with_additional([Proposal::Update(make_update_proposal("alice").await)])
            .send()
            .await;

        assert_matches!(res, Err(MlsError::InvalidProposalTypeForSender));
    }

    #[maybe_async::test(sync, async(not(sync), crate::futures_test))]
    async fn sending_update_for_committer_filters_it_out() {
        let (alice, tree) = new_tree("alice").await;
        let proposal = Proposal::Update(make_update_proposal("alice").await);
        let proposal_ref = make_proposal_ref(&proposal, alice);

        let processed_proposals =
            CommitSender::new(&tree, alice, test_cipher_suite_provider(TEST_CIPHER_SUITE))
                .cache(proposal_ref.clone(), proposal.clone(), alice)
                .send()
                .await
                .unwrap();

        assert_eq!(processed_proposals.0, Vec::new());

        #[cfg(feature = "state_update")]
        assert_eq!(
            processed_proposals.1.rejected_proposals,
            vec![(proposal_ref, proposal)]
        );
    }

    #[maybe_async::test(sync, async(not(sync), crate::futures_test))]
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

    #[maybe_async::test(sync, async(not(sync), crate::futures_test))]
    async fn sending_additional_remove_for_committer_fails() {
        let (alice, tree) = new_tree("alice").await;

        let res = CommitSender::new(&tree, alice, test_cipher_suite_provider(TEST_CIPHER_SUITE))
            .with_additional([Proposal::Remove(RemoveProposal { to_remove: alice })])
            .send()
            .await;

        assert_matches!(res, Err(MlsError::CommitterSelfRemoval));
    }

    #[maybe_async::test(sync, async(not(sync), crate::futures_test))]
    async fn sending_remove_for_committer_filters_it_out() {
        let (alice, tree) = new_tree("alice").await;
        let proposal = Proposal::Remove(RemoveProposal { to_remove: alice });
        let proposal_ref = make_proposal_ref(&proposal, alice);

        let processed_proposals =
            CommitSender::new(&tree, alice, test_cipher_suite_provider(TEST_CIPHER_SUITE))
                .cache(proposal_ref.clone(), proposal.clone(), alice)
                .send()
                .await
                .unwrap();

        assert_eq!(processed_proposals.0, Vec::new());

        #[cfg(feature = "state_update")]
        assert_eq!(
            processed_proposals.1.rejected_proposals,
            vec![(proposal_ref, proposal)]
        );
    }

    #[maybe_async::test(sync, async(not(sync), crate::futures_test))]
    async fn receiving_update_and_remove_for_same_leaf_fails() {
        let (alice, mut tree) = new_tree("alice").await;
        let bob = add_member(&mut tree, "bob").await;

        let update = Proposal::Update(make_update_proposal("bob").await);
        let update_ref = make_proposal_ref(&update, bob);

        let remove = Proposal::Remove(RemoveProposal { to_remove: bob });
        let remove_ref = make_proposal_ref(&remove, bob);

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

    #[maybe_async::test(sync, async(not(sync), crate::futures_test))]
    async fn sending_update_and_remove_for_same_leaf_filters_update_out() {
        let (alice, mut tree) = new_tree("alice").await;
        let bob = add_member(&mut tree, "bob").await;

        let update = Proposal::Update(make_update_proposal("bob").await);
        let update_ref = make_proposal_ref(&update, alice);

        let remove = Proposal::Remove(RemoveProposal { to_remove: bob });
        let remove_ref = make_proposal_ref(&remove, alice);

        let processed_proposals =
            CommitSender::new(&tree, alice, test_cipher_suite_provider(TEST_CIPHER_SUITE))
                .cache(update_ref.clone(), update.clone(), alice)
                .cache(remove_ref.clone(), remove, alice)
                .send()
                .await
                .unwrap();

        assert_eq!(processed_proposals.0, vec![remove_ref.into()]);

        #[cfg(feature = "state_update")]
        assert_eq!(
            processed_proposals.1.rejected_proposals,
            vec![(update_ref, update)]
        );
    }

    #[maybe_async::maybe_async]
    async fn make_add_proposal() -> Box<AddProposal> {
        Box::new(AddProposal {
            key_package: test_key_package(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE, "frank").await,
        })
    }

    #[cfg(feature = "custom_proposal")]
    #[maybe_async::async_impl]
    async fn make_custom_add_proposal(capabilities: Capabilities) -> AddProposal {
        AddProposal {
            key_package: test_key_package_custom(
                &test_cipher_suite_provider(TEST_CIPHER_SUITE),
                TEST_PROTOCOL_VERSION,
                "frank",
                |generator| {
                    async move {
                        generator
                            .generate(
                                Lifetime::years(1).unwrap(),
                                capabilities,
                                ExtensionList::default(),
                                ExtensionList::default(),
                            )
                            .await
                            .unwrap()
                    }
                    .boxed()
                },
            )
            .await,
        }
    }

    #[cfg(feature = "custom_proposal")]
    #[maybe_async::sync_impl]
    fn make_custom_add_proposal(capabilities: Capabilities) -> AddProposal {
        AddProposal {
            key_package: test_key_package_custom(
                &test_cipher_suite_provider(TEST_CIPHER_SUITE),
                TEST_PROTOCOL_VERSION,
                "frank",
                |generator| {
                    generator
                        .generate(
                            Lifetime::years(1).unwrap(),
                            capabilities,
                            ExtensionList::default(),
                            ExtensionList::default(),
                        )
                        .unwrap()
                },
            ),
        }
    }

    #[maybe_async::test(sync, async(not(sync), crate::futures_test))]
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

    #[maybe_async::test(sync, async(not(sync), crate::futures_test))]
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

    #[maybe_async::test(sync, async(not(sync), crate::futures_test))]
    async fn sending_add_proposals_for_same_client_keeps_only_one() {
        let (alice, tree) = new_tree("alice").await;

        let adds = [
            Proposal::Add(make_add_proposal().await),
            Proposal::Add(make_add_proposal().await),
        ];
        let add_refs = adds.clone().map(|p| make_proposal_ref(&p, alice));

        let processed_proposals =
            CommitSender::new(&tree, alice, test_cipher_suite_provider(TEST_CIPHER_SUITE))
                .cache(add_refs[0].clone(), adds[0].clone(), alice)
                .cache(add_refs[1].clone(), adds[1].clone(), alice)
                .send()
                .await
                .unwrap();

        let committed_add_ref = match &*processed_proposals.0 {
            [ProposalOrRef::Reference(add_ref)] => add_ref,
            _ => panic!("committed proposals list does not contain exactly one reference"),
        };

        assert!(add_refs.contains(committed_add_ref));

        #[cfg(feature = "state_update")]
        assert_matches!(
            &*processed_proposals.1.rejected_proposals,
            [(rejected_add_ref, _)] if committed_add_ref != rejected_add_ref && add_refs.contains(rejected_add_ref)
        );
    }

    #[maybe_async::test(sync, async(not(sync), crate::futures_test))]
    async fn receiving_update_for_different_identity_fails() {
        let (alice, mut tree) = new_tree("alice").await;
        let bob = add_member(&mut tree, "bob").await;

        let update = Proposal::Update(make_update_proposal_custom("carol", 1).await);
        let update_ref = make_proposal_ref(&update, bob);

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

    #[maybe_async::test(sync, async(not(sync), crate::futures_test))]
    async fn sending_update_for_different_identity_filters_it_out() {
        let (alice, mut tree) = new_tree("alice").await;
        let bob = add_member(&mut tree, "bob").await;

        let update = Proposal::Update(make_update_proposal("carol").await);
        let update_ref = make_proposal_ref(&update, bob);

        let processed_proposals =
            CommitSender::new(&tree, alice, test_cipher_suite_provider(TEST_CIPHER_SUITE))
                .cache(update_ref, update, bob)
                .send()
                .await
                .unwrap();

        assert_eq!(processed_proposals.0, Vec::new());

        // Bob proposed the update, so it is not listed as rejected when Alice commits it because
        // she didn't propose it.
        #[cfg(feature = "state_update")]
        assert_eq!(processed_proposals.1.rejected_proposals, Vec::new());
    }

    #[maybe_async::test(sync, async(not(sync), crate::futures_test))]
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

    #[maybe_async::test(sync, async(not(sync), crate::futures_test))]
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

    #[maybe_async::test(sync, async(not(sync), crate::futures_test))]
    async fn sending_add_for_same_client_as_existing_member_filters_it_out() {
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

        let proposal_ref = make_proposal_ref(&add, alice);

        let processed_proposals = CommitSender::new(
            &public_tree,
            alice,
            test_cipher_suite_provider(TEST_CIPHER_SUITE),
        )
        .cache(proposal_ref.clone(), add.clone(), alice)
        .send()
        .await
        .unwrap();

        assert_eq!(processed_proposals.0, Vec::new());

        #[cfg(feature = "state_update")]
        assert_eq!(
            processed_proposals.1.rejected_proposals,
            vec![(proposal_ref, add)]
        );
    }

    #[cfg(feature = "psk")]
    #[maybe_async::test(sync, async(not(sync), crate::futures_test))]
    async fn receiving_psk_proposals_with_same_psk_id_fails() {
        let (alice, tree) = new_tree("alice").await;
        let psk_proposal = Proposal::Psk(new_external_psk(b"foo"));

        let res = CommitReceiver::new(
            &tree,
            alice,
            alice,
            test_cipher_suite_provider(TEST_CIPHER_SUITE),
        )
        .receive([psk_proposal.clone(), psk_proposal])
        .await;

        assert_matches!(res, Err(MlsError::DuplicatePskIds));
    }

    #[cfg(feature = "psk")]
    #[maybe_async::test(sync, async(not(sync), crate::futures_test))]
    async fn sending_additional_psk_proposals_with_same_psk_id_fails() {
        let (alice, tree) = new_tree("alice").await;
        let psk_proposal = Proposal::Psk(new_external_psk(b"foo"));

        let res = CommitSender::new(&tree, alice, test_cipher_suite_provider(TEST_CIPHER_SUITE))
            .with_additional([psk_proposal.clone(), psk_proposal])
            .send()
            .await;

        assert_matches!(res, Err(MlsError::DuplicatePskIds));
    }

    #[cfg(feature = "psk")]
    #[maybe_async::test(sync, async(not(sync), crate::futures_test))]
    async fn sending_psk_proposals_with_same_psk_id_keeps_only_one() {
        let (alice, mut tree) = new_tree("alice").await;
        let bob = add_member(&mut tree, "bob").await;

        let proposal = Proposal::Psk(new_external_psk(b"foo"));

        let proposal_refs = [
            make_proposal_ref(&proposal, alice),
            make_proposal_ref(&proposal, bob),
        ];

        let processed_proposals =
            CommitSender::new(&tree, alice, test_cipher_suite_provider(TEST_CIPHER_SUITE))
                .cache(proposal_refs[0].clone(), proposal.clone(), alice)
                .cache(proposal_refs[1].clone(), proposal, bob)
                .send()
                .await
                .unwrap();

        let committed_ref = match &*processed_proposals.0 {
            [ProposalOrRef::Reference(r)] => r.clone(),
            _ => panic!("Expected single proposal reference in {processed_proposals:?}"),
        };

        assert!(proposal_refs.contains(&committed_ref));

        // The list of rejected proposals may be empty if Bob's proposal was the one that got
        // rejected.
        #[cfg(feature = "state_update")]
        match &*processed_proposals.1.rejected_proposals {
            [(r, _)] => {
                assert_ne!(*r, committed_ref);
                assert!(proposal_refs.contains(r));
            }
            [] => {}
            _ => panic!(
                "Expected zero or one proposal reference in {:?}",
                processed_proposals.1.rejected_proposals
            ),
        }
    }

    #[maybe_async::test(sync, async(not(sync), crate::futures_test))]
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

    #[maybe_async::test(sync, async(not(sync), crate::futures_test))]
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

    fn make_extension_list(foo: u8) -> ExtensionList {
        vec![TestExtension { foo }.into_extension().unwrap()].into()
    }

    #[maybe_async::test(sync, async(not(sync), crate::futures_test))]
    async fn sending_multiple_group_context_extensions_keeps_only_one() {
        let cipher_suite_provider = test_cipher_suite_provider(TEST_CIPHER_SUITE);

        let (alice, tree) = {
            let (signing_identity, signature_key) =
                get_test_signing_identity(TEST_CIPHER_SUITE, b"alice".to_vec());

            let properties = ConfigProperties {
                capabilities: Capabilities {
                    extensions: vec![42.into()],
                    ..Capabilities::default()
                },
                extensions: Default::default(),
            };

            let (leaf, secret) = LeafNode::generate(
                &cipher_suite_provider,
                properties,
                signing_identity,
                &signature_key,
                Lifetime::years(1).unwrap(),
            )
            .await
            .unwrap();

            let (pub_tree, priv_tree) = TreeKemPublic::derive(leaf, secret, &BasicIdentityProvider)
                .await
                .unwrap();

            (priv_tree.self_index, pub_tree)
        };

        let proposals = [
            Proposal::GroupContextExtensions(make_extension_list(0)),
            Proposal::GroupContextExtensions(make_extension_list(1)),
        ];

        let gce_refs = proposals.clone().map(|p| make_proposal_ref(&p, alice));

        let processed_proposals =
            CommitSender::new(&tree, alice, test_cipher_suite_provider(TEST_CIPHER_SUITE))
                .cache(gce_refs[0].clone(), proposals[0].clone(), alice)
                .cache(gce_refs[1].clone(), proposals[1].clone(), alice)
                .send()
                .await
                .unwrap();

        let committed_gce_ref = match &*processed_proposals.0 {
            [ProposalOrRef::Reference(gce_ref)] => gce_ref,
            _ => panic!("committed proposals list does not contain exactly one reference"),
        };

        assert!(gce_refs.contains(committed_gce_ref));

        #[cfg(feature = "state_update")]
        assert_matches!(
            &*processed_proposals.1.rejected_proposals,
            [(rejected_gce_ref, _)] if committed_gce_ref != rejected_gce_ref && gce_refs.contains(rejected_gce_ref)
        );
    }

    #[cfg(feature = "external_proposal")]
    fn make_external_senders_extension() -> ExtensionList {
        vec![ExternalSendersExt::new(vec![
            get_test_signing_identity(TEST_CIPHER_SUITE, b"alice".to_vec()).0,
        ])
        .into_extension()
        .unwrap()]
        .into()
    }

    #[cfg(feature = "external_proposal")]
    #[maybe_async::test(sync, async(not(sync), crate::futures_test))]
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
            make_external_senders_extension(),
        )])
        .await;

        assert_matches!(res, Err(MlsError::IdentityProviderError(_)));
    }

    #[cfg(feature = "external_proposal")]
    #[maybe_async::test(sync, async(not(sync), crate::futures_test))]
    async fn sending_additional_invalid_external_senders_extension_fails() {
        let (alice, tree) = new_tree("alice").await;

        let res = CommitSender::new(&tree, alice, test_cipher_suite_provider(TEST_CIPHER_SUITE))
            .with_identity_provider(FailureIdentityProvider::new())
            .with_additional([Proposal::GroupContextExtensions(
                make_external_senders_extension(),
            )])
            .send()
            .await;

        assert_matches!(res, Err(MlsError::IdentityProviderError(_)));
    }

    #[cfg(feature = "external_proposal")]
    #[maybe_async::test(sync, async(not(sync), crate::futures_test))]
    async fn sending_invalid_external_senders_extension_filters_it_out() {
        let (alice, tree) = new_tree("alice").await;

        let proposal = Proposal::GroupContextExtensions(make_external_senders_extension());

        let proposal_ref = make_proposal_ref(&proposal, alice);

        let processed_proposals =
            CommitSender::new(&tree, alice, test_cipher_suite_provider(TEST_CIPHER_SUITE))
                .with_identity_provider(FailureIdentityProvider::new())
                .cache(proposal_ref.clone(), proposal.clone(), alice)
                .send()
                .await
                .unwrap();

        assert_eq!(processed_proposals.0, Vec::new());

        #[cfg(feature = "state_update")]
        assert_eq!(
            processed_proposals.1.rejected_proposals,
            vec![(proposal_ref, proposal)]
        );
    }

    #[maybe_async::test(sync, async(not(sync), crate::futures_test))]
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

    #[maybe_async::test(sync, async(not(sync), crate::futures_test))]
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

    #[maybe_async::test(sync, async(not(sync), crate::futures_test))]
    async fn sending_reinit_with_other_proposals_filters_it_out() {
        let (alice, tree) = new_tree("alice").await;
        let reinit = Proposal::ReInit(make_reinit(TEST_PROTOCOL_VERSION));
        let reinit_ref = make_proposal_ref(&reinit, alice);
        let add = Proposal::Add(make_add_proposal().await);
        let add_ref = make_proposal_ref(&add, alice);

        let processed_proposals =
            CommitSender::new(&tree, alice, test_cipher_suite_provider(TEST_CIPHER_SUITE))
                .cache(reinit_ref.clone(), reinit.clone(), alice)
                .cache(add_ref.clone(), add, alice)
                .send()
                .await
                .unwrap();

        assert_eq!(processed_proposals.0, vec![add_ref.into()]);

        #[cfg(feature = "state_update")]
        assert_eq!(
            processed_proposals.1.rejected_proposals,
            vec![(reinit_ref, reinit)]
        );
    }

    #[maybe_async::test(sync, async(not(sync), crate::futures_test))]
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

    #[maybe_async::test(sync, async(not(sync), crate::futures_test))]
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

    #[maybe_async::test(sync, async(not(sync), crate::futures_test))]
    async fn sending_multiple_reinits_keeps_only_one() {
        let (alice, tree) = new_tree("alice").await;
        let reinit = Proposal::ReInit(make_reinit(TEST_PROTOCOL_VERSION));
        let reinit_ref = make_proposal_ref(&reinit, alice);
        let other_reinit = Proposal::ReInit(ReInitProposal {
            group_id: b"other_group".to_vec(),
            ..make_reinit(TEST_PROTOCOL_VERSION)
        });
        let other_reinit_ref = make_proposal_ref(&other_reinit, alice);

        let processed_proposals =
            CommitSender::new(&tree, alice, test_cipher_suite_provider(TEST_CIPHER_SUITE))
                .cache(reinit_ref.clone(), reinit.clone(), alice)
                .cache(other_reinit_ref.clone(), other_reinit.clone(), alice)
                .send()
                .await
                .unwrap();

        let processed_ref = match &*processed_proposals.0 {
            [ProposalOrRef::Reference(r)] => r,
            p => panic!("Expected single proposal reference but found {p:?}"),
        };

        assert!(*processed_ref == reinit_ref || *processed_ref == other_reinit_ref);

        #[cfg(feature = "state_update")]
        {
            let (rejected_ref, rejected_proposal) = match &*processed_proposals.1.rejected_proposals
            {
                [(r, p)] => (r, p),
                p => panic!("Expected single proposal but found {p:?}"),
            };

            assert_ne!(rejected_ref, processed_ref);
            assert!(*rejected_ref == reinit_ref || *rejected_ref == other_reinit_ref);
            assert!(*rejected_proposal == reinit || *rejected_proposal == other_reinit);
        }
    }

    #[cfg(feature = "external_commit")]
    fn make_external_init() -> ExternalInit {
        ExternalInit {
            kem_output: vec![33; test_cipher_suite_provider(TEST_CIPHER_SUITE).kdf_extract_size()],
        }
    }

    #[cfg(feature = "external_commit")]
    #[maybe_async::test(sync, async(not(sync), crate::futures_test))]
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

    #[cfg(feature = "external_commit")]
    #[maybe_async::test(sync, async(not(sync), crate::futures_test))]
    async fn sending_additional_external_init_from_member_fails() {
        let (alice, tree) = new_tree("alice").await;

        let res = CommitSender::new(&tree, alice, test_cipher_suite_provider(TEST_CIPHER_SUITE))
            .with_additional([Proposal::ExternalInit(make_external_init())])
            .send()
            .await;

        assert_matches!(res, Err(MlsError::InvalidProposalTypeForSender));
    }

    #[cfg(feature = "external_commit")]
    #[maybe_async::test(sync, async(not(sync), crate::futures_test))]
    async fn sending_external_init_from_member_filters_it_out() {
        let (alice, tree) = new_tree("alice").await;
        let external_init = Proposal::ExternalInit(make_external_init());
        let external_init_ref = make_proposal_ref(&external_init, alice);

        let processed_proposals =
            CommitSender::new(&tree, alice, test_cipher_suite_provider(TEST_CIPHER_SUITE))
                .cache(external_init_ref.clone(), external_init.clone(), alice)
                .send()
                .await
                .unwrap();

        assert_eq!(processed_proposals.0, Vec::new());

        #[cfg(feature = "state_update")]
        assert_eq!(
            processed_proposals.1.rejected_proposals,
            vec![(external_init_ref, external_init)]
        );
    }

    #[cfg(feature = "all_extensions")]
    fn required_capabilities_proposal(extension: u16) -> Proposal {
        let required_capabilities = RequiredCapabilitiesExt {
            extensions: vec![extension.into()],
            ..Default::default()
        };

        let ext = vec![required_capabilities.into_extension().unwrap()];

        Proposal::GroupContextExtensions(ext.into())
    }

    #[cfg(feature = "all_extensions")]
    #[maybe_async::test(sync, async(not(sync), crate::futures_test))]
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

    #[cfg(feature = "all_extensions")]
    #[maybe_async::test(sync, async(not(sync), crate::futures_test))]
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

    #[cfg(feature = "all_extensions")]
    #[maybe_async::test(sync, async(not(sync), crate::futures_test))]
    async fn sending_additional_required_capabilities_not_supported_by_member_filters_it_out() {
        let (alice, tree) = new_tree("alice").await;

        let proposal = required_capabilities_proposal(33);
        let proposal_ref = make_proposal_ref(&proposal, alice);

        let processed_proposals =
            CommitSender::new(&tree, alice, test_cipher_suite_provider(TEST_CIPHER_SUITE))
                .cache(proposal_ref.clone(), proposal.clone(), alice)
                .send()
                .await
                .unwrap();

        assert_eq!(processed_proposals.0, Vec::new());

        #[cfg(feature = "state_update")]
        assert_eq!(
            processed_proposals.1.rejected_proposals,
            vec![(proposal_ref, proposal)]
        );
    }

    #[maybe_async::test(sync, async(not(sync), crate::futures_test))]
    async fn committing_update_from_pk1_to_pk2_and_update_from_pk2_to_pk3_works() {
        let (alice_leaf, alice_secret, alice_signer) =
            get_basic_test_node_sig_key(TEST_CIPHER_SUITE, "alice").await;

        let (mut tree, priv_tree) =
            TreeKemPublic::derive(alice_leaf.clone(), alice_secret, &BasicIdentityProvider)
                .await
                .unwrap();

        let alice = priv_tree.self_index;

        let bob = add_member(&mut tree, "bob").await;
        let carol = add_member(&mut tree, "carol").await;

        let bob_current_leaf = tree.get_leaf_node(bob).unwrap();

        let mut alice_new_leaf = LeafNode {
            public_key: bob_current_leaf.public_key.clone(),
            leaf_node_source: LeafNodeSource::Update,
            ..alice_leaf
        };

        alice_new_leaf
            .sign(
                &test_cipher_suite_provider(TEST_CIPHER_SUITE),
                &alice_signer,
                &(TEST_GROUP, 0).into(),
            )
            .unwrap();

        let bob_new_leaf = update_leaf_node("bob", 1).await;

        let pk1_to_pk2 = Proposal::Update(UpdateProposal {
            leaf_node: alice_new_leaf.clone(),
        });

        let pk1_to_pk2_ref = make_proposal_ref(&pk1_to_pk2, alice);

        let pk2_to_pk3 = Proposal::Update(UpdateProposal {
            leaf_node: bob_new_leaf.clone(),
        });

        let pk2_to_pk3_ref = make_proposal_ref(&pk2_to_pk3, bob);

        let effects = CommitReceiver::new(
            &tree,
            carol,
            carol,
            test_cipher_suite_provider(TEST_CIPHER_SUITE),
        )
        .cache(pk1_to_pk2_ref.clone(), pk1_to_pk2, alice)
        .cache(pk2_to_pk3_ref.clone(), pk2_to_pk3, bob)
        .receive([pk1_to_pk2_ref, pk2_to_pk3_ref])
        .await
        .unwrap();

        assert_eq!(effects.applied_proposals.update_senders, vec![alice, bob]);

        assert_eq!(
            effects
                .applied_proposals
                .updates
                .into_iter()
                .map(|p| p.proposal.leaf_node)
                .collect_vec(),
            vec![alice_new_leaf, bob_new_leaf]
        );
    }

    #[maybe_async::test(sync, async(not(sync), crate::futures_test))]
    async fn committing_update_from_pk1_to_pk2_and_removal_of_pk2_works() {
        let cipher_suite_provider = test_cipher_suite_provider(TEST_CIPHER_SUITE);

        let (alice_leaf, alice_secret, alice_signer) =
            get_basic_test_node_sig_key(TEST_CIPHER_SUITE, "alice").await;

        let (mut tree, priv_tree) =
            TreeKemPublic::derive(alice_leaf.clone(), alice_secret, &BasicIdentityProvider)
                .await
                .unwrap();

        let alice = priv_tree.self_index;

        let bob = add_member(&mut tree, "bob").await;
        let carol = add_member(&mut tree, "carol").await;

        let bob_current_leaf = tree.get_leaf_node(bob).unwrap();

        let mut alice_new_leaf = LeafNode {
            public_key: bob_current_leaf.public_key.clone(),
            leaf_node_source: LeafNodeSource::Update,
            ..alice_leaf
        };

        alice_new_leaf
            .sign(
                &cipher_suite_provider,
                &alice_signer,
                &(TEST_GROUP, 0).into(),
            )
            .unwrap();

        let pk1_to_pk2 = Proposal::Update(UpdateProposal {
            leaf_node: alice_new_leaf.clone(),
        });

        let pk1_to_pk2_ref = make_proposal_ref(&pk1_to_pk2, alice);

        let remove_pk2 = Proposal::Remove(RemoveProposal { to_remove: bob });

        let remove_pk2_ref = make_proposal_ref(&remove_pk2, bob);

        let effects = CommitReceiver::new(
            &tree,
            carol,
            carol,
            test_cipher_suite_provider(TEST_CIPHER_SUITE),
        )
        .cache(pk1_to_pk2_ref.clone(), pk1_to_pk2, alice)
        .cache(remove_pk2_ref.clone(), remove_pk2, bob)
        .receive([pk1_to_pk2_ref, remove_pk2_ref])
        .await
        .unwrap();

        assert_eq!(effects.applied_proposals.update_senders, vec![alice]);

        assert_eq!(
            effects
                .applied_proposals
                .updates
                .into_iter()
                .map(|p| p.proposal.leaf_node)
                .collect_vec(),
            vec![alice_new_leaf]
        );

        assert_eq!(
            effects
                .applied_proposals
                .removals
                .into_iter()
                .map(|p| p.proposal.to_remove)
                .collect_vec(),
            vec![bob]
        );
    }

    #[maybe_async::maybe_async]
    async fn unsupported_credential_key_package(name: &str) -> KeyPackage {
        let (mut signing_identity, secret_key) =
            get_test_signing_identity(TEST_CIPHER_SUITE, name.as_bytes().to_vec());

        signing_identity.credential = Credential::Custom(CustomCredential::new(
            CredentialType::new(BasicWithCustomProvider::CUSTOM_CREDENTIAL_TYPE),
            random_bytes(32),
        ));

        let generator = KeyPackageGenerator {
            protocol_version: TEST_PROTOCOL_VERSION,
            cipher_suite_provider: &test_cipher_suite_provider(TEST_CIPHER_SUITE),
            signing_identity: &signing_identity,
            signing_key: &secret_key,
            identity_provider: &BasicWithCustomProvider::new(BasicIdentityProvider::new()),
        };

        generator
            .generate(
                Lifetime::years(1).unwrap(),
                Capabilities {
                    credentials: vec![42.into()],
                    ..Default::default()
                },
                Default::default(),
                Default::default(),
            )
            .await
            .unwrap()
            .key_package
    }

    #[maybe_async::test(sync, async(not(sync), crate::futures_test))]
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

    #[maybe_async::test(sync, async(not(sync), crate::futures_test))]
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

    #[maybe_async::test(sync, async(not(sync), crate::futures_test))]
    async fn sending_add_with_leaf_not_supporting_credential_type_of_other_leaf_filters_it_out() {
        let (alice, tree) = new_tree("alice").await;

        let add = Proposal::Add(Box::new(AddProposal {
            key_package: unsupported_credential_key_package("bob").await,
        }));

        let add_ref = make_proposal_ref(&add, alice);

        let processed_proposals =
            CommitSender::new(&tree, alice, test_cipher_suite_provider(TEST_CIPHER_SUITE))
                .cache(add_ref.clone(), add.clone(), alice)
                .send()
                .await
                .unwrap();

        assert_eq!(processed_proposals.0, Vec::new());

        #[cfg(feature = "state_update")]
        assert_eq!(
            processed_proposals.1.rejected_proposals,
            vec![(add_ref, add)]
        );
    }

    #[cfg(feature = "custom_proposal")]
    #[maybe_async::test(sync, async(not(sync), crate::futures_test))]
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
    #[maybe_async::test(sync, async(not(sync), crate::futures_test))]
    async fn sending_custom_proposal_with_member_not_supporting_filters_it_out() {
        let (alice, tree) = new_tree("alice").await;

        let custom_proposal = Proposal::Custom(CustomProposal::new(ProposalType::new(42), vec![]));

        let custom_ref = make_proposal_ref(&custom_proposal, alice);

        let processed_proposals =
            CommitSender::new(&tree, alice, test_cipher_suite_provider(TEST_CIPHER_SUITE))
                .cache(custom_ref.clone(), custom_proposal.clone(), alice)
                .send()
                .await
                .unwrap();

        assert_eq!(processed_proposals.0, Vec::new());

        #[cfg(feature = "state_update")]
        assert_eq!(
            processed_proposals.1.rejected_proposals,
            vec![(custom_ref, custom_proposal)]
        );
    }

    #[cfg(feature = "custom_proposal")]
    #[maybe_async::test(sync, async(not(sync), crate::futures_test))]
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

    #[cfg(feature = "all_extensions")]
    #[maybe_async::test(sync, async(not(sync), crate::futures_test))]
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

    #[cfg(feature = "all_extensions")]
    #[maybe_async::test(sync, async(not(sync), crate::futures_test))]
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

    #[cfg(feature = "all_extensions")]
    #[maybe_async::test(sync, async(not(sync), crate::futures_test))]
    async fn sending_group_extension_unsupported_by_leaf_filters_it_out() {
        let (alice, tree) = new_tree("alice").await;

        let proposal = Proposal::GroupContextExtensions(make_extension_list(0));
        let proposal_ref = make_proposal_ref(&proposal, alice);

        let processed_proposals =
            CommitSender::new(&tree, alice, test_cipher_suite_provider(TEST_CIPHER_SUITE))
                .cache(proposal_ref.clone(), proposal.clone(), alice)
                .send()
                .await
                .unwrap();

        assert_eq!(processed_proposals.0, Vec::new());

        #[cfg(feature = "state_update")]
        assert_eq!(
            processed_proposals.1.rejected_proposals,
            vec![(proposal_ref, proposal)]
        );
    }

    #[cfg(feature = "psk")]
    #[derive(Debug)]
    struct AlwaysNotFoundPskStorage;

    #[cfg(feature = "psk")]
    #[maybe_async::maybe_async]
    impl PreSharedKeyStorage for AlwaysNotFoundPskStorage {
        type Error = Infallible;

        async fn get(&self, _: &ExternalPskId) -> Result<Option<PreSharedKey>, Self::Error> {
            Ok(None)
        }
    }

    #[cfg(feature = "psk")]
    #[maybe_async::test(sync, async(not(sync), crate::futures_test))]
    async fn receiving_external_psk_with_unknown_id_fails() {
        let (alice, tree) = new_tree("alice").await;

        let res = CommitReceiver::new(
            &tree,
            alice,
            alice,
            test_cipher_suite_provider(TEST_CIPHER_SUITE),
        )
        .with_psk_storage(AlwaysNotFoundPskStorage)
        .receive([Proposal::Psk(new_external_psk(b"abc"))])
        .await;

        assert_matches!(res, Err(MlsError::MissingRequiredPsk));
    }

    #[cfg(feature = "psk")]
    #[maybe_async::test(sync, async(not(sync), crate::futures_test))]
    async fn sending_additional_external_psk_with_unknown_id_fails() {
        let (alice, tree) = new_tree("alice").await;

        let res = CommitSender::new(&tree, alice, test_cipher_suite_provider(TEST_CIPHER_SUITE))
            .with_psk_storage(AlwaysNotFoundPskStorage)
            .with_additional([Proposal::Psk(new_external_psk(b"abc"))])
            .send()
            .await;

        assert_matches!(res, Err(MlsError::MissingRequiredPsk));
    }

    #[cfg(feature = "psk")]
    #[maybe_async::test(sync, async(not(sync), crate::futures_test))]
    async fn sending_external_psk_with_unknown_id_filters_it_out() {
        let (alice, tree) = new_tree("alice").await;
        let proposal = Proposal::Psk(new_external_psk(b"abc"));
        let proposal_ref = make_proposal_ref(&proposal, alice);

        let processed_proposals =
            CommitSender::new(&tree, alice, test_cipher_suite_provider(TEST_CIPHER_SUITE))
                .with_psk_storage(AlwaysNotFoundPskStorage)
                .cache(proposal_ref.clone(), proposal.clone(), alice)
                .send()
                .await
                .unwrap();

        assert_eq!(processed_proposals.0, Vec::new());

        #[cfg(feature = "state_update")]
        assert_eq!(
            processed_proposals.1.rejected_proposals,
            vec![(proposal_ref, proposal)]
        );
    }

    #[maybe_async::test(sync, async(not(sync), crate::futures_test))]
    async fn user_defined_filter_can_remove_proposals() {
        struct RemoveGroupContextExtensions;

        #[maybe_async::maybe_async]
        impl ProposalRules for RemoveGroupContextExtensions {
            type Error = Infallible;

            #[cfg(feature = "custom_proposal")]
            async fn expand_custom_proposals(
                &self,
                _current_roster: &[Member],
                _extension_list: &ExtensionList,
                _proposals: &[ProposalInfo<CustomProposal>],
            ) -> Result<Vec<ProposalInfo<Proposal>>, Self::Error> {
                Ok(vec![])
            }

            async fn validate(
                &self,
                _: Sender,
                _: &[Member],
                _: &ExtensionList,
                _: &ProposalBundle,
            ) -> Result<(), Self::Error> {
                Ok(())
            }

            async fn filter(
                &self,
                _: Sender,
                _: &[Member],
                _: &ExtensionList,
                mut proposals: ProposalBundle,
            ) -> Result<ProposalBundle, Self::Error> {
                proposals.group_context_extensions.clear();
                Ok(proposals)
            }
        }

        let (alice, tree) = new_tree("alice").await;

        let (committed, _) =
            CommitSender::new(&tree, alice, test_cipher_suite_provider(TEST_CIPHER_SUITE))
                .with_additional([Proposal::GroupContextExtensions(Default::default())])
                .with_user_rules(RemoveGroupContextExtensions)
                .send()
                .await
                .unwrap();

        assert_eq!(committed, Vec::new());
    }

    struct FailureProposalRules;

    #[maybe_async::maybe_async]
    impl ProposalRules for FailureProposalRules {
        type Error = MlsError;

        #[cfg(feature = "custom_proposal")]
        async fn expand_custom_proposals(
            &self,
            _current_roster: &[Member],
            _extension_list: &ExtensionList,
            _proposals: &[ProposalInfo<CustomProposal>],
        ) -> Result<Vec<ProposalInfo<Proposal>>, Self::Error> {
            Ok(vec![])
        }

        async fn validate(
            &self,
            _: Sender,
            _: &[Member],
            _: &ExtensionList,
            _: &ProposalBundle,
        ) -> Result<(), Self::Error> {
            Err(MlsError::InvalidSignature)
        }

        async fn filter(
            &self,
            _: Sender,
            _: &[Member],
            _: &ExtensionList,
            _: ProposalBundle,
        ) -> Result<ProposalBundle, Self::Error> {
            Err(MlsError::InvalidSignature)
        }
    }

    #[maybe_async::test(sync, async(not(sync), crate::futures_test))]
    async fn user_defined_filter_can_refuse_to_send_commit() {
        let (alice, tree) = new_tree("alice").await;

        let res = CommitSender::new(&tree, alice, test_cipher_suite_provider(TEST_CIPHER_SUITE))
            .with_additional([Proposal::GroupContextExtensions(Default::default())])
            .with_user_rules(FailureProposalRules)
            .send()
            .await;

        assert_matches!(res, Err(MlsError::UserDefinedProposalFilterError(_)));
    }

    #[maybe_async::test(sync, async(not(sync), crate::futures_test))]
    async fn user_defined_filter_can_reject_incoming_commit() {
        let (alice, tree) = new_tree("alice").await;

        let res = CommitReceiver::new(
            &tree,
            alice,
            alice,
            test_cipher_suite_provider(TEST_CIPHER_SUITE),
        )
        .with_user_rules(FailureProposalRules)
        .receive([Proposal::GroupContextExtensions(Default::default())])
        .await;

        assert_matches!(res, Err(MlsError::UserDefinedProposalFilterError(_)));
    }

    #[cfg(feature = "custom_proposal")]
    #[derive(Debug, Clone)]
    struct ExpandCustomRules {
        to_expand: Vec<ProposalInfo<Proposal>>,
    }

    #[cfg(feature = "custom_proposal")]
    #[maybe_async::maybe_async]
    impl ProposalRules for ExpandCustomRules {
        type Error = Infallible;

        async fn expand_custom_proposals(
            &self,
            _current_roster: &[Member],
            _extension_list: &ExtensionList,
            _proposals: &[ProposalInfo<CustomProposal>],
        ) -> Result<Vec<ProposalInfo<Proposal>>, Self::Error> {
            Ok(self.to_expand.clone())
        }

        async fn validate(
            &self,
            _: Sender,
            _: &[Member],
            _: &ExtensionList,
            _: &ProposalBundle,
        ) -> Result<(), Self::Error> {
            Ok(())
        }

        async fn filter(
            &self,
            _: Sender,
            _: &[Member],
            _: &ExtensionList,
            bundle: ProposalBundle,
        ) -> Result<ProposalBundle, Self::Error> {
            Ok(bundle)
        }
    }

    #[cfg(feature = "custom_proposal")]
    #[maybe_async::test(sync, async(not(sync), crate::futures_test))]
    async fn user_defined_custom_proposal_rules_are_applied_on_send() {
        let (alice, tree) = new_tree_custom_proposals("alice", vec![ProposalType::new(42)]).await;

        let add_proposal = make_custom_add_proposal(Capabilities {
            proposals: vec![ProposalType::new(42)],
            ..get_test_capabilities()
        })
        .await;

        let expander = ExpandCustomRules {
            to_expand: vec![ProposalInfo {
                proposal: Proposal::Add(Box::new(add_proposal.clone())),
                sender: Sender::Member(alice.into()),
                source: ProposalSource::CustomRule(true),
            }],
        };

        let custom_proposal = CustomProposal::new(ProposalType::new(42), vec![]);

        let processed_proposals =
            CommitSender::new(&tree, alice, test_cipher_suite_provider(TEST_CIPHER_SUITE))
                .with_user_rules(expander)
                .with_additional(vec![Proposal::Custom(custom_proposal.clone())])
                .send()
                .await
                .unwrap();

        assert_eq!(
            processed_proposals.0,
            vec![ProposalOrRef::Proposal(Box::new(Proposal::Custom(
                custom_proposal.clone()
            )))]
        );

        #[cfg(feature = "state_update")]
        assert_eq!(
            processed_proposals.1.applied_proposals.additions[0].proposal,
            add_proposal
        );

        #[cfg(feature = "state_update")]
        assert_eq!(
            processed_proposals.1.applied_proposals.custom_proposals[0].proposal,
            custom_proposal
        )
    }

    #[cfg(feature = "custom_proposal")]
    #[maybe_async::test(sync, async(not(sync), crate::futures_test))]
    async fn user_defined_custom_proposal_rules_are_applied_on_receive() {
        let (alice, tree) = new_tree_custom_proposals("alice", vec![ProposalType::new(42)]).await;

        let add_proposal = make_custom_add_proposal(Capabilities {
            proposals: vec![ProposalType::new(42)],
            ..get_test_capabilities()
        })
        .await;

        let expander = ExpandCustomRules {
            to_expand: vec![ProposalInfo {
                proposal: Proposal::Add(Box::new(add_proposal.clone())),
                sender: Sender::Member(0),
                source: ProposalSource::CustomRule(true),
            }],
        };

        let custom_proposal = CustomProposal::new(ProposalType::new(42), vec![]);

        let processed_proposals = CommitReceiver::new(
            &tree,
            alice,
            alice,
            test_cipher_suite_provider(TEST_CIPHER_SUITE),
        )
        .with_user_rules(expander)
        .receive(vec![Proposal::Custom(custom_proposal.clone())])
        .await
        .unwrap();

        // If the add is applied, then the custom proposal must have been applied.
        #[cfg(feature = "state_update")]
        assert_eq!(
            processed_proposals.applied_proposals.additions[0].proposal,
            add_proposal
        );

        // Check that `custom_proposals` are computed correctly.
        #[cfg(feature = "state_update")]
        assert_eq!(
            processed_proposals.applied_proposals.custom_proposals[0].proposal,
            custom_proposal
        )
    }

    #[cfg(feature = "custom_proposal")]
    #[maybe_async::test(sync, async(not(sync), crate::futures_test))]
    async fn user_defined_custom_proposal_rules_are_not_exempt_from_base_rules() {
        let (alice, tree) = new_tree_custom_proposals("alice", vec![ProposalType::new(42)]).await;

        let update_proposal = ProposalInfo {
            proposal: Proposal::Update(UpdateProposal {
                leaf_node: get_basic_test_node(TEST_CIPHER_SUITE, "leaf").await,
            }),
            sender: Sender::NewMemberCommit,
            source: ProposalSource::CustomRule(true),
        };

        let expander = ExpandCustomRules {
            to_expand: vec![update_proposal],
        };

        let custom_proposal = CustomProposal::new(ProposalType::new(42), vec![]);

        let res = CommitReceiver::new(
            &tree,
            alice,
            alice,
            test_cipher_suite_provider(TEST_CIPHER_SUITE),
        )
        .with_user_rules(expander)
        .receive(vec![Proposal::Custom(custom_proposal)])
        .await;

        assert_matches!(res, Err(MlsError::InvalidProposalTypeForSender { .. }))
    }

    #[maybe_async::test(sync, async(not(sync), crate::futures_test))]
    async fn proposers_are_verified() {
        let (alice, mut tree) = new_tree("alice").await;
        let bob = add_member(&mut tree, "bob").await;

        #[cfg(feature = "external_proposal")]
        let external_senders = ExternalSendersExt::new(vec![
            get_test_signing_identity(TEST_CIPHER_SUITE, b"carol".to_vec()).0,
        ]);

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
            #[cfg(feature = "external_commit")]
            Proposal::ExternalInit(make_external_init()),
            Proposal::GroupContextExtensions(Default::default()),
        ];

        let proposers = [
            Sender::Member(*alice),
            #[cfg(feature = "external_proposal")]
            Sender::External(0),
            #[cfg(feature = "external_commit")]
            Sender::NewMemberCommit,
            Sender::NewMemberProposal,
        ];

        for ((proposer, proposal), by_ref) in proposers
            .into_iter()
            .cartesian_product(proposals)
            .cartesian_product([true])
        {
            let committer = Sender::Member(*alice);

            let receiver = CommitReceiver::new(
                &tree,
                committer,
                alice,
                test_cipher_suite_provider(TEST_CIPHER_SUITE),
            );

            #[cfg(feature = "external_proposal")]
            let extensions: ExtensionList =
                vec![external_senders.clone().into_extension().unwrap()].into();

            #[cfg(feature = "external_proposal")]
            let receiver = receiver.with_extensions(extensions);

            let (receiver, proposals, proposer) = if by_ref {
                let proposal_ref = make_proposal_ref(proposal, proposer);
                let receiver = receiver.cache(proposal_ref.clone(), proposal.clone(), proposer);
                (receiver, vec![ProposalOrRef::from(proposal_ref)], proposer)
            } else {
                (receiver, vec![proposal.clone().into()], committer)
            };

            let res = receiver.receive(proposals).await;

            if proposer_can_propose(proposer, proposal.proposal_type(), by_ref).is_err() {
                assert_matches!(res, Err(MlsError::InvalidProposalTypeForSender));
            } else {
                let is_self_update = proposal.proposal_type() == ProposalType::UPDATE
                    && by_ref
                    && matches!(proposer, Sender::Member(_));

                if !is_self_update {
                    res.unwrap();
                }
            }
        }
    }

    #[maybe_async::maybe_async]
    async fn make_update_proposal(name: &str) -> UpdateProposal {
        UpdateProposal {
            leaf_node: update_leaf_node(name, 1).await,
        }
    }

    #[maybe_async::maybe_async]
    async fn make_update_proposal_custom(name: &str, leaf_index: u32) -> UpdateProposal {
        UpdateProposal {
            leaf_node: update_leaf_node(name, leaf_index).await,
        }
    }
}
