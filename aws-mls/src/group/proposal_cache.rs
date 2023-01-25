use super::*;
use crate::{
    group::proposal_filter::{
        FailInvalidProposal, IgnoreInvalidByRefProposal, ProposalApplier, ProposalBundle,
        ProposalFilter, ProposalFilterError, ProposalInfo, ProposalState,
    },
    psk::ExternalPskIdValidator,
    time::MlsTime,
    tree_kem::leaf_node::LeafNode,
};

#[derive(Error, Debug)]
pub enum ProposalCacheError {
    #[error(transparent)]
    ProposalFilterError(#[from] ProposalFilterError),
    #[error("Proposal {0:?} not found")]
    ProposalNotFound(ProposalRef),
    #[error("Invalid required capabilities")]
    InvalidRequiredCapabilities(#[source] ExtensionError),
}

#[derive(Debug, PartialEq)]
pub(crate) struct ProposalSetEffects {
    pub tree: TreeKemPublic,
    pub added_leaf_indexes: Vec<LeafIndex>,
    pub removed_leaves: Vec<(LeafIndex, LeafNode)>,
    pub adds: Vec<KeyPackage>,
    pub updates: Vec<(LeafIndex, LeafNode)>,
    pub removes: Vec<LeafIndex>,
    pub group_context_ext: Option<ExtensionList<GroupContextExtension>>,
    pub psks: Vec<PreSharedKeyID>,
    pub reinit: Option<ReInit>,
    pub external_init: Option<(LeafIndex, ExternalInit)>,
    pub rejected_proposals: Vec<(ProposalRef, Proposal)>,
}

impl ProposalSetEffects {
    pub fn new(
        tree: TreeKemPublic,
        added_leaf_indexes: Vec<LeafIndex>,
        removed_leaves: Vec<(LeafIndex, LeafNode)>,
        proposals: ProposalBundle,
        external_leaf: Option<LeafIndex>,
        rejected_proposals: Vec<(ProposalRef, Proposal)>,
    ) -> Result<Self, ProposalCacheError> {
        let init = ProposalSetEffects {
            tree,
            added_leaf_indexes,
            removed_leaves,
            adds: Vec::new(),
            updates: Vec::new(),
            removes: Vec::new(),
            group_context_ext: None,
            psks: Vec::new(),
            reinit: None,
            external_init: None,
            rejected_proposals,
        };

        proposals
            .into_proposals()
            .try_fold(init, |effects, item| effects.add(item, external_leaf))
    }

    pub fn is_empty(&self) -> bool {
        self.adds.is_empty()
            && self.updates.is_empty()
            && self.removes.is_empty()
            && self.group_context_ext.is_none()
            && self.psks.is_empty()
            && self.reinit.is_none()
            && self.external_init.is_none()
    }

    //By default, the path field of a Commit MUST be populated. The path field MAY be omitted if
    //(a) it covers at least one proposal and (b) none of the proposals covered by the Commit are
    //of "path required" types. A proposal type requires a path if it cannot change the group
    //membership in a way that requires the forward secrecy and post-compromise security guarantees
    //that an UpdatePath provides. The only proposal types defined in this document that do not
    //require a path are:

    // add
    // psk
    // reinit
    pub fn path_update_required(&self) -> bool {
        self.is_empty()
            || self.group_context_ext.is_some()
            || !self.updates.is_empty()
            || !self.removes.is_empty()
            || self.external_init.is_some()
    }

    fn add(
        mut self,
        item: ProposalInfo<Proposal>,
        external_leaf: Option<LeafIndex>,
    ) -> Result<Self, ProposalCacheError> {
        match item.proposal {
            Proposal::Add(add) => self.adds.push(add.key_package),
            Proposal::Update(update) => {
                if let Sender::Member(package_to_replace) = item.sender {
                    self.updates
                        .push((LeafIndex(package_to_replace), update.leaf_node))
                }
            }
            Proposal::Remove(remove) => self.removes.push(remove.to_remove),
            Proposal::GroupContextExtensions(list) => self.group_context_ext = Some(list),
            Proposal::Psk(PreSharedKey { psk }) => {
                self.psks.push(psk);
            }
            Proposal::ReInit(reinit) => {
                self.reinit = Some(reinit);
            }
            Proposal::ExternalInit(external_init) => {
                let new_member_leaf_index =
                    external_leaf.ok_or(ProposalCacheError::ProposalFilterError(
                        ProposalFilterError::MissingUpdatePathInExternalCommit,
                    ))?;
                self.external_init = Some((new_member_leaf_index, external_init));
            }
        };

        Ok(self)
    }
}

#[derive(Debug, Clone, PartialEq, serde::Deserialize, serde::Serialize)]
pub struct CachedProposal {
    proposal: Proposal,
    sender: Sender,
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct ProposalCache {
    protocol_version: ProtocolVersion,
    group_id: Vec<u8>,
    proposals: HashMap<ProposalRef, CachedProposal>,
}

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
        proposals: HashMap<ProposalRef, CachedProposal>,
    ) -> Self {
        Self {
            protocol_version,
            group_id,
            proposals,
        }
    }

    pub fn clear(&mut self) {
        self.proposals.clear();
    }

    pub fn is_empty(&self) -> bool {
        self.proposals.is_empty()
    }

    pub fn insert(&mut self, proposal_ref: ProposalRef, proposal: Proposal, sender: Sender) {
        let cached_proposal = CachedProposal { proposal, sender };
        self.proposals.insert(proposal_ref, cached_proposal);
    }

    pub fn proposals(&self) -> &HashMap<ProposalRef, CachedProposal> {
        &self.proposals
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn prepare_commit<C, F, P, CSP>(
        &self,
        sender: Sender,
        additional_proposals: Vec<Proposal>,
        group_extensions: &ExtensionList<GroupContextExtension>,
        identity_provider: C,
        cipher_suite_provider: &CSP,
        public_tree: &TreeKemPublic,
        external_leaf: Option<&LeafNode>,
        external_psk_id_validator: P,
        user_filter: F,
    ) -> Result<(Vec<ProposalOrRef>, ProposalSetEffects), ProposalCacheError>
    where
        C: IdentityProvider,
        F: ProposalFilter,
        P: ExternalPskIdValidator,
        CSP: CipherSuiteProvider,
    {
        let proposals = self
            .proposals
            .iter()
            .map(|(proposal_ref, proposal)| {
                (
                    proposal.proposal.clone(),
                    proposal.sender.clone(),
                    Some(proposal_ref.clone()),
                )
            })
            .chain(
                additional_proposals
                    .into_iter()
                    .map(|p| (p, sender.clone(), None)),
            )
            .fold(
                ProposalBundle::default(),
                |mut proposals, (proposal, sender, proposal_ref)| {
                    proposals.add(proposal, sender, proposal_ref);
                    proposals
                },
            );

        let proposals = user_filter
            .filter(proposals)
            .map_err(ProposalFilterError::user_defined)?;

        let required_capabilities = group_extensions
            .get_extension()
            .map_err(ProposalCacheError::InvalidRequiredCapabilities)?;

        let applier = ProposalApplier::new(
            public_tree,
            self.protocol_version,
            cipher_suite_provider,
            &self.group_id,
            group_extensions,
            required_capabilities.as_ref(),
            external_leaf,
            &identity_provider,
            external_psk_id_validator,
        );

        let ProposalState {
            tree,
            proposals,
            added_indexes,
            removed_leaves,
            external_leaf_index,
        } = applier
            .apply_proposals(
                IgnoreInvalidByRefProposal,
                &sender,
                proposals,
                Some(MlsTime::now()),
            )
            .await?;

        let rejected = rejected_proposals(self.proposals.clone(), &proposals, &sender);

        let effects = ProposalSetEffects::new(
            tree,
            added_indexes,
            removed_leaves,
            proposals.clone(),
            external_leaf_index,
            rejected,
        )?;

        let proposals = proposals.into_proposals_or_refs().collect();
        Ok((proposals, effects))
    }

    fn resolve_item(
        &self,
        sender: Sender,
        proposal: ProposalOrRef,
    ) -> Result<CachedProposal, ProposalCacheError> {
        match proposal {
            ProposalOrRef::Proposal(proposal) => Ok(CachedProposal { proposal, sender }),
            ProposalOrRef::Reference(proposal_ref) => self
                .proposals
                .get(&proposal_ref)
                .cloned()
                .ok_or(ProposalCacheError::ProposalNotFound(proposal_ref)),
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn resolve_for_commit<C, F, P, CSP>(
        &self,
        sender: Sender,
        receiver: Option<LeafIndex>,
        proposal_list: Vec<ProposalOrRef>,
        external_leaf: Option<&LeafNode>,
        group_extensions: &ExtensionList<GroupContextExtension>,
        identity_provider: C,
        cipher_suite_provider: &CSP,
        public_tree: &TreeKemPublic,
        external_psk_id_validator: P,
        user_filter: F,
        commit_time: Option<MlsTime>,
    ) -> Result<ProposalSetEffects, ProposalCacheError>
    where
        C: IdentityProvider,
        F: ProposalFilter,
        P: ExternalPskIdValidator,
        CSP: CipherSuiteProvider,
    {
        let proposals = proposal_list.into_iter().try_fold(
            ProposalBundle::default(),
            |mut proposals, proposal| {
                let proposal_ref = match &proposal {
                    ProposalOrRef::Reference(r) => Some(r.clone()),
                    ProposalOrRef::Proposal(_) => None,
                };

                let proposal = self.resolve_item(sender.clone(), proposal)?;
                proposals.add(proposal.proposal, proposal.sender, proposal_ref);
                Ok::<_, ProposalCacheError>(proposals)
            },
        )?;

        user_filter
            .validate(&proposals)
            .map_err(ProposalFilterError::user_defined)?;

        let required_capabilities = group_extensions
            .get_extension()
            .map_err(ProposalCacheError::InvalidRequiredCapabilities)?;

        let applier = ProposalApplier::new(
            public_tree,
            self.protocol_version,
            cipher_suite_provider,
            &self.group_id,
            group_extensions,
            required_capabilities.as_ref(),
            external_leaf,
            &identity_provider,
            external_psk_id_validator,
        );

        let ProposalState {
            tree,
            proposals,
            added_indexes,
            removed_leaves,
            external_leaf_index,
        } = applier
            .apply_proposals(FailInvalidProposal, &sender, proposals, commit_time)
            .await?;

        let rejected = receiver
            .map(|index| {
                rejected_proposals(self.proposals.clone(), &proposals, &Sender::Member(*index))
            })
            .unwrap_or_default();

        ProposalSetEffects::new(
            tree,
            added_indexes,
            removed_leaves,
            proposals,
            external_leaf_index,
            rejected,
        )
    }
}

impl Extend<(ProposalRef, CachedProposal)> for ProposalCache {
    fn extend<T>(&mut self, iter: T)
    where
        T: IntoIterator<Item = (ProposalRef, CachedProposal)>,
    {
        self.proposals.extend(iter);
    }
}

fn rejected_proposals(
    mut cache: HashMap<ProposalRef, CachedProposal>,
    accepted_proposals: &ProposalBundle,
    sender: &Sender,
) -> Vec<(ProposalRef, Proposal)> {
    accepted_proposals
        .iter_proposals()
        .filter_map(|p| p.proposal_ref)
        .for_each(|r| {
            cache.remove(&r);
        });

    cache
        .into_iter()
        .filter(|(_, p)| p.sender == *sender)
        .map(|(r, p)| (r, p.proposal))
        .collect()
}

#[cfg(test)]
impl CachedProposal {
    pub fn new(proposal: Proposal, sender: Sender) -> Self {
        Self { proposal, sender }
    }
}

#[cfg(test)]
mod tests {
    use super::proposal_ref::test_utils::auth_content_from_proposal;
    use super::*;
    use crate::{
        extension::{test_utils::TestExtension, ExternalSendersExt, RequiredCapabilitiesExt},
        group::{
            proposal_filter::proposer_can_propose,
            test_utils::{random_bytes, test_group, TEST_GROUP},
        },
        identity::{
            test_utils::{get_test_signing_identity, INVALID_CREDENTIAL_TYPE},
            BasicCredential,
        },
        key_package::{
            test_utils::{test_key_package, test_key_package_custom},
            KeyPackageGenerator,
        },
        provider::{
            crypto::{self, test_utils::test_cipher_suite_provider},
            identity::BasicIdentityProvider,
        },
        psk::PassThroughPskIdValidator,
        tree_kem::{
            leaf_node::{
                test_utils::{
                    default_properties, get_basic_test_node, get_basic_test_node_sig_key,
                },
                ConfigProperties, LeafNodeSource,
            },
            leaf_node_validator::{test_utils::FailureIdentityProvider, LeafNodeValidationError},
            parent_hash::ParentHash,
            AccumulateBatchResults, Lifetime, RatchetTreeError, TreeIndexError,
        },
    };

    use assert_matches::assert_matches;
    use aws_mls_core::identity::{Credential, CredentialType};
    use futures::FutureExt;
    use itertools::Itertools;
    use std::convert::Infallible;

    const TEST_CIPHER_SUITE: CipherSuite = CipherSuite::P256Aes128;
    const TEST_PROTOCOL_VERSION: ProtocolVersion = ProtocolVersion::Mls10;

    #[cfg(target_arch = "wasm32")]
    use wasm_bindgen_test::wasm_bindgen_test as test;

    impl ProposalCache {
        #[allow(clippy::too_many_arguments)]
        pub async fn resolve_for_commit_default<C, F, P, CSP>(
            &self,
            sender: Sender,
            receiver: Option<LeafIndex>,
            proposal_list: Vec<ProposalOrRef>,
            external_leaf: Option<&LeafNode>,
            group_extensions: &ExtensionList<GroupContextExtension>,
            identity_provider: C,
            cipher_suite_provider: &CSP,
            public_tree: &TreeKemPublic,
            external_psk_id_validator: P,
            user_filter: F,
        ) -> Result<ProposalSetEffects, ProposalCacheError>
        where
            C: IdentityProvider,
            F: ProposalFilter,
            P: ExternalPskIdValidator,
            CSP: CipherSuiteProvider,
        {
            self.resolve_for_commit(
                sender,
                receiver,
                proposal_list,
                external_leaf,
                group_extensions,
                identity_provider,
                cipher_suite_provider,
                public_tree,
                external_psk_id_validator,
                user_filter,
                None,
            )
            .await
        }
    }

    fn test_sender() -> u32 {
        1
    }

    async fn new_tree(name: &str) -> (LeafIndex, TreeKemPublic) {
        let (leaf, secret, _) = get_basic_test_node_sig_key(TEST_CIPHER_SUITE, name).await;

        let (pub_tree, priv_tree) = TreeKemPublic::derive(
            leaf,
            secret,
            BasicIdentityProvider,
            &test_cipher_suite_provider(TEST_CIPHER_SUITE),
        )
        .await
        .unwrap();

        (priv_tree.self_index, pub_tree)
    }

    async fn add_member(tree: &mut TreeKemPublic, name: &str) -> LeafIndex {
        tree.add_leaves(
            vec![get_basic_test_node(TEST_CIPHER_SUITE, name).await],
            BasicIdentityProvider,
            &test_cipher_suite_provider(TEST_CIPHER_SUITE),
        )
        .await
        .unwrap()[0]
    }

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
        test_proposals: Vec<MLSAuthenticatedContent>,
        expected_effects: ProposalSetEffects,
        tree: TreeKemPublic,
    }

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
            BasicIdentityProvider,
            &cipher_suite_provider,
        )
        .await
        .unwrap();

        let add_package = test_key_package(protocol_version, cipher_suite, "dave").await;
        let update_leaf = update_leaf_node("alice", 0).await;

        let remove_leaf_index = add_member(&mut tree, "carol").await;

        let add = Proposal::Add(AddProposal {
            key_package: add_package.clone(),
        });

        let update = Proposal::Update(UpdateProposal {
            leaf_node: update_leaf.clone(),
        });

        let remove = Proposal::Remove(RemoveProposal {
            to_remove: remove_leaf_index,
        });

        let extensions = Proposal::GroupContextExtensions(ExtensionList::new());

        let proposals = vec![add, update, remove, extensions];

        let test_sender = *tree
            .add_leaves(
                vec![get_basic_test_node(cipher_suite, "charlie").await],
                BasicIdentityProvider,
                &cipher_suite_provider,
            )
            .await
            .unwrap()[0];

        let mut expected_tree = tree.clone();

        expected_tree
            .batch_edit(
                NoopAccumulator,
                &[(sender, update_leaf.clone())],
                &[remove_leaf_index],
                &[add_package.leaf_node.clone()],
                BasicIdentityProvider,
                &cipher_suite_provider,
            )
            .await
            .unwrap();

        let effects = ProposalSetEffects {
            tree: expected_tree,
            added_leaf_indexes: vec![LeafIndex(1)],
            removed_leaves: vec![(
                remove_leaf_index,
                tree.get_leaf_node(remove_leaf_index).unwrap().clone(),
            )],
            adds: vec![add_package],
            updates: vec![(sender, update_leaf)],
            removes: vec![remove_leaf_index],
            group_context_ext: Some(ExtensionList::new()),
            psks: Vec::new(),
            reinit: None,
            external_init: None,
            rejected_proposals: Vec::new(),
        };

        let plaintext = proposals
            .into_iter()
            .map(|p| auth_content_from_proposal(p, sender))
            .collect();

        TestProposals {
            test_sender,
            test_proposals: plaintext,
            expected_effects: effects,
            tree,
        }
    }

    struct NoopAccumulator;

    impl AccumulateBatchResults for NoopAccumulator {
        type Output = ();

        fn finish(self) -> Result<Self::Output, RatchetTreeError> {
            Ok(())
        }
    }

    fn filter_proposals(
        cipher_suite: CipherSuite,
        proposals: Vec<MLSAuthenticatedContent>,
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
                        CachedProposal::new(proposal.clone(), p.content.sender),
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

    fn make_proposal_cache() -> ProposalCache {
        ProposalCache::new(TEST_PROTOCOL_VERSION, TEST_GROUP.to_vec())
    }

    fn test_proposal_cache_setup(proposals: Vec<MLSAuthenticatedContent>) -> ProposalCache {
        let mut cache = make_proposal_cache();
        cache.extend(filter_proposals(TEST_CIPHER_SUITE, proposals));
        cache
    }

    fn assert_matches(
        expected_proposals: Vec<ProposalOrRef>,
        expected_effects: ProposalSetEffects,
        proposals: Vec<ProposalOrRef>,
        effects: ProposalSetEffects,
    ) {
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

        assert_eq!(expected_effects, effects);
    }

    fn pass_through_filter() -> PassThroughProposalFilter<Infallible> {
        PassThroughProposalFilter::new()
    }

    #[futures_test::test]
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

        let (proposals, effects) = cache
            .prepare_commit(
                Sender::Member(test_sender),
                vec![],
                &ExtensionList::new(),
                BasicIdentityProvider::new(),
                &cipher_suite_provider,
                &tree,
                None,
                PassThroughPskIdValidator,
                pass_through_filter(),
            )
            .await
            .unwrap();

        let expected_proposals = test_proposals
            .into_iter()
            .map(|p| {
                ProposalOrRef::Reference(
                    ProposalRef::from_content(&cipher_suite_provider, &p).unwrap(),
                )
            })
            .collect();

        assert_matches(expected_proposals, expected_effects, proposals, effects)
    }

    #[futures_test::test]
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

        let additional = vec![Proposal::Add(AddProposal {
            key_package: additional_key_package.clone(),
        })];

        let cache = test_proposal_cache_setup(test_proposals.clone());

        let (proposals, effects) = cache
            .prepare_commit(
                Sender::Member(test_sender),
                additional.clone(),
                &ExtensionList::new(),
                BasicIdentityProvider::new(),
                &cipher_suite_provider,
                &tree,
                None,
                PassThroughPskIdValidator,
                pass_through_filter(),
            )
            .await
            .unwrap();

        let mut expected_proposals = test_proposals
            .into_iter()
            .map(|p| {
                ProposalOrRef::Reference(
                    ProposalRef::from_content(&cipher_suite_provider, &p).unwrap(),
                )
            })
            .collect::<Vec<ProposalOrRef>>();

        expected_proposals.push(ProposalOrRef::Proposal(additional[0].clone()));

        expected_effects
            .tree
            .batch_edit(
                NoopAccumulator,
                &[],
                &[],
                &[additional_key_package.leaf_node.clone()],
                BasicIdentityProvider,
                &cipher_suite_provider,
            )
            .await
            .unwrap();

        expected_effects.adds.push(additional_key_package);
        expected_effects.added_leaf_indexes.push(LeafIndex(3));

        assert_matches(expected_proposals, expected_effects, proposals, effects);
    }

    #[futures_test::test]
    async fn test_proposal_cache_update_filter() {
        let cipher_suite_provider = test_cipher_suite_provider(TEST_CIPHER_SUITE);

        let TestProposals {
            test_proposals,
            tree,
            ..
        } = test_proposals(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE).await;

        let additional = vec![Proposal::Update(make_update_proposal("foo").await)];

        let cache = test_proposal_cache_setup(test_proposals);

        let res = cache
            .prepare_commit(
                Sender::Member(test_sender()),
                additional,
                &ExtensionList::new(),
                BasicIdentityProvider::new(),
                &cipher_suite_provider,
                &tree,
                None,
                PassThroughPskIdValidator,
                pass_through_filter(),
            )
            .await;

        assert_matches!(
            res,
            Err(ProposalCacheError::ProposalFilterError(
                ProposalFilterError::InvalidProposalTypeForSender {
                    proposal_type: ProposalType::UPDATE,
                    sender: Sender::Member(_),
                    by_ref: false,
                }
            ))
        );
    }

    #[futures_test::test]
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

        let (proposals, effects) = cache
            .prepare_commit(
                Sender::Member(test_sender),
                vec![],
                &ExtensionList::new(),
                BasicIdentityProvider::new(),
                &cipher_suite_provider,
                &tree,
                None,
                PassThroughPskIdValidator,
                pass_through_filter(),
            )
            .await
            .unwrap();

        assert!(effects.removes.contains(&LeafIndex(1)));
        assert!(!proposals.contains(&ProposalOrRef::Reference(update_proposal_ref)))
    }

    #[futures_test::test]
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

        let (proposals, effects) = cache
            .prepare_commit(
                Sender::Member(test_sender),
                vec![],
                &ExtensionList::new(),
                BasicIdentityProvider::new(),
                &cipher_suite_provider,
                &tree,
                None,
                PassThroughPskIdValidator,
                pass_through_filter(),
            )
            .await
            .unwrap();

        let expected_proposals = test_proposals
            .into_iter()
            .map(|p| {
                ProposalOrRef::Reference(
                    ProposalRef::from_content(&cipher_suite_provider, &p).unwrap(),
                )
            })
            .collect::<Vec<ProposalOrRef>>();

        assert_matches(expected_proposals, expected_effects, proposals, effects)
    }

    #[futures_test::test]
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
                Content::Proposal(Proposal::Update(_)) => None,
                Content::Proposal(_) => Some(plaintext),
                _ => None,
            })
            .collect::<Vec<_>>();

        cache.extend(filter_proposals(TEST_CIPHER_SUITE, additional));

        let (proposals, effects) = cache
            .prepare_commit(
                Sender::Member(2),
                Vec::new(),
                &ExtensionList::new(),
                BasicIdentityProvider::new(),
                &cipher_suite_provider,
                &tree,
                None,
                PassThroughPskIdValidator,
                pass_through_filter(),
            )
            .await
            .unwrap();

        let expected_proposals = test_proposals
            .into_iter()
            .map(|p| {
                ProposalOrRef::Reference(
                    ProposalRef::from_content(&cipher_suite_provider, &p).unwrap(),
                )
            })
            .collect::<Vec<ProposalOrRef>>();

        assert_matches(expected_proposals, expected_effects, proposals, effects)
    }

    #[test]
    fn test_proposal_cache_is_empty() {
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

    #[futures_test::test]
    async fn test_proposal_cache_resolve() {
        let cipher_suite_provider = test_cipher_suite_provider(TEST_CIPHER_SUITE);

        let TestProposals {
            test_sender,
            test_proposals,
            tree,
            ..
        } = test_proposals(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE).await;

        let cache = test_proposal_cache_setup(test_proposals);

        let additional = vec![Proposal::Add(AddProposal {
            key_package: test_key_package(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE, "frank").await,
        })];

        let identity_provider = BasicIdentityProvider::new();

        let (proposals, effects) = cache
            .prepare_commit(
                Sender::Member(test_sender),
                additional,
                &ExtensionList::new(),
                &identity_provider,
                &cipher_suite_provider,
                &tree,
                None,
                PassThroughPskIdValidator,
                pass_through_filter(),
            )
            .await
            .unwrap();

        let resolution = cache
            .resolve_for_commit_default(
                Sender::Member(test_sender),
                Some(LeafIndex(test_sender)),
                proposals,
                None,
                &ExtensionList::new(),
                &identity_provider,
                &cipher_suite_provider,
                &tree,
                PassThroughPskIdValidator,
                pass_through_filter(),
            )
            .await
            .unwrap();

        assert_eq!(effects, resolution);
    }

    #[futures_test::test]
    async fn proposal_cache_filters_duplicate_psk_ids() {
        let cipher_suite_provider = test_cipher_suite_provider(TEST_CIPHER_SUITE);

        let (alice, tree) = new_tree("alice").await;
        let cache = make_proposal_cache();

        let proposal = Proposal::Psk(make_external_psk(
            b"ted",
            PskNonce::random(&test_cipher_suite_provider(TEST_CIPHER_SUITE)).unwrap(),
        ));

        let res = cache
            .prepare_commit(
                Sender::Member(*alice),
                vec![proposal.clone(), proposal],
                &ExtensionList::new(),
                BasicIdentityProvider::new(),
                &cipher_suite_provider,
                &tree,
                None,
                PassThroughPskIdValidator,
                pass_through_filter(),
            )
            .await;

        assert_matches!(
            res,
            Err(ProposalCacheError::ProposalFilterError(
                ProposalFilterError::DuplicatePskIds
            ))
        );
    }

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
                ParentHash::empty(),
            )
            .unwrap();

        leaf_node
    }

    #[futures_test::test]
    async fn external_commit_must_have_new_leaf() {
        let cache = make_proposal_cache();
        let cipher_suite_provider = test_cipher_suite_provider(TEST_CIPHER_SUITE);

        let kem_output = vec![0; cipher_suite_provider.kdf_extract_size()];
        let group = test_group(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE).await;
        let public_tree = &group.group.state.public_tree;
        let identity_provider = BasicIdentityProvider::new();

        let res = cache
            .resolve_for_commit_default(
                Sender::NewMemberCommit,
                None,
                vec![ProposalOrRef::Proposal(Proposal::ExternalInit(
                    ExternalInit { kem_output },
                ))],
                None,
                &group.group.context().extensions,
                identity_provider,
                &cipher_suite_provider,
                public_tree,
                PassThroughPskIdValidator,
                pass_through_filter(),
            )
            .await;

        assert_matches!(
            res,
            Err(ProposalCacheError::ProposalFilterError(
                ProposalFilterError::ExternalCommitMustHaveNewLeaf
            ))
        );
    }

    #[futures_test::test]
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
                None,
                vec![ProposalOrRef::Reference(proposal_ref)],
                Some(&test_node().await),
                &group.group.context().extensions,
                BasicIdentityProvider::new(),
                &cipher_suite_provider,
                public_tree,
                PassThroughPskIdValidator,
                pass_through_filter(),
            )
            .await;

        assert_matches!(
            res,
            Err(ProposalCacheError::ProposalFilterError(
                ProposalFilterError::OnlyMembersCanCommitProposalsByRef
            ))
        );
    }

    #[futures_test::test]
    async fn proposal_cache_rejects_multiple_external_init_proposals_in_commit() {
        let cache = make_proposal_cache();
        let cipher_suite_provider = test_cipher_suite_provider(TEST_CIPHER_SUITE);
        let kem_output = vec![0; cipher_suite_provider.kdf_extract_size()];
        let group = test_group(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE).await;
        let public_tree = &group.group.state.public_tree;
        let identity_provider = BasicIdentityProvider::new();

        let res = cache
            .resolve_for_commit_default(
                Sender::NewMemberCommit,
                None,
                [
                    Proposal::ExternalInit(ExternalInit {
                        kem_output: kem_output.clone(),
                    }),
                    Proposal::ExternalInit(ExternalInit { kem_output }),
                ]
                .into_iter()
                .map(ProposalOrRef::Proposal)
                .collect(),
                Some(&test_node().await),
                &group.group.context().extensions,
                identity_provider,
                &cipher_suite_provider,
                public_tree,
                PassThroughPskIdValidator,
                pass_through_filter(),
            )
            .await;

        assert_matches!(
            res,
            Err(ProposalCacheError::ProposalFilterError(
                ProposalFilterError::ExternalCommitMustHaveExactlyOneExternalInit
            ))
        );
    }

    async fn new_member_commits_proposal(
        proposal: Proposal,
    ) -> Result<ProposalSetEffects, ProposalCacheError> {
        let cache = make_proposal_cache();
        let cipher_suite_provider = test_cipher_suite_provider(TEST_CIPHER_SUITE);
        let kem_output = vec![0; cipher_suite_provider.kdf_extract_size()];
        let group = test_group(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE).await;
        let public_tree = &group.group.state.public_tree;
        let identity_provider = BasicIdentityProvider::new();

        cache
            .resolve_for_commit_default(
                Sender::NewMemberCommit,
                None,
                [
                    Proposal::ExternalInit(ExternalInit { kem_output }),
                    proposal,
                ]
                .into_iter()
                .map(ProposalOrRef::Proposal)
                .collect(),
                Some(&test_node().await),
                &group.group.context().extensions,
                identity_provider,
                &cipher_suite_provider,
                public_tree,
                PassThroughPskIdValidator,
                pass_through_filter(),
            )
            .await
    }

    #[futures_test::test]
    async fn new_member_cannot_commit_add_proposal() {
        let res = new_member_commits_proposal(Proposal::Add(AddProposal {
            key_package: test_key_package(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE, "frank").await,
        }))
        .await;

        assert_matches!(
            res,
            Err(ProposalCacheError::ProposalFilterError(
                ProposalFilterError::InvalidProposalTypeInExternalCommit(ProposalType::ADD)
            ))
        );
    }

    #[futures_test::test]
    async fn new_member_cannot_commit_more_than_one_remove_proposal() {
        let cache = make_proposal_cache();
        let cipher_suite_provider = test_cipher_suite_provider(TEST_CIPHER_SUITE);
        let kem_output = vec![0; cipher_suite_provider.kdf_extract_size()];
        let group = test_group(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE).await;
        let group_extensions = group.group.context().extensions.clone();
        let mut public_tree = group.group.state.public_tree;
        let identity_provider = BasicIdentityProvider::new();

        let test_leaf_nodes = vec![
            get_basic_test_node(TEST_CIPHER_SUITE, "foo").await,
            get_basic_test_node(TEST_CIPHER_SUITE, "bar").await,
        ];

        let test_leaf_node_indexes = public_tree
            .add_leaves(
                test_leaf_nodes,
                BasicIdentityProvider,
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
                None,
                proposals.into_iter().map(ProposalOrRef::Proposal).collect(),
                Some(&test_node().await),
                &group_extensions,
                identity_provider,
                &cipher_suite_provider,
                &public_tree,
                PassThroughPskIdValidator,
                pass_through_filter(),
            )
            .await;

        assert_matches!(
            res,
            Err(ProposalCacheError::ProposalFilterError(
                ProposalFilterError::ExternalCommitWithMoreThanOneRemove
            ))
        );
    }

    #[futures_test::test]
    async fn new_member_remove_proposal_invalid_credential() {
        let cache = make_proposal_cache();
        let cipher_suite_provider = test_cipher_suite_provider(TEST_CIPHER_SUITE);
        let kem_output = vec![0; cipher_suite_provider.kdf_extract_size()];
        let group = test_group(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE).await;
        let group_extensions = group.group.context().extensions.clone();
        let mut public_tree = group.group.state.public_tree;

        let test_leaf_nodes = vec![get_basic_test_node(TEST_CIPHER_SUITE, "bar").await];

        let test_leaf_node_indexes = public_tree
            .add_leaves(
                test_leaf_nodes,
                BasicIdentityProvider,
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
                None,
                proposals.into_iter().map(ProposalOrRef::Proposal).collect(),
                Some(&test_node().await),
                &group_extensions,
                BasicIdentityProvider,
                &cipher_suite_provider,
                &public_tree,
                PassThroughPskIdValidator,
                pass_through_filter(),
            )
            .await;

        assert_matches!(
            res,
            Err(ProposalCacheError::ProposalFilterError(
                ProposalFilterError::ExternalCommitRemovesOtherIdentity
            ))
        );
    }

    #[futures_test::test]
    async fn new_member_remove_proposal_valid_credential() {
        let cache = make_proposal_cache();
        let cipher_suite_provider = test_cipher_suite_provider(TEST_CIPHER_SUITE);
        let kem_output = vec![0; cipher_suite_provider.kdf_extract_size()];
        let group = test_group(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE).await;
        let group_extensions = group.group.context().extensions.clone();
        let mut public_tree = group.group.state.public_tree;
        let identity_provider = BasicIdentityProvider::new();

        let test_leaf_nodes = vec![get_basic_test_node(TEST_CIPHER_SUITE, "foo").await];

        let test_leaf_node_indexes = public_tree
            .add_leaves(
                test_leaf_nodes,
                BasicIdentityProvider,
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
                None,
                proposals.into_iter().map(ProposalOrRef::Proposal).collect(),
                Some(&test_node().await),
                &group_extensions,
                identity_provider,
                &cipher_suite_provider,
                &public_tree,
                PassThroughPskIdValidator,
                pass_through_filter(),
            )
            .await;

        assert_matches!(res, Ok(_));
    }

    #[futures_test::test]
    async fn new_member_cannot_commit_update_proposal() {
        let res = new_member_commits_proposal(Proposal::Update(UpdateProposal {
            leaf_node: get_basic_test_node(TEST_CIPHER_SUITE, "foo").await,
        }))
        .await;

        assert_matches!(
            res,
            Err(ProposalCacheError::ProposalFilterError(
                ProposalFilterError::InvalidProposalTypeInExternalCommit(ProposalType::UPDATE)
            ))
        );
    }

    #[futures_test::test]
    async fn new_member_cannot_commit_group_extensions_proposal() {
        let res =
            new_member_commits_proposal(Proposal::GroupContextExtensions(ExtensionList::new()))
                .await;

        assert_matches!(
            res,
            Err(ProposalCacheError::ProposalFilterError(
                ProposalFilterError::InvalidProposalTypeInExternalCommit(
                    ProposalType::GROUP_CONTEXT_EXTENSIONS,
                )
            ))
        );
    }

    #[futures_test::test]
    async fn new_member_cannot_commit_reinit_proposal() {
        let res = new_member_commits_proposal(Proposal::ReInit(ReInit {
            group_id: b"foo".to_vec(),
            version: TEST_PROTOCOL_VERSION,
            cipher_suite: TEST_CIPHER_SUITE,
            extensions: ExtensionList::new(),
        }))
        .await;

        assert_matches!(
            res,
            Err(ProposalCacheError::ProposalFilterError(
                ProposalFilterError::InvalidProposalTypeInExternalCommit(ProposalType::RE_INIT)
            ))
        );
    }

    #[futures_test::test]
    async fn new_member_commit_must_contain_an_external_init_proposal() {
        let cache = make_proposal_cache();
        let cipher_suite_provider = test_cipher_suite_provider(TEST_CIPHER_SUITE);
        let group = test_group(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE).await;
        let public_tree = &group.group.state.public_tree;
        let identity_provider = BasicIdentityProvider::new();

        let res = cache
            .resolve_for_commit_default(
                Sender::NewMemberCommit,
                None,
                Vec::new(),
                Some(&test_node().await),
                &group.group.context().extensions,
                identity_provider,
                &cipher_suite_provider,
                public_tree,
                PassThroughPskIdValidator,
                pass_through_filter(),
            )
            .await;

        assert_matches!(
            res,
            Err(ProposalCacheError::ProposalFilterError(
                ProposalFilterError::ExternalCommitMustHaveExactlyOneExternalInit
            ))
        );
    }

    #[futures_test::test]
    async fn test_path_update_required_empty() {
        let cache = make_proposal_cache();
        let cipher_suite_provider = test_cipher_suite_provider(TEST_CIPHER_SUITE);

        let (_, effects) = cache
            .prepare_commit(
                Sender::Member(test_sender()),
                vec![],
                &ExtensionList::new(),
                BasicIdentityProvider::new(),
                &cipher_suite_provider,
                &TreeKemPublic::new(),
                None,
                PassThroughPskIdValidator,
                pass_through_filter(),
            )
            .await
            .unwrap();

        assert!(effects.path_update_required())
    }

    #[futures_test::test]
    async fn test_path_update_required_updates() {
        let mut cache = make_proposal_cache();
        let update = Proposal::Update(make_update_proposal("bar").await);
        let cipher_suite_provider = test_cipher_suite_provider(TEST_CIPHER_SUITE);

        cache.insert(
            make_proposal_ref(&update, LeafIndex(2)),
            update,
            Sender::Member(2),
        );

        let (_, effects) = cache
            .prepare_commit(
                Sender::Member(test_sender()),
                Vec::new(),
                &ExtensionList::new(),
                BasicIdentityProvider::new(),
                &cipher_suite_provider,
                &TreeKemPublic::new(),
                None,
                PassThroughPskIdValidator,
                pass_through_filter(),
            )
            .await
            .unwrap();

        assert!(effects.path_update_required())
    }

    #[futures_test::test]
    async fn test_path_update_required_removes() {
        let cache = make_proposal_cache();
        let cipher_suite_provider = test_cipher_suite_provider(TEST_CIPHER_SUITE);

        let (alice_leaf, alice_secret, _) =
            get_basic_test_node_sig_key(TEST_CIPHER_SUITE, "alice").await;
        let alice = 0;

        let (mut tree, _) = TreeKemPublic::derive(
            alice_leaf,
            alice_secret,
            BasicIdentityProvider,
            &cipher_suite_provider,
        )
        .await
        .unwrap();

        let bob = tree
            .add_leaves(
                vec![get_basic_test_node(TEST_CIPHER_SUITE, "bob").await],
                BasicIdentityProvider,
                &cipher_suite_provider,
            )
            .await
            .unwrap()[0];

        let remove = Proposal::Remove(RemoveProposal { to_remove: bob });

        let (_, effects) = cache
            .prepare_commit(
                Sender::Member(alice),
                vec![remove],
                &ExtensionList::new(),
                BasicIdentityProvider::new(),
                &cipher_suite_provider,
                &tree,
                None,
                PassThroughPskIdValidator,
                pass_through_filter(),
            )
            .await
            .unwrap();

        assert!(effects.path_update_required())
    }

    #[futures_test::test]
    async fn test_path_update_not_required() {
        let (alice, tree) = new_tree("alice").await;
        let cipher_suite_provider = test_cipher_suite_provider(TEST_CIPHER_SUITE);
        let cache = make_proposal_cache();

        let psk = Proposal::Psk(PreSharedKey {
            psk: PreSharedKeyID {
                key_id: JustPreSharedKeyID::External(ExternalPskId(vec![])),
                psk_nonce: PskNonce::random(&test_cipher_suite_provider(TEST_CIPHER_SUITE))
                    .unwrap(),
            },
        });

        let add = Proposal::Add(AddProposal {
            key_package: test_key_package(ProtocolVersion::Mls10, TEST_CIPHER_SUITE, "bob").await,
        });

        let (_, effects) = cache
            .prepare_commit(
                Sender::Member(*alice),
                vec![psk, add],
                &ExtensionList::new(),
                BasicIdentityProvider::new(),
                &cipher_suite_provider,
                &tree,
                None,
                PassThroughPskIdValidator,
                pass_through_filter(),
            )
            .await
            .unwrap();

        assert!(!effects.path_update_required())
    }

    #[futures_test::test]
    async fn path_update_is_not_required_for_re_init() {
        let cipher_suite_provider = test_cipher_suite_provider(TEST_CIPHER_SUITE);
        let (alice, tree) = new_tree("alice").await;
        let cache = make_proposal_cache();

        let reinit = Proposal::ReInit(ReInit {
            group_id: vec![],
            version: ProtocolVersion::Mls10,
            cipher_suite: TEST_CIPHER_SUITE,
            extensions: Default::default(),
        });

        let (_, effects) = cache
            .prepare_commit(
                Sender::Member(*alice),
                vec![reinit],
                &ExtensionList::new(),
                BasicIdentityProvider::new(),
                &cipher_suite_provider,
                &tree,
                None,
                PassThroughPskIdValidator,
                pass_through_filter(),
            )
            .await
            .unwrap();

        assert!(!effects.path_update_required())
    }

    #[derive(Debug)]
    struct CommitReceiver<'a, C, F, P, CSP> {
        tree: &'a TreeKemPublic,
        sender: Sender,
        receiver: LeafIndex,
        cache: ProposalCache,
        identity_provider: C,
        cipher_suite_provider: CSP,
        group_context_extensions: ExtensionList<GroupContextExtension>,
        user_filter: F,
        external_psk_id_validator: P,
    }

    impl<'a, CSP>
        CommitReceiver<
            'a,
            BasicIdentityProvider,
            PassThroughProposalFilter<Infallible>,
            PassThroughPskIdValidator,
            CSP,
        >
    {
        fn new<S>(
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
                identity_provider: BasicIdentityProvider::new(),
                group_context_extensions: Default::default(),
                user_filter: pass_through_filter(),
                external_psk_id_validator: PassThroughPskIdValidator,
                cipher_suite_provider,
            }
        }
    }

    impl<'a, C, F, P, CSP> CommitReceiver<'a, C, F, P, CSP>
    where
        C: IdentityProvider,
        F: ProposalFilter,
        P: ExternalPskIdValidator,
        CSP: CipherSuiteProvider,
    {
        fn with_identity_provider<V>(self, validator: V) -> CommitReceiver<'a, V, F, P, CSP>
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
                user_filter: self.user_filter,
                external_psk_id_validator: self.external_psk_id_validator,
                cipher_suite_provider: self.cipher_suite_provider,
            }
        }

        fn with_user_filter<G>(self, f: G) -> CommitReceiver<'a, C, G, P, CSP>
        where
            G: ProposalFilter,
        {
            CommitReceiver {
                tree: self.tree,
                sender: self.sender,
                receiver: self.receiver,
                cache: self.cache,
                identity_provider: self.identity_provider,
                group_context_extensions: self.group_context_extensions,
                user_filter: f,
                external_psk_id_validator: self.external_psk_id_validator,
                cipher_suite_provider: self.cipher_suite_provider,
            }
        }

        fn with_external_psk_id_validator<V>(self, v: V) -> CommitReceiver<'a, C, F, V, CSP>
        where
            V: ExternalPskIdValidator,
        {
            CommitReceiver {
                tree: self.tree,
                sender: self.sender,
                receiver: self.receiver,
                cache: self.cache,
                identity_provider: self.identity_provider,
                group_context_extensions: self.group_context_extensions,
                user_filter: self.user_filter,
                external_psk_id_validator: v,
                cipher_suite_provider: self.cipher_suite_provider,
            }
        }

        fn with_extensions(self, extensions: ExtensionList<GroupContextExtension>) -> Self {
            Self {
                group_context_extensions: extensions,
                ..self
            }
        }

        fn cache<S>(mut self, r: ProposalRef, p: Proposal, proposer: S) -> Self
        where
            S: Into<Sender>,
        {
            self.cache.insert(r, p, proposer.into());
            self
        }

        async fn receive<I>(&self, proposals: I) -> Result<ProposalSetEffects, ProposalCacheError>
        where
            I: IntoIterator,
            I::Item: Into<ProposalOrRef>,
        {
            self.cache
                .resolve_for_commit_default(
                    self.sender.clone(),
                    Some(self.receiver),
                    proposals.into_iter().map(Into::into).collect(),
                    None,
                    &self.group_context_extensions,
                    &self.identity_provider,
                    &self.cipher_suite_provider,
                    self.tree,
                    &self.external_psk_id_validator,
                    &self.user_filter,
                )
                .await
        }
    }

    #[derive(Debug)]
    struct CommitSender<'a, C, F, P, CSP> {
        cipher_suite_provider: CSP,
        tree: &'a TreeKemPublic,
        sender: LeafIndex,
        cache: ProposalCache,
        additional_proposals: Vec<Proposal>,
        identity_provider: C,
        user_filter: F,
        external_psk_id_validator: P,
    }

    impl<'a, CSP>
        CommitSender<
            'a,
            BasicIdentityProvider,
            PassThroughProposalFilter<Infallible>,
            PassThroughPskIdValidator,
            CSP,
        >
    {
        fn new(tree: &'a TreeKemPublic, sender: LeafIndex, cipher_suite_provider: CSP) -> Self {
            Self {
                tree,
                sender,
                cache: make_proposal_cache(),
                additional_proposals: Vec::new(),
                identity_provider: BasicIdentityProvider::new(),
                user_filter: pass_through_filter(),
                external_psk_id_validator: PassThroughPskIdValidator,
                cipher_suite_provider,
            }
        }
    }

    impl<'a, C, F, P, CSP> CommitSender<'a, C, F, P, CSP>
    where
        C: IdentityProvider,
        F: ProposalFilter,
        P: ExternalPskIdValidator,
        CSP: CipherSuiteProvider,
    {
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
                user_filter: self.user_filter,
                external_psk_id_validator: self.external_psk_id_validator,
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

        fn with_user_filter<G>(self, f: G) -> CommitSender<'a, C, G, P, CSP>
        where
            G: ProposalFilter,
        {
            CommitSender {
                tree: self.tree,
                sender: self.sender,
                cache: self.cache,
                additional_proposals: self.additional_proposals,
                identity_provider: self.identity_provider,
                user_filter: f,
                external_psk_id_validator: self.external_psk_id_validator,
                cipher_suite_provider: self.cipher_suite_provider,
            }
        }

        fn with_external_psk_id_validator<V>(self, v: V) -> CommitSender<'a, C, F, V, CSP>
        where
            V: ExternalPskIdValidator,
        {
            CommitSender {
                tree: self.tree,
                sender: self.sender,
                cache: self.cache,
                additional_proposals: self.additional_proposals,
                identity_provider: self.identity_provider,
                user_filter: self.user_filter,
                external_psk_id_validator: v,
                cipher_suite_provider: self.cipher_suite_provider,
            }
        }

        async fn send(
            &self,
        ) -> Result<(Vec<ProposalOrRef>, ProposalSetEffects), ProposalCacheError> {
            self.cache
                .prepare_commit(
                    Sender::Member(*self.sender),
                    self.additional_proposals.clone(),
                    &ExtensionList::new(),
                    &self.identity_provider,
                    &self.cipher_suite_provider,
                    self.tree,
                    None,
                    &self.external_psk_id_validator,
                    &self.user_filter,
                )
                .await
        }
    }

    async fn key_package_with_invalid_signature() -> KeyPackage {
        let mut kp = test_key_package(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE, "mallory").await;
        kp.signature.clear();
        kp
    }

    async fn key_package_with_public_key(key: crypto::HpkePublicKey) -> KeyPackage {
        let cipher_suite_provider = test_cipher_suite_provider(TEST_CIPHER_SUITE);

        test_key_package_custom(
            &cipher_suite_provider.clone(),
            TEST_PROTOCOL_VERSION,
            "test",
            |gen| {
                async move {
                    let mut key_package_gen = gen
                        .generate(
                            Default::default(),
                            Default::default(),
                            Default::default(),
                            Default::default(),
                        )
                        .await
                        .unwrap();

                    key_package_gen.key_package.leaf_node.public_key = key;
                    key_package_gen
                        .key_package
                        .sign(&cipher_suite_provider, gen.signing_key, &())
                        .unwrap();
                    key_package_gen
                }
                .boxed()
            },
        )
        .await
    }

    #[futures_test::test]
    async fn receiving_add_with_invalid_key_package_fails() {
        let (alice, tree) = new_tree("alice").await;

        let res = CommitReceiver::new(
            &tree,
            alice,
            alice,
            test_cipher_suite_provider(TEST_CIPHER_SUITE),
        )
        .receive([Proposal::Add(AddProposal {
            key_package: key_package_with_invalid_signature().await,
        })])
        .await;

        assert_matches!(
            res,
            Err(ProposalCacheError::ProposalFilterError(
                ProposalFilterError::KeyPackageValidationError(_)
            ))
        );
    }

    #[futures_test::test]
    async fn sending_additional_add_with_invalid_key_package_fails() {
        let (alice, tree) = new_tree("alice").await;

        let res = CommitSender::new(&tree, alice, test_cipher_suite_provider(TEST_CIPHER_SUITE))
            .with_additional([Proposal::Add(AddProposal {
                key_package: key_package_with_invalid_signature().await,
            })])
            .send()
            .await;

        assert_matches!(
            res,
            Err(ProposalCacheError::ProposalFilterError(
                ProposalFilterError::KeyPackageValidationError(_)
            ))
        );
    }

    #[futures_test::test]
    async fn sending_add_with_invalid_key_package_filters_it_out() {
        let (alice, tree) = new_tree("alice").await;

        let proposal = Proposal::Add(AddProposal {
            key_package: key_package_with_invalid_signature().await,
        });
        let proposal_ref = make_proposal_ref(&proposal, alice);

        let (committed, effects) =
            CommitSender::new(&tree, alice, test_cipher_suite_provider(TEST_CIPHER_SUITE))
                .cache(proposal_ref.clone(), proposal.clone(), alice)
                .send()
                .await
                .unwrap();

        assert_eq!(committed, Vec::new());
        assert_eq!(effects.rejected_proposals, vec![(proposal_ref, proposal)]);
    }

    #[futures_test::test]
    async fn sending_add_with_hpke_key_of_another_member_fails() {
        let (alice, tree) = new_tree("alice").await;

        let res = CommitSender::new(&tree, alice, test_cipher_suite_provider(TEST_CIPHER_SUITE))
            .with_additional([Proposal::Add(AddProposal {
                key_package: key_package_with_public_key(
                    tree.get_leaf_node(alice).unwrap().public_key.clone(),
                )
                .await,
            })])
            .send()
            .await;

        assert_matches!(
            res,
            Err(ProposalCacheError::ProposalFilterError(
                ProposalFilterError::KeyPackageValidationError(_)
            ))
        );
    }

    #[futures_test::test]
    async fn sending_add_with_hpke_key_of_another_member_filters_it_out() {
        let (alice, tree) = new_tree("alice").await;

        let proposal = Proposal::Add(AddProposal {
            key_package: key_package_with_public_key(
                tree.get_leaf_node(alice).unwrap().public_key.clone(),
            )
            .await,
        });

        let proposal_ref = make_proposal_ref(&proposal, alice);

        let (committed, effects) =
            CommitSender::new(&tree, alice, test_cipher_suite_provider(TEST_CIPHER_SUITE))
                .cache(proposal_ref.clone(), proposal.clone(), alice)
                .send()
                .await
                .unwrap();

        assert_eq!(committed, Vec::new());
        assert_eq!(effects.rejected_proposals, vec![(proposal_ref, proposal)]);
    }

    #[futures_test::test]
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

        assert_matches!(
            res,
            Err(ProposalCacheError::ProposalFilterError(
                ProposalFilterError::LeafNodeValidationError(_)
            ))
        );
    }

    #[futures_test::test]
    async fn sending_update_with_invalid_leaf_node_filters_it_out() {
        let (alice, mut tree) = new_tree("alice").await;
        let bob = add_member(&mut tree, "bob").await;

        let proposal = Proposal::Update(UpdateProposal {
            leaf_node: get_basic_test_node(TEST_CIPHER_SUITE, "alice").await,
        });
        let proposal_ref = make_proposal_ref(&proposal, bob);

        let (committed, effects) =
            CommitSender::new(&tree, alice, test_cipher_suite_provider(TEST_CIPHER_SUITE))
                .cache(proposal_ref, proposal, bob)
                .send()
                .await
                .unwrap();

        assert_eq!(committed, Vec::new());

        // Alice didn't propose the update. Bob did. That's why it is not returned in the list of
        // rejected proposals.
        assert_eq!(effects.rejected_proposals, Vec::new());
    }

    #[futures_test::test]
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

        assert_matches!(
            res,
            Err(ProposalCacheError::ProposalFilterError(
                ProposalFilterError::RatchetTreeError(_)
            ))
        );
    }

    #[futures_test::test]
    async fn sending_additional_remove_with_invalid_index_fails() {
        let (alice, tree) = new_tree("alice").await;

        let res = CommitSender::new(&tree, alice, test_cipher_suite_provider(TEST_CIPHER_SUITE))
            .with_additional([Proposal::Remove(RemoveProposal {
                to_remove: LeafIndex(10),
            })])
            .send()
            .await;

        assert_matches!(
            res,
            Err(ProposalCacheError::ProposalFilterError(
                ProposalFilterError::RatchetTreeError(_)
            ))
        );
    }

    #[futures_test::test]
    async fn sending_remove_with_invalid_index_filters_it_out() {
        let (alice, tree) = new_tree("alice").await;

        let proposal = Proposal::Remove(RemoveProposal {
            to_remove: LeafIndex(10),
        });
        let proposal_ref = make_proposal_ref(&proposal, alice);

        let (committed, effects) =
            CommitSender::new(&tree, alice, test_cipher_suite_provider(TEST_CIPHER_SUITE))
                .cache(proposal_ref.clone(), proposal.clone(), alice)
                .send()
                .await
                .unwrap();

        assert_eq!(committed, Vec::new());
        assert_eq!(effects.rejected_proposals, vec![(proposal_ref, proposal)]);
    }

    fn make_external_psk(id: &[u8], nonce: PskNonce) -> PreSharedKey {
        PreSharedKey {
            psk: PreSharedKeyID {
                key_id: JustPreSharedKeyID::External(ExternalPskId(id.to_vec())),
                psk_nonce: nonce,
            },
        }
    }

    fn new_external_psk(id: &[u8]) -> PreSharedKey {
        make_external_psk(
            id,
            PskNonce::random(&test_cipher_suite_provider(TEST_CIPHER_SUITE)).unwrap(),
        )
    }

    #[futures_test::test]
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

        assert_matches!(
            res,
            Err(ProposalCacheError::ProposalFilterError(
                ProposalFilterError::InvalidPskNonceLength { expected, found },
            )) if expected == test_cipher_suite_provider(TEST_CIPHER_SUITE).kdf_extract_size() && found == invalid_nonce.0.len()
        );
    }

    #[futures_test::test]
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

        assert_matches!(
            res,
            Err(ProposalCacheError::ProposalFilterError(
                ProposalFilterError::InvalidPskNonceLength { expected, found },
            )) if expected == test_cipher_suite_provider(TEST_CIPHER_SUITE).kdf_extract_size() && found == invalid_nonce.0.len()
        );
    }

    #[futures_test::test]
    async fn sending_psk_with_invalid_nonce_filters_it_out() {
        let invalid_nonce = PskNonce(vec![0, 1, 2]);
        let (alice, tree) = new_tree("alice").await;
        let proposal = Proposal::Psk(make_external_psk(b"foo", invalid_nonce));
        let proposal_ref = make_proposal_ref(&proposal, alice);

        let (committed, effects) =
            CommitSender::new(&tree, alice, test_cipher_suite_provider(TEST_CIPHER_SUITE))
                .cache(proposal_ref.clone(), proposal.clone(), alice)
                .send()
                .await
                .unwrap();

        assert_eq!(committed, Vec::new());
        assert_eq!(effects.rejected_proposals, vec![(proposal_ref, proposal)]);
    }

    fn make_resumption_psk(usage: ResumptionPSKUsage) -> PreSharedKey {
        PreSharedKey {
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

        assert_matches!(
            res,
            Err(ProposalCacheError::ProposalFilterError(
                ProposalFilterError::InvalidTypeOrUsageInPreSharedKeyProposal
            ))
        );
    }

    async fn sending_additional_resumption_psk_with_bad_usage_fails(usage: ResumptionPSKUsage) {
        let (alice, tree) = new_tree("alice").await;

        let res = CommitSender::new(&tree, alice, test_cipher_suite_provider(TEST_CIPHER_SUITE))
            .with_additional([Proposal::Psk(make_resumption_psk(usage))])
            .send()
            .await;

        assert_matches!(
            res,
            Err(ProposalCacheError::ProposalFilterError(
                ProposalFilterError::InvalidTypeOrUsageInPreSharedKeyProposal
            ))
        );
    }

    async fn sending_resumption_psk_with_bad_usage_filters_it_out(usage: ResumptionPSKUsage) {
        let (alice, tree) = new_tree("alice").await;
        let proposal = Proposal::Psk(make_resumption_psk(usage));
        let proposal_ref = make_proposal_ref(&proposal, alice);

        let (committed, effects) =
            CommitSender::new(&tree, alice, test_cipher_suite_provider(TEST_CIPHER_SUITE))
                .cache(proposal_ref.clone(), proposal.clone(), alice)
                .send()
                .await
                .unwrap();

        assert_eq!(committed, Vec::new());
        assert_eq!(effects.rejected_proposals, vec![(proposal_ref, proposal)]);
    }

    #[futures_test::test]
    async fn receiving_resumption_psk_with_reinit_usage_fails() {
        receiving_resumption_psk_with_bad_usage_fails(ResumptionPSKUsage::Reinit).await;
    }

    #[futures_test::test]
    async fn sending_additional_resumption_psk_with_reinit_usage_fails() {
        sending_additional_resumption_psk_with_bad_usage_fails(ResumptionPSKUsage::Reinit).await;
    }

    #[futures_test::test]
    async fn sending_resumption_psk_with_reinit_usage_filters_it_out() {
        sending_resumption_psk_with_bad_usage_filters_it_out(ResumptionPSKUsage::Reinit).await;
    }

    #[futures_test::test]
    async fn receiving_resumption_psk_with_branch_usage_fails() {
        receiving_resumption_psk_with_bad_usage_fails(ResumptionPSKUsage::Branch).await;
    }

    #[futures_test::test]
    async fn sending_additional_resumption_psk_with_branch_usage_fails() {
        sending_additional_resumption_psk_with_bad_usage_fails(ResumptionPSKUsage::Branch).await;
    }

    #[futures_test::test]
    async fn sending_resumption_psk_with_branch_usage_filters_it_out() {
        sending_resumption_psk_with_bad_usage_filters_it_out(ResumptionPSKUsage::Branch).await;
    }

    fn make_reinit(version: ProtocolVersion) -> ReInit {
        ReInit {
            group_id: TEST_GROUP.to_vec(),
            version,
            cipher_suite: TEST_CIPHER_SUITE,
            extensions: ExtensionList::new(),
        }
    }

    #[futures_test::test]
    async fn receiving_reinit_downgrading_version_fails() {
        let smaller_protocol_version = ProtocolVersion::Reserved;
        let (alice, tree) = new_tree("alice").await;

        let res = CommitReceiver::new(
            &tree,
            alice,
            alice,
            test_cipher_suite_provider(TEST_CIPHER_SUITE),
        )
        .receive([Proposal::ReInit(make_reinit(smaller_protocol_version))])
        .await;

        assert_matches!(
            res,
            Err(ProposalCacheError::ProposalFilterError(ProposalFilterError::InvalidProtocolVersionInReInit {
                proposed,
                original,
            })) if proposed == smaller_protocol_version && original == TEST_PROTOCOL_VERSION
        );
    }

    #[futures_test::test]
    async fn sending_additional_reinit_downgrading_version_fails() {
        let smaller_protocol_version = ProtocolVersion::Reserved;
        let (alice, tree) = new_tree("alice").await;

        let res = CommitSender::new(&tree, alice, test_cipher_suite_provider(TEST_CIPHER_SUITE))
            .with_additional([Proposal::ReInit(make_reinit(smaller_protocol_version))])
            .send()
            .await;

        assert_matches!(
            res,
            Err(ProposalCacheError::ProposalFilterError(ProposalFilterError::InvalidProtocolVersionInReInit {
                proposed,
                original,
            })) if proposed == smaller_protocol_version && original == TEST_PROTOCOL_VERSION
        );
    }

    #[futures_test::test]
    async fn sending_reinit_downgrading_version_filters_it_out() {
        let smaller_protocol_version = ProtocolVersion::Reserved;
        let (alice, tree) = new_tree("alice").await;
        let proposal = Proposal::ReInit(make_reinit(smaller_protocol_version));
        let proposal_ref = make_proposal_ref(&proposal, alice);

        let (committed, effects) =
            CommitSender::new(&tree, alice, test_cipher_suite_provider(TEST_CIPHER_SUITE))
                .cache(proposal_ref.clone(), proposal.clone(), alice)
                .send()
                .await
                .unwrap();

        assert_eq!(committed, Vec::new());
        assert_eq!(effects.rejected_proposals, vec![(proposal_ref, proposal)]);
    }

    async fn make_update_proposal(name: &str) -> UpdateProposal {
        UpdateProposal {
            leaf_node: update_leaf_node(name, 0).await,
        }
    }

    async fn make_update_proposal_custom(name: &str, leaf_index: u32) -> UpdateProposal {
        UpdateProposal {
            leaf_node: update_leaf_node(name, leaf_index).await,
        }
    }

    #[futures_test::test]
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

        assert_matches!(
            res,
            Err(ProposalCacheError::ProposalFilterError(
                ProposalFilterError::InvalidCommitSelfUpdate
            ))
        );
    }

    #[futures_test::test]
    async fn sending_additional_update_for_committer_fails() {
        let (alice, tree) = new_tree("alice").await;

        let res = CommitSender::new(&tree, alice, test_cipher_suite_provider(TEST_CIPHER_SUITE))
            .with_additional([Proposal::Update(make_update_proposal("alice").await)])
            .send()
            .await;

        assert_matches!(
            res,
            Err(ProposalCacheError::ProposalFilterError(
                ProposalFilterError::InvalidProposalTypeForSender {
                    proposal_type: ProposalType::UPDATE,
                    sender: Sender::Member(_),
                    by_ref: false,
                }
            ))
        );
    }

    #[futures_test::test]
    async fn sending_update_for_committer_filters_it_out() {
        let (alice, tree) = new_tree("alice").await;
        let proposal = Proposal::Update(make_update_proposal("alice").await);
        let proposal_ref = make_proposal_ref(&proposal, alice);

        let (committed, effects) =
            CommitSender::new(&tree, alice, test_cipher_suite_provider(TEST_CIPHER_SUITE))
                .cache(proposal_ref.clone(), proposal.clone(), alice)
                .send()
                .await
                .unwrap();

        assert_eq!(committed, Vec::new());
        assert_eq!(effects.rejected_proposals, vec![(proposal_ref, proposal)]);
    }

    #[futures_test::test]
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

        assert_matches!(
            res,
            Err(ProposalCacheError::ProposalFilterError(
                ProposalFilterError::CommitterSelfRemoval
            ))
        );
    }

    #[futures_test::test]
    async fn sending_additional_remove_for_committer_fails() {
        let (alice, tree) = new_tree("alice").await;

        let res = CommitSender::new(&tree, alice, test_cipher_suite_provider(TEST_CIPHER_SUITE))
            .with_additional([Proposal::Remove(RemoveProposal { to_remove: alice })])
            .send()
            .await;

        assert_matches!(
            res,
            Err(ProposalCacheError::ProposalFilterError(
                ProposalFilterError::CommitterSelfRemoval
            ))
        );
    }

    #[futures_test::test]
    async fn sending_remove_for_committer_filters_it_out() {
        let (alice, tree) = new_tree("alice").await;
        let proposal = Proposal::Remove(RemoveProposal { to_remove: alice });
        let proposal_ref = make_proposal_ref(&proposal, alice);

        let (committed, effects) =
            CommitSender::new(&tree, alice, test_cipher_suite_provider(TEST_CIPHER_SUITE))
                .cache(proposal_ref.clone(), proposal.clone(), alice)
                .send()
                .await
                .unwrap();

        assert_eq!(committed, Vec::new());
        assert_eq!(effects.rejected_proposals, vec![(proposal_ref, proposal)]);
    }

    #[futures_test::test]
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

        assert_matches!(
            res,
            Err(ProposalCacheError::ProposalFilterError(
                ProposalFilterError::MoreThanOneProposalForLeaf(r)
            )) if r == *bob
        );
    }

    #[futures_test::test]
    async fn sending_updae_and_remove_for_same_leaf_filters_update_out() {
        let (alice, mut tree) = new_tree("alice").await;
        let bob = add_member(&mut tree, "bob").await;

        let update = Proposal::Update(make_update_proposal("bob").await);
        let update_ref = make_proposal_ref(&update, alice);

        let remove = Proposal::Remove(RemoveProposal { to_remove: bob });
        let remove_ref = make_proposal_ref(&remove, alice);

        let (committed, effects) =
            CommitSender::new(&tree, alice, test_cipher_suite_provider(TEST_CIPHER_SUITE))
                .cache(update_ref.clone(), update.clone(), alice)
                .cache(remove_ref.clone(), remove, alice)
                .send()
                .await
                .unwrap();

        assert_eq!(committed, vec![remove_ref.into()]);
        assert_eq!(effects.rejected_proposals, vec![(update_ref, update)]);
    }

    async fn make_add_proposal() -> AddProposal {
        AddProposal {
            key_package: test_key_package(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE, "frank").await,
        }
    }

    #[futures_test::test]
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

        assert_matches!(
            res,
            Err(ProposalCacheError::ProposalFilterError(
                ProposalFilterError::RatchetTreeError(RatchetTreeError::TreeIndexError(
                    TreeIndexError::DuplicateIdentity(LeafIndex(1))
                ))
            ))
        );
    }

    #[futures_test::test]
    async fn sending_additional_add_proposals_for_same_client_fails() {
        let (alice, tree) = new_tree("alice").await;

        let res = CommitSender::new(&tree, alice, test_cipher_suite_provider(TEST_CIPHER_SUITE))
            .with_additional([
                Proposal::Add(make_add_proposal().await),
                Proposal::Add(make_add_proposal().await),
            ])
            .send()
            .await;

        assert_matches!(
            res,
            Err(ProposalCacheError::ProposalFilterError(
                ProposalFilterError::RatchetTreeError(RatchetTreeError::TreeIndexError(
                    TreeIndexError::DuplicateIdentity(LeafIndex(1))
                ))
            ))
        );
    }

    #[futures_test::test]
    async fn sending_add_proposals_for_same_client_keeps_only_one() {
        let (alice, tree) = new_tree("alice").await;

        let adds = [
            Proposal::Add(make_add_proposal().await),
            Proposal::Add(make_add_proposal().await),
        ];
        let add_refs = adds.clone().map(|p| make_proposal_ref(&p, alice));

        let (committed, effects) =
            CommitSender::new(&tree, alice, test_cipher_suite_provider(TEST_CIPHER_SUITE))
                .cache(add_refs[0].clone(), adds[0].clone(), alice)
                .cache(add_refs[1].clone(), adds[1].clone(), alice)
                .send()
                .await
                .unwrap();

        assert_matches!(
            (&*committed, &*effects.rejected_proposals),
            ([ProposalOrRef::Reference(cr)], [(rr, _)]) if cr != rr && add_refs.contains(cr) && add_refs.contains(rr)
        );
    }

    #[futures_test::test]
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

        assert_matches!(
            res,
            Err(ProposalCacheError::ProposalFilterError(
                ProposalFilterError::RatchetTreeError(RatchetTreeError::DifferentIdentityInUpdate(
                    LeafIndex(1)
                ))
            ))
        );
    }

    #[futures_test::test]
    async fn sending_update_for_different_identity_filters_it_out() {
        let (alice, mut tree) = new_tree("alice").await;
        let bob = add_member(&mut tree, "bob").await;

        let update = Proposal::Update(make_update_proposal("carol").await);
        let update_ref = make_proposal_ref(&update, bob);

        let (committed, effects) =
            CommitSender::new(&tree, alice, test_cipher_suite_provider(TEST_CIPHER_SUITE))
                .cache(update_ref, update, bob)
                .send()
                .await
                .unwrap();

        assert_eq!(committed, Vec::new());

        // Bob proposed the update, so it is not listed as rejected when Alice commits it because
        // she didn't propose it.
        assert_eq!(effects.rejected_proposals, Vec::new());
    }

    #[futures_test::test]
    async fn receiving_add_for_same_client_as_existing_member_fails() {
        let (alice, tree) = new_tree("alice").await;
        let add = Proposal::Add(make_add_proposal().await);

        let ProposalSetEffects { tree, .. } = CommitReceiver::new(
            &tree,
            alice,
            alice,
            test_cipher_suite_provider(TEST_CIPHER_SUITE),
        )
        .receive([add.clone()])
        .await
        .unwrap();

        let res = CommitReceiver::new(
            &tree,
            alice,
            alice,
            test_cipher_suite_provider(TEST_CIPHER_SUITE),
        )
        .receive([add])
        .await;

        assert_matches!(
            res,
            Err(ProposalCacheError::ProposalFilterError(
                ProposalFilterError::RatchetTreeError(RatchetTreeError::TreeIndexError(
                    TreeIndexError::DuplicateSignatureKeys(LeafIndex(1))
                ))
            ))
        );
    }

    #[futures_test::test]
    async fn sending_additional_add_for_same_client_as_existing_member_fails() {
        let (alice, tree) = new_tree("alice").await;
        let add = Proposal::Add(make_add_proposal().await);

        let ProposalSetEffects { tree, .. } = CommitReceiver::new(
            &tree,
            alice,
            alice,
            test_cipher_suite_provider(TEST_CIPHER_SUITE),
        )
        .receive([add.clone()])
        .await
        .unwrap();

        let res = CommitSender::new(&tree, alice, test_cipher_suite_provider(TEST_CIPHER_SUITE))
            .with_additional([add])
            .send()
            .await;

        assert_matches!(
            res,
            Err(ProposalCacheError::ProposalFilterError(
                ProposalFilterError::RatchetTreeError(RatchetTreeError::TreeIndexError(
                    TreeIndexError::DuplicateSignatureKeys(LeafIndex(1))
                ))
            ))
        );
    }

    #[futures_test::test]
    async fn sending_add_for_same_client_as_existing_member_filters_it_out() {
        let (alice, tree) = new_tree("alice").await;
        let add = Proposal::Add(make_add_proposal().await);

        let ProposalSetEffects { tree, .. } = CommitReceiver::new(
            &tree,
            alice,
            alice,
            test_cipher_suite_provider(TEST_CIPHER_SUITE),
        )
        .receive([add.clone()])
        .await
        .unwrap();

        let proposal_ref = make_proposal_ref(&add, alice);

        let (committed, effects) =
            CommitSender::new(&tree, alice, test_cipher_suite_provider(TEST_CIPHER_SUITE))
                .cache(proposal_ref.clone(), add.clone(), alice)
                .send()
                .await
                .unwrap();

        assert_eq!(committed, Vec::new());
        assert_eq!(effects.rejected_proposals, vec![(proposal_ref, add)]);
    }

    #[futures_test::test]
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

        assert_matches!(
            res,
            Err(ProposalCacheError::ProposalFilterError(
                ProposalFilterError::DuplicatePskIds
            ))
        );
    }

    #[futures_test::test]
    async fn sending_additional_psk_proposals_with_same_psk_id_fails() {
        let (alice, tree) = new_tree("alice").await;
        let psk_proposal = Proposal::Psk(new_external_psk(b"foo"));

        let res = CommitSender::new(&tree, alice, test_cipher_suite_provider(TEST_CIPHER_SUITE))
            .with_additional([psk_proposal.clone(), psk_proposal])
            .send()
            .await;

        assert_matches!(
            res,
            Err(ProposalCacheError::ProposalFilterError(
                ProposalFilterError::DuplicatePskIds
            ))
        );
    }

    #[futures_test::test]
    async fn sending_psk_proposals_with_same_psk_id_keeps_only_one() {
        let (alice, mut tree) = new_tree("alice").await;
        let bob = add_member(&mut tree, "bob").await;

        let proposal = Proposal::Psk(new_external_psk(b"foo"));
        let proposal_refs = [
            make_proposal_ref(&proposal, alice),
            make_proposal_ref(&proposal, bob),
        ];

        let (committed, effects) =
            CommitSender::new(&tree, alice, test_cipher_suite_provider(TEST_CIPHER_SUITE))
                .cache(proposal_refs[0].clone(), proposal.clone(), alice)
                .cache(proposal_refs[1].clone(), proposal, bob)
                .send()
                .await
                .unwrap();

        let committed_ref = match &*committed {
            [ProposalOrRef::Reference(r)] => r.clone(),
            _ => panic!("Expected single proposal reference in {:?}", committed),
        };

        assert!(proposal_refs.contains(&committed_ref));

        // The list of rejected proposals may be empty if Bob's proposal was the one that got
        // rejected.
        match &*effects.rejected_proposals {
            [(r, _)] => {
                assert_ne!(*r, committed_ref);
                assert!(proposal_refs.contains(r));
            }
            [] => {}
            _ => panic!(
                "Expected zero or one proposal reference in {:?}",
                effects.rejected_proposals
            ),
        }
    }

    #[futures_test::test]
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
            Err(ProposalCacheError::ProposalFilterError(
                ProposalFilterError::MoreThanOneGroupContextExtensionsProposal
            ))
        );
    }

    #[futures_test::test]
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
            Err(ProposalCacheError::ProposalFilterError(
                ProposalFilterError::MoreThanOneGroupContextExtensionsProposal
            ))
        );
    }

    fn make_extension_list(foo: u8) -> ExtensionList<GroupContextExtension> {
        [TestExtension { foo }].try_into().unwrap()
    }

    #[futures_test::test]
    async fn sending_multiple_group_context_extensions_keeps_only_one() {
        let cipher_suite_provider = test_cipher_suite_provider(TEST_CIPHER_SUITE);

        let (alice, tree) = {
            let (signing_identity, signature_key) =
                get_test_signing_identity(TEST_CIPHER_SUITE, b"alice".to_vec());

            let properties = ConfigProperties {
                capabilities: Capabilities {
                    extensions: vec![42],
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
                &BasicIdentityProvider::new(),
            )
            .await
            .unwrap();

            let (pub_tree, priv_tree) =
                TreeKemPublic::derive(leaf, secret, BasicIdentityProvider, &cipher_suite_provider)
                    .await
                    .unwrap();

            (priv_tree.self_index, pub_tree)
        };

        let proposals = [
            Proposal::GroupContextExtensions(make_extension_list(0)),
            Proposal::GroupContextExtensions(make_extension_list(1)),
        ];

        let proposal_refs = proposals.clone().map(|p| make_proposal_ref(&p, alice));

        let (committed, effects) =
            CommitSender::new(&tree, alice, test_cipher_suite_provider(TEST_CIPHER_SUITE))
                .cache(proposal_refs[0].clone(), proposals[0].clone(), alice)
                .cache(proposal_refs[1].clone(), proposals[1].clone(), alice)
                .send()
                .await
                .unwrap();

        assert_matches!(
            (&*committed, &*effects.rejected_proposals),
            ([ProposalOrRef::Reference(cr)], [(rr, _)]) if cr != rr && proposal_refs.contains(cr) && proposal_refs.contains(rr)
        );
    }

    fn make_external_senders_extension() -> ExtensionList<GroupContextExtension> {
        [ExternalSendersExt::new(vec![
            get_test_signing_identity(TEST_CIPHER_SUITE, b"alice".to_vec()).0,
        ])]
        .try_into()
        .unwrap()
    }

    #[futures_test::test]
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

        assert_matches!(
            res,
            Err(ProposalCacheError::ProposalFilterError(
                ProposalFilterError::IdentityProviderError(_)
            ))
        );
    }

    #[futures_test::test]
    async fn sending_additional_invalid_external_senders_extension_fails() {
        let (alice, tree) = new_tree("alice").await;

        let res = CommitSender::new(&tree, alice, test_cipher_suite_provider(TEST_CIPHER_SUITE))
            .with_identity_provider(FailureIdentityProvider::new())
            .with_additional([Proposal::GroupContextExtensions(
                make_external_senders_extension(),
            )])
            .send()
            .await;

        assert_matches!(
            res,
            Err(ProposalCacheError::ProposalFilterError(
                ProposalFilterError::IdentityProviderError(_)
            ))
        );
    }

    #[futures_test::test]
    async fn sending_invalid_external_senders_extension_filters_it_out() {
        let (alice, tree) = new_tree("alice").await;

        let proposal = Proposal::GroupContextExtensions(make_external_senders_extension());

        let proposal_ref = make_proposal_ref(&proposal, alice);

        let (committed, effects) =
            CommitSender::new(&tree, alice, test_cipher_suite_provider(TEST_CIPHER_SUITE))
                .with_identity_provider(FailureIdentityProvider::new())
                .cache(proposal_ref.clone(), proposal.clone(), alice)
                .send()
                .await
                .unwrap();

        assert_eq!(committed, Vec::new());
        assert_eq!(effects.rejected_proposals, vec![(proposal_ref, proposal)]);
    }

    #[futures_test::test]
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

        assert_matches!(
            res,
            Err(ProposalCacheError::ProposalFilterError(
                ProposalFilterError::OtherProposalWithReInit
            ))
        );
    }

    #[futures_test::test]
    async fn sending_additional_reinit_with_other_proposals_fails() {
        let (alice, tree) = new_tree("alice").await;

        let res = CommitSender::new(&tree, alice, test_cipher_suite_provider(TEST_CIPHER_SUITE))
            .with_additional([
                Proposal::ReInit(make_reinit(TEST_PROTOCOL_VERSION)),
                Proposal::Add(make_add_proposal().await),
            ])
            .send()
            .await;

        assert_matches!(
            res,
            Err(ProposalCacheError::ProposalFilterError(
                ProposalFilterError::OtherProposalWithReInit
            ))
        );
    }

    #[futures_test::test]
    async fn sending_reinit_with_other_proposals_filters_it_out() {
        let (alice, tree) = new_tree("alice").await;
        let reinit = Proposal::ReInit(make_reinit(TEST_PROTOCOL_VERSION));
        let reinit_ref = make_proposal_ref(&reinit, alice);
        let add = Proposal::Add(make_add_proposal().await);
        let add_ref = make_proposal_ref(&add, alice);

        let (committed, effects) =
            CommitSender::new(&tree, alice, test_cipher_suite_provider(TEST_CIPHER_SUITE))
                .cache(reinit_ref.clone(), reinit.clone(), alice)
                .cache(add_ref.clone(), add, alice)
                .send()
                .await
                .unwrap();

        assert_eq!(committed, vec![add_ref.into()]);
        assert_eq!(effects.rejected_proposals, vec![(reinit_ref, reinit)]);
    }

    fn make_external_init() -> ExternalInit {
        ExternalInit {
            kem_output: vec![33; test_cipher_suite_provider(TEST_CIPHER_SUITE).kdf_extract_size()],
        }
    }

    #[futures_test::test]
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

        assert_matches!(
            res,
            Err(ProposalCacheError::ProposalFilterError(
                ProposalFilterError::InvalidProposalTypeForSender {
                    proposal_type: ProposalType::EXTERNAL_INIT,
                    sender: Sender::Member(_),
                    by_ref: false,
                }
            ))
        );
    }

    #[futures_test::test]
    async fn sending_additional_external_init_from_member_fails() {
        let (alice, tree) = new_tree("alice").await;

        let res = CommitSender::new(&tree, alice, test_cipher_suite_provider(TEST_CIPHER_SUITE))
            .with_additional([Proposal::ExternalInit(make_external_init())])
            .send()
            .await;

        assert_matches!(
            res,
            Err(ProposalCacheError::ProposalFilterError(
                ProposalFilterError::InvalidProposalTypeForSender {
                    proposal_type: ProposalType::EXTERNAL_INIT,
                    sender: Sender::Member(_),
                    by_ref: false,
                }
            ))
        );
    }

    #[futures_test::test]
    async fn sending_external_init_from_member_filters_it_out() {
        let (alice, tree) = new_tree("alice").await;
        let external_init = Proposal::ExternalInit(make_external_init());
        let external_init_ref = make_proposal_ref(&external_init, alice);

        let (committed, effects) =
            CommitSender::new(&tree, alice, test_cipher_suite_provider(TEST_CIPHER_SUITE))
                .cache(external_init_ref.clone(), external_init.clone(), alice)
                .send()
                .await
                .unwrap();

        assert_eq!(committed, Vec::new());
        assert_eq!(
            effects.rejected_proposals,
            vec![(external_init_ref, external_init)]
        );
    }

    fn required_capabilities_proposal(extension: u16) -> Proposal {
        let required_capabilities = RequiredCapabilitiesExt {
            extensions: vec![extension],
            ..Default::default()
        };
        Proposal::GroupContextExtensions([required_capabilities].try_into().unwrap())
    }

    #[futures_test::test]
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
            Err(ProposalCacheError::ProposalFilterError(
                ProposalFilterError::LeafNodeValidationError(
                    LeafNodeValidationError::RequiredExtensionNotFound(33)
                )
            ))
        );
    }

    #[futures_test::test]
    async fn sending_required_capabilities_not_supported_by_member_fails() {
        let (alice, tree) = new_tree("alice").await;

        let res = CommitSender::new(&tree, alice, test_cipher_suite_provider(TEST_CIPHER_SUITE))
            .with_additional([required_capabilities_proposal(33)])
            .send()
            .await;

        assert_matches!(
            res,
            Err(ProposalCacheError::ProposalFilterError(
                ProposalFilterError::LeafNodeValidationError(
                    LeafNodeValidationError::RequiredExtensionNotFound(33)
                )
            ))
        );
    }

    #[futures_test::test]
    async fn sending_additional_required_capabilities_not_supported_by_member_filters_it_out() {
        let (alice, tree) = new_tree("alice").await;

        let proposal = required_capabilities_proposal(33);
        let proposal_ref = make_proposal_ref(&proposal, alice);

        let (committed, effects) =
            CommitSender::new(&tree, alice, test_cipher_suite_provider(TEST_CIPHER_SUITE))
                .cache(proposal_ref.clone(), proposal.clone(), alice)
                .send()
                .await
                .unwrap();

        assert_eq!(committed, Vec::new());
        assert_eq!(effects.rejected_proposals, vec![(proposal_ref, proposal)]);
    }

    #[futures_test::test]
    async fn committing_update_from_pk1_to_pk2_and_update_from_pk2_to_pk3_works() {
        let cipher_suite_provider = test_cipher_suite_provider(TEST_CIPHER_SUITE);

        let (alice_leaf, alice_secret, alice_signer) =
            get_basic_test_node_sig_key(TEST_CIPHER_SUITE, "alice").await;

        let (mut tree, priv_tree) = TreeKemPublic::derive(
            alice_leaf.clone(),
            alice_secret,
            BasicIdentityProvider,
            &cipher_suite_provider,
        )
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

        assert_eq!(
            effects.updates,
            vec![(alice, alice_new_leaf), (bob, bob_new_leaf)]
        );
    }

    #[futures_test::test]
    async fn committing_update_from_pk1_to_pk2_and_removal_of_pk2_works() {
        let cipher_suite_provider = test_cipher_suite_provider(TEST_CIPHER_SUITE);

        let (alice_leaf, alice_secret, alice_signer) =
            get_basic_test_node_sig_key(TEST_CIPHER_SUITE, "alice").await;

        let (mut tree, priv_tree) = TreeKemPublic::derive(
            alice_leaf.clone(),
            alice_secret,
            BasicIdentityProvider,
            &cipher_suite_provider,
        )
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

        assert_eq!(effects.updates, vec![(alice, alice_new_leaf)]);
        assert_eq!(effects.removes, vec![bob]);
    }

    async fn unsupported_credential_key_package(name: &str) -> KeyPackage {
        let (mut signing_identity, secret_key) =
            get_test_signing_identity(TEST_CIPHER_SUITE, name.as_bytes().to_vec());

        signing_identity.credential = Credential {
            credential_type: CredentialType::new(INVALID_CREDENTIAL_TYPE),
            credential_data: random_bytes(32),
        };

        let generator = KeyPackageGenerator {
            protocol_version: TEST_PROTOCOL_VERSION,
            cipher_suite_provider: &test_cipher_suite_provider(TEST_CIPHER_SUITE),
            signing_identity: &signing_identity,
            signing_key: &secret_key,
            identity_provider: &BasicIdentityProvider::new(),
        };

        generator
            .generate(
                Lifetime::years(1).unwrap(),
                Capabilities {
                    credentials: vec![INVALID_CREDENTIAL_TYPE.into()],
                    ..Default::default()
                },
                Default::default(),
                Default::default(),
            )
            .await
            .unwrap()
            .key_package
    }

    #[futures_test::test]
    async fn receiving_add_with_leaf_not_supporting_credential_type_of_other_leaf_fails() {
        let (alice, tree) = new_tree("alice").await;

        let res = CommitReceiver::new(
            &tree,
            alice,
            alice,
            test_cipher_suite_provider(TEST_CIPHER_SUITE),
        )
        .receive([Proposal::Add(AddProposal {
            key_package: unsupported_credential_key_package("bob").await,
        })])
        .await;

        assert_matches!(
            res,
            Err(ProposalCacheError::ProposalFilterError(
                ProposalFilterError::RatchetTreeError(RatchetTreeError::TreeIndexError(
                    TreeIndexError::InUseCredentialTypeUnsupportedByNewLeaf(c, _)
                ))
            )) if c == BasicCredential::credential_type()
        );
    }

    #[futures_test::test]
    async fn sending_additional_add_with_leaf_not_supporting_credential_type_of_other_leaf_fails() {
        let (alice, tree) = new_tree("alice").await;

        let res = CommitSender::new(&tree, alice, test_cipher_suite_provider(TEST_CIPHER_SUITE))
            .with_additional([Proposal::Add(AddProposal {
                key_package: unsupported_credential_key_package("bob").await,
            })])
            .send()
            .await;

        assert_matches!(
            res,
            Err(ProposalCacheError::ProposalFilterError(
                ProposalFilterError::RatchetTreeError(RatchetTreeError::TreeIndexError(
                    TreeIndexError::InUseCredentialTypeUnsupportedByNewLeaf(
                        c,
                        _
                    )
                ))
            )) if c == BasicCredential::credential_type()
        );
    }

    #[futures_test::test]
    async fn sending_add_with_leaf_not_supporting_credential_type_of_other_leaf_filters_it_out() {
        let (alice, tree) = new_tree("alice").await;

        let add = Proposal::Add(AddProposal {
            key_package: unsupported_credential_key_package("bob").await,
        });

        let add_ref = make_proposal_ref(&add, alice);

        let (committed, effects) =
            CommitSender::new(&tree, alice, test_cipher_suite_provider(TEST_CIPHER_SUITE))
                .cache(add_ref.clone(), add.clone(), alice)
                .send()
                .await
                .unwrap();

        assert_eq!(committed, Vec::new());
        assert_eq!(effects.rejected_proposals, vec![(add_ref, add)]);
    }

    #[futures_test::test]
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
            Err(ProposalCacheError::ProposalFilterError(
                ProposalFilterError::UnsupportedGroupExtension(42)
            ))
        );
    }

    #[futures_test::test]
    async fn sending_additional_group_extension_unsupported_by_leaf_fails() {
        let (alice, tree) = new_tree("alice").await;

        let res = CommitSender::new(&tree, alice, test_cipher_suite_provider(TEST_CIPHER_SUITE))
            .with_additional([Proposal::GroupContextExtensions(make_extension_list(0))])
            .send()
            .await;

        assert_matches!(
            res,
            Err(ProposalCacheError::ProposalFilterError(
                ProposalFilterError::UnsupportedGroupExtension(42)
            ))
        );
    }

    #[futures_test::test]
    async fn sending_group_extension_unsupported_by_leaf_filters_it_out() {
        let (alice, tree) = new_tree("alice").await;

        let proposal = Proposal::GroupContextExtensions(make_extension_list(0));
        let proposal_ref = make_proposal_ref(&proposal, alice);

        let (committed, effects) =
            CommitSender::new(&tree, alice, test_cipher_suite_provider(TEST_CIPHER_SUITE))
                .cache(proposal_ref.clone(), proposal.clone(), alice)
                .send()
                .await
                .unwrap();

        assert_eq!(committed, Vec::new());
        assert_eq!(effects.rejected_proposals, vec![(proposal_ref, proposal)]);
    }

    #[derive(Debug)]
    struct FailurePskIdValidator;

    impl ExternalPskIdValidator for FailurePskIdValidator {
        type Error = std::io::Error;

        fn validate(&self, _: &ExternalPskId) -> Result<(), Self::Error> {
            Err(std::io::ErrorKind::InvalidData.into())
        }
    }

    #[futures_test::test]
    async fn receiving_external_psk_with_unknown_id_fails() {
        let (alice, tree) = new_tree("alice").await;

        let res = CommitReceiver::new(
            &tree,
            alice,
            alice,
            test_cipher_suite_provider(TEST_CIPHER_SUITE),
        )
        .with_external_psk_id_validator(FailurePskIdValidator)
        .receive([Proposal::Psk(new_external_psk(b"abc"))])
        .await;

        assert_matches!(
            res,
            Err(ProposalCacheError::ProposalFilterError(
                ProposalFilterError::PskIdValidationError(_)
            ))
        );
    }

    #[futures_test::test]
    async fn sending_additional_external_psk_with_unknown_id_fails() {
        let (alice, tree) = new_tree("alice").await;

        let res = CommitSender::new(&tree, alice, test_cipher_suite_provider(TEST_CIPHER_SUITE))
            .with_external_psk_id_validator(FailurePskIdValidator)
            .with_additional([Proposal::Psk(new_external_psk(b"abc"))])
            .send()
            .await;

        assert_matches!(
            res,
            Err(ProposalCacheError::ProposalFilterError(
                ProposalFilterError::PskIdValidationError(_)
            ))
        );
    }

    #[futures_test::test]
    async fn sending_external_psk_with_unknown_id_filters_it_out() {
        let (alice, tree) = new_tree("alice").await;
        let proposal = Proposal::Psk(new_external_psk(b"abc"));
        let proposal_ref = make_proposal_ref(&proposal, alice);

        let (committed, effects) =
            CommitSender::new(&tree, alice, test_cipher_suite_provider(TEST_CIPHER_SUITE))
                .with_external_psk_id_validator(FailurePskIdValidator)
                .cache(proposal_ref.clone(), proposal.clone(), alice)
                .send()
                .await
                .unwrap();

        assert_eq!(committed, Vec::new());
        assert_eq!(effects.rejected_proposals, vec![(proposal_ref, proposal)]);
    }

    #[futures_test::test]
    async fn user_defined_filter_can_remove_proposals() {
        struct RemoveGroupContextExtensions;

        impl ProposalFilter for RemoveGroupContextExtensions {
            type Error = Infallible;

            fn validate(&self, _: &ProposalBundle) -> Result<(), Self::Error> {
                Ok(())
            }

            fn filter(&self, mut proposals: ProposalBundle) -> Result<ProposalBundle, Self::Error> {
                proposals.clear_group_context_extensions();
                Ok(proposals)
            }
        }

        let (alice, tree) = new_tree("alice").await;

        let (committed, _) =
            CommitSender::new(&tree, alice, test_cipher_suite_provider(TEST_CIPHER_SUITE))
                .with_additional([Proposal::GroupContextExtensions(Default::default())])
                .with_user_filter(RemoveGroupContextExtensions)
                .send()
                .await
                .unwrap();

        assert_eq!(committed, Vec::new());
    }

    struct FailureProposalFilter;

    impl ProposalFilter for FailureProposalFilter {
        type Error = std::io::Error;

        fn validate(&self, _: &ProposalBundle) -> Result<(), Self::Error> {
            Err(std::io::ErrorKind::TimedOut.into())
        }

        fn filter(&self, _: ProposalBundle) -> Result<ProposalBundle, Self::Error> {
            Err(std::io::ErrorKind::TimedOut.into())
        }
    }

    #[futures_test::test]
    async fn user_defined_filter_can_refuse_to_send_commit() {
        let (alice, tree) = new_tree("alice").await;

        let res = CommitSender::new(&tree, alice, test_cipher_suite_provider(TEST_CIPHER_SUITE))
            .with_additional([Proposal::GroupContextExtensions(Default::default())])
            .with_user_filter(FailureProposalFilter)
            .send()
            .await;

        assert_matches!(
            res,
            Err(ProposalCacheError::ProposalFilterError(
                ProposalFilterError::UserDefined(_)
            ))
        );
    }

    #[futures_test::test]
    async fn user_defined_filter_can_reject_incoming_commit() {
        let (alice, tree) = new_tree("alice").await;

        let res = CommitReceiver::new(
            &tree,
            alice,
            alice,
            test_cipher_suite_provider(TEST_CIPHER_SUITE),
        )
        .with_user_filter(FailureProposalFilter)
        .receive([Proposal::GroupContextExtensions(Default::default())])
        .await;

        assert_matches!(
            res,
            Err(ProposalCacheError::ProposalFilterError(
                ProposalFilterError::UserDefined(_)
            ))
        );
    }

    #[futures_test::test]
    async fn proposers_are_verified() {
        let (alice, mut tree) = new_tree("alice").await;
        let bob = add_member(&mut tree, "bob").await;

        let external_senders = ExternalSendersExt::new(vec![
            get_test_signing_identity(TEST_CIPHER_SUITE, b"carol".to_vec()).0,
        ]);

        let sender_is_valid = |sender: &Sender| match sender {
            Sender::Member(i) => tree.get_leaf_node(LeafIndex(*i)).is_ok(),
            Sender::External(i) => (*i as usize) < external_senders.allowed_senders.len(),
            _ => true,
        };

        let proposals: &[Proposal] = &[
            Proposal::Add(make_add_proposal().await),
            Proposal::Update(make_update_proposal("alice").await),
            Proposal::Remove(RemoveProposal { to_remove: bob }),
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
            Sender::Member(33),
            Sender::External(0),
            Sender::External(1),
            Sender::NewMemberCommit,
            Sender::NewMemberProposal,
        ];

        for ((proposer, proposal), by_ref) in proposers
            .into_iter()
            .cartesian_product(proposals)
            .cartesian_product([false, true])
        {
            let committer = Sender::Member(*alice);

            let receiver = CommitReceiver::new(
                &tree,
                committer.clone(),
                alice,
                test_cipher_suite_provider(TEST_CIPHER_SUITE),
            )
            .with_extensions([external_senders.clone()].try_into().unwrap());

            let (receiver, proposals, proposer) = if by_ref {
                let proposal_ref = make_proposal_ref(proposal, proposer.clone());
                let receiver =
                    receiver.cache(proposal_ref.clone(), proposal.clone(), proposer.clone());
                (receiver, vec![ProposalOrRef::from(proposal_ref)], proposer)
            } else {
                (receiver, vec![proposal.clone().into()], committer)
            };

            let res = receiver.receive(proposals).await;

            if !proposer_can_propose(&proposer, proposal.proposal_type(), by_ref) {
                assert_matches!(
                    res,
                    Err(ProposalCacheError::ProposalFilterError(
                        ProposalFilterError::InvalidProposalTypeForSender {
                            proposal_type: found_type,
                            sender: found_sender,
                            by_ref: found_by_ref,
                        }
                    )) if found_type == proposal.proposal_type() && found_sender == proposer && found_by_ref == by_ref
                );
            } else if !sender_is_valid(&proposer) {
                match proposer {
                    Sender::Member(i) => assert_matches!(
                        res,
                        Err(ProposalCacheError::ProposalFilterError(
                            ProposalFilterError::InvalidMemberProposer(index)
                        )) if i == index
                    ),
                    Sender::External(i) => assert_matches!(
                        res,
                        Err(ProposalCacheError::ProposalFilterError(
                            ProposalFilterError::InvalidExternalSenderIndex(index)
                        )) if i == index
                    ),
                    _ => unreachable!(),
                }
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
}
