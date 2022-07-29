use super::*;
use crate::{
    extension::RequiredCapabilitiesExt,
    group::proposal_filter::{
        FailInvalidProposal, IgnoreInvalidByRefProposal, ProposalApplier, ProposalBundle,
        ProposalFilter, ProposalFilterError, ProposalInfo, ProposalState,
    },
    psk::PreSharedKeyID,
    tree_kem::leaf_node::LeafNode,
};

#[derive(Error, Debug)]
pub enum ProposalCacheError {
    #[error(transparent)]
    ProposalFilterError(#[from] ProposalFilterError),
    #[error("Proposal {0:?} not found")]
    ProposalNotFound(ProposalRef),
}

#[derive(Debug, PartialEq)]
pub struct ProposalSetEffects {
    pub tree: TreeKemPublic,
    pub added_leaf_indexes: Vec<LeafIndex>,
    pub removed_leaves: Vec<(LeafIndex, LeafNode)>,
    pub adds: Vec<KeyPackage>,
    pub updates: Vec<(LeafIndex, LeafNode)>,
    pub removes: Vec<LeafIndex>,
    pub group_context_ext: Option<ExtensionList>,
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
                    self.updates.push((package_to_replace, update.leaf_node))
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

#[derive(
    Debug,
    Clone,
    TlsSerialize,
    TlsSize,
    TlsDeserialize,
    PartialEq,
    serde::Deserialize,
    serde::Serialize,
)]
pub struct CachedProposal {
    proposal: Proposal,
    sender: Sender,
}

impl CachedProposal {
    pub fn new(proposal: Proposal, sender: Sender) -> Self {
        Self { proposal, sender }
    }
}

#[derive(
    Clone,
    Debug,
    TlsSize,
    TlsSerialize,
    TlsDeserialize,
    PartialEq,
    serde::Deserialize,
    serde::Serialize,
)]
pub(crate) struct ProposalCache {
    protocol_version: ProtocolVersion,
    cipher_suite: CipherSuite,
    #[tls_codec(with = "crate::tls::ByteVec")]
    #[serde(with = "hex")]
    group_id: Vec<u8>,
    #[tls_codec(with = "crate::tls::DefMap")]
    #[serde(with = "crate::serde_utils::map_as_seq")]
    proposals: HashMap<ProposalRef, CachedProposal>,
}

impl ProposalCache {
    pub fn new(
        protocol_version: ProtocolVersion,
        cipher_suite: CipherSuite,
        group_id: Vec<u8>,
    ) -> Self {
        Self {
            protocol_version,
            cipher_suite,
            group_id,
            proposals: Default::default(),
        }
    }

    pub fn import(
        protocol_version: ProtocolVersion,
        cipher_suite: CipherSuite,
        group_id: Vec<u8>,
        proposals: HashMap<ProposalRef, CachedProposal>,
    ) -> Self {
        Self {
            protocol_version,
            cipher_suite,
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
    pub fn prepare_commit<C, F>(
        &self,
        sender: Sender,
        additional_proposals: Vec<Proposal>,
        required_capabilities: Option<RequiredCapabilitiesExt>,
        credential_validator: C,
        public_tree: &TreeKemPublic,
        external_leaf: Option<&LeafNode>,
        user_filter: F,
    ) -> Result<(Vec<ProposalOrRef>, ProposalSetEffects), ProposalCacheError>
    where
        C: CredentialValidator,
        F: ProposalFilter,
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

        let applier = ProposalApplier::new(
            public_tree,
            self.protocol_version,
            self.cipher_suite,
            &self.group_id,
            required_capabilities.as_ref(),
            external_leaf,
            &credential_validator,
        );

        let ProposalState {
            tree,
            proposals,
            added_indexes,
            removed_leaves,
            external_leaf_index,
        } = applier.apply_proposals(IgnoreInvalidByRefProposal, &sender, proposals)?;

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
    pub fn resolve_for_commit<C, F>(
        &self,
        sender: Sender,
        receiver: Option<LeafIndex>,
        proposal_list: Vec<ProposalOrRef>,
        external_leaf: Option<&LeafNode>,
        required_capabilities: Option<RequiredCapabilitiesExt>,
        credential_validator: C,
        public_tree: &TreeKemPublic,
        user_filter: F,
    ) -> Result<ProposalSetEffects, ProposalCacheError>
    where
        C: CredentialValidator,
        F: ProposalFilter,
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

        let applier = ProposalApplier::new(
            public_tree,
            self.protocol_version,
            self.cipher_suite,
            &self.group_id,
            required_capabilities.as_ref(),
            external_leaf,
            &credential_validator,
        );

        let ProposalState {
            tree,
            proposals,
            added_indexes,
            removed_leaves,
            external_leaf_index,
        } = applier.apply_proposals(FailInvalidProposal, &sender, proposals)?;

        let rejected = receiver
            .map(|index| {
                rejected_proposals(self.proposals.clone(), &proposals, &Sender::Member(index))
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
mod tests {
    use super::proposal_ref::test_utils::plaintext_from_proposal;
    use super::*;
    use crate::{
        client_config::PassthroughCredentialValidator,
        extension::{test_utils::TestExtension, ExternalSendersExt},
        group::test_utils::{test_group, TEST_GROUP},
        key_package::test_utils::test_key_package,
        signing_identity::test_utils::get_test_signing_identity,
        tree_kem::{
            leaf_node::{
                test_utils::{get_basic_test_node, get_basic_test_node_sig_key},
                LeafNodeSource,
            },
            leaf_node_validator::test_utils::FailureCredentialValidator,
            parent_hash::ParentHash,
            AccumulateBatchResults, TreeIndexError,
        },
        PassThroughProposalFilter,
    };
    use assert_matches::assert_matches;
    use ferriscrypt::kdf::hkdf::Hkdf;
    use std::convert::Infallible;

    const TEST_CIPHER_SUITE: CipherSuite = CipherSuite::P256Aes128;
    const TEST_PROTOCOL_VERSION: ProtocolVersion = ProtocolVersion::Mls10;

    #[cfg(target_arch = "wasm32")]
    use wasm_bindgen_test::wasm_bindgen_test as test;

    fn test_sender() -> LeafIndex {
        LeafIndex(1)
    }

    fn new_tree(name: &str) -> (LeafIndex, TreeKemPublic) {
        let (leaf, secret, _) = get_basic_test_node_sig_key(TEST_CIPHER_SUITE, name);
        let (pub_tree, priv_tree) = TreeKemPublic::derive(TEST_CIPHER_SUITE, leaf, secret).unwrap();
        (priv_tree.self_index, pub_tree)
    }

    fn add_member(tree: &mut TreeKemPublic, name: &str) -> LeafIndex {
        tree.add_leaves(vec![get_basic_test_node(TEST_CIPHER_SUITE, name)])
            .unwrap()[0]
    }

    fn update_leaf_node(name: &str) -> LeafNode {
        let (mut leaf, _, signer) = get_basic_test_node_sig_key(TEST_CIPHER_SUITE, name);

        leaf.update(TEST_CIPHER_SUITE, TEST_GROUP, None, None, &signer)
            .unwrap();

        leaf
    }

    struct TestProposals {
        test_sender: LeafIndex,
        test_proposals: Vec<MLSPlaintext>,
        expected_effects: ProposalSetEffects,
        tree: TreeKemPublic,
    }

    fn test_proposals(
        protocol_version: ProtocolVersion,
        cipher_suite: CipherSuite,
    ) -> TestProposals {
        let (sender_leaf, sender_leaf_secret, _) = get_basic_test_node_sig_key(cipher_suite, "bar");
        let sender = LeafIndex(0);

        let (mut tree, _) =
            TreeKemPublic::derive(cipher_suite, sender_leaf, sender_leaf_secret).unwrap();

        let add_package = test_key_package(protocol_version, cipher_suite);
        let update_leaf = update_leaf_node("foo");

        let remove_leaf_index = add_member(&mut tree, "baz");

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

        let test_sender = tree
            .add_leaves(vec![get_basic_test_node(cipher_suite, "quux")])
            .unwrap()[0];

        let mut expected_tree = tree.clone();
        expected_tree
            .batch_edit(
                NoopAccumulator,
                &[(sender, update_leaf.clone())],
                &[remove_leaf_index],
                &[add_package.leaf_node.clone()],
            )
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
            .map(|p| plaintext_from_proposal(p, sender))
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
        plaintexts: Vec<MLSPlaintext>,
    ) -> impl Iterator<Item = (ProposalRef, CachedProposal)> {
        plaintexts
            .into_iter()
            .filter_map(move |p| match &p.content.content {
                Content::Proposal(proposal) => {
                    let proposal_ref =
                        ProposalRef::from_plaintext(cipher_suite, &p, false).unwrap();
                    Some((
                        proposal_ref,
                        CachedProposal::new(proposal.clone(), p.content.sender),
                    ))
                }
                _ => None,
            })
    }

    fn make_proposal_ref(p: &Proposal, sender: LeafIndex) -> ProposalRef {
        ProposalRef::from_plaintext(
            TEST_CIPHER_SUITE,
            &plaintext_from_proposal(p.clone(), sender),
            false,
        )
        .unwrap()
    }

    fn make_proposal_cache() -> ProposalCache {
        ProposalCache::new(
            TEST_PROTOCOL_VERSION,
            TEST_CIPHER_SUITE,
            TEST_GROUP.to_vec(),
        )
    }

    fn test_proposal_cache_setup(plaintexts: Vec<MLSPlaintext>) -> ProposalCache {
        let mut cache = make_proposal_cache();
        cache.extend(filter_proposals(TEST_CIPHER_SUITE, plaintexts));
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

    fn pass_through_filter() -> impl ProposalFilter<Error = Infallible> {
        PassThroughProposalFilter::new()
    }

    #[test]
    fn test_proposal_cache_commit_all_cached() {
        let TestProposals {
            test_sender,
            test_proposals,
            expected_effects,
            tree,
            ..
        } = test_proposals(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE);

        let cache = test_proposal_cache_setup(test_proposals.clone());

        let (proposals, effects) = cache
            .prepare_commit(
                Sender::Member(test_sender),
                vec![],
                None,
                PassthroughCredentialValidator::new(),
                &tree,
                None,
                pass_through_filter(),
            )
            .unwrap();

        let expected_proposals = test_proposals
            .into_iter()
            .map(|p| {
                ProposalOrRef::Reference(
                    ProposalRef::from_plaintext(TEST_CIPHER_SUITE, &p, false).unwrap(),
                )
            })
            .collect();

        assert_matches(expected_proposals, expected_effects, proposals, effects)
    }

    #[test]
    fn test_proposal_cache_commit_additional() {
        let TestProposals {
            test_sender,
            test_proposals,
            mut expected_effects,
            tree,
            ..
        } = test_proposals(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE);

        let additional_key_package = test_key_package(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE);

        let additional = vec![Proposal::Add(AddProposal {
            key_package: additional_key_package.clone(),
        })];

        let cache = test_proposal_cache_setup(test_proposals.clone());

        let (proposals, effects) = cache
            .prepare_commit(
                Sender::Member(test_sender),
                additional.clone(),
                None,
                PassthroughCredentialValidator::new(),
                &tree,
                None,
                pass_through_filter(),
            )
            .unwrap();

        let mut expected_proposals = test_proposals
            .into_iter()
            .map(|p| {
                ProposalOrRef::Reference(
                    ProposalRef::from_plaintext(TEST_CIPHER_SUITE, &p, false).unwrap(),
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
            )
            .unwrap();

        expected_effects.adds.push(additional_key_package);
        expected_effects.added_leaf_indexes.push(LeafIndex(3));

        assert_matches(expected_proposals, expected_effects, proposals, effects);
    }

    #[test]
    fn test_proposal_cache_update_filter() {
        let TestProposals {
            test_proposals,
            tree,
            ..
        } = test_proposals(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE);

        let additional = vec![Proposal::Update(make_update_proposal("foo"))];

        let cache = test_proposal_cache_setup(test_proposals);

        let res = cache.prepare_commit(
            Sender::Member(test_sender()),
            additional,
            None,
            PassthroughCredentialValidator::new(),
            &tree,
            None,
            pass_through_filter(),
        );

        assert_matches!(
            res,
            Err(ProposalCacheError::ProposalFilterError(
                ProposalFilterError::InvalidCommitSelfUpdate
            ))
        );
    }

    #[test]
    fn test_proposal_cache_removal_override_update() {
        let TestProposals {
            test_sender,
            test_proposals,
            tree,
            ..
        } = test_proposals(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE);

        let update = Proposal::Update(make_update_proposal("foo"));
        let update_proposal_ref = make_proposal_ref(&update, LeafIndex(1));
        let mut cache = test_proposal_cache_setup(test_proposals);

        cache.insert(
            update_proposal_ref.clone(),
            update,
            Sender::Member(LeafIndex(1)),
        );

        let (proposals, effects) = cache
            .prepare_commit(
                Sender::Member(test_sender),
                vec![],
                None,
                PassthroughCredentialValidator::new(),
                &tree,
                None,
                pass_through_filter(),
            )
            .unwrap();

        assert!(effects.removes.contains(&LeafIndex(1)));
        assert!(!proposals.contains(&ProposalOrRef::Reference(update_proposal_ref)))
    }

    #[test]
    fn test_proposal_cache_filter_duplicates_insert() {
        let TestProposals {
            test_sender,
            test_proposals,
            expected_effects,
            tree,
            ..
        } = test_proposals(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE);

        let mut cache = test_proposal_cache_setup(test_proposals.clone());
        cache.extend(filter_proposals(TEST_CIPHER_SUITE, test_proposals.clone()));

        let (proposals, effects) = cache
            .prepare_commit(
                Sender::Member(test_sender),
                vec![],
                None,
                PassthroughCredentialValidator::new(),
                &tree,
                None,
                pass_through_filter(),
            )
            .unwrap();

        let expected_proposals = test_proposals
            .into_iter()
            .map(|p| {
                ProposalOrRef::Reference(
                    ProposalRef::from_plaintext(TEST_CIPHER_SUITE, &p, false).unwrap(),
                )
            })
            .collect::<Vec<ProposalOrRef>>();

        assert_matches(expected_proposals, expected_effects, proposals, effects)
    }

    #[test]
    fn test_proposal_cache_filter_duplicates_additional() {
        let TestProposals {
            test_proposals,
            expected_effects,
            tree,
            ..
        } = test_proposals(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE);

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
                Sender::Member(LeafIndex(2)),
                Vec::new(),
                None,
                PassthroughCredentialValidator::new(),
                &tree,
                None,
                pass_through_filter(),
            )
            .unwrap();

        let expected_proposals = test_proposals
            .into_iter()
            .map(|p| {
                ProposalOrRef::Reference(
                    ProposalRef::from_plaintext(TEST_CIPHER_SUITE, &p, false).unwrap(),
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
            to_remove: test_sender(),
        });

        let proposer = test_sender();
        let test_proposal_ref = make_proposal_ref(&test_proposal, proposer);
        cache.insert(test_proposal_ref, test_proposal, Sender::Member(proposer));

        assert!(!cache.is_empty())
    }

    #[test]
    fn test_proposal_cache_resolve() {
        let TestProposals {
            test_sender,
            test_proposals,
            tree,
            ..
        } = test_proposals(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE);

        let cache = test_proposal_cache_setup(test_proposals);

        let additional = vec![Proposal::Add(AddProposal {
            key_package: test_key_package(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE),
        })];

        let credential_validator = PassthroughCredentialValidator::new();

        let (proposals, effects) = cache
            .prepare_commit(
                Sender::Member(test_sender),
                additional,
                None,
                &credential_validator,
                &tree,
                None,
                pass_through_filter(),
            )
            .unwrap();

        let resolution = cache
            .resolve_for_commit(
                Sender::Member(test_sender),
                Some(test_sender),
                proposals,
                None,
                None,
                &credential_validator,
                &tree,
                pass_through_filter(),
            )
            .unwrap();

        assert_eq!(effects, resolution);
    }

    #[test]
    fn proposal_cache_filters_duplicate_psk_ids() {
        let cache = make_proposal_cache();
        let len = Hkdf::from(TEST_CIPHER_SUITE.kdf_type()).extract_size();

        let psk_id = PreSharedKeyID {
            key_id: JustPreSharedKeyID::External(ExternalPskId(vec![1; len])),
            psk_nonce: PskNonce::random(TEST_CIPHER_SUITE).unwrap(),
        };

        let proposal = Proposal::Psk(PreSharedKey { psk: psk_id });

        let res = cache.prepare_commit(
            Sender::Member(test_sender()),
            vec![proposal.clone(), proposal],
            None,
            PassthroughCredentialValidator::new(),
            &TreeKemPublic::new(TEST_CIPHER_SUITE),
            None,
            pass_through_filter(),
        );

        assert_matches!(
            res,
            Err(ProposalCacheError::ProposalFilterError(
                ProposalFilterError::DuplicatePskIds
            ))
        );
    }

    fn test_node() -> LeafNode {
        let (mut leaf_node, _, signer) = get_basic_test_node_sig_key(TEST_CIPHER_SUITE, "foo");

        leaf_node
            .commit(TEST_CIPHER_SUITE, TEST_GROUP, None, None, &signer, |_| {
                Ok(ParentHash::empty())
            })
            .unwrap();

        leaf_node
    }

    #[test]
    fn external_commit_must_have_new_leaf() {
        let cache = make_proposal_cache();
        let kem_output = vec![0; Hkdf::from(TEST_CIPHER_SUITE.kdf_type()).extract_size()];
        let group = test_group(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE);
        let public_tree = &group.group.core.current_tree;
        let credential_validator = PassthroughCredentialValidator::new();

        let res = cache.resolve_for_commit(
            Sender::NewMemberCommit,
            None,
            vec![ProposalOrRef::Proposal(Proposal::ExternalInit(
                ExternalInit { kem_output },
            ))],
            None,
            group.required_capabilities(),
            credential_validator,
            public_tree,
            pass_through_filter(),
        );

        assert_matches!(
            res,
            Err(ProposalCacheError::ProposalFilterError(
                ProposalFilterError::ExternalCommitMustHaveNewLeaf
            ))
        );
    }

    #[test]
    fn proposal_cache_rejects_proposals_by_ref_for_new_member() {
        let mut cache = make_proposal_cache();

        let proposal = {
            let kem_output = vec![0; Hkdf::from(TEST_CIPHER_SUITE.kdf_type()).extract_size()];
            Proposal::ExternalInit(ExternalInit { kem_output })
        };

        let proposal_ref = make_proposal_ref(&proposal, test_sender());

        cache.insert(
            proposal_ref.clone(),
            proposal,
            Sender::Member(test_sender()),
        );

        let group = test_group(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE);
        let public_tree = &group.group.core.current_tree;

        let res = cache.resolve_for_commit(
            Sender::NewMemberCommit,
            None,
            vec![ProposalOrRef::Reference(proposal_ref)],
            Some(&test_node()),
            group.required_capabilities(),
            PassthroughCredentialValidator::new(),
            public_tree,
            pass_through_filter(),
        );

        assert_matches!(
            res,
            Err(ProposalCacheError::ProposalFilterError(
                ProposalFilterError::OnlyMembersCanCommitProposalsByRef
            ))
        );
    }

    #[test]
    fn proposal_cache_rejects_multiple_external_init_proposals_in_commit() {
        let cache = make_proposal_cache();
        let kem_output = vec![0; Hkdf::from(TEST_CIPHER_SUITE.kdf_type()).extract_size()];
        let group = test_group(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE);
        let public_tree = &group.group.core.current_tree;
        let credential_validator = PassthroughCredentialValidator::new();

        let res = cache.resolve_for_commit(
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
            Some(&test_node()),
            group.required_capabilities(),
            credential_validator,
            public_tree,
            pass_through_filter(),
        );

        assert_matches!(
            res,
            Err(ProposalCacheError::ProposalFilterError(
                ProposalFilterError::ExternalCommitMustHaveExactlyOneExternalInit
            ))
        );
    }

    fn new_member_commits_proposal(
        proposal: Proposal,
    ) -> Result<ProposalSetEffects, ProposalCacheError> {
        let cache = make_proposal_cache();
        let kem_output = vec![0; Hkdf::from(TEST_CIPHER_SUITE.kdf_type()).extract_size()];
        let group = test_group(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE);
        let public_tree = &group.group.core.current_tree;
        let credential_validator = PassthroughCredentialValidator::new();

        cache.resolve_for_commit(
            Sender::NewMemberCommit,
            None,
            [
                Proposal::ExternalInit(ExternalInit { kem_output }),
                proposal,
            ]
            .into_iter()
            .map(ProposalOrRef::Proposal)
            .collect(),
            Some(&test_node()),
            group.required_capabilities(),
            credential_validator,
            public_tree,
            pass_through_filter(),
        )
    }

    #[test]
    fn new_member_cannot_commit_add_proposal() {
        let res = new_member_commits_proposal(Proposal::Add(AddProposal {
            key_package: test_key_package(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE),
        }));

        assert_matches!(
            res,
            Err(ProposalCacheError::ProposalFilterError(
                ProposalFilterError::InvalidProposalTypeInExternalCommit(ProposalType::ADD)
            ))
        );
    }

    #[test]
    fn new_member_cannot_commit_more_than_one_remove_proposal() {
        let cache = make_proposal_cache();
        let kem_output = vec![0; Hkdf::from(TEST_CIPHER_SUITE.kdf_type()).extract_size()];
        let group = test_group(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE);
        let required_capabilities = group.required_capabilities();
        let mut public_tree = group.group.core.current_tree;
        let credential_validator = PassthroughCredentialValidator::new();

        let test_leaf_nodes = vec![
            get_basic_test_node(TEST_CIPHER_SUITE, "foo"),
            get_basic_test_node(TEST_CIPHER_SUITE, "bar"),
        ];

        let test_leaf_node_indexes = public_tree.add_leaves(test_leaf_nodes).unwrap();

        let proposals = vec![
            Proposal::ExternalInit(ExternalInit { kem_output }),
            Proposal::Remove(RemoveProposal {
                to_remove: test_leaf_node_indexes[0],
            }),
            Proposal::Remove(RemoveProposal {
                to_remove: test_leaf_node_indexes[1],
            }),
        ];

        let res = cache.resolve_for_commit(
            Sender::NewMemberCommit,
            None,
            proposals.into_iter().map(ProposalOrRef::Proposal).collect(),
            Some(&test_node()),
            required_capabilities,
            credential_validator,
            &public_tree,
            pass_through_filter(),
        );

        assert_matches!(
            res,
            Err(ProposalCacheError::ProposalFilterError(
                ProposalFilterError::ExternalCommitWithMoreThanOneRemove
            ))
        );
    }

    #[test]
    fn new_member_remove_proposal_invalid_credential() {
        let cache = make_proposal_cache();
        let kem_output = vec![0; Hkdf::from(TEST_CIPHER_SUITE.kdf_type()).extract_size()];
        let group = test_group(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE);
        let required_capabilities = group.required_capabilities();
        let mut public_tree = group.group.core.current_tree;
        let credential_validator = FailureCredentialValidator::new().pass_validation(true);

        let test_leaf_nodes = vec![get_basic_test_node(TEST_CIPHER_SUITE, "foo")];

        let test_leaf_node_indexes = public_tree.add_leaves(test_leaf_nodes).unwrap();

        let proposals = vec![
            Proposal::ExternalInit(ExternalInit { kem_output }),
            Proposal::Remove(RemoveProposal {
                to_remove: test_leaf_node_indexes[0],
            }),
        ];

        let res = cache.resolve_for_commit(
            Sender::NewMemberCommit,
            None,
            proposals.into_iter().map(ProposalOrRef::Proposal).collect(),
            Some(&test_node()),
            required_capabilities,
            credential_validator,
            &public_tree,
            pass_through_filter(),
        );

        assert_matches!(
            res,
            Err(ProposalCacheError::ProposalFilterError(
                ProposalFilterError::ExternalCommitRemovesOtherIdentity
            ))
        );
    }

    #[test]
    fn new_member_remove_proposal_valid_credential() {
        let cache = make_proposal_cache();
        let kem_output = vec![0; Hkdf::from(TEST_CIPHER_SUITE.kdf_type()).extract_size()];
        let group = test_group(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE);
        let required_capabilities = group.required_capabilities();
        let mut public_tree = group.group.core.current_tree;
        let credential_validator = PassthroughCredentialValidator::new();

        let test_leaf_nodes = vec![get_basic_test_node(TEST_CIPHER_SUITE, "foo")];

        let test_leaf_node_indexes = public_tree.add_leaves(test_leaf_nodes).unwrap();

        let proposals = vec![
            Proposal::ExternalInit(ExternalInit { kem_output }),
            Proposal::Remove(RemoveProposal {
                to_remove: test_leaf_node_indexes[0],
            }),
        ];

        let res = cache.resolve_for_commit(
            Sender::NewMemberCommit,
            None,
            proposals.into_iter().map(ProposalOrRef::Proposal).collect(),
            Some(&test_node()),
            required_capabilities,
            credential_validator,
            &public_tree,
            pass_through_filter(),
        );

        assert_matches!(res, Ok(_));
    }

    #[test]
    fn new_member_cannot_commit_update_proposal() {
        let res = new_member_commits_proposal(Proposal::Update(UpdateProposal {
            leaf_node: get_basic_test_node(TEST_CIPHER_SUITE, "foo"),
        }));

        assert_matches!(
            res,
            Err(ProposalCacheError::ProposalFilterError(
                ProposalFilterError::InvalidProposalTypeInExternalCommit(ProposalType::UPDATE)
            ))
        );
    }

    #[test]
    fn new_member_cannot_commit_group_extensions_proposal() {
        let res =
            new_member_commits_proposal(Proposal::GroupContextExtensions(ExtensionList::new()));

        assert_matches!(
            res,
            Err(ProposalCacheError::ProposalFilterError(
                ProposalFilterError::InvalidProposalTypeInExternalCommit(
                    ProposalType::GROUP_CONTEXT_EXTENSIONS,
                )
            ))
        );
    }

    #[test]
    fn new_member_cannot_commit_reinit_proposal() {
        let res = new_member_commits_proposal(Proposal::ReInit(ReInit {
            group_id: b"foo".to_vec(),
            version: TEST_PROTOCOL_VERSION,
            cipher_suite: TEST_CIPHER_SUITE,
            extensions: ExtensionList::new(),
        }));

        assert_matches!(
            res,
            Err(ProposalCacheError::ProposalFilterError(
                ProposalFilterError::InvalidProposalTypeInExternalCommit(ProposalType::RE_INIT)
            ))
        );
    }

    #[test]
    fn new_member_commit_must_contain_an_external_init_proposal() {
        let cache = make_proposal_cache();
        let group = test_group(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE);
        let public_tree = &group.group.core.current_tree;
        let credential_validator = PassthroughCredentialValidator::new();

        let res = cache.resolve_for_commit(
            Sender::NewMemberCommit,
            None,
            Vec::new(),
            Some(&test_node()),
            group.required_capabilities(),
            credential_validator,
            public_tree,
            pass_through_filter(),
        );

        assert_matches!(
            res,
            Err(ProposalCacheError::ProposalFilterError(
                ProposalFilterError::ExternalCommitMustHaveExactlyOneExternalInit
            ))
        );
    }

    #[test]
    fn test_path_update_required_empty() {
        let cache = make_proposal_cache();

        let (_, effects) = cache
            .prepare_commit(
                Sender::Member(test_sender()),
                vec![],
                None,
                PassthroughCredentialValidator::new(),
                &TreeKemPublic::new(TEST_CIPHER_SUITE),
                None,
                pass_through_filter(),
            )
            .unwrap();

        assert!(effects.path_update_required())
    }

    #[test]
    fn test_path_update_required_updates() {
        let mut cache = make_proposal_cache();
        let update = Proposal::Update(make_update_proposal("bar"));

        cache.insert(
            make_proposal_ref(&update, LeafIndex(2)),
            update,
            Sender::Member(LeafIndex(2)),
        );

        let (_, effects) = cache
            .prepare_commit(
                Sender::Member(test_sender()),
                Vec::new(),
                None,
                PassthroughCredentialValidator::new(),
                &TreeKemPublic::new(TEST_CIPHER_SUITE),
                None,
                pass_through_filter(),
            )
            .unwrap();

        assert!(effects.path_update_required())
    }

    #[test]
    fn test_path_update_required_removes() {
        let cache = make_proposal_cache();

        let (alice_leaf, alice_secret, _) = get_basic_test_node_sig_key(TEST_CIPHER_SUITE, "alice");
        let alice = LeafIndex(0);

        let (mut tree, _) =
            TreeKemPublic::derive(TEST_CIPHER_SUITE, alice_leaf, alice_secret).unwrap();

        let bob = tree
            .add_leaves(vec![get_basic_test_node(TEST_CIPHER_SUITE, "bob")])
            .unwrap()[0];

        let remove = Proposal::Remove(RemoveProposal { to_remove: bob });

        let (_, effects) = cache
            .prepare_commit(
                Sender::Member(alice),
                vec![remove],
                None,
                PassthroughCredentialValidator::new(),
                &tree,
                None,
                pass_through_filter(),
            )
            .unwrap();

        assert!(effects.path_update_required())
    }

    #[test]
    fn test_path_update_not_required() {
        let cache = make_proposal_cache();

        let psk = Proposal::Psk(PreSharedKey {
            psk: PreSharedKeyID {
                key_id: JustPreSharedKeyID::External(ExternalPskId(vec![])),
                psk_nonce: PskNonce::random(TEST_CIPHER_SUITE).unwrap(),
            },
        });

        let add = Proposal::Add(AddProposal {
            key_package: test_key_package(ProtocolVersion::Mls10, TEST_CIPHER_SUITE),
        });

        let (_, effects) = cache
            .prepare_commit(
                Sender::Member(test_sender()),
                vec![psk, add],
                None,
                PassthroughCredentialValidator::new(),
                &TreeKemPublic::new(TEST_CIPHER_SUITE),
                None,
                pass_through_filter(),
            )
            .unwrap();

        assert!(!effects.path_update_required())
    }

    #[test]
    fn path_update_is_not_required_for_re_init() {
        let cache = make_proposal_cache();

        let reinit = Proposal::ReInit(ReInit {
            group_id: vec![],
            version: ProtocolVersion::Mls10,
            cipher_suite: TEST_CIPHER_SUITE,
            extensions: Default::default(),
        });

        let (_, effects) = cache
            .prepare_commit(
                Sender::Member(test_sender()),
                vec![reinit],
                None,
                PassthroughCredentialValidator::new(),
                &TreeKemPublic::new(TEST_CIPHER_SUITE),
                None,
                pass_through_filter(),
            )
            .unwrap();

        assert!(!effects.path_update_required())
    }

    #[derive(Debug)]
    struct CommitReceiver<'a, C> {
        tree: &'a TreeKemPublic,
        sender: Sender,
        receiver: LeafIndex,
        cache: ProposalCache,
        credential_validator: C,
    }

    impl<'a> CommitReceiver<'a, PassthroughCredentialValidator> {
        fn new<S>(tree: &'a TreeKemPublic, sender: S, receiver: LeafIndex) -> Self
        where
            S: Into<Sender>,
        {
            Self {
                tree,
                sender: sender.into(),
                receiver,
                cache: make_proposal_cache(),
                credential_validator: PassthroughCredentialValidator::new(),
            }
        }
    }

    impl<'a, C> CommitReceiver<'a, C>
    where
        C: CredentialValidator,
    {
        fn with_credential_validator<V>(self, validator: V) -> CommitReceiver<'a, V>
        where
            V: CredentialValidator,
        {
            CommitReceiver {
                tree: self.tree,
                sender: self.sender,
                receiver: self.receiver,
                cache: self.cache,
                credential_validator: validator,
            }
        }

        fn cache<S>(mut self, r: ProposalRef, p: Proposal, proposer: S) -> Self
        where
            S: Into<Sender>,
        {
            self.cache.insert(r, p, proposer.into());
            self
        }

        fn receive<I>(&self, proposals: I) -> Result<ProposalSetEffects, ProposalCacheError>
        where
            I: IntoIterator,
            I::Item: Into<ProposalOrRef>,
        {
            self.cache.resolve_for_commit(
                self.sender.clone(),
                Some(self.receiver),
                proposals.into_iter().map(Into::into).collect(),
                None,
                None,
                &self.credential_validator,
                self.tree,
                pass_through_filter(),
            )
        }
    }

    #[derive(Debug)]
    struct CommitSender<'a, C> {
        tree: &'a TreeKemPublic,
        sender: LeafIndex,
        cache: ProposalCache,
        additional_proposals: Vec<Proposal>,
        credential_validator: C,
    }

    impl<'a> CommitSender<'a, PassthroughCredentialValidator> {
        fn new(tree: &'a TreeKemPublic, sender: LeafIndex) -> Self {
            Self {
                tree,
                sender,
                cache: make_proposal_cache(),
                additional_proposals: Vec::new(),
                credential_validator: PassthroughCredentialValidator::new(),
            }
        }
    }

    impl<'a, C> CommitSender<'a, C>
    where
        C: CredentialValidator,
    {
        fn with_credential_validator<V>(self, validator: V) -> CommitSender<'a, V>
        where
            V: CredentialValidator,
        {
            CommitSender {
                tree: self.tree,
                sender: self.sender,
                cache: self.cache,
                additional_proposals: self.additional_proposals,
                credential_validator: validator,
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

        fn send(&self) -> Result<(Vec<ProposalOrRef>, ProposalSetEffects), ProposalCacheError> {
            self.cache.prepare_commit(
                Sender::Member(self.sender),
                self.additional_proposals.clone(),
                None,
                &self.credential_validator,
                self.tree,
                None,
                pass_through_filter(),
            )
        }
    }

    fn key_package_with_invalid_signature() -> KeyPackage {
        let mut kp = test_key_package(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE);
        kp.signature.clear();
        kp
    }

    #[test]
    fn receiving_add_with_invalid_key_package_fails() {
        let (alice, tree) = new_tree("alice");

        let res = CommitReceiver::new(&tree, alice, alice).receive([Proposal::Add(AddProposal {
            key_package: key_package_with_invalid_signature(),
        })]);

        assert_matches!(
            res,
            Err(ProposalCacheError::ProposalFilterError(
                ProposalFilterError::KeyPackageValidationError(_)
            ))
        );
    }

    #[test]
    fn sending_additional_add_with_invalid_key_package_fails() {
        let (alice, tree) = new_tree("alice");

        let res = CommitSender::new(&tree, alice)
            .with_additional([Proposal::Add(AddProposal {
                key_package: key_package_with_invalid_signature(),
            })])
            .send();

        assert_matches!(
            res,
            Err(ProposalCacheError::ProposalFilterError(
                ProposalFilterError::KeyPackageValidationError(_)
            ))
        );
    }

    #[test]
    fn sending_add_with_invalid_key_package_filters_it_out() {
        let (alice, tree) = new_tree("alice");

        let proposal = Proposal::Add(AddProposal {
            key_package: key_package_with_invalid_signature(),
        });
        let proposal_ref = make_proposal_ref(&proposal, alice);

        let (committed, effects) = CommitSender::new(&tree, alice)
            .cache(proposal_ref.clone(), proposal.clone(), alice)
            .send()
            .unwrap();

        assert_eq!(committed, Vec::new());
        assert_eq!(effects.rejected_proposals, vec![(proposal_ref, proposal)]);
    }

    #[test]
    fn receiving_update_with_invalid_leaf_node_fails() {
        let (alice, mut tree) = new_tree("alice");
        let bob = add_member(&mut tree, "bob");

        let proposal = Proposal::Update(UpdateProposal {
            leaf_node: get_basic_test_node(TEST_CIPHER_SUITE, "alice"),
        });
        let proposal_ref = make_proposal_ref(&proposal, bob);

        let res = CommitReceiver::new(&tree, alice, bob)
            .cache(proposal_ref.clone(), proposal, bob)
            .receive([proposal_ref]);

        assert_matches!(
            res,
            Err(ProposalCacheError::ProposalFilterError(
                ProposalFilterError::LeafNodeValidationError(_)
            ))
        );
    }

    #[test]
    fn sending_update_with_invalid_leaf_node_filters_it_out() {
        let (alice, mut tree) = new_tree("alice");
        let bob = add_member(&mut tree, "bob");

        let proposal = Proposal::Update(UpdateProposal {
            leaf_node: get_basic_test_node(TEST_CIPHER_SUITE, "alice"),
        });
        let proposal_ref = make_proposal_ref(&proposal, bob);

        let (committed, effects) = CommitSender::new(&tree, alice)
            .cache(proposal_ref, proposal, bob)
            .send()
            .unwrap();

        assert_eq!(committed, Vec::new());

        // Alice didn't propose the update. Bob did. That's why it is not returned in the list of
        // rejected proposals.
        assert_eq!(effects.rejected_proposals, Vec::new());
    }

    #[test]
    fn receiving_remove_with_invalid_index_fails() {
        let (alice, tree) = new_tree("alice");

        let res =
            CommitReceiver::new(&tree, alice, alice).receive([Proposal::Remove(RemoveProposal {
                to_remove: LeafIndex(10),
            })]);

        assert_matches!(
            res,
            Err(ProposalCacheError::ProposalFilterError(
                ProposalFilterError::RatchetTreeError(_)
            ))
        );
    }

    #[test]
    fn sending_additional_remove_with_invalid_index_fails() {
        let (alice, tree) = new_tree("alice");

        let res = CommitSender::new(&tree, alice)
            .with_additional([Proposal::Remove(RemoveProposal {
                to_remove: LeafIndex(10),
            })])
            .send();

        assert_matches!(
            res,
            Err(ProposalCacheError::ProposalFilterError(
                ProposalFilterError::RatchetTreeError(_)
            ))
        );
    }

    #[test]
    fn sending_remove_with_invalid_index_filters_it_out() {
        let (alice, tree) = new_tree("alice");

        let proposal = Proposal::Remove(RemoveProposal {
            to_remove: LeafIndex(10),
        });
        let proposal_ref = make_proposal_ref(&proposal, alice);

        let (committed, effects) = CommitSender::new(&tree, alice)
            .cache(proposal_ref.clone(), proposal.clone(), alice)
            .send()
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
        make_external_psk(id, PskNonce::random(TEST_CIPHER_SUITE).unwrap())
    }

    #[test]
    fn receiving_psk_with_invalid_nonce_fails() {
        let invalid_nonce = PskNonce(vec![0, 1, 2]);
        let (alice, tree) = new_tree("alice");

        let res = CommitReceiver::new(&tree, alice, alice).receive([Proposal::Psk(
            make_external_psk(b"foo", invalid_nonce.clone()),
        )]);

        assert_matches!(
            res,
            Err(ProposalCacheError::ProposalFilterError(
                ProposalFilterError::InvalidPskNonceLength { expected, found },
            )) if expected == Hkdf::from(TEST_CIPHER_SUITE.kdf_type()).extract_size() && found == invalid_nonce.0.len()
        );
    }

    #[test]
    fn sending_additional_psk_with_invalid_nonce_fails() {
        let invalid_nonce = PskNonce(vec![0, 1, 2]);
        let (alice, tree) = new_tree("alice");

        let res = CommitSender::new(&tree, alice)
            .with_additional([Proposal::Psk(make_external_psk(
                b"foo",
                invalid_nonce.clone(),
            ))])
            .send();

        assert_matches!(
            res,
            Err(ProposalCacheError::ProposalFilterError(
                ProposalFilterError::InvalidPskNonceLength { expected, found },
            )) if expected == Hkdf::from(TEST_CIPHER_SUITE.kdf_type()).extract_size() && found == invalid_nonce.0.len()
        );
    }

    #[test]
    fn sending_psk_with_invalid_nonce_filters_it_out() {
        let invalid_nonce = PskNonce(vec![0, 1, 2]);
        let (alice, tree) = new_tree("alice");
        let proposal = Proposal::Psk(make_external_psk(b"foo", invalid_nonce));
        let proposal_ref = make_proposal_ref(&proposal, alice);

        let (committed, effects) = CommitSender::new(&tree, alice)
            .cache(proposal_ref.clone(), proposal.clone(), alice)
            .send()
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
                psk_nonce: PskNonce::random(TEST_CIPHER_SUITE).unwrap(),
            },
        }
    }

    fn receiving_resumption_psk_with_bad_usage_fails(usage: ResumptionPSKUsage) {
        let (alice, tree) = new_tree("alice");

        let res = CommitReceiver::new(&tree, alice, alice)
            .receive([Proposal::Psk(make_resumption_psk(usage))]);

        assert_matches!(
            res,
            Err(ProposalCacheError::ProposalFilterError(
                ProposalFilterError::InvalidTypeOrUsageInPreSharedKeyProposal
            ))
        );
    }

    fn sending_additional_resumption_psk_with_bad_usage_fails(usage: ResumptionPSKUsage) {
        let (alice, tree) = new_tree("alice");

        let res = CommitSender::new(&tree, alice)
            .with_additional([Proposal::Psk(make_resumption_psk(usage))])
            .send();

        assert_matches!(
            res,
            Err(ProposalCacheError::ProposalFilterError(
                ProposalFilterError::InvalidTypeOrUsageInPreSharedKeyProposal
            ))
        );
    }

    fn sending_resumption_psk_with_bad_usage_filters_it_out(usage: ResumptionPSKUsage) {
        let (alice, tree) = new_tree("alice");
        let proposal = Proposal::Psk(make_resumption_psk(usage));
        let proposal_ref = make_proposal_ref(&proposal, alice);

        let (committed, effects) = CommitSender::new(&tree, alice)
            .cache(proposal_ref.clone(), proposal.clone(), alice)
            .send()
            .unwrap();

        assert_eq!(committed, Vec::new());
        assert_eq!(effects.rejected_proposals, vec![(proposal_ref, proposal)]);
    }

    #[test]
    fn receiving_resumption_psk_with_reinit_usage_fails() {
        receiving_resumption_psk_with_bad_usage_fails(ResumptionPSKUsage::Reinit);
    }

    #[test]
    fn sending_additional_resumption_psk_with_reinit_usage_fails() {
        sending_additional_resumption_psk_with_bad_usage_fails(ResumptionPSKUsage::Reinit);
    }

    #[test]
    fn sending_resumption_psk_with_reinit_usage_filters_it_out() {
        sending_resumption_psk_with_bad_usage_filters_it_out(ResumptionPSKUsage::Reinit);
    }

    #[test]
    fn receiving_resumption_psk_with_branch_usage_fails() {
        receiving_resumption_psk_with_bad_usage_fails(ResumptionPSKUsage::Branch);
    }

    #[test]
    fn sending_additional_resumption_psk_with_branch_usage_fails() {
        sending_additional_resumption_psk_with_bad_usage_fails(ResumptionPSKUsage::Branch);
    }

    #[test]
    fn sending_resumption_psk_with_branch_usage_filters_it_out() {
        sending_resumption_psk_with_bad_usage_filters_it_out(ResumptionPSKUsage::Branch);
    }

    fn make_reinit(version: ProtocolVersion) -> ReInit {
        ReInit {
            group_id: TEST_GROUP.to_vec(),
            version,
            cipher_suite: TEST_CIPHER_SUITE,
            extensions: ExtensionList::new(),
        }
    }

    // The `ignore` attribute does not seem to be supported by `wasm_bindgen_test`.
    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    #[ignore = "Cannot be fully implemented until https://github.com/WickrInc/mls/issues/392"]
    fn receiving_reinit_downgrading_version_fails() {
        let smaller_protocol_version = TEST_PROTOCOL_VERSION;
        let (alice, tree) = new_tree("alice");

        let res = CommitReceiver::new(&tree, alice, alice)
            .receive([Proposal::ReInit(make_reinit(smaller_protocol_version))]);

        assert_matches!(
            res,
            Err(ProposalCacheError::ProposalFilterError(ProposalFilterError::InvalidProtocolVersionInReInit {
                proposed,
                original,
            })) if proposed == smaller_protocol_version && original == TEST_PROTOCOL_VERSION
        );
    }

    // The `ignore` attribute does not seem to be supported by `wasm_bindgen_test`.
    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    #[ignore = "Cannot be fully implemented until https://github.com/WickrInc/mls/issues/392"]
    fn sending_additional_reinit_downgrading_version_fails() {
        let smaller_protocol_version = TEST_PROTOCOL_VERSION;
        let (alice, tree) = new_tree("alice");

        let res = CommitSender::new(&tree, alice)
            .with_additional([Proposal::ReInit(make_reinit(smaller_protocol_version))])
            .send();

        assert_matches!(
            res,
            Err(ProposalCacheError::ProposalFilterError(ProposalFilterError::InvalidProtocolVersionInReInit {
                proposed,
                original,
            })) if proposed == smaller_protocol_version && original == TEST_PROTOCOL_VERSION
        );
    }

    // The `ignore` attribute does not seem to be supported by `wasm_bindgen_test`.
    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    #[ignore = "Cannot be fully implemented until https://github.com/WickrInc/mls/issues/392"]
    fn sending_reinit_downgrading_version_filters_it_out() {
        let smaller_protocol_version = TEST_PROTOCOL_VERSION;
        let (alice, tree) = new_tree("alice");
        let proposal = Proposal::ReInit(make_reinit(smaller_protocol_version));
        let proposal_ref = make_proposal_ref(&proposal, alice);

        let (committed, effects) = CommitSender::new(&tree, alice)
            .cache(proposal_ref.clone(), proposal.clone(), alice)
            .send()
            .unwrap();

        assert_eq!(committed, Vec::new());
        assert_eq!(effects.rejected_proposals, vec![(proposal_ref, proposal)]);
    }

    fn make_update_proposal(name: &str) -> UpdateProposal {
        UpdateProposal {
            leaf_node: update_leaf_node(name),
        }
    }

    #[test]
    fn receiving_update_for_committer_fails() {
        let (alice, tree) = new_tree("alice");

        let res = CommitReceiver::new(&tree, alice, alice)
            .receive([Proposal::Update(make_update_proposal("alice"))]);

        assert_matches!(
            res,
            Err(ProposalCacheError::ProposalFilterError(
                ProposalFilterError::InvalidCommitSelfUpdate
            ))
        );
    }

    #[test]
    fn sending_additional_update_for_committer_fails() {
        let (alice, tree) = new_tree("alice");

        let res = CommitSender::new(&tree, alice)
            .with_additional([Proposal::Update(make_update_proposal("alice"))])
            .send();

        assert_matches!(
            res,
            Err(ProposalCacheError::ProposalFilterError(
                ProposalFilterError::InvalidCommitSelfUpdate
            ))
        );
    }

    #[test]
    fn sending_update_for_committer_filters_it_out() {
        let (alice, tree) = new_tree("alice");
        let proposal = Proposal::Update(make_update_proposal("alice"));
        let proposal_ref = make_proposal_ref(&proposal, alice);

        let (committed, effects) = CommitSender::new(&tree, alice)
            .cache(proposal_ref.clone(), proposal.clone(), alice)
            .send()
            .unwrap();

        assert_eq!(committed, Vec::new());
        assert_eq!(effects.rejected_proposals, vec![(proposal_ref, proposal)]);
    }

    #[test]
    fn receiving_remove_for_committer_fails() {
        let (alice, tree) = new_tree("alice");

        let res = CommitReceiver::new(&tree, alice, alice)
            .receive([Proposal::Remove(RemoveProposal { to_remove: alice })]);

        assert_matches!(
            res,
            Err(ProposalCacheError::ProposalFilterError(
                ProposalFilterError::CommitterSelfRemoval
            ))
        );
    }

    #[test]
    fn sending_additional_remove_for_committer_fails() {
        let (alice, tree) = new_tree("alice");

        let res = CommitSender::new(&tree, alice)
            .with_additional([Proposal::Remove(RemoveProposal { to_remove: alice })])
            .send();

        assert_matches!(
            res,
            Err(ProposalCacheError::ProposalFilterError(
                ProposalFilterError::CommitterSelfRemoval
            ))
        );
    }

    #[test]
    fn sending_remove_for_committer_filters_it_out() {
        let (alice, tree) = new_tree("alice");
        let proposal = Proposal::Remove(RemoveProposal { to_remove: alice });
        let proposal_ref = make_proposal_ref(&proposal, alice);

        let (committed, effects) = CommitSender::new(&tree, alice)
            .cache(proposal_ref.clone(), proposal.clone(), alice)
            .send()
            .unwrap();

        assert_eq!(committed, Vec::new());
        assert_eq!(effects.rejected_proposals, vec![(proposal_ref, proposal)]);
    }

    #[test]
    fn receiving_update_and_remove_for_same_leaf_fails() {
        let (alice, mut tree) = new_tree("alice");
        let bob = add_member(&mut tree, "bob");

        let update = Proposal::Update(make_update_proposal("bob"));
        let update_ref = make_proposal_ref(&update, bob);

        let remove = Proposal::Remove(RemoveProposal { to_remove: bob });
        let remove_ref = make_proposal_ref(&remove, bob);

        let res = CommitReceiver::new(&tree, alice, alice)
            .cache(update_ref.clone(), update, bob)
            .cache(remove_ref.clone(), remove, bob)
            .receive([update_ref, remove_ref]);

        assert_matches!(
            res,
            Err(ProposalCacheError::ProposalFilterError(
                ProposalFilterError::MoreThanOneProposalForLeaf(r)
            )) if r == bob
        );
    }

    #[test]
    fn sending_update_and_remove_for_same_leaf_filters_update_out() {
        let (alice, mut tree) = new_tree("alice");
        let bob = add_member(&mut tree, "bob");

        let update = Proposal::Update(make_update_proposal("bob"));
        let update_ref = make_proposal_ref(&update, alice);

        let remove = Proposal::Remove(RemoveProposal { to_remove: bob });
        let remove_ref = make_proposal_ref(&remove, alice);

        let (committed, effects) = CommitSender::new(&tree, alice)
            .cache(update_ref.clone(), update.clone(), alice)
            .cache(remove_ref.clone(), remove, alice)
            .send()
            .unwrap();

        assert_eq!(committed, vec![remove_ref.into()]);
        assert_eq!(effects.rejected_proposals, vec![(update_ref, update)]);
    }

    fn make_add_proposal() -> AddProposal {
        AddProposal {
            key_package: test_key_package(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE),
        }
    }

    // The `ignore` attribute does not seem to be supported by `wasm_bindgen_test`.
    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    #[ignore = "Cannot be fully implemented until https://github.com/WickrInc/mls/issues/342"]
    fn receiving_add_proposals_for_same_client_fails() {
        let (alice, tree) = new_tree("alice");

        let res = CommitReceiver::new(&tree, alice, alice).receive([
            Proposal::Add(make_add_proposal()),
            Proposal::Add(make_add_proposal()),
        ]);

        // todo: Use precise error when this test is enabled.
        assert_matches!(res, Err(_));
    }

    // The `ignore` attribute does not seem to be supported by `wasm_bindgen_test`.
    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    #[ignore = "Cannot be fully implemented until https://github.com/WickrInc/mls/issues/342"]
    fn sending_additional_add_proposals_for_same_client_fails() {
        let (alice, tree) = new_tree("alice");

        let res = CommitSender::new(&tree, alice)
            .with_additional([
                Proposal::Add(make_add_proposal()),
                Proposal::Add(make_add_proposal()),
            ])
            .send();

        // todo: Use precise error when this test is enabled.
        assert_matches!(res, Err(_));
    }

    // The `ignore` attribute does not seem to be supported by `wasm_bindgen_test`.
    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    #[ignore = "Cannot be fully implemented until https://github.com/WickrInc/mls/issues/342"]
    fn sending_add_proposals_for_same_client_keeps_only_one() {
        let (alice, tree) = new_tree("alice");

        let adds = [
            Proposal::Add(make_add_proposal()),
            Proposal::Add(make_add_proposal()),
        ];
        let add_refs = adds.clone().map(|p| make_proposal_ref(&p, alice));

        let (committed, effects) = CommitSender::new(&tree, alice)
            .cache(add_refs[0].clone(), adds[0].clone(), alice)
            .cache(add_refs[1].clone(), adds[1].clone(), alice)
            .send()
            .unwrap();

        assert_matches!(
            (&*committed, &*effects.rejected_proposals),
            ([ProposalOrRef::Reference(cr)], [(rr, _)]) if cr != rr && add_refs.contains(cr) && add_refs.contains(rr)
        );
    }

    #[test]
    fn receiving_add_for_same_client_as_existing_member_fails() {
        let (alice, tree) = new_tree("alice");
        let add = Proposal::Add(make_add_proposal());

        let ProposalSetEffects { tree, .. } = CommitReceiver::new(&tree, alice, alice)
            .receive([add.clone()])
            .unwrap();

        let res = CommitReceiver::new(&tree, alice, alice).receive([add]);

        assert_matches!(
            res,
            Err(ProposalCacheError::ProposalFilterError(
                ProposalFilterError::RatchetTreeError(RatchetTreeError::TreeIndexError(
                    TreeIndexError::DuplicateSignatureKeys(LeafIndex(1))
                ))
            ))
        );
    }

    #[test]
    fn sending_additional_add_for_same_client_as_existing_member_fails() {
        let (alice, tree) = new_tree("alice");
        let add = Proposal::Add(make_add_proposal());

        let ProposalSetEffects { tree, .. } = CommitReceiver::new(&tree, alice, alice)
            .receive([add.clone()])
            .unwrap();

        let res = CommitSender::new(&tree, alice)
            .with_additional([add])
            .send();

        assert_matches!(
            res,
            Err(ProposalCacheError::ProposalFilterError(
                ProposalFilterError::RatchetTreeError(RatchetTreeError::TreeIndexError(
                    TreeIndexError::DuplicateSignatureKeys(LeafIndex(1))
                ))
            ))
        );
    }

    #[test]
    fn sending_add_for_same_client_as_existing_member_filters_it_out() {
        let (alice, tree) = new_tree("alice");
        let add = Proposal::Add(make_add_proposal());

        let ProposalSetEffects { tree, .. } = CommitReceiver::new(&tree, alice, alice)
            .receive([add.clone()])
            .unwrap();

        let proposal_ref = make_proposal_ref(&add, alice);

        let (committed, effects) = CommitSender::new(&tree, alice)
            .cache(proposal_ref.clone(), add.clone(), alice)
            .send()
            .unwrap();

        assert_eq!(committed, Vec::new());
        assert_eq!(effects.rejected_proposals, vec![(proposal_ref, add)]);
    }

    #[test]
    fn receiving_psk_proposals_with_same_psk_id_fails() {
        let (alice, tree) = new_tree("alice");
        let psk_proposal = Proposal::Psk(new_external_psk(b"foo"));

        let res =
            CommitReceiver::new(&tree, alice, alice).receive([psk_proposal.clone(), psk_proposal]);

        assert_matches!(
            res,
            Err(ProposalCacheError::ProposalFilterError(
                ProposalFilterError::DuplicatePskIds
            ))
        );
    }

    #[test]
    fn sending_additional_psk_proposals_with_same_psk_id_fails() {
        let (alice, tree) = new_tree("alice");
        let psk_proposal = Proposal::Psk(new_external_psk(b"foo"));

        let res = CommitSender::new(&tree, alice)
            .with_additional([psk_proposal.clone(), psk_proposal])
            .send();

        assert_matches!(
            res,
            Err(ProposalCacheError::ProposalFilterError(
                ProposalFilterError::DuplicatePskIds
            ))
        );
    }

    #[test]
    fn sending_psk_proposals_with_same_psk_id_keeps_only_one() {
        let (alice, mut tree) = new_tree("alice");
        let bob = add_member(&mut tree, "bob");

        let proposal = Proposal::Psk(new_external_psk(b"foo"));
        let proposal_refs = [
            make_proposal_ref(&proposal, alice),
            make_proposal_ref(&proposal, bob),
        ];

        let (committed, effects) = CommitSender::new(&tree, alice)
            .cache(proposal_refs[0].clone(), proposal.clone(), alice)
            .cache(proposal_refs[1].clone(), proposal, bob)
            .send()
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

    #[test]
    fn receiving_multiple_group_context_extensions_fails() {
        let (alice, tree) = new_tree("alice");

        let res = CommitReceiver::new(&tree, alice, alice).receive([
            Proposal::GroupContextExtensions(ExtensionList::new()),
            Proposal::GroupContextExtensions(ExtensionList::new()),
        ]);

        assert_matches!(
            res,
            Err(ProposalCacheError::ProposalFilterError(
                ProposalFilterError::MoreThanOneGroupContextExtensionsProposal
            ))
        );
    }

    #[test]
    fn sending_multiple_additional_group_context_extensions_fails() {
        let (alice, tree) = new_tree("alice");

        let res = CommitSender::new(&tree, alice)
            .with_additional([
                Proposal::GroupContextExtensions(ExtensionList::new()),
                Proposal::GroupContextExtensions(ExtensionList::new()),
            ])
            .send();

        assert_matches!(
            res,
            Err(ProposalCacheError::ProposalFilterError(
                ProposalFilterError::MoreThanOneGroupContextExtensionsProposal
            ))
        );
    }

    fn make_extension_list(foo: u8) -> ExtensionList {
        let mut list = ExtensionList::new();
        list.set_extension(TestExtension { foo }).unwrap();
        list
    }

    #[test]
    fn sending_multiple_group_context_extensions_keeps_only_one() {
        let (alice, tree) = new_tree("alice");

        let proposals = [
            Proposal::GroupContextExtensions(make_extension_list(0)),
            Proposal::GroupContextExtensions(make_extension_list(1)),
        ];

        let proposal_refs = proposals.clone().map(|p| make_proposal_ref(&p, alice));

        let (committed, effects) = CommitSender::new(&tree, alice)
            .cache(proposal_refs[0].clone(), proposals[0].clone(), alice)
            .cache(proposal_refs[1].clone(), proposals[1].clone(), alice)
            .send()
            .unwrap();

        assert_matches!(
            (&*committed, &*effects.rejected_proposals),
            ([ProposalOrRef::Reference(cr)], [(rr, _)]) if cr != rr && proposal_refs.contains(cr) && proposal_refs.contains(rr)
        );
    }

    fn make_external_senders_extension() -> ExtensionList {
        let mut extensions = ExtensionList::new();
        extensions
            .set_extension(ExternalSendersExt::new(vec![
                get_test_signing_identity(TEST_CIPHER_SUITE, b"alice".to_vec()).0,
            ]))
            .unwrap();
        extensions
    }

    #[test]
    fn receiving_invalid_external_senders_extension_fails() {
        let (alice, tree) = new_tree("alice");

        let res = CommitReceiver::new(&tree, alice, alice)
            .with_credential_validator(FailureCredentialValidator::new())
            .receive([Proposal::GroupContextExtensions(
                make_external_senders_extension(),
            )]);

        assert_matches!(
            res,
            Err(ProposalCacheError::ProposalFilterError(
                ProposalFilterError::SigningIdentityError(
                    SigningIdentityError::CredentialValidatorError(_)
                )
            ))
        );
    }

    #[test]
    fn sending_additional_invalid_external_senders_extension_fails() {
        let (alice, tree) = new_tree("alice");

        let res = CommitSender::new(&tree, alice)
            .with_credential_validator(FailureCredentialValidator::new())
            .with_additional([Proposal::GroupContextExtensions(
                make_external_senders_extension(),
            )])
            .send();

        assert_matches!(
            res,
            Err(ProposalCacheError::ProposalFilterError(
                ProposalFilterError::SigningIdentityError(
                    SigningIdentityError::CredentialValidatorError(_)
                )
            ))
        );
    }

    #[test]
    fn sending_invalid_external_senders_extension_filters_it_out() {
        let (alice, tree) = new_tree("alice");

        let proposal = Proposal::GroupContextExtensions(make_external_senders_extension());

        let proposal_ref = make_proposal_ref(&proposal, alice);

        let (committed, effects) = CommitSender::new(&tree, alice)
            .with_credential_validator(FailureCredentialValidator::new())
            .cache(proposal_ref.clone(), proposal.clone(), alice)
            .send()
            .unwrap();

        assert_eq!(committed, Vec::new());
        assert_eq!(effects.rejected_proposals, vec![(proposal_ref, proposal)]);
    }

    #[test]
    fn receiving_reinit_with_other_proposals_fails() {
        let (alice, tree) = new_tree("alice");

        let res = CommitReceiver::new(&tree, alice, alice).receive([
            Proposal::ReInit(make_reinit(TEST_PROTOCOL_VERSION)),
            Proposal::Add(make_add_proposal()),
        ]);

        assert_matches!(
            res,
            Err(ProposalCacheError::ProposalFilterError(
                ProposalFilterError::OtherProposalWithReInit
            ))
        );
    }

    #[test]
    fn sending_additional_reinit_with_other_proposals_fails() {
        let (alice, tree) = new_tree("alice");

        let res = CommitSender::new(&tree, alice)
            .with_additional([
                Proposal::ReInit(make_reinit(TEST_PROTOCOL_VERSION)),
                Proposal::Add(make_add_proposal()),
            ])
            .send();

        assert_matches!(
            res,
            Err(ProposalCacheError::ProposalFilterError(
                ProposalFilterError::OtherProposalWithReInit
            ))
        );
    }

    #[test]
    fn sending_reinit_with_other_proposals_filters_it_out() {
        let (alice, tree) = new_tree("alice");
        let reinit = Proposal::ReInit(make_reinit(TEST_PROTOCOL_VERSION));
        let reinit_ref = make_proposal_ref(&reinit, alice);
        let add = Proposal::Add(make_add_proposal());
        let add_ref = make_proposal_ref(&add, alice);

        let (committed, effects) = CommitSender::new(&tree, alice)
            .cache(reinit_ref.clone(), reinit.clone(), alice)
            .cache(add_ref.clone(), add, alice)
            .send()
            .unwrap();

        assert_eq!(committed, vec![add_ref.into()]);
        assert_eq!(effects.rejected_proposals, vec![(reinit_ref, reinit)]);
    }

    fn make_external_init() -> ExternalInit {
        ExternalInit {
            kem_output: vec![33; Hkdf::from(TEST_CIPHER_SUITE.kdf_type()).extract_size()],
        }
    }

    #[test]
    fn receiving_external_init_from_member_fails() {
        let (alice, tree) = new_tree("alice");

        let res = CommitReceiver::new(&tree, alice, alice)
            .receive([Proposal::ExternalInit(make_external_init())]);

        assert_matches!(
            res,
            Err(ProposalCacheError::ProposalFilterError(
                ProposalFilterError::ExternalInitMustBeCommittedByNewMember
            ))
        );
    }

    #[test]
    fn sending_additional_external_init_from_member_fails() {
        let (alice, tree) = new_tree("alice");

        let res = CommitSender::new(&tree, alice)
            .with_additional([Proposal::ExternalInit(make_external_init())])
            .send();

        assert_matches!(
            res,
            Err(ProposalCacheError::ProposalFilterError(
                ProposalFilterError::ExternalInitMustBeCommittedByNewMember
            ))
        );
    }

    #[test]
    fn sending_external_init_from_member_filters_it_out() {
        let (alice, tree) = new_tree("alice");
        let external_init = Proposal::ExternalInit(make_external_init());
        let external_init_ref = make_proposal_ref(&external_init, alice);

        let (committed, effects) = CommitSender::new(&tree, alice)
            .cache(external_init_ref.clone(), external_init.clone(), alice)
            .send()
            .unwrap();

        assert_eq!(committed, Vec::new());
        assert_eq!(
            effects.rejected_proposals,
            vec![(external_init_ref, external_init)]
        );
    }

    #[test]
    fn committing_update_from_pk1_to_pk2_and_update_from_pk2_to_pk3_works() {
        let (alice_leaf, alice_secret, alice_signer) =
            get_basic_test_node_sig_key(TEST_CIPHER_SUITE, "alice");

        let (mut tree, priv_tree) =
            TreeKemPublic::derive(TEST_CIPHER_SUITE, alice_leaf.clone(), alice_secret).unwrap();

        let alice = priv_tree.self_index;

        let bob = add_member(&mut tree, "bob");
        let carol = add_member(&mut tree, "carol");

        let bob_current_leaf = tree.get_leaf_node(bob).unwrap();

        let mut alice_new_leaf = LeafNode {
            public_key: bob_current_leaf.public_key.clone(),
            leaf_node_source: LeafNodeSource::Update,
            ..alice_leaf
        };
        alice_new_leaf
            .sign(&alice_signer, &Some(TEST_GROUP))
            .unwrap();

        let bob_new_leaf = update_leaf_node("bob");

        let pk1_to_pk2 = Proposal::Update(UpdateProposal {
            leaf_node: alice_new_leaf.clone(),
        });

        let pk1_to_pk2_ref = make_proposal_ref(&pk1_to_pk2, alice);

        let pk2_to_pk3 = Proposal::Update(UpdateProposal {
            leaf_node: bob_new_leaf.clone(),
        });

        let pk2_to_pk3_ref = make_proposal_ref(&pk2_to_pk3, bob);

        let effects = CommitReceiver::new(&tree, carol, carol)
            .cache(pk1_to_pk2_ref.clone(), pk1_to_pk2, alice)
            .cache(pk2_to_pk3_ref.clone(), pk2_to_pk3, bob)
            .receive([pk1_to_pk2_ref, pk2_to_pk3_ref])
            .unwrap();

        assert_eq!(
            effects.updates,
            vec![(alice, alice_new_leaf), (bob, bob_new_leaf)]
        );
    }

    #[test]
    fn committing_update_from_pk1_to_pk2_and_removal_of_pk2_works() {
        let (alice_leaf, alice_secret, alice_signer) =
            get_basic_test_node_sig_key(TEST_CIPHER_SUITE, "alice");

        let (mut tree, priv_tree) =
            TreeKemPublic::derive(TEST_CIPHER_SUITE, alice_leaf.clone(), alice_secret).unwrap();

        let alice = priv_tree.self_index;

        let bob = add_member(&mut tree, "bob");
        let carol = add_member(&mut tree, "carol");

        let bob_current_leaf = tree.get_leaf_node(bob).unwrap();

        let mut alice_new_leaf = LeafNode {
            public_key: bob_current_leaf.public_key.clone(),
            leaf_node_source: LeafNodeSource::Update,
            ..alice_leaf
        };
        alice_new_leaf
            .sign(&alice_signer, &Some(TEST_GROUP))
            .unwrap();

        let pk1_to_pk2 = Proposal::Update(UpdateProposal {
            leaf_node: alice_new_leaf.clone(),
        });

        let pk1_to_pk2_ref = make_proposal_ref(&pk1_to_pk2, alice);

        let remove_pk2 = Proposal::Remove(RemoveProposal { to_remove: bob });

        let remove_pk2_ref = make_proposal_ref(&remove_pk2, bob);

        let effects = CommitReceiver::new(&tree, carol, carol)
            .cache(pk1_to_pk2_ref.clone(), pk1_to_pk2, alice)
            .cache(remove_pk2_ref.clone(), remove_pk2, bob)
            .receive([pk1_to_pk2_ref, remove_pk2_ref])
            .unwrap();

        assert_eq!(effects.updates, vec![(alice, alice_new_leaf)]);
        assert_eq!(effects.removes, vec![bob]);
    }
}
