use super::*;
use crate::{
    extension::RequiredCapabilitiesExt,
    group::proposal_filter::{
        AddProposalFilter, ExternalCommitFilter, GroupContextExtensionsProposalFilter,
        ProposalBundle, ProposalFilter, ProposalFilterError, ProposalInfo, PskProposalFilter,
        ReInitProposalFilter, RemoveProposalFilter, SingleProposalForLeaf, UniqueKeysInTree,
        UpdateProposalFilter,
    },
    psk::PreSharedKeyID,
    tree_kem::leaf_node::{LeafNode, LeafNodeError},
};

#[derive(Error, Debug)]
pub enum ProposalCacheError {
    #[error(transparent)]
    LeafNodeError(#[from] LeafNodeError),
    #[error(transparent)]
    TlsSerializationError(#[from] tls_codec::Error),
    #[error(transparent)]
    KdfError(#[from] KdfError),
    #[error(transparent)]
    ProposalFilterError(#[from] ProposalFilterError),
    #[error("Proposal {0:?} not found")]
    ProposalNotFound(ProposalRef),
    #[error("Only members can commit proposals by reference")]
    OnlyMembersCanCommitProposalsByRef,
    #[error("Missing update path in external commit")]
    MissingUpdatePathInExternalCommit,
    #[error(transparent)]
    RatchetTreeError(#[from] RatchetTreeError),
}

#[derive(Debug, Default, PartialEq)]
pub struct ProposalSetEffects {
    pub adds: Vec<KeyPackage>,
    pub updates: Vec<(LeafIndex, LeafNode)>,
    pub removes: Vec<LeafIndex>,
    pub group_context_ext: Option<ExtensionList>,
    pub psks: Vec<PreSharedKeyID>,
    pub reinit: Option<ReInit>,
    pub external_init: Option<(LeafNode, ExternalInit)>,
}

impl ProposalSetEffects {
    pub fn new(
        proposals: ProposalBundle,
        update_path: Option<&UpdatePath>,
    ) -> Result<Self, ProposalCacheError> {
        proposals
            .into_iter()
            .try_fold(ProposalSetEffects::default(), |effects, item| {
                effects.add(item, update_path)
            })
    }

    pub fn is_empty(&self) -> bool {
        self.adds.is_empty()
            && self.updates.is_empty()
            && self.removes.is_empty()
            && self.group_context_ext.is_none()
            && self.psks.is_empty()
            && self.reinit.is_none()
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
    }

    fn add(
        mut self,
        item: ProposalInfo<Proposal>,
        update_path: Option<&UpdatePath>,
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
                let new_member_leaf = update_path
                    .ok_or(ProposalCacheError::MissingUpdatePathInExternalCommit)?
                    .leaf_node
                    .clone();

                self.external_init = Some((new_member_leaf, external_init));
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

    pub fn prepare_commit<C>(
        &self,
        sender_index: LeafIndex,
        additional_proposals: Vec<Proposal>,
        required_capabilities: Option<RequiredCapabilitiesExt>,
        credential_validator: C,
        public_tree: &TreeKemPublic,
    ) -> Result<(Vec<ProposalOrRef>, ProposalSetEffects), ProposalCacheError>
    where
        C: CredentialValidator,
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
                    .map(|p| (p, Sender::Member(sender_index), None)),
            )
            .fold(
                ProposalBundle::default(),
                |mut proposals, (proposal, sender, proposal_ref)| {
                    proposals.add(proposal, sender, proposal_ref);
                    proposals
                },
            );

        let filter = proposal_filter(
            self.protocol_version,
            self.cipher_suite,
            self.group_id.clone(),
            Sender::Member(sender_index),
            required_capabilities,
            &credential_validator,
            public_tree,
            None,
        );

        let proposals = filter.filter(proposals)?;
        let effects = ProposalSetEffects::new(proposals.clone(), None)?;
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

    pub fn resolve_for_commit<C>(
        &self,
        sender: Sender,
        proposal_list: Vec<ProposalOrRef>,
        update_path: Option<&UpdatePath>,
        required_capabilities: Option<RequiredCapabilitiesExt>,
        credential_validator: C,
        public_tree: &TreeKemPublic,
    ) -> Result<ProposalSetEffects, ProposalCacheError>
    where
        C: CredentialValidator,
    {
        let committer_is_member = matches!(sender, Sender::Member(_));

        let proposals = proposal_list.into_iter().try_fold(
            ProposalBundle::default(),
            |mut proposals, proposal| {
                if !committer_is_member && matches!(proposal, ProposalOrRef::Reference(_)) {
                    return Err(ProposalCacheError::OnlyMembersCanCommitProposalsByRef);
                }

                let proposal_ref = match &proposal {
                    ProposalOrRef::Reference(r) => Some(r.clone()),
                    ProposalOrRef::Proposal(_) => None,
                };

                let proposal = self.resolve_item(sender.clone(), proposal)?;
                proposals.add(proposal.proposal, proposal.sender, proposal_ref);
                Ok(proposals)
            },
        )?;

        let filter = proposal_filter(
            self.protocol_version,
            self.cipher_suite,
            self.group_id.clone(),
            sender,
            required_capabilities,
            &credential_validator,
            public_tree,
            update_path,
        );

        filter.validate(&proposals)?;

        ProposalSetEffects::new(proposals, update_path)
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

#[allow(clippy::too_many_arguments)]
fn proposal_filter<'a, C>(
    protocol_version: ProtocolVersion,
    cipher_suite: CipherSuite,
    group_id: Vec<u8>,
    committer: Sender,
    required_capabilities: Option<RequiredCapabilitiesExt>,
    credential_validator: &'a C,
    tree: &'a TreeKemPublic,
    update_path: Option<&'a UpdatePath>,
) -> impl ProposalFilter<Error = ProposalFilterError> + 'a
where
    C: CredentialValidator,
{
    AddProposalFilter::new(
        protocol_version,
        cipher_suite,
        required_capabilities.clone(),
        credential_validator,
        tree,
    )
    .and(UpdateProposalFilter::new(
        committer.clone(),
        group_id.clone(),
        cipher_suite,
        required_capabilities.clone(),
        credential_validator,
        tree,
    ))
    .and(RemoveProposalFilter::new(tree))
    .and(PskProposalFilter::new(cipher_suite))
    .and(ReInitProposalFilter::new(protocol_version))
    .and(GroupContextExtensionsProposalFilter)
    .and(SingleProposalForLeaf)
    .and(ExternalCommitFilter::new(
        cipher_suite,
        group_id,
        committer,
        update_path,
        tree,
        required_capabilities,
        credential_validator,
    ))
    .and(UniqueKeysInTree::new(tree))
}

#[cfg(test)]
mod tests {
    use super::proposal_ref::test_utils::plaintext_from_proposal;
    use super::*;
    use crate::{
        client_config::PassthroughCredentialValidator,
        group::test_utils::{test_group, TEST_GROUP},
        key_package::test_utils::test_key_package,
        tree_kem::{
            leaf_node::test_utils::{get_basic_test_node, get_basic_test_node_sig_key},
            leaf_node_validator::test_utils::FailureCredentialValidator,
            parent_hash::ParentHash,
        },
    };
    use assert_matches::assert_matches;
    use ferriscrypt::kdf::hkdf::Hkdf;

    const TEST_CIPHER_SUITE: CipherSuite = CipherSuite::P256Aes128;
    const TEST_PROTOCOL_VERSION: ProtocolVersion = ProtocolVersion::Mls10;

    #[cfg(target_arch = "wasm32")]
    use wasm_bindgen_test::wasm_bindgen_test as test;

    fn test_sender() -> LeafIndex {
        LeafIndex(1)
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
        let update_package = {
            let (mut leaf, _, signer) = get_basic_test_node_sig_key(cipher_suite, "foo");

            leaf.update(TEST_CIPHER_SUITE, TEST_GROUP, None, None, &signer)
                .unwrap();

            leaf
        };

        let remove_package_leaf = get_basic_test_node(cipher_suite, "baz");

        let remove_package = tree.add_leaves(vec![remove_package_leaf]).unwrap()[0];

        let add = Proposal::Add(AddProposal {
            key_package: add_package.clone(),
        });

        let update = Proposal::Update(UpdateProposal {
            leaf_node: update_package.clone(),
        });

        let remove = Proposal::Remove(RemoveProposal {
            to_remove: remove_package,
        });

        let extensions = Proposal::GroupContextExtensions(ExtensionList::new());

        let proposals = vec![add, update, remove, extensions];
        let effects = ProposalSetEffects {
            adds: vec![add_package],
            updates: vec![(sender, update_package)],
            removes: vec![remove_package],
            group_context_ext: Some(ExtensionList::new()),
            ..ProposalSetEffects::default()
        };

        let plaintext = proposals
            .into_iter()
            .map(|p| plaintext_from_proposal(p, sender))
            .collect();

        TestProposals {
            test_sender: sender,
            test_proposals: plaintext,
            expected_effects: effects,
            tree,
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

    #[test]
    fn test_proposal_cache_commit_all_cached() {
        let TestProposals {
            test_proposals,
            expected_effects,
            tree,
            ..
        } = test_proposals(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE);

        let cache = test_proposal_cache_setup(test_proposals.clone());

        let (proposals, effects) = cache
            .prepare_commit(
                test_sender(),
                vec![],
                None,
                PassthroughCredentialValidator::new(),
                &tree,
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
                test_sender(),
                additional.clone(),
                None,
                PassthroughCredentialValidator::new(),
                &tree,
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
        expected_effects.adds.push(additional_key_package);

        assert_matches(expected_proposals, expected_effects, proposals, effects)
    }

    #[test]
    fn test_proposal_cache_update_filter() {
        let additional_key_package = get_basic_test_node(TEST_CIPHER_SUITE, "foo");

        let TestProposals {
            test_proposals,
            tree,
            ..
        } = test_proposals(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE);

        let additional = vec![Proposal::Update(UpdateProposal {
            leaf_node: additional_key_package.clone(),
        })];

        let commiter_index = test_sender();
        let cache = test_proposal_cache_setup(test_proposals);

        let (proposals, effects) = cache
            .prepare_commit(
                commiter_index,
                additional.clone(),
                None,
                PassthroughCredentialValidator::new(),
                &tree,
            )
            .unwrap();

        assert!(!proposals.contains(&ProposalOrRef::Proposal(additional[0].clone())),);

        assert!(!effects
            .updates
            .contains(&(commiter_index, additional_key_package)))
    }

    #[test]
    fn test_proposal_cache_removal_override_update() {
        let TestProposals {
            test_proposals,
            tree,
            ..
        } = test_proposals(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE);

        let (mut update_leaf, _, signing_key) =
            get_basic_test_node_sig_key(TEST_CIPHER_SUITE, "foo");

        update_leaf
            .update(TEST_CIPHER_SUITE, b"test_group", None, None, &signing_key)
            .unwrap();

        let update = Proposal::Update(UpdateProposal {
            leaf_node: update_leaf,
        });

        let mut cache = test_proposal_cache_setup(test_proposals);

        let update_proposal_ref = ProposalRef::from_plaintext(
            TEST_CIPHER_SUITE,
            &plaintext_from_proposal(update.clone(), LeafIndex(1)),
            false,
        )
        .unwrap();

        cache.insert(
            update_proposal_ref.clone(),
            update,
            Sender::Member(LeafIndex(1)),
        );

        let (proposals, effects) = cache
            .prepare_commit(
                test_sender(),
                vec![],
                None,
                PassthroughCredentialValidator::new(),
                &tree,
            )
            .unwrap();

        assert!(effects.removes.contains(&LeafIndex(1)));
        assert!(!proposals.contains(&ProposalOrRef::Reference(update_proposal_ref)))
    }

    #[test]
    fn test_proposal_cache_filter_duplicates_insert() {
        let TestProposals {
            test_proposals,
            expected_effects,
            tree,
            ..
        } = test_proposals(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE);

        let mut cache = test_proposal_cache_setup(test_proposals.clone());
        cache.extend(filter_proposals(TEST_CIPHER_SUITE, test_proposals.clone()));

        let (proposals, effects) = cache
            .prepare_commit(
                test_sender(),
                vec![],
                None,
                PassthroughCredentialValidator::new(),
                &tree,
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

        let cache: ProposalCache = test_proposal_cache_setup(test_proposals.clone());

        // Updates from different senders will be allowed so we test duplicates for add / remove
        let additional = test_proposals
            .clone()
            .into_iter()
            .filter_map(|plaintext| {
                if let Content::Proposal(proposal) = plaintext.content.content {
                    if !matches!(proposal, Proposal::Update(_)) {
                        Some(proposal)
                    } else {
                        None
                    }
                } else {
                    None
                }
            })
            .collect::<Vec<Proposal>>();

        let (proposals, effects) = cache
            .prepare_commit(
                test_sender(),
                additional,
                None,
                PassthroughCredentialValidator::new(),
                &tree,
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

        let test_proposal_ref = ProposalRef::from_plaintext(
            TEST_CIPHER_SUITE,
            &plaintext_from_proposal(test_proposal.clone(), proposer),
            false,
        )
        .unwrap();

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
            .prepare_commit(test_sender, additional, None, &credential_validator, &tree)
            .unwrap();

        let resolution = cache
            .resolve_for_commit(
                Sender::Member(test_sender),
                proposals,
                None,
                None,
                &credential_validator,
                &tree,
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
        let proposal = Proposal::Psk(PreSharedKey {
            psk: psk_id.clone(),
        });
        let (proposals, effects) = cache
            .prepare_commit(
                test_sender(),
                vec![proposal.clone(), proposal],
                None,
                PassthroughCredentialValidator::new(),
                &TreeKemPublic::new(TEST_CIPHER_SUITE),
            )
            .unwrap();
        assert_eq!(proposals.len(), 1);
        assert_eq!(effects.psks, [psk_id]);
    }

    fn test_update_path() -> UpdatePath {
        let (mut leaf_node, _, signer) = get_basic_test_node_sig_key(TEST_CIPHER_SUITE, "foo");

        leaf_node
            .commit(TEST_CIPHER_SUITE, TEST_GROUP, None, None, &signer, |_| {
                Ok(ParentHash::empty())
            })
            .unwrap();

        UpdatePath {
            leaf_node,
            nodes: Vec::new(),
        }
    }

    #[test]
    fn external_commit_must_have_update_path() {
        let cache = make_proposal_cache();
        let kem_output = vec![0; Hkdf::from(TEST_CIPHER_SUITE.kdf_type()).extract_size()];
        let group = test_group(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE);
        let public_tree = &group.group.current_public_epoch.public_tree;
        let credential_validator = PassthroughCredentialValidator::new();

        let res = cache.resolve_for_commit(
            Sender::NewMember,
            vec![ProposalOrRef::Proposal(Proposal::ExternalInit(
                ExternalInit { kem_output },
            ))],
            None,
            group.required_capabilities(),
            credential_validator,
            public_tree,
        );

        assert_matches!(
            res,
            Err(ProposalCacheError::ProposalFilterError(
                ProposalFilterError::MissingUpdatePathInExternalCommit
            ))
        );
    }

    #[test]
    fn proposal_cache_rejects_proposals_by_ref_for_new_member() {
        let cache = make_proposal_cache();
        let kem_output = vec![0; Hkdf::from(TEST_CIPHER_SUITE.kdf_type()).extract_size()];
        let proposal = ProposalRef::from_plaintext(
            TEST_CIPHER_SUITE,
            &plaintext_from_proposal(
                Proposal::ExternalInit(ExternalInit { kem_output }),
                test_sender(),
            ),
            false,
        )
        .unwrap();
        let group = test_group(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE);
        let public_tree = &group.group.current_public_epoch.public_tree;
        let credential_validator = PassthroughCredentialValidator::new();

        let res = cache.resolve_for_commit(
            Sender::NewMember,
            vec![ProposalOrRef::Reference(proposal)],
            Some(&test_update_path()),
            group.required_capabilities(),
            credential_validator,
            public_tree,
        );
        assert_matches!(
            res,
            Err(ProposalCacheError::OnlyMembersCanCommitProposalsByRef)
        );
    }

    #[test]
    fn proposal_cache_rejects_multiple_external_init_proposals_in_commit() {
        let cache = make_proposal_cache();
        let kem_output = vec![0; Hkdf::from(TEST_CIPHER_SUITE.kdf_type()).extract_size()];
        let group = test_group(TEST_PROTOCOL_VERSION, TEST_CIPHER_SUITE);
        let public_tree = &group.group.current_public_epoch.public_tree;
        let credential_validator = PassthroughCredentialValidator::new();

        let res = cache.resolve_for_commit(
            Sender::NewMember,
            [
                Proposal::ExternalInit(ExternalInit {
                    kem_output: kem_output.clone(),
                }),
                Proposal::ExternalInit(ExternalInit { kem_output }),
            ]
            .into_iter()
            .map(ProposalOrRef::Proposal)
            .collect(),
            Some(&test_update_path()),
            group.required_capabilities(),
            credential_validator,
            public_tree,
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
        let public_tree = &group.group.current_public_epoch.public_tree;
        let credential_validator = PassthroughCredentialValidator::new();

        cache.resolve_for_commit(
            Sender::NewMember,
            [
                Proposal::ExternalInit(ExternalInit { kem_output }),
                proposal,
            ]
            .into_iter()
            .map(ProposalOrRef::Proposal)
            .collect(),
            Some(&test_update_path()),
            group.required_capabilities(),
            credential_validator,
            public_tree,
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
        let mut public_tree = group.group.current_public_epoch.public_tree;
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
            Sender::NewMember,
            proposals.into_iter().map(ProposalOrRef::Proposal).collect(),
            Some(&test_update_path()),
            required_capabilities,
            credential_validator,
            &public_tree,
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
        let mut public_tree = group.group.current_public_epoch.public_tree;
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
            Sender::NewMember,
            proposals.into_iter().map(ProposalOrRef::Proposal).collect(),
            Some(&test_update_path()),
            required_capabilities,
            credential_validator,
            &public_tree,
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
        let mut public_tree = group.group.current_public_epoch.public_tree;
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
            Sender::NewMember,
            proposals.into_iter().map(ProposalOrRef::Proposal).collect(),
            Some(&test_update_path()),
            required_capabilities,
            credential_validator,
            &public_tree,
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
                ProposalFilterError::InvalidProposalTypeForProposer(ProposalType::UPDATE, _)
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
        let public_tree = &group.group.current_public_epoch.public_tree;
        let credential_validator = PassthroughCredentialValidator::new();

        let res = cache.resolve_for_commit(
            Sender::NewMember,
            Vec::new(),
            Some(&test_update_path()),
            group.required_capabilities(),
            credential_validator,
            public_tree,
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
                test_sender(),
                vec![],
                None,
                PassthroughCredentialValidator::new(),
                &TreeKemPublic::new(TEST_CIPHER_SUITE),
            )
            .unwrap();

        assert!(effects.path_update_required())
    }

    #[test]
    fn test_path_update_required_updates() {
        let cache = make_proposal_cache();

        let update = Proposal::Update(UpdateProposal {
            leaf_node: get_basic_test_node(TEST_CIPHER_SUITE, "bar"),
        });

        let (_, effects) = cache
            .prepare_commit(
                test_sender(),
                vec![update],
                None,
                PassthroughCredentialValidator::new(),
                &TreeKemPublic::new(TEST_CIPHER_SUITE),
            )
            .unwrap();

        assert!(effects.path_update_required())
    }

    #[test]
    fn test_path_update_required_removes() {
        let cache = make_proposal_cache();

        let remove = Proposal::Remove(RemoveProposal {
            to_remove: LeafIndex(1),
        });

        let (_, effects) = cache
            .prepare_commit(
                test_sender(),
                vec![remove],
                None,
                PassthroughCredentialValidator::new(),
                &TreeKemPublic::new(TEST_CIPHER_SUITE),
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
                psk_nonce: PskNonce(vec![]),
            },
        });

        let add = Proposal::Add(AddProposal {
            key_package: test_key_package(ProtocolVersion::Mls10, TEST_CIPHER_SUITE),
        });

        let reinit = Proposal::ReInit(ReInit {
            group_id: vec![],
            version: ProtocolVersion::Mls10,
            cipher_suite: TEST_CIPHER_SUITE,
            extensions: Default::default(),
        });

        let (_, effects) = cache
            .prepare_commit(
                test_sender(),
                vec![psk, add, reinit],
                None,
                PassthroughCredentialValidator::new(),
                &TreeKemPublic::new(TEST_CIPHER_SUITE),
            )
            .unwrap();

        assert!(!effects.path_update_required())
    }

    #[test]
    fn external_commit_with_invalid_leaf_node_in_path_is_rejected() {
        let cache = make_proposal_cache();
        let leaf = get_basic_test_node(TEST_CIPHER_SUITE, "foo");

        let external_init = ExternalInit {
            kem_output: vec![0; Hkdf::from(TEST_CIPHER_SUITE.kdf_type()).extract_size()],
        };

        let res = cache.resolve_for_commit(
            Sender::NewMember,
            vec![ProposalOrRef::Proposal(Proposal::ExternalInit(
                external_init,
            ))],
            Some(&UpdatePath {
                // This leaf does not have the right leaf node source, which must cause the commit
                // to be rejected.
                leaf_node: leaf,
                nodes: Vec::new(),
            }),
            None,
            PassthroughCredentialValidator::new(),
            &TreeKemPublic::new(TEST_CIPHER_SUITE),
        );

        assert_matches!(
            res,
            Err(ProposalCacheError::ProposalFilterError(
                ProposalFilterError::LeafNodeValidationError(_)
            ))
        );
    }
}
