use super::*;
use crate::psk::PreSharedKeyID;
use std::collections::HashSet;

#[derive(Error, Debug)]
pub enum ProposalCacheError {
    #[error(transparent)]
    KeyPackageError(#[from] KeyPackageError),
    #[error(transparent)]
    TlsSerializationError(#[from] tls_codec::Error),
    #[error(transparent)]
    KdfError(#[from] KdfError),
    #[error("Proposal {0:?} not found")]
    ProposalNotFound(ProposalRef),
    #[error("Commits only allowed from members")]
    NonMemberCommit,
    #[error("Plaintext must be a proposal")]
    PlaintextNotProposal,
}

#[derive(Debug, Default, PartialEq)]
pub struct ProposalSetEffects {
    pub adds: Vec<KeyPackage>,
    pub updates: Vec<(KeyPackageRef, KeyPackage)>,
    pub removes: Vec<KeyPackageRef>,
    pub group_context_ext: Option<ExtensionList>,
    pub psks: Vec<PreSharedKeyID>,
}

impl ProposalSetEffects {
    pub fn is_empty(&self) -> bool {
        self.adds.is_empty()
            && self.updates.is_empty()
            && self.removes.is_empty()
            && self.group_context_ext.is_none()
            && self.psks.is_empty()
    }
}

#[derive(Debug, Clone, TlsSerialize, TlsSize, TlsDeserialize, PartialEq)]
pub struct CachedProposal {
    proposal: Proposal,
    sender: Sender,
}

#[derive(Clone)]
struct ProposalSetItem {
    proposal: CachedProposal,
    proposal_ref: Option<ProposalRef>,
}

impl From<CachedProposal> for ProposalSetItem {
    fn from(cp: CachedProposal) -> Self {
        ProposalSetItem {
            proposal: cp,
            proposal_ref: None,
        }
    }
}

impl From<ProposalSetItem> for ProposalOrRef {
    fn from(item: ProposalSetItem) -> Self {
        if let Some(item_ref) = item.proposal_ref {
            ProposalOrRef::Reference(item_ref)
        } else {
            ProposalOrRef::Proposal(item.proposal.proposal)
        }
    }
}

#[derive(Clone, Default)]
struct ProposalSet {
    leaf_ops: HashMap<KeyPackageRef, usize>,
    removes: HashMap<KeyPackageRef, usize>,
    items: Vec<Option<ProposalSetItem>>,
    group_context_ext: Option<usize>,
    seen_psk_ids: HashSet<PreSharedKeyID>,
}

impl ProposalSet {
    pub fn new() -> Self {
        Default::default()
    }

    fn leaf_ops_insert(&mut self, reference: KeyPackageRef) -> bool {
        if self.removes.contains_key(&reference) {
            return false;
        }

        if let Some(dupe_index) = self.leaf_ops.insert(reference, self.items.len()) {
            self.items[dupe_index] = None;
        }

        true
    }

    fn push_add(&mut self, add: &AddProposal) -> Result<bool, ProposalCacheError> {
        let reference = add.key_package.to_reference()?;
        Ok(self.leaf_ops_insert(reference))
    }

    fn push_update(&mut self, local_key_package: &KeyPackageRef, sender: Sender) -> bool {
        if let Sender::Member(sender) = sender {
            // Do not allow someone to commit to an update for themselves
            if &sender == local_key_package {
                false
            } else {
                self.leaf_ops_insert(sender)
            }
        } else {
            false
        }
    }

    fn push_remove(&mut self, remove: &RemoveProposal) -> bool {
        if let Some(removed_index) = self.leaf_ops.get(&remove.to_remove) {
            self.items[*removed_index] = None;
        }

        if let Some(dupe_remove) = self
            .removes
            .insert(remove.to_remove.clone(), self.items.len())
        {
            self.items[dupe_remove] = None;
        }

        true
    }

    fn push_group_context_ext(&mut self) -> bool {
        if let Some(removed_index) = self.group_context_ext {
            self.items[removed_index] = None;
        }

        self.group_context_ext = Some(self.items.len());

        true
    }

    fn push_psk(&mut self, psk_id: &PreSharedKeyID) -> bool {
        self.seen_psk_ids.insert(psk_id.clone())
    }

    fn push_item(
        &mut self,
        local_key_package: &KeyPackageRef,
        item: ProposalSetItem,
    ) -> Result<(), ProposalCacheError> {
        let should_push = match &item.proposal.proposal {
            Proposal::Add(add) => self.push_add(add)?,
            Proposal::Update(_) => {
                self.push_update(local_key_package, item.proposal.sender.clone())
            }
            Proposal::Remove(remove) => self.push_remove(remove),
            Proposal::GroupContextExtensions(_) => self.push_group_context_ext(),
            Proposal::Psk(PreSharedKey { psk }) => self.push_psk(psk),
        };

        if should_push {
            self.items.push(Some(item));
        }

        Ok(())
    }

    pub fn push_items(
        &mut self,
        local_key_package: &KeyPackageRef,
        items: Vec<ProposalSetItem>,
    ) -> Result<(), ProposalCacheError> {
        items
            .into_iter()
            .try_for_each(|item| self.push_item(local_key_package, item))
    }

    pub fn into_effects(mut self) -> ProposalSetEffects {
        self.items
            .drain(..)
            .flatten()
            .fold(ProposalSetEffects::default(), |mut effects, item| {
                match item.proposal.proposal {
                    Proposal::Add(add) => effects.adds.push(add.key_package),
                    Proposal::Update(update) => {
                        if let Sender::Member(package_to_replace) = item.proposal.sender {
                            effects
                                .updates
                                .push((package_to_replace, update.key_package))
                        }
                    }
                    Proposal::Remove(remove) => effects.removes.push(remove.to_remove),
                    Proposal::GroupContextExtensions(list) => {
                        effects.group_context_ext = Some(list)
                    }
                    Proposal::Psk(PreSharedKey { psk }) => {
                        effects.psks.push(psk);
                    }
                };
                effects
            })
    }

    pub fn into_proposals(mut self) -> Vec<ProposalOrRef> {
        self.items
            .drain(..)
            .flatten()
            .map(ProposalOrRef::from)
            .collect()
    }
}

#[derive(Clone, Debug, TlsSize, TlsSerialize, TlsDeserialize, PartialEq)]
pub(crate) struct ProposalCache(
    #[tls_codec(with = "crate::tls::DefMap")] HashMap<ProposalRef, CachedProposal>,
);

impl ProposalCache {
    pub fn new() -> Self {
        Self(HashMap::new())
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn insert(
        &mut self,
        cipher_suite: CipherSuite,
        proposal_plaintext: &MLSPlaintext,
    ) -> Result<Option<CachedProposal>, ProposalCacheError> {
        if let Content::Proposal(proposal) = &proposal_plaintext.content {
            let proposal_ref = ProposalRef::from_plaintext(cipher_suite, proposal_plaintext)?;

            let cached_proposal = CachedProposal {
                proposal: proposal.clone(),
                sender: proposal_plaintext.sender.clone(),
            };

            Ok(self.0.insert(proposal_ref, cached_proposal))
        } else {
            Err(ProposalCacheError::PlaintextNotProposal)
        }
    }

    pub fn prepare_commit(
        &self,
        local_key_package: &KeyPackageRef,
        additional_proposals: Vec<Proposal>,
    ) -> Result<(Vec<ProposalOrRef>, ProposalSetEffects), ProposalCacheError> {
        let received_proposals =
            self.0
                .clone()
                .into_iter()
                .map(|(proposal_ref, cached)| ProposalSetItem {
                    proposal: cached,
                    proposal_ref: Some(proposal_ref),
                });

        let new_proposals = additional_proposals
            .into_iter()
            .map(|proposal| ProposalSetItem {
                proposal: CachedProposal {
                    sender: Sender::Member(local_key_package.clone()),
                    proposal,
                },
                proposal_ref: None,
            });

        let mut proposal_set = ProposalSet::new();
        proposal_set.push_items(local_key_package, received_proposals.collect())?;
        proposal_set.push_items(local_key_package, new_proposals.collect())?;

        // We have to clone the set because we are potentially returning the same data in both sets
        let effects = proposal_set.clone().into_effects();
        let proposals = proposal_set.into_proposals();

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
                .0
                .get(&proposal_ref)
                .cloned()
                .ok_or(ProposalCacheError::ProposalNotFound(proposal_ref)),
        }
    }

    pub fn resolve_for_commit(
        &self,
        sender: Sender,
        proposal_list: Vec<ProposalOrRef>,
    ) -> Result<ProposalSetEffects, ProposalCacheError> {
        if let Sender::Member(local_key_package) = &sender {
            let items = proposal_list
                .into_iter()
                .map(|proposal_or_ref| {
                    self.resolve_item(sender.clone(), proposal_or_ref)
                        .map(ProposalSetItem::from)
                })
                .collect::<Result<_, ProposalCacheError>>()?;

            let mut proposal_set = ProposalSet::new();
            proposal_set.push_items(local_key_package, items)?;

            Ok(proposal_set.into_effects())
        } else {
            Err(ProposalCacheError::NonMemberCommit)
        }
    }
}

#[cfg(test)]
mod test {
    use super::proposal_ref::test_util::plaintext_from_proposal;
    use super::*;
    use crate::key_package::test_util::test_key_package;
    use ferriscrypt::kdf::hkdf::Hkdf;

    fn test_ref() -> KeyPackageRef {
        let mut buffer = [0u8; 16];
        SecureRng::fill(&mut buffer).unwrap();
        KeyPackageRef::from(buffer)
    }

    fn test_proposals(
        sender: KeyPackageRef,
        cipher_suite: CipherSuite,
    ) -> (Vec<MLSPlaintext>, ProposalSetEffects) {
        let add_package = test_key_package(cipher_suite);
        let update_package = test_key_package(cipher_suite);
        let remove_package = test_ref();

        let add = Proposal::Add(AddProposal {
            key_package: add_package.clone(),
        });

        let update = Proposal::Update(UpdateProposal {
            key_package: update_package.clone(),
        });

        let remove = Proposal::Remove(RemoveProposal {
            to_remove: remove_package.clone(),
        });

        let extensions = Proposal::GroupContextExtensions(ExtensionList::new());

        let proposals = vec![add, update, remove, extensions];
        let effects = ProposalSetEffects {
            adds: vec![add_package],
            updates: vec![(sender.clone(), update_package)],
            removes: vec![remove_package],
            group_context_ext: Some(ExtensionList::new()),
            ..ProposalSetEffects::default()
        };

        let plaintext = proposals
            .into_iter()
            .map(|p| plaintext_from_proposal(p, sender.clone()))
            .collect();

        (plaintext, effects)
    }

    fn test_proposal_cache_setup(
        cipher_suite: CipherSuite,
        test_proposals: Vec<MLSPlaintext>,
    ) -> ProposalCache {
        let mut cache = ProposalCache::new();

        test_proposals.into_iter().for_each(|p| {
            let res = cache.insert(cipher_suite, &p).unwrap();
            assert_eq!(res, None);
        });

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
        let cipher_suite = CipherSuite::P256Aes128V1;
        let test_sender = test_ref();
        let (test_proposals, expected_effects) = test_proposals(test_sender, cipher_suite);

        let cache = test_proposal_cache_setup(cipher_suite, test_proposals.clone());

        let (proposals, effects) = cache.prepare_commit(&test_ref(), vec![]).unwrap();

        let expected_proposals = test_proposals
            .into_iter()
            .map(|p| {
                ProposalOrRef::Reference(ProposalRef::from_plaintext(cipher_suite, &p).unwrap())
            })
            .collect();

        assert_matches(expected_proposals, expected_effects, proposals, effects)
    }

    #[test]
    fn test_proposal_cache_commit_additional() {
        let cipher_suite = CipherSuite::P256Aes128V1;
        let test_sender = test_ref();

        let (test_proposals, mut expected_effects) = test_proposals(test_sender, cipher_suite);

        let additional_key_package = test_key_package(cipher_suite);

        let additional = vec![Proposal::Add(AddProposal {
            key_package: additional_key_package.clone(),
        })];

        let cache = test_proposal_cache_setup(cipher_suite, test_proposals.clone());

        let (proposals, effects) = cache
            .prepare_commit(&test_ref(), additional.clone())
            .unwrap();

        let mut expected_proposals = test_proposals
            .into_iter()
            .map(|p| {
                ProposalOrRef::Reference(ProposalRef::from_plaintext(cipher_suite, &p).unwrap())
            })
            .collect::<Vec<ProposalOrRef>>();

        expected_proposals.push(ProposalOrRef::Proposal(additional[0].clone()));
        expected_effects.adds.push(additional_key_package);

        assert_matches(expected_proposals, expected_effects, proposals, effects)
    }

    #[test]
    fn test_proposal_cache_update_filter() {
        let cipher_suite = CipherSuite::P256Aes128V1;
        let additional_key_package = test_key_package(cipher_suite);
        let test_sender = test_ref();
        let (test_proposals, _) = test_proposals(test_sender, cipher_suite);

        let additional = vec![Proposal::Update(UpdateProposal {
            key_package: additional_key_package.clone(),
        })];

        let commiter_ref = test_ref();
        let cache = test_proposal_cache_setup(cipher_suite, test_proposals);

        let (proposals, effects) = cache
            .prepare_commit(&commiter_ref, additional.clone())
            .unwrap();

        assert!(!proposals.contains(&ProposalOrRef::Proposal(additional[0].clone())),);

        assert!(!effects
            .updates
            .contains(&(commiter_ref, additional_key_package)))
    }

    #[test]
    fn test_proposal_cache_removal_override_update() {
        let cipher_suite = CipherSuite::P256Aes128V1;
        let test_sender = test_ref();
        let (test_proposals, _) = test_proposals(test_sender.clone(), cipher_suite);

        let removal = Proposal::Remove(RemoveProposal {
            to_remove: test_sender.clone(),
        });

        let cache = test_proposal_cache_setup(cipher_suite, test_proposals.clone());

        let (proposals, effects) = cache.prepare_commit(&test_ref(), vec![removal]).unwrap();

        assert!(effects.removes.contains(&test_sender));

        assert!(!proposals.contains(&ProposalOrRef::Reference(
            ProposalRef::from_plaintext(cipher_suite, &test_proposals[1]).unwrap()
        )))
    }

    #[test]
    fn test_proposal_cache_filter_duplicates_insert() {
        let cipher_suite = CipherSuite::P256Aes128V1;
        let test_sender = test_ref();
        let (test_proposals, expected_effects) = test_proposals(test_sender, cipher_suite);

        let mut cache: ProposalCache =
            test_proposal_cache_setup(cipher_suite, test_proposals.clone());

        test_proposals.clone().into_iter().for_each(|p| {
            cache.insert(cipher_suite, &p).unwrap();
        });

        let (proposals, effects) = cache.prepare_commit(&test_ref(), vec![]).unwrap();

        let expected_proposals = test_proposals
            .into_iter()
            .map(|p| {
                ProposalOrRef::Reference(ProposalRef::from_plaintext(cipher_suite, &p).unwrap())
            })
            .collect::<Vec<ProposalOrRef>>();

        assert_matches(expected_proposals, expected_effects, proposals, effects)
    }

    #[test]
    fn test_proposal_cache_filter_duplicates_additional() {
        let cipher_suite = CipherSuite::P256Aes128V1;
        let test_sender = test_ref();
        let (test_proposals, expected_effects) = test_proposals(test_sender, cipher_suite);

        let cache: ProposalCache = test_proposal_cache_setup(cipher_suite, test_proposals.clone());

        // Updates from different senders will be allowed so we test duplicates for add / remove
        let additional = test_proposals
            .clone()
            .into_iter()
            .filter_map(|plaintext| {
                if let Content::Proposal(proposal) = plaintext.content {
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
            .prepare_commit(&test_ref(), additional.clone())
            .unwrap();

        let mut expected_proposals = vec![ProposalOrRef::Reference(
            ProposalRef::from_plaintext(cipher_suite, &test_proposals[1]).unwrap(),
        )];

        additional
            .into_iter()
            .for_each(|p| expected_proposals.push(ProposalOrRef::Proposal(p)));

        assert_matches(expected_proposals, expected_effects, proposals, effects)
    }

    #[test]
    fn test_proposal_cache_is_empty() {
        let mut cache = ProposalCache::new();
        assert!(cache.is_empty());

        let test_proposal = Proposal::Remove(RemoveProposal {
            to_remove: test_ref(),
        });

        cache
            .insert(
                CipherSuite::P256Aes128V1,
                &plaintext_from_proposal(test_proposal, test_ref()),
            )
            .unwrap();

        assert!(!cache.is_empty())
    }

    #[test]
    fn test_proposal_cache_resolve() {
        let cipher_suite = CipherSuite::P256Aes128V1;
        let test_sender = test_ref();
        let (test_proposals, _) = test_proposals(test_sender.clone(), cipher_suite);

        let cache = test_proposal_cache_setup(cipher_suite, test_proposals);

        let additional = vec![Proposal::Add(AddProposal {
            key_package: test_key_package(cipher_suite),
        })];

        let (proposals, effects) = cache.prepare_commit(&test_sender, additional).unwrap();

        let resolution = cache
            .resolve_for_commit(Sender::Member(test_sender), proposals)
            .unwrap();

        assert_eq!(effects, resolution);
    }

    #[test]
    fn proposal_cache_filters_duplicate_psk_ids() {
        let cipher_suite = CipherSuite::P256Aes128V1;
        let cache = ProposalCache::new();
        let len = Hkdf::from(cipher_suite.kdf_type()).extract_size();
        let psk_id = PreSharedKeyID {
            key_id: JustPreSharedKeyID::External(ExternalPskId(vec![1; len])),
            psk_nonce: PskNonce::random(cipher_suite).unwrap(),
        };
        let proposal = Proposal::Psk(PreSharedKey {
            psk: psk_id.clone(),
        });
        let (proposals, effects) = cache
            .prepare_commit(
                &test_key_package(cipher_suite).to_reference().unwrap(),
                vec![proposal.clone(), proposal],
            )
            .unwrap();
        assert_eq!(proposals.len(), 1);
        assert_eq!(effects.psks, [psk_id]);
    }
}
