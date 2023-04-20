use alloc::vec::Vec;
use itertools::Itertools;

use crate::{
    group::{
        proposal::CustomProposal, AddProposal, BorrowedProposal, PreSharedKeyProposal, Proposal,
        ProposalOrRef, ProposalRef, ProposalType, ReInitProposal, RemoveProposal, Sender,
        UpdateProposal,
    },
    ExtensionList,
};

#[cfg(feature = "external_commit")]
use crate::group::ExternalInit;

use core::marker::PhantomData;

#[derive(Clone, Debug, Default)]
/// A collection of proposals.
pub struct ProposalBundle {
    additions: Vec<ProposalInfo<AddProposal>>,
    updates: Vec<ProposalInfo<UpdateProposal>>,
    removals: Vec<ProposalInfo<RemoveProposal>>,
    psks: Vec<ProposalInfo<PreSharedKeyProposal>>,
    reinitializations: Vec<ProposalInfo<ReInitProposal>>,
    #[cfg(feature = "external_commit")]
    external_initializations: Vec<ProposalInfo<ExternalInit>>,
    group_context_extensions: Vec<ProposalInfo<ExtensionList>>,
    pub(crate) custom_proposals: Vec<ProposalInfo<CustomProposal>>,
}

impl ProposalBundle {
    pub(crate) fn add(&mut self, proposal: Proposal, sender: Sender, source: ProposalSource) {
        match proposal {
            Proposal::Add(proposal) => self.additions.push(ProposalInfo {
                proposal,
                sender,
                source,
            }),
            Proposal::Update(proposal) => self.updates.push(ProposalInfo {
                proposal,
                sender,
                source,
            }),
            Proposal::Remove(proposal) => self.removals.push(ProposalInfo {
                proposal,
                sender,
                source,
            }),
            Proposal::Psk(proposal) => self.psks.push(ProposalInfo {
                proposal,
                sender,
                source,
            }),
            Proposal::ReInit(proposal) => self.reinitializations.push(ProposalInfo {
                proposal,
                sender,
                source,
            }),
            #[cfg(feature = "external_commit")]
            Proposal::ExternalInit(proposal) => self.external_initializations.push(ProposalInfo {
                proposal,
                sender,
                source,
            }),
            Proposal::GroupContextExtensions(proposal) => {
                self.group_context_extensions.push(ProposalInfo {
                    proposal,
                    sender,
                    source,
                })
            }
            Proposal::Custom(proposal) => self.custom_proposals.push(ProposalInfo {
                proposal,
                sender,
                source,
            }),
        }
    }

    pub(crate) fn add_proposal(&mut self, p: ProposalInfo<Proposal>) {
        self.add(p.proposal, p.sender, p.source)
    }

    /// Remove the proposal of type `T` at `index`
    ///
    /// Type `T` can be any of the standard MLS proposal types defined in the
    /// [`proposal`](crate::group::proposal) module.
    ///
    /// `index` is consistent with the index returned by any of the proposal
    /// type specific functions in this module.
    pub fn remove<T: Proposable>(&mut self, index: usize) {
        T::remove(self, index);
    }

    /// Iterate over proposals, filtered by type.
    ///
    /// Type `T` can be any of the standard MLS proposal types defined in the
    /// [`proposal`](crate::group::proposal) module.
    pub fn by_type<'a, T: Proposable + 'a>(&'a self) -> impl Iterator<Item = &'a ProposalInfo<T>> {
        T::filter(self).iter()
    }

    pub(crate) fn by_index<'a, T: Proposable + 'a>(&'a self) -> ProposalBundleIndex<'a, T> {
        ProposalBundleIndex::new(self)
    }

    /// Retain proposals, filtered by type.
    ///
    /// Type `T` can be any of the standard MLS proposal types defined in the
    /// [`proposal`](crate::group::proposal) module.
    pub fn retain_by_type<T, F, E>(&mut self, mut f: F) -> Result<(), E>
    where
        T: Proposable,
        F: FnMut(&ProposalInfo<T>) -> Result<bool, E>,
    {
        let mut res = Ok(());

        T::retain(self, |p| match f(p) {
            Ok(keep) => keep,
            Err(e) => {
                if res.is_ok() {
                    res = Err(e);
                }
                false
            }
        });

        res
    }

    /// Retain custom proposals in the bundle.
    pub fn retain_custom<F, E>(&mut self, mut f: F) -> Result<(), E>
    where
        F: FnMut(&ProposalInfo<CustomProposal>) -> Result<bool, E>,
    {
        let mut res = Ok(());

        self.custom_proposals.retain(|p| match f(p) {
            Ok(keep) => keep,
            Err(e) => {
                if res.is_ok() {
                    res = Err(e);
                }
                false
            }
        });

        res
    }

    /// Retain MLS standard proposals in the bundle.
    pub fn retain<F, E>(&mut self, mut f: F) -> Result<(), E>
    where
        F: FnMut(&ProposalInfo<BorrowedProposal<'_>>) -> Result<bool, E>,
    {
        self.retain_by_type::<AddProposal, _, _>(|proposal| {
            f(&proposal.by_ref().map(BorrowedProposal::from))
        })?;

        self.retain_by_type::<UpdateProposal, _, _>(|proposal| {
            f(&proposal.by_ref().map(BorrowedProposal::from))
        })?;

        self.retain_by_type::<RemoveProposal, _, _>(|proposal| {
            f(&proposal.by_ref().map(BorrowedProposal::from))
        })?;

        self.retain_by_type::<PreSharedKeyProposal, _, _>(|proposal| {
            f(&proposal.by_ref().map(BorrowedProposal::from))
        })?;

        self.retain_by_type::<ReInitProposal, _, _>(|proposal| {
            f(&proposal.by_ref().map(BorrowedProposal::from))
        })?;

        #[cfg(feature = "external_commit")]
        self.retain_by_type::<ExternalInit, _, _>(|proposal| {
            f(&proposal.by_ref().map(BorrowedProposal::from))
        })?;

        self.retain_by_type::<ExtensionList, _, _>(|proposal| {
            f(&proposal.by_ref().map(BorrowedProposal::from))
        })?;

        Ok(())
    }

    /// Iterate over all proposals inside the bundle.
    pub fn iter_proposals(&self) -> impl Iterator<Item = ProposalInfo<BorrowedProposal<'_>>> {
        let res = self
            .additions
            .iter()
            .map(|p| p.by_ref().map(BorrowedProposal::Add))
            .chain(
                self.updates
                    .iter()
                    .map(|p| p.by_ref().map(BorrowedProposal::Update)),
            )
            .chain(
                self.removals
                    .iter()
                    .map(|p| p.by_ref().map(BorrowedProposal::Remove)),
            )
            .chain(
                self.psks
                    .iter()
                    .map(|p| p.by_ref().map(BorrowedProposal::Psk)),
            )
            .chain(
                self.reinitializations
                    .iter()
                    .map(|p| p.by_ref().map(BorrowedProposal::ReInit)),
            );

        #[cfg(feature = "external_commit")]
        let res = res.chain(
            self.external_initializations
                .iter()
                .map(|p| p.by_ref().map(BorrowedProposal::ExternalInit)),
        );

        res.chain(
            self.group_context_extensions
                .iter()
                .map(|p| p.by_ref().map(BorrowedProposal::GroupContextExtensions)),
        )
        .chain(
            self.custom_proposals
                .iter()
                .map(|p| p.by_ref().map(BorrowedProposal::Custom)),
        )
    }

    /// Iterate over proposal in the bundle, consuming the bundle.
    pub fn into_proposals(self) -> impl Iterator<Item = ProposalInfo<Proposal>> {
        let res = self
            .additions
            .into_iter()
            .map(|p| p.map(Proposal::Add))
            .chain(self.updates.into_iter().map(|p| p.map(Proposal::Update)))
            .chain(self.removals.into_iter().map(|p| p.map(Proposal::Remove)))
            .chain(self.psks.into_iter().map(|p| p.map(Proposal::Psk)))
            .chain(
                self.reinitializations
                    .into_iter()
                    .map(|p| p.map(Proposal::ReInit)),
            );

        #[cfg(feature = "external_commit")]
        let res = res.chain(
            self.external_initializations
                .into_iter()
                .map(|p| p.map(Proposal::ExternalInit)),
        );

        res.chain(
            self.group_context_extensions
                .into_iter()
                .map(|p| p.map(Proposal::GroupContextExtensions)),
        )
        .chain(
            self.custom_proposals
                .into_iter()
                .map(|p| p.map(Proposal::Custom)),
        )
    }

    pub(crate) fn into_proposals_or_refs(self) -> impl Iterator<Item = ProposalOrRef> {
        self.into_proposals().filter_map(|p| match p.source {
            ProposalSource::ByValue => Some(ProposalOrRef::Proposal(p.proposal)),
            ProposalSource::ByReference(reference) => Some(ProposalOrRef::Reference(reference)),
            _ => None,
        })
    }

    /// Add proposals in the bundle.
    pub fn add_proposals(&self) -> &[ProposalInfo<AddProposal>] {
        &self.additions
    }

    /// Update proposals in the bundle.
    pub fn update_proposals(&self) -> &[ProposalInfo<UpdateProposal>] {
        &self.updates
    }

    /// Remove proposals in the bundle.
    pub fn remove_proposals(&self) -> &[ProposalInfo<RemoveProposal>] {
        &self.removals
    }

    /// Pre-shared key proposals in the bundle.
    pub fn psk_proposals(&self) -> &[ProposalInfo<PreSharedKeyProposal>] {
        &self.psks
    }

    /// Reinit proposals in the bundle.
    pub fn reinit_proposals(&self) -> &[ProposalInfo<ReInitProposal>] {
        &self.reinitializations
    }

    /// External init proposals in the bundle.
    #[cfg(feature = "external_commit")]
    pub fn external_init_proposals(&self) -> &[ProposalInfo<ExternalInit>] {
        &self.external_initializations
    }

    /// Group context extension proposals in the bundle.
    pub fn group_context_ext_proposals(&self) -> &[ProposalInfo<ExtensionList>] {
        &self.group_context_extensions
    }

    /// Custom proposals in the bundle.
    pub fn custom_proposals(&self) -> &[ProposalInfo<CustomProposal>] {
        &self.custom_proposals
    }

    pub(crate) fn group_context_extensions_proposal(&self) -> Option<&ProposalInfo<ExtensionList>> {
        self.group_context_extensions.first()
    }

    pub(crate) fn clear_group_context_extensions(&mut self) {
        self.group_context_extensions.clear();
    }

    /// Custom proposal types that are in use within this bundle.
    pub fn custom_proposal_types(&self) -> impl Iterator<Item = ProposalType> + '_ {
        #[cfg(feature = "std")]
        let res = self
            .custom_proposals
            .iter()
            .map(|v| v.proposal.proposal_type())
            .unique();

        #[cfg(not(feature = "std"))]
        let res = self
            .custom_proposals
            .iter()
            .map(|v| v.proposal.proposal_type())
            .collect::<alloc::collections::BTreeSet<_>>()
            .into_iter();

        res
    }

    /// Standard proposal types that are in use within this bundle.
    pub fn proposal_types(&self) -> impl Iterator<Item = ProposalType> + '_ {
        let res = (!self.additions.is_empty())
            .then_some(ProposalType::ADD)
            .into_iter()
            .chain((!self.updates.is_empty()).then_some(ProposalType::UPDATE))
            .chain((!self.removals.is_empty()).then_some(ProposalType::REMOVE))
            .chain((!self.psks.is_empty()).then_some(ProposalType::PSK))
            .chain((!self.reinitializations.is_empty()).then_some(ProposalType::RE_INIT));

        #[cfg(feature = "external_commit")]
        let res = res.chain(
            (!self.external_initializations.is_empty()).then_some(ProposalType::EXTERNAL_INIT),
        );

        res.chain(
            (!self.group_context_extensions.is_empty())
                .then_some(ProposalType::GROUP_CONTEXT_EXTENSIONS),
        )
        .chain(self.custom_proposal_types())
    }
}

impl FromIterator<ProposalInfo<Proposal>> for ProposalBundle {
    fn from_iter<T>(iter: T) -> Self
    where
        T: IntoIterator<Item = ProposalInfo<Proposal>>,
    {
        iter.into_iter()
            .fold(ProposalBundle::default(), |mut bundle, p| {
                bundle.add_proposal(p);
                bundle
            })
    }
}

impl Extend<ProposalInfo<Proposal>> for ProposalBundle {
    fn extend<T>(&mut self, iter: T)
    where
        T: IntoIterator<Item = ProposalInfo<Proposal>>,
    {
        iter.into_iter().for_each(|p| self.add_proposal(p));
    }
}

#[derive(Debug)]
pub struct ProposalBundleIndex<'a, T> {
    proposals: &'a ProposalBundle,
    marker: PhantomData<&'a T>,
}

impl<'a, T> ProposalBundleIndex<'a, T> {
    fn new(proposals: &'a ProposalBundle) -> Self {
        Self {
            proposals,
            marker: PhantomData,
        }
    }
}

impl<T: Proposable> core::ops::Index<usize> for ProposalBundleIndex<'_, T> {
    type Output = ProposalInfo<T>;

    fn index(&self, index: usize) -> &Self::Output {
        &T::filter(self.proposals)[index]
    }
}

#[derive(Clone, Debug)]
pub enum ProposalSource {
    ByValue,
    ByReference(ProposalRef),
    /// True if originally by value.
    CustomRule(bool),
}

#[derive(Clone, Debug)]
/// Proposal description used as input to a
/// [`ProposalRules`](crate::ProposalRules).
pub struct ProposalInfo<T> {
    pub(crate) proposal: T,
    pub(crate) sender: Sender,
    pub(crate) source: ProposalSource,
}

impl ProposalInfo<CustomProposal> {
    /// Expand this proposal to multiple proposals.
    ///
    /// The resulting Vec of ProposalInfo values will have the same sender as
    /// the original and will be specifically flagged as being generated by
    /// a custom rule. This function is useful when implementing custom
    /// [`ProposalRules`].
    pub fn expand(&self, expanded: Vec<Proposal>) -> Vec<ProposalInfo<Proposal>> {
        expanded
            .into_iter()
            .map(|p| ProposalInfo {
                proposal: p,
                sender: self.sender,
                source: match self.source {
                    ProposalSource::ByValue => ProposalSource::CustomRule(true),
                    ProposalSource::ByReference(_) => ProposalSource::CustomRule(false),
                    ProposalSource::CustomRule(value) => ProposalSource::CustomRule(value),
                },
            })
            .collect_vec()
    }
}

impl ProposalInfo<Proposal> {
    /// Create a new ProposalInfo.
    ///
    /// The resulting value will be specifically flagged as being generated by
    /// a custom rule either by-value or by-reference depending on the value of
    /// `by_value`. This function is useful when implementing custom
    /// [`ProposalRules`].
    pub fn new(proposal: Proposal, sender: Sender, by_value: bool) -> ProposalInfo<Proposal> {
        ProposalInfo {
            proposal,
            sender,
            source: ProposalSource::CustomRule(by_value),
        }
    }
}

impl<T> ProposalInfo<T> {
    pub(crate) fn map<U, F>(self, f: F) -> ProposalInfo<U>
    where
        F: FnOnce(T) -> U,
    {
        ProposalInfo {
            proposal: f(self.proposal),
            sender: self.sender,
            source: self.source,
        }
    }

    pub(crate) fn by_ref(&self) -> ProposalInfo<&T> {
        ProposalInfo {
            proposal: &self.proposal,
            sender: self.sender,
            source: self.source.clone(),
        }
    }

    #[inline(always)]
    pub fn is_by_value(&self) -> bool {
        match self.source {
            ProposalSource::ByValue => true,
            ProposalSource::ByReference(_) => false,
            ProposalSource::CustomRule(by_value) => by_value,
        }
    }

    #[inline(always)]
    pub fn is_by_reference(&self) -> bool {
        !self.is_by_value()
    }

    /// The sender of this proposal.
    pub fn sender(&self) -> Sender {
        self.sender
    }

    /// The underlying proposal value.
    pub fn proposal(&self) -> &T {
        &self.proposal
    }
}

pub trait Proposable: Sized {
    const TYPE: ProposalType;

    fn filter(bundle: &ProposalBundle) -> &[ProposalInfo<Self>];
    fn remove(bundle: &mut ProposalBundle, index: usize);
    fn retain<F>(bundle: &mut ProposalBundle, keep: F)
    where
        F: FnMut(&ProposalInfo<Self>) -> bool;
}

macro_rules! impl_proposable {
    ($ty:ty, $proposal_type:ident, $field:ident) => {
        impl Proposable for $ty {
            const TYPE: ProposalType = ProposalType::$proposal_type;

            fn filter(bundle: &ProposalBundle) -> &[ProposalInfo<Self>] {
                &bundle.$field
            }

            fn remove(bundle: &mut ProposalBundle, index: usize) {
                if index < bundle.$field.len() {
                    bundle.$field.remove(index);
                }
            }

            fn retain<F>(bundle: &mut ProposalBundle, keep: F)
            where
                F: FnMut(&ProposalInfo<Self>) -> bool,
            {
                bundle.$field.retain(keep);
            }
        }
    };
}

impl_proposable!(AddProposal, ADD, additions);
impl_proposable!(UpdateProposal, UPDATE, updates);
impl_proposable!(RemoveProposal, REMOVE, removals);
impl_proposable!(PreSharedKeyProposal, PSK, psks);
impl_proposable!(ReInitProposal, RE_INIT, reinitializations);
#[cfg(feature = "external_commit")]
impl_proposable!(ExternalInit, EXTERNAL_INIT, external_initializations);
impl_proposable!(
    ExtensionList,
    GROUP_CONTEXT_EXTENSIONS,
    group_context_extensions
);
