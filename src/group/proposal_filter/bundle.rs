use crate::{
    extension::{ExtensionList, GroupContextExtension},
    group::{
        AddProposal, BorrowedProposal, ExternalInit, PreSharedKey, Proposal, ProposalOrRef,
        ProposalRef, ProposalType, ReInit, RemoveProposal, Sender, UpdateProposal,
    },
};
use std::marker::PhantomData;

#[derive(Clone, Debug, Default)]
pub struct ProposalBundle {
    additions: Vec<ProposalInfo<AddProposal>>,
    updates: Vec<ProposalInfo<UpdateProposal>>,
    removals: Vec<ProposalInfo<RemoveProposal>>,
    psks: Vec<ProposalInfo<PreSharedKey>>,
    reinitializations: Vec<ProposalInfo<ReInit>>,
    external_initializations: Vec<ProposalInfo<ExternalInit>>,
    group_context_extensions: Vec<ProposalInfo<ExtensionList<GroupContextExtension>>>,
}

impl ProposalBundle {
    pub fn add(&mut self, proposal: Proposal, sender: Sender, proposal_ref: Option<ProposalRef>) {
        match proposal {
            Proposal::Add(proposal) => self.additions.push(ProposalInfo {
                proposal,
                sender,
                proposal_ref,
            }),
            Proposal::Update(proposal) => self.updates.push(ProposalInfo {
                proposal,
                sender,
                proposal_ref,
            }),
            Proposal::Remove(proposal) => self.removals.push(ProposalInfo {
                proposal,
                sender,
                proposal_ref,
            }),
            Proposal::Psk(proposal) => self.psks.push(ProposalInfo {
                proposal,
                sender,
                proposal_ref,
            }),
            Proposal::ReInit(proposal) => self.reinitializations.push(ProposalInfo {
                proposal,
                sender,
                proposal_ref,
            }),
            Proposal::ExternalInit(proposal) => self.external_initializations.push(ProposalInfo {
                proposal,
                sender,
                proposal_ref,
            }),
            Proposal::GroupContextExtensions(proposal) => {
                self.group_context_extensions.push(ProposalInfo {
                    proposal,
                    sender,
                    proposal_ref,
                })
            }
        }
    }

    pub fn add_proposal(&mut self, p: ProposalInfo<Proposal>) {
        self.add(p.proposal, p.sender, p.proposal_ref)
    }

    pub fn by_type<'a, T: Proposable + 'a>(&'a self) -> impl Iterator<Item = &'a ProposalInfo<T>> {
        T::filter(self).iter()
    }

    pub fn by_index<'a, T: Proposable + 'a>(&'a self) -> ProposalBundleIndex<'a, T> {
        ProposalBundleIndex::new(self)
    }

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

    pub fn iter_proposals(&self) -> impl Iterator<Item = ProposalInfo<BorrowedProposal<'_>>> {
        self.additions
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
            )
            .chain(
                self.external_initializations
                    .iter()
                    .map(|p| p.by_ref().map(BorrowedProposal::ExternalInit)),
            )
            .chain(
                self.group_context_extensions
                    .iter()
                    .map(|p| p.by_ref().map(BorrowedProposal::GroupContextExtensions)),
            )
    }

    pub fn into_proposals(self) -> impl Iterator<Item = ProposalInfo<Proposal>> {
        self.additions
            .into_iter()
            .map(|p| p.map(Proposal::Add))
            .chain(self.updates.into_iter().map(|p| p.map(Proposal::Update)))
            .chain(self.removals.into_iter().map(|p| p.map(Proposal::Remove)))
            .chain(self.psks.into_iter().map(|p| p.map(Proposal::Psk)))
            .chain(
                self.reinitializations
                    .into_iter()
                    .map(|p| p.map(Proposal::ReInit)),
            )
            .chain(
                self.external_initializations
                    .into_iter()
                    .map(|p| p.map(Proposal::ExternalInit)),
            )
            .chain(
                self.group_context_extensions
                    .into_iter()
                    .map(|p| p.map(Proposal::GroupContextExtensions)),
            )
    }

    pub(crate) fn into_proposals_or_refs(self) -> impl Iterator<Item = ProposalOrRef> {
        self.into_proposals().map(|p| {
            p.proposal_ref.map_or_else(
                || ProposalOrRef::Proposal(p.proposal),
                ProposalOrRef::Reference,
            )
        })
    }

    pub fn group_context_extensions_proposal(
        &self,
    ) -> Option<&ProposalInfo<ExtensionList<GroupContextExtension>>> {
        self.group_context_extensions.first()
    }

    pub fn clear_group_context_extensions(&mut self) {
        self.group_context_extensions.clear();
    }

    pub fn proposal_types(&self) -> impl Iterator<Item = ProposalType> + '_ {
        (!self.additions.is_empty())
            .then(|| ProposalType::ADD)
            .into_iter()
            .chain((!self.updates.is_empty()).then(|| ProposalType::UPDATE))
            .chain((!self.removals.is_empty()).then(|| ProposalType::REMOVE))
            .chain((!self.psks.is_empty()).then(|| ProposalType::PSK))
            .chain((!self.reinitializations.is_empty()).then(|| ProposalType::RE_INIT))
            .chain((!self.external_initializations.is_empty()).then(|| ProposalType::EXTERNAL_INIT))
            .chain(
                (!self.group_context_extensions.is_empty())
                    .then(|| ProposalType::GROUP_CONTEXT_EXTENSIONS),
            )
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

impl<T: Proposable> std::ops::Index<usize> for ProposalBundleIndex<'_, T> {
    type Output = ProposalInfo<T>;

    fn index(&self, index: usize) -> &Self::Output {
        &T::filter(self.proposals)[index]
    }
}

#[derive(Clone, Debug)]
pub struct ProposalInfo<T> {
    pub proposal: T,
    pub sender: Sender,
    pub proposal_ref: Option<ProposalRef>,
}

impl<T> ProposalInfo<T> {
    pub fn map<U, F>(self, f: F) -> ProposalInfo<U>
    where
        F: FnOnce(T) -> U,
    {
        ProposalInfo {
            proposal: f(self.proposal),
            sender: self.sender,
            proposal_ref: self.proposal_ref,
        }
    }

    pub fn by_ref(&self) -> ProposalInfo<&T> {
        ProposalInfo {
            proposal: &self.proposal,
            sender: self.sender.clone(),
            proposal_ref: self.proposal_ref.clone(),
        }
    }
}

pub trait Proposable: Sized {
    const TYPE: ProposalType;

    fn filter(bundle: &ProposalBundle) -> &[ProposalInfo<Self>];
    fn retain<F>(bundle: &mut ProposalBundle, f: F)
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

            fn retain<F>(bundle: &mut ProposalBundle, f: F)
            where
                F: FnMut(&ProposalInfo<Self>) -> bool,
            {
                bundle.$field.retain(f)
            }
        }
    };
}

impl_proposable!(AddProposal, ADD, additions);
impl_proposable!(UpdateProposal, UPDATE, updates);
impl_proposable!(RemoveProposal, REMOVE, removals);
impl_proposable!(PreSharedKey, PSK, psks);
impl_proposable!(ReInit, RE_INIT, reinitializations);
impl_proposable!(ExternalInit, EXTERNAL_INIT, external_initializations);
impl_proposable!(
    ExtensionList<GroupContextExtension>,
    GROUP_CONTEXT_EXTENSIONS,
    group_context_extensions
);
