use crate::{
    extension::{ExtensionList, RequiredCapabilitiesExt},
    group::{
        AddProposal, ExternalInit, PreSharedKey, Proposal, ProposalOrRef, ProposalRef,
        ProposalType, ReInit, RemoveProposal, Sender, UpdateProposal,
    },
};

#[derive(Clone, Debug, Default)]
pub struct ProposalBundle {
    additions: Vec<ProposalInfo<AddProposal>>,
    updates: Vec<ProposalInfo<UpdateProposal>>,
    removals: Vec<ProposalInfo<RemoveProposal>>,
    psks: Vec<ProposalInfo<PreSharedKey>>,
    reinitializations: Vec<ProposalInfo<ReInit>>,
    external_initializations: Vec<ProposalInfo<ExternalInit>>,
    group_context_extensions: Vec<ProposalInfo<ExtensionList>>,
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

    pub fn by_type<'a, T: Proposable + 'a>(&'a self) -> impl Iterator<Item = &'a ProposalInfo<T>> {
        T::filter(self).iter()
    }

    pub fn retain_by_type<T, F>(&mut self, f: F)
    where
        T: Proposable,
        F: FnMut(&ProposalInfo<T>) -> bool,
    {
        T::retain(self, f);
    }

    pub fn into_iter(self) -> impl Iterator<Item = ProposalInfo<Proposal>> {
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

    pub fn into_proposals_or_refs(self) -> impl Iterator<Item = ProposalOrRef> {
        self.into_iter().map(|p| {
            p.proposal_ref.map_or_else(
                || ProposalOrRef::Proposal(p.proposal),
                ProposalOrRef::Reference,
            )
        })
    }

    pub fn group_context_extensions(&self) -> Option<&ExtensionList> {
        self.group_context_extensions.first().map(|p| &p.proposal)
    }

    pub fn effective_required_capabilities(
        &self,
        original_capabilities: Option<RequiredCapabilitiesExt>,
    ) -> Option<RequiredCapabilitiesExt> {
        self.group_context_extensions()
            .and_then(|extensions| extensions.get_extension().ok().flatten())
            .or(original_capabilities)
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

#[derive(Clone, Debug)]
pub struct ProposalInfo<T> {
    pub proposal: T,
    pub sender: Sender,
    pub proposal_ref: Option<ProposalRef>,
}

impl<T> ProposalInfo<T> {
    fn map<U, F>(self, f: F) -> ProposalInfo<U>
    where
        F: FnOnce(T) -> U,
    {
        ProposalInfo {
            proposal: f(self.proposal),
            sender: self.sender,
            proposal_ref: self.proposal_ref,
        }
    }
}

pub trait Proposable: Sized {
    fn filter(bundle: &ProposalBundle) -> &[ProposalInfo<Self>];
    fn retain<F>(bundle: &mut ProposalBundle, f: F)
    where
        F: FnMut(&ProposalInfo<Self>) -> bool;
}

macro_rules! impl_proposable {
    ($ty:ty, $field:ident) => {
        impl Proposable for $ty {
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

impl_proposable!(AddProposal, additions);
impl_proposable!(UpdateProposal, updates);
impl_proposable!(RemoveProposal, removals);
impl_proposable!(PreSharedKey, psks);
impl_proposable!(ReInit, reinitializations);
impl_proposable!(ExternalInit, external_initializations);
impl_proposable!(ExtensionList, group_context_extensions);
