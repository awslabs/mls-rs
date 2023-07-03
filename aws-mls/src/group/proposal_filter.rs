mod bundle;
mod filter;
mod filtering_common;

#[cfg(feature = "by_ref_proposal")]
mod filtering;
#[cfg(not(feature = "by_ref_proposal"))]
pub mod filtering_lite;
#[cfg(all(feature = "custom_proposal", not(feature = "by_ref_proposal")))]
use filtering_lite as filtering;

pub use bundle::{Proposable, ProposalBundle, ProposalInfo, ProposalSource};
pub use filter::{PassThroughProposalRules, ProposalRules};

#[cfg(feature = "by_ref_proposal")]
pub(crate) use filtering::FilterStrategy;

pub(crate) use filtering_common::ProposalApplier;

#[cfg(all(feature = "by_ref_proposal", test))]
pub(crate) use filtering::proposer_can_propose;
