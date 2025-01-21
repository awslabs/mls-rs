// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// Copyright by contributors to this project.
// SPDX-License-Identifier: (Apache-2.0 OR MIT)

mod builder;
pub(crate) mod processor;

pub use builder::*;
use mls_rs_core::group::Member;
use mls_rs_core::identity::SigningIdentity;
pub use processor::*;

use alloc::vec::Vec;

use mls_rs_codec::{self, MlsDecode, MlsEncode, MlsSize};

use crate::error::MlsError;
use crate::group::ProposalOrRef;
use crate::tree_kem::leaf_node::LeafNode;
use crate::tree_kem::{TreeKemPublic, UpdatePath};

use super::Sender;

#[derive(Clone, Debug, PartialEq, MlsSize, MlsEncode, MlsDecode)]
#[cfg_attr(feature = "arbitrary", derive(mls_rs_core::arbitrary::Arbitrary))]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub(crate) struct Commit {
    pub proposals: Vec<ProposalOrRef>,
    pub path: Option<UpdatePath>,
}

/// The source of the commit: either a current member or a new member joining
/// via external commit.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CommitSource {
    ExistingMember(Member),
    NewMember(SigningIdentity),
}

impl CommitSource {
    pub(crate) fn new(
        sender: &Sender,
        public_tree: &TreeKemPublic,
        external_leaf: Option<&LeafNode>,
    ) -> Result<Self, MlsError> {
        match sender {
            Sender::Member(index) => Ok(CommitSource::ExistingMember(
                public_tree.roster().member_with_index(*index)?,
            )),
            #[cfg(feature = "by_ref_proposal")]
            Sender::NewMemberProposal => Err(MlsError::InvalidSender),
            #[cfg(feature = "by_ref_proposal")]
            Sender::External(_) => Err(MlsError::InvalidSender),
            Sender::NewMemberCommit => Ok(CommitSource::NewMember(
                external_leaf
                    .map(|l| l.signing_identity.clone())
                    .ok_or(MlsError::ExternalCommitMustHaveNewLeaf)?,
            )),
        }
    }
}
