// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// Copyright by contributors to this project.
// SPDX-License-Identifier: (Apache-2.0 OR MIT)

use crate::{
    error::MlsError,
    group::{Roster, Sender},
    tree_kem::{leaf_node::LeafNode, TreeKemPublic},
};

#[cfg(feature = "private_message")]
use crate::{group::padding::PaddingMode, WireFormat};

use alloc::boxed::Box;
use core::convert::Infallible;
use mls_rs_core::{error::IntoAnyError, group::Member, identity::SigningIdentity};

use super::GroupContext;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum CommitDirection {
    Send,
    Receive,
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

/// Options controlling encryption of control and application messages
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct EncryptionOptions {
    #[cfg(feature = "private_message")]
    pub encrypt_control_messages: bool,
    #[cfg(feature = "private_message")]
    pub padding_mode: PaddingMode,
}

#[cfg(feature = "private_message")]
impl EncryptionOptions {
    pub fn new(encrypt_control_messages: bool, padding_mode: PaddingMode) -> Self {
        Self {
            encrypt_control_messages,
            padding_mode,
        }
    }

    pub(crate) fn control_wire_format(&self, sender: Sender) -> WireFormat {
        match sender {
            Sender::Member(_) if self.encrypt_control_messages => WireFormat::PrivateMessage,
            _ => WireFormat::PublicMessage,
        }
    }
}

/// A set of user controlled rules that customize the behavior of MLS.
#[cfg_attr(not(mls_build_async), maybe_async::must_be_sync)]
#[cfg_attr(mls_build_async, maybe_async::must_be_async)]
pub trait MlsRules: Send + Sync {
    type Error: IntoAnyError;

    /// This is called when sending any packet. For proposals and commits, this determines whether to
    /// encrypt them. For any encrypted packet, this determines the padding mode used.
    ///
    /// Note that for commits, the `current_roster` and `current_extension_list` describe the group state
    /// before the commit, unlike in [commit_options](MlsRules::commit_options).
    fn encryption_options(
        &self,
        current_roster: &Roster,
        current_context: &GroupContext,
    ) -> Result<EncryptionOptions, Self::Error>;
}

macro_rules! delegate_mls_rules {
    ($implementer:ty) => {
        #[cfg_attr(not(mls_build_async), maybe_async::must_be_sync)]
        #[cfg_attr(mls_build_async, maybe_async::must_be_async)]
        impl<T: MlsRules + ?Sized> MlsRules for $implementer {
            type Error = T::Error;

            fn encryption_options(
                &self,
                roster: &Roster,
                context: &GroupContext,
            ) -> Result<EncryptionOptions, Self::Error> {
                (**self).encryption_options(roster, context)
            }
        }
    };
}

delegate_mls_rules!(Box<T>);
delegate_mls_rules!(&T);

#[derive(Clone, Debug, Default)]
#[non_exhaustive]
/// Default MLS rules with pass-through proposal filter and customizable options.
pub struct DefaultMlsRules {
    pub encryption_options: EncryptionOptions,
}

impl DefaultMlsRules {
    /// Create new MLS rules with default settings: do not enforce path and do
    /// put the ratchet tree in the extension.
    pub fn new() -> Self {
        Default::default()
    }

    /// Set encryption options.
    pub fn with_encryption_options(self, encryption_options: EncryptionOptions) -> Self {
        Self { encryption_options }
    }
}

#[cfg_attr(not(mls_build_async), maybe_async::must_be_sync)]
#[cfg_attr(mls_build_async, maybe_async::must_be_async)]
impl MlsRules for DefaultMlsRules {
    type Error = Infallible;

    fn encryption_options(
        &self,
        _: &Roster,
        _: &GroupContext,
    ) -> Result<EncryptionOptions, Self::Error> {
        Ok(self.encryption_options)
    }
}
