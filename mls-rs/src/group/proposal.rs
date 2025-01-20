// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// Copyright by contributors to this project.
// SPDX-License-Identifier: (Apache-2.0 OR MIT)

use alloc::{boxed::Box, vec::Vec};

#[cfg(feature = "by_ref_proposal")]
use crate::tree_kem::leaf_node::LeafNode;

use crate::{
    client::MlsError, client_config::ClientConfig, tree_kem::node::LeafIndex, CipherSuite,
    KeyPackage, MlsMessage, ProtocolVersion,
};
use core::fmt::{self, Debug};
use mls_rs_codec::{MlsDecode, MlsEncode, MlsSize};
use mls_rs_core::{
    crypto::CipherSuiteProvider, crypto::SignatureSecretKey, error::IntoAnyError,
    group::Capabilities, identity::SigningIdentity,
};

#[cfg(feature = "by_ref_proposal")]
use crate::group::proposal_ref::ProposalRef;

pub use mls_rs_core::extension::ExtensionList;
pub use mls_rs_core::group::ProposalType;

#[cfg(feature = "psk")]
use crate::psk::{ExternalPskId, JustPreSharedKeyID, PreSharedKeyID, ResumptionPsk};

use super::{
    AuthenticatedContent, Content, EncryptionMode, Group, ProposalMessageDescription, Sender,
};

#[derive(Clone, Debug, PartialEq, MlsSize, MlsEncode, MlsDecode)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
/// A proposal that adds a member to a [`Group`](crate::group::Group).
pub struct AddProposal {
    pub(crate) key_package: KeyPackage,
}

impl AddProposal {
    /// The [`KeyPackage`] used by this proposal to add
    /// a [`Member`](mls_rs_core::group::Member) to the group.
    pub fn key_package(&self) -> &KeyPackage {
        &self.key_package
    }

    /// The [`SigningIdentity`] of the [`Member`](mls_rs_core::group::Member)
    /// that will be added by this proposal.
    pub fn signing_identity(&self) -> &SigningIdentity {
        self.key_package.signing_identity()
    }

    /// Client [`Capabilities`] of the [`Member`](mls_rs_core::group::Member)
    /// that will be added by this proposal.
    pub fn capabilities(&self) -> Capabilities {
        self.key_package.leaf_node.ungreased_capabilities()
    }

    /// Key package extensions that are assoiciated with the
    /// [`Member`](mls_rs_core::group::Member) that will be added by this proposal.
    pub fn key_package_extensions(&self) -> ExtensionList {
        self.key_package.ungreased_extensions()
    }

    /// Leaf node extensions that will be entered into the group state for the
    /// [`Member`](mls_rs_core::group::Member) that will be added.
    pub fn leaf_node_extensions(&self) -> ExtensionList {
        self.key_package.leaf_node.ungreased_extensions()
    }
}

impl From<KeyPackage> for AddProposal {
    fn from(key_package: KeyPackage) -> Self {
        Self { key_package }
    }
}

impl TryFrom<MlsMessage> for AddProposal {
    type Error = MlsError;

    fn try_from(value: MlsMessage) -> Result<Self, Self::Error> {
        value
            .into_key_package()
            .ok_or(MlsError::UnexpectedMessageType)
            .map(Into::into)
    }
}

#[cfg(feature = "by_ref_proposal")]
#[derive(Clone, Debug, PartialEq, MlsSize, MlsEncode, MlsDecode)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
/// A proposal that will update an existing [`Member`](mls_rs_core::group::Member) of a
/// [`Group`](crate::group::Group).
pub struct UpdateProposal {
    pub(crate) leaf_node: LeafNode,
}

#[cfg(feature = "by_ref_proposal")]
impl UpdateProposal {
    /// The new [`SigningIdentity`] of the [`Member`](mls_rs_core::group::Member)
    /// that is being updated by this proposal.
    pub fn signing_identity(&self) -> &SigningIdentity {
        &self.leaf_node.signing_identity
    }

    /// New Client [`Capabilities`] of the [`Member`](mls_rs_core::group::Member)
    /// that will be updated by this proposal.
    pub fn capabilities(&self) -> Capabilities {
        self.leaf_node.ungreased_capabilities()
    }

    /// New Leaf node extensions that will be entered into the group state for the
    /// [`Member`](mls_rs_core::group::Member) that is being updated by this proposal.
    pub fn leaf_node_extensions(&self) -> ExtensionList {
        self.leaf_node.ungreased_extensions()
    }
}

#[derive(Clone, Debug, PartialEq, Eq, MlsSize, MlsEncode, MlsDecode)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
/// A proposal to remove an existing [`Member`](mls_rs_core::group::Member) of a
/// [`Group`](crate::group::Group).
pub struct RemoveProposal {
    pub(crate) to_remove: LeafIndex,
}

impl RemoveProposal {
    /// The index of the [`Member`](mls_rs_core::group::Member) that will be removed by
    /// this proposal.
    pub fn to_remove(&self) -> u32 {
        *self.to_remove
    }
}

impl From<u32> for RemoveProposal {
    fn from(value: u32) -> Self {
        RemoveProposal {
            to_remove: LeafIndex(value),
        }
    }
}

#[cfg(feature = "psk")]
#[derive(Clone, Debug, PartialEq, Eq, MlsSize, MlsEncode, MlsDecode)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
/// A proposal to add a pre-shared key to a group.
pub struct PreSharedKeyProposal {
    pub(crate) psk: PreSharedKeyID,
}

#[cfg(feature = "psk")]
impl PreSharedKeyProposal {
    /// The external pre-shared key id of this proposal.
    ///
    /// MLS requires the pre-shared key type for PreSharedKeyProposal to be of
    /// type `External`.
    ///
    /// Returns `None` in the condition that the underlying psk is not external.
    pub fn external_psk_id(&self) -> Option<&ExternalPskId> {
        match self.psk.key_id {
            JustPreSharedKeyID::External(ref ext) => Some(ext),
            JustPreSharedKeyID::Resumption(_) => None,
        }
    }

    pub fn resumption_psk_id(&self) -> Option<&ResumptionPsk> {
        match self.psk.key_id {
            JustPreSharedKeyID::External(_) => None,
            JustPreSharedKeyID::Resumption(ref ext) => Some(ext),
        }
    }
}

#[derive(Clone, PartialEq, MlsSize, MlsEncode, MlsDecode)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
/// A proposal to reinitialize a group using new parameters.
pub struct ReInitProposal {
    #[mls_codec(with = "mls_rs_codec::byte_vec")]
    #[cfg_attr(feature = "serde", serde(with = "mls_rs_core::vec_serde"))]
    pub(crate) group_id: Vec<u8>,
    pub(crate) version: ProtocolVersion,
    pub(crate) cipher_suite: CipherSuite,
    pub(crate) extensions: ExtensionList,
}

impl Debug for ReInitProposal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ReInitProposal")
            .field(
                "group_id",
                &mls_rs_core::debug::pretty_group_id(&self.group_id),
            )
            .field("version", &self.version)
            .field("cipher_suite", &self.cipher_suite)
            .field("extensions", &self.extensions)
            .finish()
    }
}

impl ReInitProposal {
    /// The unique id of the new group post reinitialization.
    pub fn group_id(&self) -> &[u8] {
        &self.group_id
    }

    /// The new protocol version to use post reinitialization.
    pub fn new_version(&self) -> ProtocolVersion {
        self.version
    }

    /// The new ciphersuite to use post reinitialization.
    pub fn new_cipher_suite(&self) -> CipherSuite {
        self.cipher_suite
    }

    /// Group context extensions to set in the new group post reinitialization.
    pub fn new_group_context_extensions(&self) -> &ExtensionList {
        &self.extensions
    }
}

#[derive(Clone, PartialEq, Eq, MlsSize, MlsEncode, MlsDecode)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
/// A proposal used for external commits.
pub struct ExternalInit {
    #[mls_codec(with = "mls_rs_codec::byte_vec")]
    #[cfg_attr(feature = "serde", serde(with = "mls_rs_core::vec_serde"))]
    pub(crate) kem_output: Vec<u8>,
}

impl Debug for ExternalInit {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ExternalInit")
            .field(
                "kem_output",
                &mls_rs_core::debug::pretty_bytes(&self.kem_output),
            )
            .finish()
    }
}

#[cfg(feature = "custom_proposal")]
#[derive(Clone, PartialEq, Eq)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[cfg_attr(
    all(feature = "ffi", not(test)),
    safer_ffi_gen::ffi_type(clone, opaque)
)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
/// A user defined custom proposal.
///
/// User defined proposals are passed through the protocol as an opaque value.
pub struct CustomProposal {
    proposal_type: ProposalType,
    #[cfg_attr(feature = "serde", serde(with = "mls_rs_core::vec_serde"))]
    data: Vec<u8>,
}

#[cfg(feature = "custom_proposal")]
impl Debug for CustomProposal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CustomProposal")
            .field("proposal_type", &self.proposal_type)
            .field("data", &mls_rs_core::debug::pretty_bytes(&self.data))
            .finish()
    }
}

#[cfg(feature = "custom_proposal")]
#[cfg_attr(all(feature = "ffi", not(test)), safer_ffi_gen::safer_ffi_gen)]
impl CustomProposal {
    /// Create a custom proposal.
    ///
    /// # Warning
    ///
    /// Avoid using the [`ProposalType`] values that have constants already
    /// defined by this crate. Using existing constants in a custom proposal
    /// has unspecified behavior.
    pub fn new(proposal_type: ProposalType, data: Vec<u8>) -> Self {
        Self {
            proposal_type,
            data,
        }
    }

    /// The proposal type used for this custom proposal.
    pub fn proposal_type(&self) -> ProposalType {
        self.proposal_type
    }

    /// The opaque data communicated by this custom proposal.
    pub fn data(&self) -> &[u8] {
        &self.data
    }
}

/// Trait to simplify creating custom proposals that are serialized with MLS
/// encoding.
#[cfg(feature = "custom_proposal")]
pub trait MlsCustomProposal: MlsSize + MlsEncode + MlsDecode + Sized {
    fn proposal_type() -> ProposalType;

    fn to_custom_proposal(&self) -> Result<CustomProposal, mls_rs_codec::Error> {
        Ok(CustomProposal::new(
            Self::proposal_type(),
            self.mls_encode_to_vec()?,
        ))
    }

    fn from_custom_proposal(proposal: &CustomProposal) -> Result<Self, mls_rs_codec::Error> {
        if proposal.proposal_type() != Self::proposal_type() {
            // #[cfg(feature = "std")]
            // return Err(mls_rs_codec::Error::Custom(
            //     "invalid proposal type".to_string(),
            // ));

            //#[cfg(not(feature = "std"))]
            return Err(mls_rs_codec::Error::Custom(4));
        }

        Self::mls_decode(&mut proposal.data())
    }
}

#[allow(clippy::large_enum_variant)]
#[derive(Clone, Debug, PartialEq)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[repr(u16)]
#[non_exhaustive]
/// An enum that represents all possible types of proposals.
pub enum Proposal {
    Add(alloc::boxed::Box<AddProposal>),
    #[cfg(feature = "by_ref_proposal")]
    Update(UpdateProposal),
    Remove(RemoveProposal),
    #[cfg(feature = "psk")]
    Psk(PreSharedKeyProposal),
    ReInit(ReInitProposal),
    ExternalInit(ExternalInit),
    GroupContextExtensions(ExtensionList),
    #[cfg(feature = "custom_proposal")]
    Custom(CustomProposal),
}

impl MlsSize for Proposal {
    fn mls_encoded_len(&self) -> usize {
        let inner_len = match self {
            Proposal::Add(p) => p.mls_encoded_len(),
            #[cfg(feature = "by_ref_proposal")]
            Proposal::Update(p) => p.mls_encoded_len(),
            Proposal::Remove(p) => p.mls_encoded_len(),
            #[cfg(feature = "psk")]
            Proposal::Psk(p) => p.mls_encoded_len(),
            Proposal::ReInit(p) => p.mls_encoded_len(),
            Proposal::ExternalInit(p) => p.mls_encoded_len(),
            Proposal::GroupContextExtensions(p) => p.mls_encoded_len(),
            #[cfg(feature = "custom_proposal")]
            Proposal::Custom(p) => mls_rs_codec::byte_vec::mls_encoded_len(&p.data),
        };

        self.proposal_type().mls_encoded_len() + inner_len
    }
}

impl MlsEncode for Proposal {
    fn mls_encode(&self, writer: &mut Vec<u8>) -> Result<(), mls_rs_codec::Error> {
        self.proposal_type().mls_encode(writer)?;

        match self {
            Proposal::Add(p) => p.mls_encode(writer),
            #[cfg(feature = "by_ref_proposal")]
            Proposal::Update(p) => p.mls_encode(writer),
            Proposal::Remove(p) => p.mls_encode(writer),
            #[cfg(feature = "psk")]
            Proposal::Psk(p) => p.mls_encode(writer),
            Proposal::ReInit(p) => p.mls_encode(writer),
            Proposal::ExternalInit(p) => p.mls_encode(writer),
            Proposal::GroupContextExtensions(p) => p.mls_encode(writer),
            #[cfg(feature = "custom_proposal")]
            Proposal::Custom(p) => {
                if p.proposal_type.raw_value() <= 7 {
                    // #[cfg(feature = "std")]
                    // return Err(mls_rs_codec::Error::Custom(
                    //     "custom proposal types can not be set to defined values of 0-7".to_string(),
                    // ));

                    // #[cfg(not(feature = "std"))]
                    return Err(mls_rs_codec::Error::Custom(2));
                }
                mls_rs_codec::byte_vec::mls_encode(&p.data, writer)
            }
        }
    }
}

impl MlsDecode for Proposal {
    fn mls_decode(reader: &mut &[u8]) -> Result<Self, mls_rs_codec::Error> {
        let proposal_type = ProposalType::mls_decode(reader)?;

        Ok(match proposal_type {
            ProposalType::ADD => {
                Proposal::Add(alloc::boxed::Box::new(AddProposal::mls_decode(reader)?))
            }
            #[cfg(feature = "by_ref_proposal")]
            ProposalType::UPDATE => Proposal::Update(UpdateProposal::mls_decode(reader)?),
            ProposalType::REMOVE => Proposal::Remove(RemoveProposal::mls_decode(reader)?),
            #[cfg(feature = "psk")]
            ProposalType::PSK => Proposal::Psk(PreSharedKeyProposal::mls_decode(reader)?),
            ProposalType::RE_INIT => Proposal::ReInit(ReInitProposal::mls_decode(reader)?),
            ProposalType::EXTERNAL_INIT => {
                Proposal::ExternalInit(ExternalInit::mls_decode(reader)?)
            }
            ProposalType::GROUP_CONTEXT_EXTENSIONS => {
                Proposal::GroupContextExtensions(ExtensionList::mls_decode(reader)?)
            }
            #[cfg(feature = "custom_proposal")]
            custom => Proposal::Custom(CustomProposal {
                proposal_type: custom,
                data: mls_rs_codec::byte_vec::mls_decode(reader)?,
            }),
            // TODO fix test dependency on openssl loading codec with default features
            #[cfg(not(feature = "custom_proposal"))]
            _ => return Err(mls_rs_codec::Error::Custom(3)),
        })
    }
}

impl Proposal {
    pub fn proposal_type(&self) -> ProposalType {
        match self {
            Proposal::Add(_) => ProposalType::ADD,
            #[cfg(feature = "by_ref_proposal")]
            Proposal::Update(_) => ProposalType::UPDATE,
            Proposal::Remove(_) => ProposalType::REMOVE,
            #[cfg(feature = "psk")]
            Proposal::Psk(_) => ProposalType::PSK,
            Proposal::ReInit(_) => ProposalType::RE_INIT,
            Proposal::ExternalInit(_) => ProposalType::EXTERNAL_INIT,
            Proposal::GroupContextExtensions(_) => ProposalType::GROUP_CONTEXT_EXTENSIONS,
            #[cfg(feature = "custom_proposal")]
            Proposal::Custom(c) => c.proposal_type,
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
/// An enum that represents a borrowed version of [`Proposal`].
pub enum BorrowedProposal<'a> {
    Add(&'a AddProposal),
    #[cfg(feature = "by_ref_proposal")]
    Update(&'a UpdateProposal),
    Remove(&'a RemoveProposal),
    #[cfg(feature = "psk")]
    Psk(&'a PreSharedKeyProposal),
    ReInit(&'a ReInitProposal),
    ExternalInit(&'a ExternalInit),
    GroupContextExtensions(&'a ExtensionList),
    #[cfg(feature = "custom_proposal")]
    Custom(&'a CustomProposal),
}

impl<'a> From<BorrowedProposal<'a>> for Proposal {
    fn from(value: BorrowedProposal<'a>) -> Self {
        match value {
            BorrowedProposal::Add(add) => Proposal::Add(alloc::boxed::Box::new(add.clone())),
            #[cfg(feature = "by_ref_proposal")]
            BorrowedProposal::Update(update) => Proposal::Update(update.clone()),
            BorrowedProposal::Remove(remove) => Proposal::Remove(remove.clone()),
            #[cfg(feature = "psk")]
            BorrowedProposal::Psk(psk) => Proposal::Psk(psk.clone()),
            BorrowedProposal::ReInit(reinit) => Proposal::ReInit(reinit.clone()),
            BorrowedProposal::ExternalInit(external) => Proposal::ExternalInit(external.clone()),
            BorrowedProposal::GroupContextExtensions(ext) => {
                Proposal::GroupContextExtensions(ext.clone())
            }
            #[cfg(feature = "custom_proposal")]
            BorrowedProposal::Custom(custom) => Proposal::Custom(custom.clone()),
        }
    }
}

impl BorrowedProposal<'_> {
    pub fn proposal_type(&self) -> ProposalType {
        match self {
            BorrowedProposal::Add(_) => ProposalType::ADD,
            #[cfg(feature = "by_ref_proposal")]
            BorrowedProposal::Update(_) => ProposalType::UPDATE,
            BorrowedProposal::Remove(_) => ProposalType::REMOVE,
            #[cfg(feature = "psk")]
            BorrowedProposal::Psk(_) => ProposalType::PSK,
            BorrowedProposal::ReInit(_) => ProposalType::RE_INIT,
            BorrowedProposal::ExternalInit(_) => ProposalType::EXTERNAL_INIT,
            BorrowedProposal::GroupContextExtensions(_) => ProposalType::GROUP_CONTEXT_EXTENSIONS,
            #[cfg(feature = "custom_proposal")]
            BorrowedProposal::Custom(c) => c.proposal_type,
        }
    }
}

impl<'a> From<&'a Proposal> for BorrowedProposal<'a> {
    fn from(p: &'a Proposal) -> Self {
        match p {
            Proposal::Add(p) => BorrowedProposal::Add(p),
            #[cfg(feature = "by_ref_proposal")]
            Proposal::Update(p) => BorrowedProposal::Update(p),
            Proposal::Remove(p) => BorrowedProposal::Remove(p),
            #[cfg(feature = "psk")]
            Proposal::Psk(p) => BorrowedProposal::Psk(p),
            Proposal::ReInit(p) => BorrowedProposal::ReInit(p),
            Proposal::ExternalInit(p) => BorrowedProposal::ExternalInit(p),
            Proposal::GroupContextExtensions(p) => BorrowedProposal::GroupContextExtensions(p),
            #[cfg(feature = "custom_proposal")]
            Proposal::Custom(p) => BorrowedProposal::Custom(p),
        }
    }
}

impl<'a> From<&'a AddProposal> for BorrowedProposal<'a> {
    fn from(p: &'a AddProposal) -> Self {
        Self::Add(p)
    }
}

#[cfg(feature = "by_ref_proposal")]
impl<'a> From<&'a UpdateProposal> for BorrowedProposal<'a> {
    fn from(p: &'a UpdateProposal) -> Self {
        Self::Update(p)
    }
}

impl<'a> From<&'a RemoveProposal> for BorrowedProposal<'a> {
    fn from(p: &'a RemoveProposal) -> Self {
        Self::Remove(p)
    }
}

#[cfg(feature = "psk")]
impl<'a> From<&'a PreSharedKeyProposal> for BorrowedProposal<'a> {
    fn from(p: &'a PreSharedKeyProposal) -> Self {
        Self::Psk(p)
    }
}

impl<'a> From<&'a ReInitProposal> for BorrowedProposal<'a> {
    fn from(p: &'a ReInitProposal) -> Self {
        Self::ReInit(p)
    }
}

impl<'a> From<&'a ExternalInit> for BorrowedProposal<'a> {
    fn from(p: &'a ExternalInit) -> Self {
        Self::ExternalInit(p)
    }
}

impl<'a> From<&'a ExtensionList> for BorrowedProposal<'a> {
    fn from(p: &'a ExtensionList) -> Self {
        Self::GroupContextExtensions(p)
    }
}

#[cfg(feature = "custom_proposal")]
impl<'a> From<&'a CustomProposal> for BorrowedProposal<'a> {
    fn from(p: &'a CustomProposal) -> Self {
        Self::Custom(p)
    }
}

#[derive(Clone, Debug, PartialEq, MlsSize, MlsEncode, MlsDecode)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[repr(u8)]
pub(crate) enum ProposalOrRef {
    Proposal(Box<Proposal>) = 1u8,
    #[cfg(feature = "by_ref_proposal")]
    Reference(ProposalRef) = 2u8,
}

impl From<Proposal> for ProposalOrRef {
    fn from(proposal: Proposal) -> Self {
        Self::Proposal(Box::new(proposal))
    }
}

#[cfg(feature = "by_ref_proposal")]
impl From<ProposalRef> for ProposalOrRef {
    fn from(r: ProposalRef) -> Self {
        Self::Reference(r)
    }
}

/// Build a proposal.
pub struct ProposalBuilder<'a, C: ClientConfig, P> {
    group: &'a mut Group<C>,
    proposal_input: ProposalInput<P>,
    authenticated_data: Vec<u8>,
    encryption_mode: EncryptionMode,

    // Update
    signer: Option<SignatureSecretKey>,
    signing_identity: Option<SigningIdentity>,
    leaf_node_extensions: Option<ExtensionList>,

    // Reinit
    group_id: Option<Vec<u8>>,
    version: ProtocolVersion,
    cipher_suite: CipherSuite,
    extensions: ExtensionList,
}

pub(crate) enum ProposalInput<P> {
    Update,
    ExternalPsk { psk_id: ExternalPskId },
    ResumptionPsk { psk_id: ResumptionPsk },
    ReInit,
    Other { proposal: P },
}

impl<'a, C: ClientConfig, P: Into<Proposal> + Clone> ProposalBuilder<'a, C, P> {
    pub(crate) fn new(group: &'a mut Group<C>, proposal_input: ProposalInput<P>) -> Self {
        ProposalBuilder {
            group_id: None,
            version: group.protocol_version(),
            cipher_suite: group.cipher_suite(),
            extensions: Default::default(),
            group,
            proposal_input,
            authenticated_data: Default::default(),
            encryption_mode: Default::default(),
            signer: Default::default(),
            signing_identity: Default::default(),
            leaf_node_extensions: Default::default(),
        }
    }

    pub fn authenticated_data(self, authenticated_data: Vec<u8>) -> Self {
        Self {
            authenticated_data,
            ..self
        }
    }

    pub fn encryption_mode(self, encryption_mode: EncryptionMode) -> Self {
        Self {
            encryption_mode,
            ..self
        }
    }

    #[cfg_attr(not(mls_build_async), maybe_async::must_be_sync)]
    pub async fn build(mut self) -> Result<MlsMessage, MlsError> {
        let proposal = self.proposal().await?;
        self.proposal_message(proposal).await
    }

    #[cfg_attr(not(mls_build_async), maybe_async::must_be_sync)]
    pub(crate) async fn proposal_message(self, proposal: Proposal) -> Result<MlsMessage, MlsError> {
        let group = self.group;
        let sender = Sender::Member(*group.private_tree.self_index);

        let auth_content = AuthenticatedContent::new_signed(
            &group.cipher_suite_provider,
            group.context(),
            sender,
            Content::Proposal(Box::new(proposal.clone())),
            &group.signer,
            self.encryption_mode,
            self.authenticated_data,
        )
        .await?;

        let sender = auth_content.content.sender;

        let proposal_desc =
            ProposalMessageDescription::new(&group.cipher_suite_provider, &auth_content, proposal)
                .await?;

        let message = group
            .format_for_wire(auth_content, self.encryption_mode)
            .await?;

        group
            .state
            .proposals
            .insert_own(
                proposal_desc,
                &message,
                sender,
                &group.cipher_suite_provider,
            )
            .await?;

        Ok(message)
    }

    #[cfg_attr(not(mls_build_async), maybe_async::must_be_sync)]
    pub(crate) async fn proposal(&mut self) -> Result<Proposal, MlsError> {
        match &mut self.proposal_input {
            ProposalInput::Other { proposal } => Ok(proposal.clone().into()),
            ProposalInput::Update => {
                self.group
                    .update_proposal(
                        self.signer.take(),
                        self.signing_identity.take(),
                        self.leaf_node_extensions.take(),
                    )
                    .await
            }
            ProposalInput::ExternalPsk { psk_id } => Ok(Proposal::Psk(PreSharedKeyProposal {
                psk: PreSharedKeyID::new(
                    JustPreSharedKeyID::External(psk_id.clone()),
                    &self.group.cipher_suite_provider,
                )?,
            })),
            ProposalInput::ResumptionPsk { psk_id } => Ok(Proposal::Psk(PreSharedKeyProposal {
                psk: PreSharedKeyID::new(
                    JustPreSharedKeyID::Resumption(psk_id.clone()),
                    &self.group.cipher_suite_provider,
                )?,
            })),
            ProposalInput::ReInit => {
                let group_id = self.group_id.take().map(Ok).unwrap_or_else(|| {
                    self.group
                        .cipher_suite_provider
                        .random_bytes_vec(self.group.cipher_suite_provider.kdf_extract_size())
                        .map_err(|e| MlsError::CryptoProviderError(e.into_any_error()))
                })?;

                Ok(Proposal::ReInit(ReInitProposal {
                    group_id,
                    version: self.version,
                    cipher_suite: self.cipher_suite,
                    extensions: core::mem::take(&mut self.extensions),
                }))
            }
        }
    }
}

impl<C: ClientConfig> ProposalBuilder<'_, C, UpdateProposal> {
    pub fn signer(self, signer: SignatureSecretKey) -> Self {
        Self {
            signer: Some(signer),
            ..self
        }
    }

    /// Create a proposal message that updates your own public keys
    /// as well as your credential.
    ///
    /// This proposal is useful for contributing additional forward secrecy
    /// and post-compromise security to the group without having to perform
    /// the necessary computation of a [`Group::commit`].
    ///
    /// Identity updates are allowed by the group by default assuming that the
    /// new identity provided is considered
    /// [valid](crate::IdentityProvider::validate_member)
    /// by and matches the output of the
    /// [identity](crate::IdentityProvider)
    /// function of the current
    /// [`IdentityProvider`](crate::IdentityProvider).
    ///
    /// `authenticated_data` will be sent unencrypted along with the contents
    /// of the proposal message.
    pub fn signing_identity(self, signing_identity: SigningIdentity) -> Self {
        Self {
            signing_identity: Some(signing_identity),
            ..self
        }
    }

    pub fn leaf_node_extensions(self, leaf_node_extensions: ExtensionList) -> Self {
        Self {
            leaf_node_extensions: Some(leaf_node_extensions),
            ..self
        }
    }
}

impl<C: ClientConfig> ProposalBuilder<'_, C, ReInitProposal> {
    pub fn group_id(self, group_id: Vec<u8>) -> Self {
        Self {
            group_id: Some(group_id),
            ..self
        }
    }

    pub fn version(self, version: ProtocolVersion) -> Self {
        Self { version, ..self }
    }

    pub fn cipher_suite(self, cipher_suite: CipherSuite) -> Self {
        Self {
            cipher_suite,
            ..self
        }
    }

    pub fn extensions(self, extensions: ExtensionList) -> Self {
        Self { extensions, ..self }
    }
}

macro_rules! impl_into_proposal {
    ($ty:ty, $proposal_type:ident) => {
        impl From<$ty> for Proposal {
            fn from(value: $ty) -> Self {
                Proposal::$proposal_type(value.into())
            }
        }
    };
}

impl_into_proposal!(CustomProposal, Custom);
impl_into_proposal!(AddProposal, Add);
impl_into_proposal!(UpdateProposal, Update);
impl_into_proposal!(RemoveProposal, Remove);
impl_into_proposal!(PreSharedKeyProposal, Psk);
impl_into_proposal!(ExternalInit, ExternalInit);
impl_into_proposal!(ReInitProposal, ReInit);
impl_into_proposal!(ExtensionList, GroupContextExtensions);
