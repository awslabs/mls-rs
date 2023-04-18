use super::*;
use crate::{psk::PreSharedKeyID, tree_kem::leaf_node::LeafNode};
use core::fmt::Debug;

use alloc::string::ToString;
use proposal_ref::ProposalRef;

pub use aws_mls_core::extension::ExtensionList;
pub use aws_mls_core::group::ProposalType;

#[derive(
    Clone, Debug, PartialEq, MlsSize, MlsEncode, MlsDecode, serde::Deserialize, serde::Serialize,
)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
/// A proposal that adds a member to a [`Group`](super::Group).
pub struct AddProposal {
    pub(crate) key_package: KeyPackage,
}

impl AddProposal {
    /// The [`SigningIdentity`](crate::identity::SigningIdentity)
    /// of the [`Member`](super::Member) that will be added by this proposal.
    pub fn signing_identity(&self) -> &SigningIdentity {
        self.key_package.signing_identity()
    }

    /// Client [`Capabilities`](super::Capabilities) of the
    /// [`Member`](super::Member) that will be added by this proposal.
    pub fn capabilities(&self) -> Capabilities {
        self.key_package.leaf_node.ungreased_capabilities()
    }

    /// Key package extensions that are assoiciated with the
    /// [`Member`](super::Member) that will be added by this proposal.
    pub fn key_package_extensions(&self) -> ExtensionList {
        self.key_package.ungreased_extensions()
    }

    /// Leaf node extensions that will be entered into the group state for the
    /// [`Member`](super::Member) that will be added.
    pub fn leaf_node_extensions(&self) -> ExtensionList {
        self.key_package.leaf_node.ungreased_extensions()
    }
}

impl From<KeyPackage> for AddProposal {
    fn from(key_package: KeyPackage) -> Self {
        Self { key_package }
    }
}

impl TryFrom<MLSMessage> for AddProposal {
    type Error = MlsError;

    fn try_from(value: MLSMessage) -> Result<Self, Self::Error> {
        value
            .into_key_package()
            .ok_or(MlsError::NotKeyPackage)
            .map(Into::into)
    }
}

#[derive(
    Clone, Debug, PartialEq, MlsSize, MlsEncode, MlsDecode, serde::Deserialize, serde::Serialize,
)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
/// A proposal that will update an existing [`Member`](super::Member) of a
/// [`Group`](super::Group)
pub struct UpdateProposal {
    pub(crate) leaf_node: LeafNode,
}

impl UpdateProposal {
    /// The new [`SigningIdentity`](crate::identity::SigningIdentity)
    /// of the [`Member`](super::Member) that is being updated by this proposal.
    pub fn signing_identity(&self) -> &SigningIdentity {
        &self.leaf_node.signing_identity
    }

    /// New Client [`Capabilities`](super::Capabilities) of the
    /// [`Member`](super::Member) that will be updated by this proposal.
    pub fn capabilities(&self) -> Capabilities {
        self.leaf_node.ungreased_capabilities()
    }

    /// New Leaf node extensions that will be entered into the group state for the
    /// [`Member`](super::Member) that is being updated by this proposal.
    pub fn leaf_node_extensions(&self) -> ExtensionList {
        self.leaf_node.ungreased_extensions()
    }
}

#[derive(
    Clone, Debug, PartialEq, Eq, MlsSize, MlsEncode, MlsDecode, serde::Deserialize, serde::Serialize,
)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
/// A proposal to remove an existing [`Member`](super::Member) of a
/// [`Group`](super::Group).
pub struct RemoveProposal {
    pub(crate) to_remove: LeafIndex,
}

impl RemoveProposal {
    /// The index of the [`Member`](super::Member) that will be removed by
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

#[derive(
    Clone, Debug, PartialEq, Eq, MlsSize, MlsEncode, MlsDecode, serde::Deserialize, serde::Serialize,
)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
/// A proposal to add a pre-shared key to a group.
pub struct PreSharedKeyProposal {
    pub(crate) psk: PreSharedKeyID,
}

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
}

#[serde_as]
#[derive(
    Clone, Debug, PartialEq, MlsSize, MlsEncode, MlsDecode, serde::Deserialize, serde::Serialize,
)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
/// A proposal to reinitialize a group using new parameters.
pub struct ReInitProposal {
    #[mls_codec(with = "aws_mls_codec::byte_vec")]
    #[serde_as(as = "VecAsBase64")]
    pub(crate) group_id: Vec<u8>,
    pub(crate) version: ProtocolVersion,
    pub(crate) cipher_suite: CipherSuite,
    pub(crate) extensions: ExtensionList,
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

#[serde_as]
#[derive(
    Clone, Debug, PartialEq, Eq, MlsSize, MlsEncode, MlsDecode, serde::Deserialize, serde::Serialize,
)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
/// A proposal used for external commits.
pub struct ExternalInit {
    #[mls_codec(with = "aws_mls_codec::byte_vec")]
    #[serde_as(as = "VecAsBase64")]
    pub(crate) kem_output: Vec<u8>,
}

#[serde_as]
#[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
/// A user defined custom proposal.
///
/// User defined proposals are passed through the protocol as an opaque value.
pub struct CustomProposal {
    proposal_type: ProposalType,
    data: Vec<u8>,
}

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
pub trait MlsCustomProposal: MlsSize + MlsEncode + MlsDecode + Sized {
    fn proposal_type() -> ProposalType;

    fn to_custom_proposal(&self) -> Result<CustomProposal, aws_mls_codec::Error> {
        Ok(CustomProposal::new(
            Self::proposal_type(),
            self.mls_encode_to_vec()?,
        ))
    }

    fn from_custom_proposal(proposal: &CustomProposal) -> Result<Self, aws_mls_codec::Error> {
        if proposal.proposal_type() != Self::proposal_type() {
            return Err(aws_mls_codec::Error::Custom(
                "invalid proposal type".to_string(),
            ));
        }

        Self::mls_decode(&mut proposal.data())
    }
}

#[derive(Clone, Debug, PartialEq, serde::Deserialize, serde::Serialize)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[repr(u16)]
/// An enum that represents all possible types of proposals.
pub enum Proposal {
    Add(AddProposal),
    Update(UpdateProposal),
    Remove(RemoveProposal),
    Psk(PreSharedKeyProposal),
    ReInit(ReInitProposal),
    ExternalInit(ExternalInit),
    GroupContextExtensions(ExtensionList),
    Custom(CustomProposal),
}

impl MlsSize for Proposal {
    fn mls_encoded_len(&self) -> usize {
        let inner_len = match self {
            Proposal::Add(p) => p.mls_encoded_len(),
            Proposal::Update(p) => p.mls_encoded_len(),
            Proposal::Remove(p) => p.mls_encoded_len(),
            Proposal::Psk(p) => p.mls_encoded_len(),
            Proposal::ReInit(p) => p.mls_encoded_len(),
            Proposal::ExternalInit(p) => p.mls_encoded_len(),
            Proposal::GroupContextExtensions(p) => p.mls_encoded_len(),
            Proposal::Custom(p) => aws_mls_codec::byte_vec::mls_encoded_len(&p.data),
        };

        self.proposal_type().mls_encoded_len() + inner_len
    }
}

impl MlsEncode for Proposal {
    fn mls_encode(&self, writer: &mut Vec<u8>) -> Result<(), aws_mls_codec::Error> {
        self.proposal_type().mls_encode(writer)?;

        match self {
            Proposal::Add(p) => p.mls_encode(writer),
            Proposal::Update(p) => p.mls_encode(writer),
            Proposal::Remove(p) => p.mls_encode(writer),
            Proposal::Psk(p) => p.mls_encode(writer),
            Proposal::ReInit(p) => p.mls_encode(writer),
            Proposal::ExternalInit(p) => p.mls_encode(writer),
            Proposal::GroupContextExtensions(p) => p.mls_encode(writer),

            Proposal::Custom(p) => {
                if p.proposal_type.raw_value() <= 7 {
                    return Err(aws_mls_codec::Error::Custom(
                        "custom proposal types can not be set to defined values of 0-7".to_string(),
                    ));
                }
                aws_mls_codec::byte_vec::mls_encode(&p.data, writer)
            }
        }
    }
}

impl MlsDecode for Proposal {
    fn mls_decode(reader: &mut &[u8]) -> Result<Self, aws_mls_codec::Error> {
        let proposal_type = ProposalType::mls_decode(reader)?;

        Ok(match proposal_type {
            ProposalType::ADD => Proposal::Add(AddProposal::mls_decode(reader)?),
            ProposalType::UPDATE => Proposal::Update(UpdateProposal::mls_decode(reader)?),
            ProposalType::REMOVE => Proposal::Remove(RemoveProposal::mls_decode(reader)?),
            ProposalType::PSK => Proposal::Psk(PreSharedKeyProposal::mls_decode(reader)?),
            ProposalType::RE_INIT => Proposal::ReInit(ReInitProposal::mls_decode(reader)?),
            ProposalType::EXTERNAL_INIT => {
                Proposal::ExternalInit(ExternalInit::mls_decode(reader)?)
            }
            ProposalType::GROUP_CONTEXT_EXTENSIONS => {
                Proposal::GroupContextExtensions(ExtensionList::mls_decode(reader)?)
            }
            custom => Proposal::Custom(CustomProposal {
                proposal_type: custom,
                data: aws_mls_codec::byte_vec::mls_decode(reader)?,
            }),
        })
    }
}

impl Proposal {
    pub fn proposal_type(&self) -> ProposalType {
        match self {
            Proposal::Add(_) => ProposalType::ADD,
            Proposal::Update(_) => ProposalType::UPDATE,
            Proposal::Remove(_) => ProposalType::REMOVE,
            Proposal::Psk(_) => ProposalType::PSK,
            Proposal::ReInit(_) => ProposalType::RE_INIT,
            Proposal::ExternalInit(_) => ProposalType::EXTERNAL_INIT,
            Proposal::GroupContextExtensions(_) => ProposalType::GROUP_CONTEXT_EXTENSIONS,
            Proposal::Custom(c) => c.proposal_type,
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
/// An enum that represents a borrowed version of [`Proposal`].
pub enum BorrowedProposal<'a> {
    Add(&'a AddProposal),
    Update(&'a UpdateProposal),
    Remove(&'a RemoveProposal),
    Psk(&'a PreSharedKeyProposal),
    ReInit(&'a ReInitProposal),
    ExternalInit(&'a ExternalInit),
    GroupContextExtensions(&'a ExtensionList),
    Custom(&'a CustomProposal),
}

impl<'a> From<BorrowedProposal<'a>> for Proposal {
    fn from(value: BorrowedProposal<'a>) -> Self {
        match value {
            BorrowedProposal::Add(add) => Proposal::Add(add.clone()),
            BorrowedProposal::Update(update) => Proposal::Update(update.clone()),
            BorrowedProposal::Remove(remove) => Proposal::Remove(remove.clone()),
            BorrowedProposal::Psk(psk) => Proposal::Psk(psk.clone()),
            BorrowedProposal::ReInit(reinit) => Proposal::ReInit(reinit.clone()),
            BorrowedProposal::ExternalInit(external) => Proposal::ExternalInit(external.clone()),
            BorrowedProposal::GroupContextExtensions(ext) => {
                Proposal::GroupContextExtensions(ext.clone())
            }
            BorrowedProposal::Custom(custom) => Proposal::Custom(custom.clone()),
        }
    }
}

impl BorrowedProposal<'_> {
    pub fn proposal_type(&self) -> ProposalType {
        match self {
            BorrowedProposal::Add(_) => ProposalType::ADD,
            BorrowedProposal::Update(_) => ProposalType::UPDATE,
            BorrowedProposal::Remove(_) => ProposalType::REMOVE,
            BorrowedProposal::Psk(_) => ProposalType::PSK,
            BorrowedProposal::ReInit(_) => ProposalType::RE_INIT,
            BorrowedProposal::ExternalInit(_) => ProposalType::EXTERNAL_INIT,
            BorrowedProposal::GroupContextExtensions(_) => ProposalType::GROUP_CONTEXT_EXTENSIONS,
            BorrowedProposal::Custom(c) => c.proposal_type,
        }
    }
}

impl<'a> From<&'a Proposal> for BorrowedProposal<'a> {
    fn from(p: &'a Proposal) -> Self {
        match p {
            Proposal::Add(p) => BorrowedProposal::Add(p),
            Proposal::Update(p) => BorrowedProposal::Update(p),
            Proposal::Remove(p) => BorrowedProposal::Remove(p),
            Proposal::Psk(p) => BorrowedProposal::Psk(p),
            Proposal::ReInit(p) => BorrowedProposal::ReInit(p),
            Proposal::ExternalInit(p) => BorrowedProposal::ExternalInit(p),
            Proposal::GroupContextExtensions(p) => BorrowedProposal::GroupContextExtensions(p),
            Proposal::Custom(p) => BorrowedProposal::Custom(p),
        }
    }
}

impl<'a> From<&'a AddProposal> for BorrowedProposal<'a> {
    fn from(p: &'a AddProposal) -> Self {
        Self::Add(p)
    }
}

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

impl<'a> From<&'a CustomProposal> for BorrowedProposal<'a> {
    fn from(p: &'a CustomProposal) -> Self {
        Self::Custom(p)
    }
}

#[derive(Clone, Debug, PartialEq, MlsSize, MlsEncode, MlsDecode)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[repr(u8)]
#[allow(clippy::large_enum_variant)]
pub(crate) enum ProposalOrRef {
    Proposal(Proposal) = 1u8,
    Reference(ProposalRef) = 2u8,
}

impl From<Proposal> for ProposalOrRef {
    fn from(proposal: Proposal) -> Self {
        Self::Proposal(proposal)
    }
}

impl From<ProposalRef> for ProposalOrRef {
    fn from(r: ProposalRef) -> Self {
        Self::Reference(r)
    }
}
