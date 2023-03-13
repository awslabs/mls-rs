use super::*;
use crate::{psk::PreSharedKeyID, tree_kem::leaf_node::LeafNode};
use std::fmt::Debug;

use aws_mls_core::tls::ByteVec;

use proposal_ref::ProposalRef;

pub use aws_mls_core::extension::ExtensionList;
pub use aws_mls_core::group::ProposalType;

#[derive(
    Clone,
    Debug,
    PartialEq,
    TlsDeserialize,
    TlsSerialize,
    TlsSize,
    serde::Deserialize,
    serde::Serialize,
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
    pub fn capabilities(&self) -> &Capabilities {
        &self.key_package.leaf_node.capabilities
    }

    /// Key package extensions that are assoiciated with the
    /// [`Member`](super::Member) that will be added by this proposal.
    pub fn key_package_extensions(&self) -> &ExtensionList {
        self.key_package.extensions()
    }

    /// Leaf node extensions that will be entered into the group state for the
    /// [`Member`](super::Member) that will be added.
    pub fn leaf_node_extensions(&self) -> &ExtensionList {
        &self.key_package.leaf_node.extensions
    }
}

#[derive(
    Clone,
    Debug,
    PartialEq,
    TlsDeserialize,
    TlsSerialize,
    TlsSize,
    serde::Deserialize,
    serde::Serialize,
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
    pub fn capabilities(&self) -> &Capabilities {
        &self.leaf_node.capabilities
    }

    /// New Leaf node extensions that will be entered into the group state for the
    /// [`Member`](super::Member) that is being updated by this proposal.
    pub fn leaf_node_extensions(&self) -> &ExtensionList {
        &self.leaf_node.extensions
    }
}

#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    TlsDeserialize,
    TlsSerialize,
    TlsSize,
    serde::Deserialize,
    serde::Serialize,
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

#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    TlsDeserialize,
    TlsSerialize,
    TlsSize,
    serde::Deserialize,
    serde::Serialize,
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
    Clone,
    Debug,
    PartialEq,
    TlsDeserialize,
    TlsSerialize,
    TlsSize,
    serde::Deserialize,
    serde::Serialize,
)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
/// A proposal to reinitialize a group using new parameters.
pub struct ReInitProposal {
    #[tls_codec(with = "crate::tls::ByteVec")]
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
    Clone,
    Debug,
    PartialEq,
    Eq,
    TlsDeserialize,
    TlsSerialize,
    TlsSize,
    serde::Deserialize,
    serde::Serialize,
)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
/// A proposal used for external commits.
pub struct ExternalInit {
    #[tls_codec(with = "crate::tls::ByteVec")]
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

impl tls_codec::Size for Proposal {
    fn tls_serialized_len(&self) -> usize {
        let inner_len = match self {
            Proposal::Add(p) => p.tls_serialized_len(),
            Proposal::Update(p) => p.tls_serialized_len(),
            Proposal::Remove(p) => p.tls_serialized_len(),
            Proposal::Psk(p) => p.tls_serialized_len(),
            Proposal::ReInit(p) => p.tls_serialized_len(),
            Proposal::ExternalInit(p) => p.tls_serialized_len(),
            Proposal::GroupContextExtensions(p) => p.tls_serialized_len(),
            Proposal::Custom(p) => ByteVec::tls_serialized_len(&p.data),
        };

        self.proposal_type().tls_serialized_len() + inner_len
    }
}

impl tls_codec::Serialize for Proposal {
    fn tls_serialize<W: std::io::Write>(&self, writer: &mut W) -> Result<usize, tls_codec::Error> {
        let type_len = self.proposal_type().tls_serialize(writer)?;

        let inner_len = match self {
            Proposal::Add(p) => p.tls_serialize(writer),
            Proposal::Update(p) => p.tls_serialize(writer),
            Proposal::Remove(p) => p.tls_serialize(writer),
            Proposal::Psk(p) => p.tls_serialize(writer),
            Proposal::ReInit(p) => p.tls_serialize(writer),
            Proposal::ExternalInit(p) => p.tls_serialize(writer),
            Proposal::GroupContextExtensions(p) => p.tls_serialize(writer),

            Proposal::Custom(p) => {
                if p.proposal_type.raw_value() <= 7 {
                    return Err(tls_codec::Error::EncodingError(
                        "custom proposal types can not be set to defined values of 0-7".to_string(),
                    ));
                }
                ByteVec::tls_serialize(&p.data, writer)
            }
        }?;

        Ok(type_len + inner_len)
    }
}

impl tls_codec::Deserialize for Proposal {
    fn tls_deserialize<R: std::io::Read>(bytes: &mut R) -> Result<Self, tls_codec::Error>
    where
        Self: Sized,
    {
        let proposal_type = ProposalType::tls_deserialize(bytes)?;

        Ok(match proposal_type {
            ProposalType::ADD => Proposal::Add(AddProposal::tls_deserialize(bytes)?),
            ProposalType::UPDATE => Proposal::Update(UpdateProposal::tls_deserialize(bytes)?),
            ProposalType::REMOVE => Proposal::Remove(RemoveProposal::tls_deserialize(bytes)?),
            ProposalType::PSK => Proposal::Psk(PreSharedKeyProposal::tls_deserialize(bytes)?),
            ProposalType::RE_INIT => Proposal::ReInit(ReInitProposal::tls_deserialize(bytes)?),
            ProposalType::EXTERNAL_INIT => {
                Proposal::ExternalInit(ExternalInit::tls_deserialize(bytes)?)
            }
            ProposalType::GROUP_CONTEXT_EXTENSIONS => {
                Proposal::GroupContextExtensions(ExtensionList::tls_deserialize(bytes)?)
            }
            custom => Proposal::Custom(CustomProposal {
                proposal_type: custom,
                data: ByteVec::tls_deserialize(bytes)?,
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
    CustomProposal(&'a CustomProposal),
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
            Proposal::Custom(p) => BorrowedProposal::CustomProposal(p),
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
        Self::CustomProposal(p)
    }
}

#[derive(Clone, Debug, PartialEq, TlsDeserialize, TlsSerialize, TlsSize)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[repr(u8)]
#[allow(clippy::large_enum_variant)]
pub(crate) enum ProposalOrRef {
    #[tls_codec(discriminant = 1)]
    Proposal(Proposal),
    Reference(ProposalRef),
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
