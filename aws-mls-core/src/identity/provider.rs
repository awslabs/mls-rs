use crate::{error::IntoAnyError, extension::ExtensionList, group::RosterUpdate, time::MlsTime};
use alloc::boxed::Box;
use alloc::vec::Vec;

use super::{CredentialType, SigningIdentity};

#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
/// Customizable identity warning returned by an [`IdentityProvider`].
pub struct IdentityWarning {
    member_index: u32,
    code: u64,
}

impl IdentityWarning {
    /// Create a new identity warning.
    pub fn new(member_index: u32, code: u64) -> IdentityWarning {
        IdentityWarning { member_index, code }
    }

    /// Index in the group roster associated with this warning.
    pub fn member_index(&self) -> u32 {
        self.member_index
    }

    /// Code to indicate the reason for the warning.
    pub fn code(&self) -> u64 {
        self.code
    }
}

/// Identity system that can be used to validate a
/// [`SigningIdentity`](aws-mls-core::identity::SigningIdentity)
#[maybe_async::maybe_async]
pub trait IdentityProvider: Send + Sync {
    /// Error type that this provider returns on internal failure.
    type Error: IntoAnyError;

    /// Determine if `signing_identity` is valid for a group member.
    ///
    /// A `timestamp` value can optionally be supplied to aid with validation
    /// of a [`Credential`](aws-mls-core::identity::Credential) that requires
    /// time based context. For example, X.509 certificates can become expired.
    async fn validate_member(
        &self,
        signing_identity: &SigningIdentity,
        timestamp: Option<MlsTime>,
        extensions: Option<&ExtensionList>,
    ) -> Result<(), Self::Error>;

    /// Determine if `signing_identity` is valid for an external sender in
    /// [`ExternalSendersExt`](crate::extension::ExternalSendersExt) stored in the
    /// group context.
    ///
    /// A `timestamp` value can optionally be supplied to aid with validation
    /// of a [`Credential`](aws-mls-core::identity::Credential) that requires
    /// time based context. For example, X.509 certificates can become expired.
    #[cfg(feature = "external_proposal")]
    async fn validate_external_sender(
        &self,
        signing_identity: &SigningIdentity,
        timestamp: Option<MlsTime>,
        extensions: Option<&ExtensionList>,
    ) -> Result<(), Self::Error>;

    /// A unique identifier for `signing_identity`.
    ///
    /// The MLS protocol requires that each member of a group has a unique
    /// set of identifiers according to the application.
    async fn identity(&self, signing_identity: &SigningIdentity) -> Result<Vec<u8>, Self::Error>;

    /// Determines if `successor` can remove `predecessor` as part of an external commit.
    ///
    /// The MLS protocol allows for removal of an existing member when adding a
    /// new member via external commit. This function determines if a removal
    /// should be allowed by providing the target member to be removed as
    /// `predecessor` and the new member as `successor`.
    async fn valid_successor(
        &self,
        predecessor: &SigningIdentity,
        successor: &SigningIdentity,
    ) -> Result<bool, Self::Error>;

    /// Credential types that are supported by this provider.
    fn supported_types(&self) -> Vec<CredentialType>;

    /// Throw warnings based on changes to a group roster.
    ///
    /// For example, if a credential consists of only a public key an
    /// application may want to issue a warning the key has changed to
    /// existing members rather than say the new credential is invalid.
    async fn identity_warnings(
        &self,
        update: &RosterUpdate,
    ) -> Result<Vec<IdentityWarning>, Self::Error>
    where
        Self: Sized;
}
