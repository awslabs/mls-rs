use crate::{group::RosterUpdate, time::MlsTime};
use async_trait::async_trait;

use super::{CredentialType, SigningIdentity};

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
/// Customizable identity warning returned by an [`IdentityProvider`].
pub struct IdentityWarning {
    pub member_index: u32,
    pub code: u64,
}

#[async_trait]
/// Identity system that can be used to validate a
/// [`SigningIdentity`](aws-mls-core::identity::SigningIdentity)
pub trait IdentityProvider: Send + Sync {
    /// Error type that this provider returns on internal failure.
    type Error: std::error::Error + Send + Sync + 'static;

    /// Determine if `signing_identity` is valid.
    ///
    /// A `timestamp` value can optionally be supplied to aid with validation
    /// of a [`Credential`](aws-mls-core::identity::Credential) that requires
    /// time based context. For example, X.509 certificates can become expired.
    async fn validate(
        &self,
        signing_identity: &SigningIdentity,
        timestamp: Option<MlsTime>,
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

#[async_trait]
impl<T: IdentityProvider> IdentityProvider for &T {
    type Error = T::Error;

    async fn validate(
        &self,
        signing_identity: &SigningIdentity,
        timestamp: Option<MlsTime>,
    ) -> Result<(), Self::Error> {
        (*self).validate(signing_identity, timestamp).await
    }

    async fn identity(&self, signing_id: &SigningIdentity) -> Result<Vec<u8>, Self::Error> {
        (*self).identity(signing_id).await
    }

    async fn valid_successor(
        &self,
        predecessor: &SigningIdentity,
        successor: &SigningIdentity,
    ) -> Result<bool, Self::Error> {
        (*self).valid_successor(predecessor, successor).await
    }

    fn supported_types(&self) -> Vec<CredentialType> {
        (*self).supported_types()
    }

    async fn identity_warnings(
        &self,
        update: &RosterUpdate,
    ) -> Result<Vec<IdentityWarning>, Self::Error>
    where
        Self: Sized,
    {
        (*self).identity_warnings(update).await
    }
}
