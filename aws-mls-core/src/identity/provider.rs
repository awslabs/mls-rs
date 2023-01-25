use crate::{
    group::{RosterEntry, RosterUpdate},
    time::MlsTime,
};
use async_trait::async_trait;

use super::{CredentialType, SigningIdentity};

#[async_trait]
pub trait IdentityProvider: Send + Sync {
    type Error: std::error::Error + Send + Sync + 'static;
    type IdentityEvent: Send;

    async fn validate(
        &self,
        signing_identity: &SigningIdentity,
        timestamp: Option<MlsTime>,
    ) -> Result<(), Self::Error>;

    async fn identity(&self, signing_id: &SigningIdentity) -> Result<Vec<u8>, Self::Error>;

    async fn valid_successor(
        &self,
        predecessor: &SigningIdentity,
        successor: &SigningIdentity,
    ) -> Result<bool, Self::Error>;

    fn supported_types(&self) -> Vec<CredentialType>;

    async fn identity_events<T: RosterEntry + 'static>(
        &self,
        update: &RosterUpdate<T>,
        prior_roster: Vec<T>,
    ) -> Result<Vec<Self::IdentityEvent>, Self::Error>
    where
        Self: Sized;
}

#[async_trait]
impl<T: IdentityProvider> IdentityProvider for &T {
    type Error = T::Error;
    type IdentityEvent = T::IdentityEvent;

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

    async fn identity_events<R: RosterEntry + 'static>(
        &self,
        update: &RosterUpdate<R>,
        prior_roster: Vec<R>,
    ) -> Result<Vec<Self::IdentityEvent>, Self::Error>
    where
        Self: Sized,
    {
        (*self).identity_events(update, prior_roster).await
    }
}
