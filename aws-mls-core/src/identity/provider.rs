use crate::{
    group::{RosterEntry, RosterUpdate},
    time::MlsTime,
};

use super::{CredentialType, SigningIdentity};

pub trait IdentityProvider {
    type Error: std::error::Error + Send + Sync + 'static;
    type IdentityEvent;

    fn validate(
        &self,
        signing_identity: &SigningIdentity,
        timestamp: Option<MlsTime>,
    ) -> Result<(), Self::Error>;

    fn identity(&self, signing_id: &SigningIdentity) -> Result<Vec<u8>, Self::Error>;

    fn valid_successor(
        &self,
        predecessor: &SigningIdentity,
        successor: &SigningIdentity,
    ) -> Result<bool, Self::Error>;

    fn supported_types(&self) -> Vec<CredentialType>;

    fn identity_events<T: RosterEntry + 'static>(
        &self,
        update: &RosterUpdate<T>,
        prior_roster: Vec<T>,
    ) -> Result<Vec<Self::IdentityEvent>, Self::Error>
    where
        Self: Sized;
}

impl<T: IdentityProvider> IdentityProvider for &T {
    type Error = T::Error;
    type IdentityEvent = T::IdentityEvent;

    fn validate(
        &self,
        signing_identity: &SigningIdentity,
        timestamp: Option<MlsTime>,
    ) -> Result<(), Self::Error> {
        (*self).validate(signing_identity, timestamp)
    }

    fn identity(&self, signing_id: &SigningIdentity) -> Result<Vec<u8>, Self::Error> {
        (*self).identity(signing_id)
    }

    fn valid_successor(
        &self,
        predecessor: &SigningIdentity,
        successor: &SigningIdentity,
    ) -> Result<bool, Self::Error> {
        (*self).valid_successor(predecessor, successor)
    }

    fn supported_types(&self) -> Vec<CredentialType> {
        (*self).supported_types()
    }

    fn identity_events<R: RosterEntry + 'static>(
        &self,
        update: &RosterUpdate<R>,
        prior_roster: Vec<R>,
    ) -> Result<Vec<Self::IdentityEvent>, Self::Error>
    where
        Self: Sized,
    {
        (*self).identity_events(update, prior_roster)
    }
}
