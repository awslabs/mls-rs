use crate::group::message_processor::RosterUpdate;
use crate::group::Member;
use crate::{cipher_suite::CipherSuite, identity::CredentialType, identity::SigningIdentity};

mod basic;
mod x509;

pub use self::basic::*;
pub use self::x509::*;

pub trait IdentityProvider {
    type Error: std::error::Error + Send + Sync + 'static;
    type IdentityEvent;

    fn validate(
        &self,
        signing_identity: &SigningIdentity,
        cipher_suite: CipherSuite,
    ) -> Result<(), Self::Error>;

    fn identity(&self, signing_id: &SigningIdentity) -> Result<Vec<u8>, Self::Error>;

    fn valid_successor(
        &self,
        predecessor: &SigningIdentity,
        successor: &SigningIdentity,
    ) -> Result<bool, Self::Error>;

    fn supported_types(&self) -> Vec<CredentialType>;

    fn identity_events(
        &self,
        update: &RosterUpdate,
        prior_roster: Vec<Member>,
    ) -> Result<Vec<Self::IdentityEvent>, Self::Error>;
}

impl<T: IdentityProvider> IdentityProvider for &T {
    type Error = T::Error;
    type IdentityEvent = T::IdentityEvent;

    fn validate(
        &self,
        signing_identity: &SigningIdentity,
        cipher_suite: CipherSuite,
    ) -> Result<(), Self::Error> {
        (*self).validate(signing_identity, cipher_suite)
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

    fn identity_events(
        &self,
        update: &RosterUpdate,
        prior_roster: Vec<Member>,
    ) -> Result<Vec<Self::IdentityEvent>, Self::Error> {
        (*self).identity_events(update, prior_roster)
    }
}
