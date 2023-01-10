use std::convert::Infallible;

use aws_mls_core::{
    group::{RosterEntry, RosterUpdate},
    identity::IdentityProvider,
};

use crate::{
    identity::SigningIdentity,
    identity::{BasicCredential, CredentialType},
    time::MlsTime,
};

#[derive(Clone, Debug, Default)]
pub struct BasicIdentityProvider;

impl BasicIdentityProvider {
    pub fn new() -> Self {
        Self
    }
}

impl IdentityProvider for BasicIdentityProvider {
    type Error = Infallible;
    type IdentityEvent = ();

    fn validate(
        &self,
        _signing_identity: &SigningIdentity,
        _timestamp: Option<MlsTime>,
    ) -> Result<(), Self::Error> {
        //TODO: Is it actually beneficial to check the key, or does that already happen elsewhere before
        //this point?
        Ok(())
    }

    fn identity(&self, signing_id: &SigningIdentity) -> Result<Vec<u8>, Self::Error> {
        Ok(signing_id.credential.credential_data.clone())
    }

    fn valid_successor(
        &self,
        predecessor: &SigningIdentity,
        successor: &SigningIdentity,
    ) -> Result<bool, Self::Error> {
        Ok(predecessor.credential.credential_data == successor.credential.credential_data)
    }

    fn supported_types(&self) -> Vec<CredentialType> {
        vec![BasicCredential::credential_type()]
    }

    fn identity_events<T: RosterEntry>(
        &self,
        _update: &RosterUpdate<T>,
        _prior_roster: Vec<T>,
    ) -> Result<Vec<Self::IdentityEvent>, Self::Error> {
        Ok(vec![])
    }
}
