use crate::{
    cipher_suite::CipherSuite,
    group::Member,
    identity::{CredentialType, CREDENTIAL_TYPE_BASIC},
    identity::{SigningIdentity, SigningIdentityError},
    time::MlsTime,
};

use super::IdentityProvider;

#[derive(Clone, Debug, Default)]
pub struct BasicIdentityProvider;

impl BasicIdentityProvider {
    pub fn new() -> Self {
        Self
    }
}

impl IdentityProvider for BasicIdentityProvider {
    type Error = SigningIdentityError;
    type IdentityEvent = ();

    fn validate(
        &self,
        signing_identity: &SigningIdentity,
        cipher_suite: CipherSuite,
        _timestamp: Option<MlsTime>,
    ) -> Result<(), Self::Error> {
        // Check that using the public key won't cause errors later
        signing_identity
            .public_key(cipher_suite)
            .map(|_| ())
            .map_err(Into::into)
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
        vec![CREDENTIAL_TYPE_BASIC]
    }

    fn identity_events(
        &self,
        _update: &crate::group::message_processor::RosterUpdate,
        _prior_roster: Vec<Member>,
    ) -> Result<Vec<Self::IdentityEvent>, Self::Error> {
        Ok(vec![])
    }
}
