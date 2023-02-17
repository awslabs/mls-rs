use crate::{identity::CredentialType, identity::SigningIdentity, time::MlsTime};
use async_trait::async_trait;
use aws_mls_core::{
    group::RosterUpdate,
    identity::{IdentityProvider, IdentityWarning},
};
use thiserror::Error;

pub use aws_mls_core::identity::BasicCredential;

#[derive(Debug, Error)]
#[error("unsupported credential type found: {0:?}")]
pub struct BasicCredentialError(CredentialType);

impl From<CredentialType> for BasicCredentialError {
    fn from(value: CredentialType) -> Self {
        BasicCredentialError(value)
    }
}

impl BasicCredentialError {
    pub fn credential_type(&self) -> CredentialType {
        self.0
    }
}

#[derive(Clone, Debug, Default)]
pub struct BasicIdentityProvider;

impl BasicIdentityProvider {
    pub fn new() -> Self {
        Self
    }
}

fn resolve_basic_identity(
    signing_id: &SigningIdentity,
) -> Result<&BasicCredential, BasicCredentialError> {
    signing_id
        .credential
        .as_basic()
        .ok_or_else(|| BasicCredentialError(signing_id.credential.credential_type()))
}

#[async_trait]
impl IdentityProvider for BasicIdentityProvider {
    type Error = BasicCredentialError;

    async fn validate(
        &self,
        _signing_identity: &SigningIdentity,
        _timestamp: Option<MlsTime>,
    ) -> Result<(), Self::Error> {
        //TODO: Is it actually beneficial to check the key, or does that already happen elsewhere before
        //this point?
        Ok(())
    }

    async fn identity(&self, signing_id: &SigningIdentity) -> Result<Vec<u8>, Self::Error> {
        resolve_basic_identity(signing_id).map(|b| b.identifier().to_vec())
    }

    async fn valid_successor(
        &self,
        predecessor: &SigningIdentity,
        successor: &SigningIdentity,
    ) -> Result<bool, Self::Error> {
        Ok(resolve_basic_identity(predecessor)? == resolve_basic_identity(successor)?)
    }

    fn supported_types(&self) -> Vec<CredentialType> {
        vec![BasicCredential::credential_type()]
    }

    async fn identity_warnings(
        &self,
        _update: &RosterUpdate,
    ) -> Result<Vec<IdentityWarning>, Self::Error> {
        Ok(vec![])
    }
}
