use crate::{group::RosterUpdate, time::MlsTime};
use async_trait::async_trait;

use super::{CredentialType, SigningIdentity};

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct IdentityWarning {
    member_index: u32,
    code: u64,
}

#[async_trait]
pub trait IdentityProvider: Send + Sync {
    type Error: std::error::Error + Send + Sync + 'static;

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

    async fn identity_events(
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

    async fn identity_events(
        &self,
        update: &RosterUpdate,
    ) -> Result<Vec<IdentityWarning>, Self::Error>
    where
        Self: Sized,
    {
        (*self).identity_events(update).await
    }
}
