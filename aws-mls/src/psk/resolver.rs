use aws_mls_core::{
    crypto::CipherSuiteProvider,
    group::GroupStateStorage,
    psk::{ExternalPskId, PreSharedKeyStorage},
};
use futures::{StreamExt, TryStreamExt};

use crate::{
    group::{epoch::EpochSecrets, state_repo::GroupStateRepository, GroupContext},
    provider::key_package::KeyPackageStorage,
};

use super::{
    secret::{PskSecret, PskSecretInput},
    JustPreSharedKeyID, PreSharedKeyID, PskError,
};

pub(crate) struct PskResolver<'a, GS, K, PS>
where
    GS: GroupStateStorage,
    PS: PreSharedKeyStorage,
    K: KeyPackageStorage,
{
    pub group_context: &'a GroupContext,
    pub current_epoch: &'a EpochSecrets,
    pub prior_epochs: &'a GroupStateRepository<GS, K>,
    pub psk_store: &'a PS,
}

impl<GS: GroupStateStorage, K: KeyPackageStorage, PS: PreSharedKeyStorage> Clone
    for PskResolver<'_, GS, K, PS>
{
    fn clone(&self) -> Self {
        Self {
            group_context: self.group_context,
            current_epoch: self.current_epoch,
            prior_epochs: self.prior_epochs,
            psk_store: self.psk_store,
        }
    }
}

impl<GS: GroupStateStorage, K: KeyPackageStorage, PS: PreSharedKeyStorage>
    PskResolver<'_, GS, K, PS>
{
    async fn resolve_resumption(
        &self,
        id: &PreSharedKeyID,
        epoch_id: u64,
    ) -> Result<PskSecretInput, PskError> {
        if epoch_id == self.group_context.epoch {
            Some(self.current_epoch.resumption_secret.clone())
        } else {
            self.prior_epochs.resumption_secret(epoch_id).await?
        }
        .ok_or(PskError::EpochNotFound(epoch_id))
        .map(|psk| PskSecretInput {
            id: id.clone(),
            psk,
        })
    }

    async fn resolve_external(
        &self,
        id: &PreSharedKeyID,
        external_id: &ExternalPskId,
    ) -> Result<PskSecretInput, PskError> {
        self.psk_store
            .get(external_id)
            .await
            .map_err(|e| PskError::PskStoreError(e.into()))?
            .ok_or_else(|| PskError::NoPskForId(external_id.clone()))
            .map(|psk| PskSecretInput {
                id: id.clone(),
                psk,
            })
    }

    async fn resolve(&self, id: &[PreSharedKeyID]) -> Result<Vec<PskSecretInput>, PskError> {
        futures::stream::iter(id.iter())
            .then(|id| async {
                match &id.key_id {
                    JustPreSharedKeyID::External(external) => {
                        self.resolve_external(id, external).await
                    }
                    JustPreSharedKeyID::Resumption(resumption) => {
                        self.resolve_resumption(id, resumption.psk_epoch).await
                    }
                }
            })
            .try_collect()
            .await
    }

    pub async fn resolve_to_secret<P: CipherSuiteProvider>(
        &self,
        id: &[PreSharedKeyID],
        cipher_suite_provider: &P,
    ) -> Result<PskSecret, PskError> {
        self.resolve(id)
            .await
            .and_then(|psk| PskSecret::calculate(&psk, cipher_suite_provider))
    }
}
