use alloc::vec::Vec;
use aws_mls_core::{
    crypto::CipherSuiteProvider,
    group::GroupStateStorage,
    key_package::KeyPackageStorage,
    psk::{ExternalPskId, PreSharedKey, PreSharedKeyStorage},
};
use futures::{StreamExt, TryStreamExt};

use crate::group::{epoch::EpochSecrets, state_repo::GroupStateRepository, GroupContext};

use super::{
    secret::{PskSecret, PskSecretInput},
    JustPreSharedKeyID, PreSharedKeyID, PskError, ResumptionPsk,
};

pub(crate) struct PskResolver<'a, GS, K, PS>
where
    GS: GroupStateStorage,
    PS: PreSharedKeyStorage,
    K: KeyPackageStorage,
{
    pub group_context: Option<&'a GroupContext>,
    pub current_epoch: Option<&'a EpochSecrets>,
    pub prior_epochs: Option<&'a GroupStateRepository<GS, K>>,
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
    async fn resolve_resumption(&self, psk_id: &ResumptionPsk) -> Result<PreSharedKey, PskError> {
        if let Some(ctx) = self.group_context {
            if ctx.epoch == psk_id.psk_epoch && ctx.group_id == psk_id.psk_group_id.0 {
                let epoch = self.current_epoch.ok_or(PskError::OldGroupStateNotFound)?;
                return Ok(epoch.resumption_secret.clone());
            }
        }

        if let Some(eps) = self.prior_epochs {
            if let Some(psk) = eps.resumption_secret(psk_id).await? {
                return Ok(psk);
            }
        }

        Err(PskError::OldGroupStateNotFound)
    }

    async fn resolve_external(&self, psk_id: &ExternalPskId) -> Result<PreSharedKey, PskError> {
        self.psk_store
            .get(psk_id)
            .await
            .map_err(|e| PskError::PskStoreError(e.into()))?
            .ok_or_else(|| PskError::NoPskForId(psk_id.clone()))
    }

    async fn resolve(&self, id: &[PreSharedKeyID]) -> Result<Vec<PskSecretInput>, PskError> {
        futures::stream::iter(id.iter())
            .then(|id| async {
                let psk = match &id.key_id {
                    JustPreSharedKeyID::External(external) => self.resolve_external(external).await,
                    JustPreSharedKeyID::Resumption(resumption) => {
                        self.resolve_resumption(resumption).await
                    }
                }?;

                Ok(PskSecretInput {
                    id: id.clone(),
                    psk,
                })
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
