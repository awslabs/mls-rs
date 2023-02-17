use std::{
    collections::HashMap,
    convert::Infallible,
    sync::{Arc, Mutex},
};

use async_trait::async_trait;
use aws_mls_core::psk::{ExternalPskId, PreSharedKey, PreSharedKeyStorage};

#[derive(Clone, Debug, Default)]
/// In memory pre-shared key storage backed by a HashMap.
///
/// All clones of an instance of this type share the same underlying HashMap.
pub struct InMemoryPreSharedKeyStorage {
    inner: Arc<Mutex<HashMap<ExternalPskId, PreSharedKey>>>,
}

impl InMemoryPreSharedKeyStorage {
    /// Insert a pre-shared key into storage.
    pub fn insert(&mut self, id: ExternalPskId, psk: PreSharedKey) {
        self.inner.lock().unwrap().insert(id, psk);
    }

    /// Get a pre-shared key by `id`.
    pub fn get(&self, id: &ExternalPskId) -> Option<PreSharedKey> {
        self.inner.lock().unwrap().get(id).cloned()
    }

    /// Delete a pre-shared key from storage.
    pub fn delete(&mut self, id: &ExternalPskId) {
        self.inner.lock().unwrap().remove(id);
    }
}

#[async_trait]
impl PreSharedKeyStorage for InMemoryPreSharedKeyStorage {
    type Error = Infallible;

    async fn get(&self, id: &ExternalPskId) -> Result<Option<PreSharedKey>, Self::Error> {
        Ok(self.get(id))
    }
}
