#[cfg(feature = "std")]
use alloc::sync::Arc;

#[cfg(not(feature = "std"))]
use portable_atomic_util::Arc;

use core::convert::Infallible;

#[cfg(feature = "std")]
use std::collections::HashMap;

#[cfg(not(feature = "std"))]
use alloc::collections::BTreeMap;

use aws_mls_core::psk::{ExternalPskId, PreSharedKey, PreSharedKeyStorage};

#[cfg(not(sync))]
use alloc::boxed::Box;
#[cfg(feature = "std")]
use std::sync::Mutex;

#[cfg(not(feature = "std"))]
use spin::Mutex;

#[derive(Clone, Debug, Default)]
/// In memory pre-shared key storage backed by a HashMap.
///
/// All clones of an instance of this type share the same underlying HashMap.
pub struct InMemoryPreSharedKeyStorage {
    #[cfg(feature = "std")]
    inner: Arc<Mutex<HashMap<ExternalPskId, PreSharedKey>>>,
    #[cfg(not(feature = "std"))]
    inner: Arc<Mutex<BTreeMap<ExternalPskId, PreSharedKey>>>,
}

impl InMemoryPreSharedKeyStorage {
    /// Insert a pre-shared key into storage.
    pub fn insert(&mut self, id: ExternalPskId, psk: PreSharedKey) {
        #[cfg(feature = "std")]
        let mut lock = self.inner.lock().unwrap();

        #[cfg(not(feature = "std"))]
        let mut lock = self.inner.lock();

        lock.insert(id, psk);
    }

    /// Get a pre-shared key by `id`.
    pub fn get(&self, id: &ExternalPskId) -> Option<PreSharedKey> {
        #[cfg(feature = "std")]
        let lock = self.inner.lock().unwrap();

        #[cfg(not(feature = "std"))]
        let lock = self.inner.lock();

        lock.get(id).cloned()
    }

    /// Delete a pre-shared key from storage.
    pub fn delete(&mut self, id: &ExternalPskId) {
        #[cfg(feature = "std")]
        let mut lock = self.inner.lock().unwrap();

        #[cfg(not(feature = "std"))]
        let mut lock = self.inner.lock();

        lock.remove(id);
    }
}

#[maybe_async::maybe_async]
impl PreSharedKeyStorage for InMemoryPreSharedKeyStorage {
    type Error = Infallible;

    async fn get(&self, id: &ExternalPskId) -> Result<Option<PreSharedKey>, Self::Error> {
        Ok(self.get(id))
    }
}
