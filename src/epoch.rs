use indexmap::IndexMap;
use std::{
    convert::Infallible,
    sync::{Arc, Mutex},
};

const DEFAULT_EPOCH_RETENTION_LIMIT: usize = 3;

#[derive(Clone, Debug, PartialEq)]
pub struct Epoch(crate::group::epoch::Epoch);

impl Epoch {
    pub fn id(&self) -> u64 {
        self.0.identifier
    }

    pub(crate) fn into_inner(self) -> crate::group::epoch::Epoch {
        self.0
    }

    pub(crate) fn inner_mut(&mut self) -> &mut crate::group::epoch::Epoch {
        &mut self.0
    }
}

impl From<crate::group::epoch::Epoch> for Epoch {
    fn from(e: crate::group::epoch::Epoch) -> Self {
        Epoch(e)
    }
}

pub trait EpochRepository {
    type Error: std::error::Error + Send + Sync + 'static;

    fn get(&self, epoch_id: u64) -> Result<Option<Epoch>, Self::Error>;
    fn insert(&mut self, epoch: Epoch) -> Result<(), Self::Error>;
}

#[derive(Clone, Debug)]
pub struct InMemoryEpochRepository {
    inner: Arc<Mutex<IndexMap<u64, Epoch>>>,
    retention_limit: usize,
}

impl InMemoryEpochRepository {
    fn new() -> Self {
        Self {
            inner: Default::default(),
            retention_limit: DEFAULT_EPOCH_RETENTION_LIMIT,
        }
    }

    fn get(&self, epoch_id: u64) -> Option<Epoch> {
        self.inner.lock().unwrap().get(&epoch_id).cloned()
    }

    fn insert(&self, epoch: Epoch) {
        let mut map = self.inner.lock().unwrap();
        map.insert(epoch.id(), epoch);
        if map.len() > self.retention_limit {
            map.shift_remove_index(0);
        }
    }
}

impl Default for InMemoryEpochRepository {
    fn default() -> Self {
        Self::new()
    }
}

impl EpochRepository for InMemoryEpochRepository {
    type Error = Infallible;

    fn get(&self, epoch_id: u64) -> Result<Option<Epoch>, Self::Error> {
        Ok(self.get(epoch_id))
    }

    fn insert(&mut self, epoch: Epoch) -> Result<(), Self::Error> {
        (*self).insert(epoch);
        Ok(())
    }
}