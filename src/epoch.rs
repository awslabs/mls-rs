#[cfg(feature = "benchmark")]
use crate::group::secret_tree::SecretTree;

use std::{
    collections::{HashMap, VecDeque},
    sync::{Arc, Mutex},
};
use thiserror::Error;

const DEFAULT_EPOCH_RETENTION_LIMIT: usize = 3;

#[derive(Clone, Debug, PartialEq)]
pub struct Epoch(crate::group::epoch::Epoch);

impl Epoch {
    pub(crate) fn inner(&self) -> &crate::group::epoch::Epoch {
        &self.0
    }

    pub(crate) fn into_inner(self) -> crate::group::epoch::Epoch {
        self.0
    }

    pub(crate) fn inner_mut(&mut self) -> &mut crate::group::epoch::Epoch {
        &mut self.0
    }

    #[cfg(feature = "benchmark")]
    pub fn secret_tree(&self) -> &SecretTree {
        self.0.get_secret_tree()
    }
}

impl From<crate::group::epoch::Epoch> for Epoch {
    fn from(e: crate::group::epoch::Epoch) -> Self {
        Epoch(e)
    }
}

pub trait EpochRepository {
    type Error: std::error::Error + Send + Sync + 'static;

    fn get(&self, group_id: &[u8], epoch_id: u64) -> Result<Option<Epoch>, Self::Error>;
    fn insert(&mut self, epoch: Epoch) -> Result<(), Self::Error>;
}

#[derive(Debug, Error)]
pub enum InMemoryEpochRepositoryError {
    #[error("Invalid insert of epoch id {0}, repository max epoch value is {1}")]
    InvalidInsert(u64, u64),
}

#[derive(Clone, Debug)]
pub struct InMemoryEpochRepository {
    inner: Arc<Mutex<HashMap<Vec<u8>, VecDeque<Epoch>>>>,
    retention_limit: usize,
}

impl InMemoryEpochRepository {
    fn new() -> Self {
        Self {
            inner: Default::default(),
            retention_limit: DEFAULT_EPOCH_RETENTION_LIMIT,
        }
    }

    fn get(&self, group_id: &[u8], epoch_id: u64) -> Option<Epoch> {
        let map = self.inner.lock().unwrap();

        map.get(group_id).and_then(|epoch_vec| {
            epoch_vec
                .front()
                .map(|e| e.inner().context.epoch)
                .and_then(|front| {
                    if epoch_id > front {
                        return None;
                    }

                    epoch_vec.get((front - epoch_id) as usize).cloned()
                })
        })
    }

    fn insert(&self, epoch: Epoch) -> Result<(), InMemoryEpochRepositoryError> {
        let mut map = self.inner.lock().unwrap();
        let group_id = &epoch.inner().context.group_id;

        let vec = map
            .entry(group_id.to_vec())
            .or_insert_with(Default::default);

        if let Some(front) = vec.front() {
            let front_epoch = front.inner().context.epoch;
            let epoch_id = epoch.inner().context.epoch;

            if epoch_id == front_epoch + 1 {
                vec.push_front(epoch);
            } else if front_epoch >= epoch_id {
                if let Some(e) = vec.get_mut((front_epoch - epoch_id) as usize) {
                    *e = epoch;
                } else {
                    return Err(InMemoryEpochRepositoryError::InvalidInsert(
                        epoch_id,
                        front_epoch,
                    ));
                }
            } else {
                return Err(InMemoryEpochRepositoryError::InvalidInsert(
                    epoch_id,
                    front_epoch,
                ));
            }
        } else {
            vec.push_front(epoch)
        }

        if vec.len() > self.retention_limit {
            vec.pop_back();
        }

        Ok(())
    }
}

impl Default for InMemoryEpochRepository {
    fn default() -> Self {
        Self::new()
    }
}

impl EpochRepository for InMemoryEpochRepository {
    type Error = InMemoryEpochRepositoryError;

    fn get(&self, group_id: &[u8], epoch_id: u64) -> Result<Option<Epoch>, Self::Error> {
        Ok(self.get(group_id, epoch_id))
    }

    fn insert(&mut self, epoch: Epoch) -> Result<(), Self::Error> {
        (*self).insert(epoch)
    }
}

#[cfg(test)]
mod tests {
    use assert_matches::assert_matches;

    use crate::{cipher_suite::CipherSuite, group::epoch::test_utils::get_test_epoch};

    use super::*;

    const TEST_CIPHER_SUITE: CipherSuite = CipherSuite::Curve25519Aes128;

    #[test]
    fn test_in_memory_repository() {
        let repo = InMemoryEpochRepository::new();

        let mut test_epoch_1 = get_test_epoch(TEST_CIPHER_SUITE);
        let mut test_epoch_2 = get_test_epoch(TEST_CIPHER_SUITE);

        test_epoch_1.context.epoch = 1;
        test_epoch_2.context.epoch = 2;

        repo.insert(Epoch(test_epoch_1.clone())).unwrap();
        repo.insert(Epoch(test_epoch_2.clone())).unwrap();

        assert_eq!(
            repo.get(&test_epoch_1.context.group_id, 1),
            Some(Epoch(test_epoch_1.clone()))
        );

        assert_eq!(
            repo.get(&test_epoch_1.context.group_id, 2),
            Some(Epoch(test_epoch_2))
        );

        assert_eq!(repo.get(&test_epoch_1.context.group_id, 3), None);
    }

    #[test]
    fn test_in_memory_repository_invalid_insert() {
        let repo = InMemoryEpochRepository::new();

        let mut test_epoch_1 = get_test_epoch(TEST_CIPHER_SUITE);
        let mut test_epoch_2 = get_test_epoch(TEST_CIPHER_SUITE);

        test_epoch_1.context.epoch = 1;
        test_epoch_2.context.epoch = 3;

        repo.insert(Epoch(test_epoch_1)).unwrap();
        let res = repo.insert(Epoch(test_epoch_2));

        assert_matches!(res, Err(InMemoryEpochRepositoryError::InvalidInsert(3, 1)));
    }
}
