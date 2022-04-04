use super::*;
use std::collections::VecDeque;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum EpochRepositoryError {
    #[error("Unexpected empty epoch repository")]
    EmptyRepository,
    #[error("Epoch data not found for epoch {0}")]
    EpochNotFound(u64),
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct EpochRepository {
    retention_limit: u32,
    internal_queue: VecDeque<Epoch>,
}

impl EpochRepository {
    pub fn new(epoch: Epoch, retention_limit: u32) -> Self {
        let mut internal_queue = VecDeque::with_capacity(retention_limit as usize);
        internal_queue.push_front(epoch);

        Self {
            retention_limit,
            internal_queue,
        }
    }

    pub fn add(&mut self, epoch: Epoch) -> Option<Epoch> {
        self.internal_queue.push_front(epoch);

        if self.internal_queue.len() > self.retention_limit as usize {
            self.internal_queue.pop_back()
        } else {
            None
        }
    }

    pub fn current(&self) -> Result<&Epoch, EpochRepositoryError> {
        self.internal_queue
            .front()
            .ok_or(EpochRepositoryError::EmptyRepository)
    }

    pub fn current_mut(&mut self) -> Result<&mut Epoch, EpochRepositoryError> {
        self.internal_queue
            .front_mut()
            .ok_or(EpochRepositoryError::EmptyRepository)
    }

    #[allow(unused)]
    pub fn get(&self, epoch_id: u64) -> Result<&Epoch, EpochRepositoryError> {
        self.internal_queue
            .iter()
            .find(|e| e.identifier == epoch_id)
            .ok_or(EpochRepositoryError::EpochNotFound(epoch_id))
    }

    pub fn get_mut(&mut self, epoch_id: u64) -> Result<&mut Epoch, EpochRepositoryError> {
        self.internal_queue
            .iter_mut()
            .find(|e| e.identifier == epoch_id)
            .ok_or(EpochRepositoryError::EpochNotFound(epoch_id))
    }
}

#[cfg(test)]
mod tests {
    use crate::group::epoch::test_utils::get_test_epoch;
    use assert_matches::assert_matches;

    use super::*;

    #[cfg(target_arch = "wasm32")]
    use wasm_bindgen_test::wasm_bindgen_test as test;

    fn test_epoch(identifier: u64) -> Epoch {
        let mut epoch = get_test_epoch(
            CipherSuite::Curve25519Aes128V1,
            SecureRng::gen(32).unwrap(),
            SecureRng::gen(32).unwrap(),
        );
        epoch.identifier = identifier;
        epoch
    }

    #[test]
    fn test_create() {
        let test_epoch = test_epoch(42);
        let test_repo = EpochRepository::new(test_epoch.clone(), 5);
        assert_eq!(test_repo.retention_limit, 5);
        assert_eq!(test_repo.current().unwrap(), &test_epoch);
    }

    #[test]
    fn test_current_failure() {
        // This can only happen if the repo is serialized and then tampered with
        let test_repo = EpochRepository {
            retention_limit: 5,
            internal_queue: VecDeque::new(),
        };

        assert_matches!(
            test_repo.current(),
            Err(EpochRepositoryError::EmptyRepository)
        );
    }

    #[test]
    fn test_add() {
        let original_epoch = test_epoch(42);
        let mut test_repo = EpochRepository::new(original_epoch, 5);

        let added = test_epoch(43);
        let removed = test_repo.add(added.clone());

        // No epoch should be removed because we are still under the capacity limit
        assert_eq!(removed, None);

        // The most recently added epoch is the current one
        assert_eq!(test_repo.current().unwrap(), &added);
        assert_eq!(test_repo.current_mut().unwrap(), &added);
    }

    #[test]
    fn test_add_capacity() {
        let original_epoch = test_epoch(42);
        let mut test_repo = EpochRepository::new(original_epoch.clone(), 1);

        let added = test_epoch(43);
        let removed = test_repo.add(added.clone());

        // The first value should be kicked out when the new one is added due to capacity limits
        assert_eq!(removed, Some(original_epoch));

        // The most recently added epoch is the current one
        assert_eq!(test_repo.current().unwrap(), &added);
        assert_eq!(test_repo.current_mut().unwrap(), &added);
    }

    #[test]
    fn test_get() {
        let original_epoch = test_epoch(0);
        let mut test_repo = EpochRepository::new(original_epoch.clone(), 5);

        let test_epochs: Vec<Epoch> = (1u64..5).map(test_epoch).collect();

        test_epochs.iter().for_each(|e| {
            test_repo.add(e.clone());
        });

        assert_eq!(test_repo.get(0).unwrap(), &original_epoch);
        assert_eq!(test_repo.get_mut(0).unwrap(), &original_epoch);

        test_epochs.iter().for_each(|e| {
            assert_eq!(test_repo.get(e.identifier).unwrap(), e);
            assert_eq!(test_repo.get_mut(e.identifier).unwrap(), e);
        });
    }

    #[test]
    fn test_get_not_found() {
        let original_epoch = test_epoch(42);
        let mut test_repo = EpochRepository::new(original_epoch, 1);

        assert_matches!(
            test_repo.get(1),
            Err(EpochRepositoryError::EpochNotFound(1))
        );

        assert_matches!(
            test_repo.get_mut(1),
            Err(EpochRepositoryError::EpochNotFound(1))
        );
    }
}
