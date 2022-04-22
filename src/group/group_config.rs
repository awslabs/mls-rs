use crate::{EpochRepository, InMemoryEpochRepository};

pub trait GroupConfig {
    type EpochRepository: EpochRepository;

    fn epoch_repo(&self) -> Self::EpochRepository;
}

#[derive(Clone, Debug, Default)]
pub struct InMemoryGroupConfig {
    pub epoch_repo: InMemoryEpochRepository,
}

impl GroupConfig for InMemoryGroupConfig {
    type EpochRepository = InMemoryEpochRepository;

    fn epoch_repo(&self) -> InMemoryEpochRepository {
        self.epoch_repo.clone()
    }
}
