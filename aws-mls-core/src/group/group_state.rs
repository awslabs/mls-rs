pub trait GroupState {
    fn id(&self) -> Vec<u8>;
}

pub trait EpochRecord {
    fn id(&self) -> u64;
}

/// Group state storage
pub trait GroupStateStorage {
    type Error: std::error::Error + Send + Sync + 'static;

    fn state<T>(&self, group_id: &[u8]) -> Result<Option<T>, Self::Error>
    where
        T: GroupState + serde::Serialize + serde::de::DeserializeOwned;

    fn epoch<T>(&self, group_id: &[u8], epoch_id: u64) -> Result<Option<T>, Self::Error>
    where
        T: EpochRecord + serde::Serialize + serde::de::DeserializeOwned;

    fn write<ST, ET>(
        &mut self,
        state: ST,
        epoch_inserts: Vec<ET>,
        epoch_updates: Vec<ET>,
        delete_epoch_under: Option<u64>,
    ) -> Result<(), Self::Error>
    where
        ST: GroupState + serde::Serialize + serde::de::DeserializeOwned,
        ET: EpochRecord + serde::Serialize + serde::de::DeserializeOwned;

    fn max_epoch_id(&self, group_id: &[u8]) -> Result<Option<u64>, Self::Error>;
}
