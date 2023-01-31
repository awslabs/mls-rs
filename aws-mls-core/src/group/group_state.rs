use async_trait::async_trait;

pub trait GroupState {
    fn id(&self) -> Vec<u8>;
}

pub trait EpochRecord {
    fn id(&self) -> u64;
}

/// Group state storage
#[async_trait]
pub trait GroupStateStorage: Send + Sync {
    type Error: std::error::Error + Send + Sync + 'static;

    async fn state<T>(&self, group_id: &[u8]) -> Result<Option<T>, Self::Error>
    where
        T: GroupState + serde::Serialize + serde::de::DeserializeOwned;

    async fn epoch<T>(&self, group_id: &[u8], epoch_id: u64) -> Result<Option<T>, Self::Error>
    where
        T: EpochRecord + serde::Serialize + serde::de::DeserializeOwned;

    async fn write<ST, ET>(
        &mut self,
        state: ST,
        epoch_inserts: Vec<ET>,
        epoch_updates: Vec<ET>,
        delete_epoch_under: Option<u64>,
    ) -> Result<(), Self::Error>
    where
        ST: GroupState + serde::Serialize + serde::de::DeserializeOwned + Send + Sync,
        ET: EpochRecord + serde::Serialize + serde::de::DeserializeOwned + Send + Sync;

    async fn max_epoch_id(&self, group_id: &[u8]) -> Result<Option<u64>, Self::Error>;
}
