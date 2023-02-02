use async_trait::async_trait;

use crate::crypto::HpkeSecretKey;

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[non_exhaustive]
pub struct KeyPackageData {
    pub pkg: Vec<u8>,
    pub init_key: HpkeSecretKey,
    pub leaf_node_key: HpkeSecretKey,
}

impl KeyPackageData {
    pub fn new(
        pkg: Vec<u8>,
        init_key: HpkeSecretKey,
        leaf_node_key: HpkeSecretKey,
    ) -> KeyPackageData {
        Self {
            pkg,
            init_key,
            leaf_node_key,
        }
    }
}

#[async_trait]
pub trait KeyPackageStorage: Send + Sync {
    type Error: std::error::Error + Send + Sync + 'static;

    async fn delete(&mut self, id: &[u8]) -> Result<(), Self::Error>;

    async fn insert(&mut self, id: Vec<u8>, pkg: KeyPackageData) -> Result<(), Self::Error>;

    async fn get(&self, id: &[u8]) -> Result<Option<KeyPackageData>, Self::Error>;
}
