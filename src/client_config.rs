use ferriscrypt::asym::ec_key::PublicKey;
use std::collections::HashMap;

pub trait ClientConfig {
    fn external_signing_key(&self, external_key_id: &[u8]) -> Option<PublicKey> {
        DefaultClientConfig::default().external_signing_key(external_key_id)
    }

    fn encrypt_controls(&self) -> bool {
        DefaultClientConfig::default().encrypt_controls()
    }

    fn ratchet_tree_extension(&self) -> bool {
        DefaultClientConfig::default().ratchet_tree_extension()
    }

    fn external_key_id(&self) -> Option<Vec<u8>> {
        DefaultClientConfig::default().external_key_id()
    }
}

#[derive(Clone, Debug, Default)]
#[non_exhaustive]
pub struct DefaultClientConfig {
    encrypt_controls: bool,
    ratchet_tree_extension: bool,
    external_signing_keys: HashMap<Vec<u8>, PublicKey>,
    external_key_id: Option<Vec<u8>>,
}

impl DefaultClientConfig {
    #[must_use]
    pub fn with_control_encryption(self, yes: bool) -> Self {
        Self {
            encrypt_controls: yes,
            ..self
        }
    }

    #[must_use]
    pub fn with_ratchet_tree_extension(self, yes: bool) -> Self {
        Self {
            ratchet_tree_extension: yes,
            ..self
        }
    }

    #[must_use]
    pub fn with_external_signing_key(mut self, id: Vec<u8>, key: PublicKey) -> Self {
        self.external_signing_keys.insert(id, key);
        self
    }

    #[must_use]
    pub fn with_external_key_id(self, id: Vec<u8>) -> Self {
        Self {
            external_key_id: Some(id),
            ..self
        }
    }
}

impl ClientConfig for DefaultClientConfig {
    fn external_signing_key(&self, external_key_id: &[u8]) -> Option<PublicKey> {
        self.external_signing_keys.get(external_key_id).cloned()
    }

    fn encrypt_controls(&self) -> bool {
        self.encrypt_controls
    }

    fn ratchet_tree_extension(&self) -> bool {
        self.ratchet_tree_extension
    }

    fn external_key_id(&self) -> Option<Vec<u8>> {
        self.external_key_id.clone()
    }
}
