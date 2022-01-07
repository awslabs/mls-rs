use ferriscrypt::asym::ec_key::PublicKey;

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
}

#[derive(Clone, Debug, Default)]
#[non_exhaustive]
pub struct DefaultClientConfig {
    encrypt_controls: bool,
    ratchet_tree_extension: bool,
}

impl DefaultClientConfig {
    pub fn with_control_encryption(self, yes: bool) -> Self {
        Self {
            encrypt_controls: yes,
            ..self
        }
    }

    pub fn with_ratchet_tree_extension(self, yes: bool) -> Self {
        Self {
            ratchet_tree_extension: yes,
            ..self
        }
    }
}

impl ClientConfig for DefaultClientConfig {
    fn external_signing_key(&self, _: &[u8]) -> Option<PublicKey> {
        None
    }

    fn encrypt_controls(&self) -> bool {
        self.encrypt_controls
    }

    fn ratchet_tree_extension(&self) -> bool {
        self.ratchet_tree_extension
    }
}
