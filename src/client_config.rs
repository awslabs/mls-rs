use ferriscrypt::asym::ec_key::PublicKey;

pub trait ClientConfig {
    fn external_signing_key(&self, _external_key_id: &[u8]) -> Option<PublicKey> {
        None
    }
}

#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct DefaultClientConfig;

impl Default for DefaultClientConfig {
    fn default() -> Self {
        Self
    }
}

impl ClientConfig for DefaultClientConfig {}
